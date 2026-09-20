"""Safe website fetcher/crawler — the HIGH-RISK SSRF boundary of CREATE.

- https only, port 443 only, no IP literals/userinfo/odd hosts (``validate_url``), on the start URL AND every hop.
- DNS is resolved by us, every answer must be globally routable, and the validated address is the one connected
  to (``PinnedTransport``), so DNS rebinding between check and use is impossible.
- Redirects are followed manually (max 3) with the full validation per hop. No cookies, no auth, no referer.
- text/html and text/plain only; 2 MiB/page decoded, 10 MiB/import, 10 pages, depth 2, 60 s wall clock.
- This module holds no secrets and needs none: it runs in the isolated scraper service in production.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from dataclasses import dataclass, field

import httpx

from app.ingestion import policy
from app.ingestion.html_extract import ExtractedPage, extract_html, extract_plain
from app.logging_config import get_logger
from app.security.breakers import Feature, require
from app.security.ssrf import IMPORT_URL_POLICY, SafeClientConfig, SSRFBlocked, build_safe_client, read_capped, validate_url
from app.settings import Settings

log = get_logger("ingestion.fetch")


class FetchError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail[:200]


@dataclass
class CrawlResult:
    pages: list[ExtractedPage] = field(default_factory=list)
    bytes_fetched: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (url, safe error code)


class SafeFetcher:
    def __init__(self, settings: Settings, client_config: SafeClientConfig | None = None) -> None:
        self._settings = settings
        self._config = client_config or SafeClientConfig(url_policy=IMPORT_URL_POLICY)

    async def fetch(self, url: str, *, budget: int = policy.MAX_PAGE_BYTES) -> tuple[str, str, bytes]:
        """GET one page. Returns (final_url, media_type, decoded_body)."""
        require(self._settings, Feature.EXTERNAL_FETCH)
        current = validate_url(url, self._config.url_policy).url
        async with build_safe_client(self._config) as client:
            for _hop in range(policy.MAX_REDIRECTS + 1):
                try:
                    async with client.stream("GET", current, headers={"Accept": "text/html, text/plain;q=0.8"}) as response:
                        if response.status_code in (301, 302, 303, 307, 308):
                            location = response.headers.get("location", "")
                            if not location:
                                raise FetchError("redirect_invalid", "redirect without Location")
                            # full URL policy on every hop; DNS/IP policy is re-applied by the transport on connect
                            current = validate_url(str(response.url.join(location)).split("#", 1)[0], self._config.url_policy).url
                            continue
                        if response.status_code != 200:
                            raise FetchError("http_status", f"HTTP {response.status_code}")
                        media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        if media_type not in policy.ALLOWED_CONTENT_TYPES:
                            raise FetchError("content_type_not_allowed", media_type[:60])
                        body = await read_capped(response, min(policy.MAX_PAGE_BYTES, budget))
                        return current, media_type, body
                except httpx.HTTPError as exc:
                    raise FetchError("unreachable", type(exc).__name__) from exc
        raise FetchError("too_many_redirects", f"more than {policy.MAX_REDIRECTS} redirects")

    async def crawl(self, start_url: str) -> CrawlResult:
        """Breadth-first, same-host crawl within the hard page/depth/size/time budgets."""
        start = validate_url(start_url, self._config.url_policy)
        result = CrawlResult()
        site_host = start.host
        queue: deque[tuple[str, int]] = deque([(start.url, 0)])
        seen = {start.url}
        deadline = time.monotonic() + policy.CRAWL_WALL_CLOCK_S
        while queue and len(result.pages) < policy.MAX_PAGES:
            url, depth = queue.popleft()
            remaining_bytes = policy.MAX_TOTAL_BYTES - result.bytes_fetched
            remaining_time = deadline - time.monotonic()
            if remaining_bytes <= 0 or remaining_time <= 0:
                result.skipped.append((url, "budget_exhausted"))
                break
            try:
                final_url, media_type, body = await asyncio.wait_for(self.fetch(url, budget=remaining_bytes), remaining_time)
            except (SSRFBlocked, FetchError) as exc:
                if not result.pages and depth == 0:
                    raise  # the start page itself failed: surface the precise safe code to the owner
                result.skipped.append((url, exc.code))
                continue
            except TimeoutError:
                if not result.pages:
                    raise FetchError("timeout", "import exceeded its time budget") from None
                result.skipped.append((url, "timeout"))
                break
            final_host = validate_url(final_url, self._config.url_policy).host
            if depth == 0 and final_host in (f"www.{site_host}", site_host.removeprefix("www.")):
                site_host = final_host  # apex ↔ www canonicalisation of the start page is the same site
            if final_host != site_host:
                if depth == 0 and not result.pages:
                    raise FetchError("redirect_off_site", "start URL redirects to a different host")
                result.skipped.append((url, "redirect_off_site"))
                continue
            result.bytes_fetched += len(body)
            page = extract_html(body, final_url) if media_type == "text/html" else extract_plain(body, final_url)
            result.pages.append(page)
            if depth < policy.MAX_DEPTH:
                for link in page.links:
                    if link not in seen and len(seen) < policy.MAX_PAGES * 6:
                        seen.add(link)
                        queue.append((link, depth + 1))
        log.info("crawl finished", extra={"pages": len(result.pages), "bytes": result.bytes_fetched, "skipped": len(result.skipped)})
        return result
