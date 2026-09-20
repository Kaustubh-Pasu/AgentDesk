"""Scraper isolation: the crawl runs in a separate, secret-less service (``SERVICE_ROLE=scraper``).

The desk talks to it over the private network with ONE typed request (a URL that already passed our URL policy)
and gets back bounded extracted TEXT — never raw HTML, never anything executable. The response is re-validated
here because the scraper handles hostile input and is therefore itself treated as less trusted.
With ``SCRAPER_URL`` empty (development / single-process role ``all``) the same crawler runs in-process.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.ingestion import policy
from app.ingestion.html_extract import ExtractedPage
from app.ingestion.safe_fetch import CrawlResult, FetchError, SafeFetcher
from app.security.ssrf import IMPORT_URL_POLICY, SSRFBlocked, validate_url
from app.settings import Settings


class Crawler(Protocol):
    async def crawl(self, start_url: str) -> CrawlResult: ...


class _Page(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(max_length=2048)
    title: str = Field("", max_length=200)
    description: str = Field("", max_length=500)
    headings: list[str] = Field(default_factory=list, max_length=40)
    text: str = Field("", max_length=policy.MAX_TEXT_CHARS_PER_PAGE)
    structured: list[dict[str, Any]] = Field(default_factory=list, max_length=5)


class _CrawlResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pages: list[_Page] = Field(max_length=policy.MAX_PAGES)
    bytes_fetched: int = Field(ge=0, le=policy.MAX_TOTAL_BYTES)
    skipped: list[tuple[str, str]] = Field(default_factory=list, max_length=100)


def scraper_routes(settings: Settings, fetcher: SafeFetcher | None = None) -> list[Route]:
    """Routes of the scraper service. It has no DB, no Redis, no PAT, no session secret in its environment."""
    fetcher = fetcher or SafeFetcher(settings)

    async def crawl(request: Request) -> JSONResponse:
        try:
            body = await request.json()
            url = body["url"] if isinstance(body, dict) and isinstance(body.get("url"), str) else ""
            result = await fetcher.crawl(url)
        except (SSRFBlocked, FetchError) as exc:
            return JSONResponse({"error": {"code": exc.code}}, 422)
        except (ValueError, KeyError):
            return JSONResponse({"error": {"code": "bad_request"}}, 400)
        pages = [
            {
                "url": p.url,
                "title": p.title,
                "description": p.description,
                "headings": p.headings,
                "text": p.text,
                "structured": p.structured,
            }
            for p in result.pages
        ]
        return JSONResponse(
            {"pages": pages, "bytes_fetched": result.bytes_fetched, "skipped": result.skipped[:100]}
        )

    return [Route("/internal/crawl", crawl, methods=["POST"])]


class RemoteScraper:
    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport

    async def crawl(self, start_url: str) -> CrawlResult:
        validate_url(start_url, IMPORT_URL_POLICY)  # never even ask the scraper for a URL that fails policy
        try:
            async with httpx.AsyncClient(
                timeout=policy.CRAWL_WALL_CLOCK_S + 15,
                trust_env=False,
                follow_redirects=False,
                transport=self._transport,
            ) as client:
                response = await client.post(
                    f"{self._settings.scraper_url.rstrip('/')}/internal/crawl", json={"url": start_url}
                )
        except httpx.HTTPError as exc:
            raise FetchError("scraper_unavailable", type(exc).__name__) from exc
        if response.status_code == 422:
            try:
                code = str(response.json()["error"]["code"])[:64]
            except (ValueError, KeyError, TypeError):
                code = "fetch_failed"
            raise FetchError(code)
        if response.status_code != 200 or len(response.content) > 4 * 1024 * 1024:
            raise FetchError("scraper_unavailable", f"HTTP {response.status_code}")
        try:
            parsed = _CrawlResponse.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise FetchError("scraper_bad_response") from exc
        pages = [
            ExtractedPage(
                url=p.url,
                title=p.title,
                description=p.description,
                headings=p.headings,
                text=p.text,
                structured=p.structured,
            )
            for p in parsed.pages
        ]
        return CrawlResult(pages=pages, bytes_fetched=parsed.bytes_fetched, skipped=list(parsed.skipped))


def build_crawler(settings: Settings) -> Crawler:
    return RemoteScraper(settings) if settings.scraper_url else SafeFetcher(settings)
