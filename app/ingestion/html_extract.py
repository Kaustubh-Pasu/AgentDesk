"""Static HTML → bounded visible-ish text. No JavaScript, no plugins, no subresource loading — just parsing.

Everything that comes out of this module is UNTRUSTED TEXT. Hidden content, comments, scripts, styles, forms and
meta instructions are dropped so the most common injection carriers never reach the extraction model; whatever
injection text remains is harmless because the model that reads it has no tools, no secrets and no network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup, Comment, Tag

from app.ingestion import policy
from app.models.schemas import clean_text

_DROP_TAGS = ("script", "style", "noscript", "template", "iframe", "frame", "frameset", "object", "embed", "applet", "svg",
              "canvas", "form", "input", "button", "select", "textarea", "link", "meta", "base", "audio", "video", "source",
              "dialog")
_HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(\.0+)?\s*(;|$)", re.I)
_JSONLD_KEYS = ("name", "description", "telephone", "email", "address", "openingHours", "openingHoursSpecification",
                "priceRange", "servesCuisine", "url")
_BUSINESS_TYPES = re.compile(r"business|restaurant|cafe|store|organization|shop|service|hotel|clinic|salon|bakery|bar", re.I)


@dataclass
class ExtractedPage:
    url: str
    title: str = ""
    description: str = ""
    headings: list[str] = field(default_factory=list)
    text: str = ""
    links: list[str] = field(default_factory=list)
    structured: list[dict[str, Any]] = field(default_factory=list)


def _bounded_json(value: Any, depth: int = 0) -> Any:
    """Keep only small, plain JSON-LD values (strings/numbers/shallow dicts+lists). Never evaluates anything."""
    if depth > 4:
        return None
    if isinstance(value, str):
        return clean_text(value)[:500]
    if isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, list):
        return [v for v in (_bounded_json(i, depth + 1) for i in value[:20]) if v not in (None, "", [], {})]
    if isinstance(value, dict):
        out = {str(k)[:40]: _bounded_json(v, depth + 1) for k, v in list(value.items())[:20] if not str(k).startswith("@") or k == "@type"}
        return {k: v for k, v in out.items() if v not in (None, "", [], {})}
    return None


def _json_ld(soup: BeautifulSoup) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"})[:5]:
        raw = tag.string or ""
        if not raw or len(raw) > policy.MAX_JSONLD_BYTES:
            continue
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            continue
        nodes = data if isinstance(data, list) else data.get("@graph", [data]) if isinstance(data, dict) else []
        for node in nodes[:10] if isinstance(nodes, list) else []:
            if isinstance(node, dict) and _BUSINESS_TYPES.search(str(node.get("@type", ""))):
                kept = {k: _bounded_json(node[k]) for k in _JSONLD_KEYS if k in node}
                kept = {k: v for k, v in kept.items() if v not in (None, "", [], {})}
                if kept:
                    found.append(kept)
    return found[:5]


def _is_hidden(tag: Tag) -> bool:
    if tag.attrs is None:
        return False
    if tag.has_attr("hidden") or str(tag.get("aria-hidden", "")).lower() == "true":
        return True
    return bool(_HIDDEN_STYLE.search(str(tag.get("style", ""))))


def _same_site_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    base = urlsplit(base_url)
    out: list[str] = []
    for anchor in soup.find_all("a", href=True)[:400]:
        href = str(anchor["href"]).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        try:
            parts = urlsplit(urljoin(base_url, href))
        except ValueError:
            continue
        # Same ORIGIN as the (already policy-validated) page URL only: a link can never widen scheme, host or port.
        if (parts.scheme, (parts.hostname or "").lower(), parts.port) != (base.scheme, (base.hostname or "").lower(), base.port):
            continue
        path = parts.path or "/"
        lowered = path.lower()
        if lowered.startswith(policy.SKIP_PATH_PREFIXES) or lowered.endswith(policy.SKIP_EXTENSIONS):
            continue
        url = f"{base.scheme}://{base.netloc.lower()}{path}"  # query strings + fragments dropped
        if url not in out and len(url) <= 512:
            out.append(url)
        if len(out) >= policy.MAX_LINKS_PER_PAGE:
            break
    return out


def extract_html(body: bytes, url: str) -> ExtractedPage:
    soup = BeautifulSoup(body[: policy.MAX_PAGE_BYTES], "lxml")
    page = ExtractedPage(url=url)
    page.structured = _json_ld(soup)  # parsed as DATA before scripts are removed
    if soup.title and soup.title.string:
        page.title = clean_text(soup.title.string)[:200]
    meta = soup.find("meta", attrs={"name": re.compile(r"^description$", re.I)})
    if isinstance(meta, Tag):
        page.description = clean_text(str(meta.get("content", "")))[:500]
    page.links = _same_site_links(soup, url)
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()
    for tag in soup.find_all(_DROP_TAGS):
        tag.decompose()
    for tag in [t for t in soup.find_all(True) if _is_hidden(t)]:
        if not tag.decomposed:
            tag.decompose()
    page.headings = [h for h in (clean_text(t.get_text(" ", strip=True))[:160] for t in soup.find_all(["h1", "h2", "h3"])[:40]) if h]
    root = soup.find("main") or soup.body or soup
    lines = [clean_text(line) for line in root.get_text("\n", strip=True).split("\n")]
    page.text = "\n".join(line for line in lines if line)[: policy.MAX_TEXT_CHARS_PER_PAGE]
    return page


def extract_plain(body: bytes, url: str) -> ExtractedPage:
    text = clean_text(body[: policy.MAX_PAGE_BYTES].decode("utf-8", errors="replace"))
    return ExtractedPage(url=url, text=text[: policy.MAX_TEXT_CHARS_PER_PAGE])
