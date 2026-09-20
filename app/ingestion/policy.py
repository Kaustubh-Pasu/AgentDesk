"""Hard limits for website import (spec §22.3). Constants, not settings: they cannot be relaxed by environment."""

from __future__ import annotations

MAX_PAGES = 10
MAX_DEPTH = 2
MAX_REDIRECTS = 3
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
CRAWL_WALL_CLOCK_S = 60.0
ALLOWED_CONTENT_TYPES = frozenset({"text/html", "text/plain"})
MAX_LINKS_PER_PAGE = 60
MAX_TEXT_CHARS_PER_PAGE = 20_000
MAX_TEXT_CHARS_TOTAL = 60_000
MAX_JSONLD_BYTES = 64 * 1024

#: Path prefixes that are never worth crawling and often hide traps or state-changing GETs.
SKIP_PATH_PREFIXES = ("/wp-admin", "/admin", "/login", "/logout", "/cart", "/checkout", "/account", "/cgi-bin", "/api/")
SKIP_EXTENSIONS = (".pdf", ".zip", ".gz", ".tar", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".exe", ".dmg", ".iso",
                   ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".mp3", ".mp4", ".mov", ".avi", ".css", ".js",
                   ".json", ".xml", ".rss", ".woff", ".woff2", ".ttf")
