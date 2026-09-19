"""CSRF defence for cookie-authenticated browser routes. Three independent checks, all must pass:

1. **Fetch Metadata** – unsafe requests with ``Sec-Fetch-Site`` other than ``same-origin`` are refused.
2. **Origin / Referer** – must equal the configured canonical admin origin (never derived from Host).
   A request with neither header is refused.
3. **Token** – per-session random token (server-side), sent as form field ``csrf_token`` or header
   ``X-CSRF-Token``. Before login a signed double-submit token protects the login form itself.

A2A / MCP endpoints never use cookies, so they carry no ambient authority to forge.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import Response

from app.settings import Settings

LOGIN_CSRF_COOKIE = "__Host-agentdesk_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class CSRFError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _origin_of(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc or "@" in parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}".lower()


def check_request_origin(request: Request, settings: Settings) -> None:
    """Checks 1 + 2. Cheap, header-only – also run as middleware for every unsafe browser request."""
    expected = settings.desk_origin.lower()
    site = request.headers.get("sec-fetch-site")
    if site is not None and site.strip().lower() != "same-origin":
        raise CSRFError("csrf_fetch_metadata")
    origin_header = request.headers.get("origin")
    if origin_header is not None:
        if origin_header.strip().lower() != expected:
            raise CSRFError("csrf_origin")
        return
    referer = request.headers.get("referer")
    if referer is None:
        raise CSRFError("csrf_origin_missing")
    if _origin_of(referer.strip()) != expected:
        raise CSRFError("csrf_referer")


def check_token(supplied: str | None, expected: str | None) -> None:
    if not supplied or not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
        raise CSRFError("csrf_token")


async def supplied_token(request: Request) -> str | None:
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header
    content_type = request.headers.get("content-type", "")
    if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        value = form.get(CSRF_FORM_FIELD)
        return value if isinstance(value, str) else None
    return None


# ---- pre-session (login form) signed double-submit -------------------------------------------------
def _sign(settings: Settings, nonce: str) -> str:
    return hmac.new(
        settings.csrf_secret.get_secret_value().encode(), nonce.encode(), hashlib.sha256
    ).hexdigest()


def issue_login_csrf(response: Response, settings: Settings) -> str:
    nonce = secrets.token_urlsafe(24)
    response.set_cookie(
        LOGIN_CSRF_COOKIE, nonce, max_age=1800, path="/", secure=True, httponly=True, samesite="strict"
    )
    return _sign(settings, nonce)


def login_token_for(request: Request, settings: Settings) -> str | None:
    nonce = request.cookies.get(LOGIN_CSRF_COOKIE)
    return _sign(settings, nonce) if nonce else None


def check_login_csrf(request: Request, settings: Settings, supplied: str | None) -> None:
    check_request_origin(request, settings)
    check_token(supplied, login_token_for(request, settings))
