"""Security response headers (pure ASGI middleware – safe for streaming A2A/MCP responses).

The same header set is also emitted by Caddy (deploy/Caddyfile); the app sets it too so the policy holds
even if the proxy config drifts, and so it can be unit-tested.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
)
HSTS = "max-age=63072000; includeSubDomains"

BASE_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY",
}

_NO_STORE_PREFIXES = ("/admin", "/login", "/logout", "/api/")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in BASE_HEADERS.items():
                    headers[name] = value
                if self.hsts:
                    headers["Strict-Transport-Security"] = HSTS
                if path.startswith(_NO_STORE_PREFIXES) and "cache-control" not in headers:
                    headers["Cache-Control"] = "no-store"
                # never advertise the server stack, never emit permissive CORS
                del headers["server"]
                del headers["x-powered-by"]
                for cors in (
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                    "access-control-allow-headers",
                    "access-control-allow-methods",
                ):
                    del headers[cors]
            await send(message)

        await self.app(scope, receive, send_with_headers)
