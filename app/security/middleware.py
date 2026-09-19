"""Request-pipeline middleware (pure ASGI): correlation IDs + access log, trusted hosts, body limits,
and the header-level CSRF guard for unsafe browser requests."""

from __future__ import annotations

import ipaddress
import json
import time
import uuid
from collections.abc import Iterable

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.logging_config import correlation_id_var, get_logger
from app.security.csrf import SAFE_METHODS, CSRFError, check_request_origin
from app.security.hosts import is_allowed_request_host
from app.settings import Settings

log = get_logger("access")

# Paths that use protocol-level auth (never cookies) and therefore are exempt from the browser CSRF guard.
PROTOCOL_PREFIXES = ("/a2a", "/mcp", "/internal/", "/api/v1/")


def _json_error(
    status: int,
    code: str,
    message: str,
    correlation_id: str,
    extra_headers: Iterable[tuple[bytes, bytes]] = (),
) -> tuple[Message, Message]:
    body = json.dumps(
        {"error": {"code": code, "message": message, "correlation_id": correlation_id}}
    ).encode()
    start: Message = {
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control", b"no-store"),
            *extra_headers,
        ],
    }
    return start, {"type": "http.response.body", "body": body}


async def _reject(send: Send, status: int, code: str, message: str) -> None:
    start, body = _json_error(status, code, message, correlation_id_var.get())
    await send(start)
    await send(body)


def client_ip_from_scope(scope: Scope, settings: Settings) -> str:
    """Peer address, or the right-most untrusted X-Forwarded-For hop when the peer is OUR proxy."""
    client = scope.get("client")
    peer = client[0] if client else "0.0.0.0"  # noqa: S104 - placeholder, not a bind address
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    networks = settings.trusted_proxy_networks
    if not any(peer_ip in net for net in networks):
        return str(peer_ip)  # direct connection: forwarded headers are attacker-controlled → ignored
    forwarded = ""
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            forwarded = value.decode("latin-1")
    for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
        try:
            hop_ip = ipaddress.ip_address(hop)
        except ValueError:
            break
        if not any(hop_ip in net for net in networks):
            return str(hop_ip)
    return str(peer_ip)


def client_ip(request: Request, settings: Settings) -> str:
    return client_ip_from_scope(request.scope, settings)


class CorrelationMiddleware:
    """Generates the correlation ID (client-supplied IDs are ignored) and writes one access-log line."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        correlation_id = uuid.uuid4().hex
        token = correlation_id_var.set(correlation_id)
        started = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                message.setdefault("headers", [])
                message["headers"] = [*message["headers"], (b"x-request-id", correlation_id.encode())]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            host = ""
            for name, value in scope.get("headers", []):
                if name == b"host":
                    host = value.decode("latin-1")
            log.info(
                "request",
                extra={
                    "method": scope.get("method", ""),
                    "path": scope.get("path", ""),  # never the query string (may carry secrets)
                    "host": host,
                    "status": status_holder["status"],
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "client_ip": client_ip_from_scope(scope, self.settings),
                },
            )
            correlation_id_var.reset(token)


class TrustedHostMiddleware:
    """Only BASE_DOMAIN children are served; anything else is a 400 (Host-header poisoning defence)."""

    def __init__(self, app: ASGIApp, settings: Settings, extra_hosts: frozenset[str] = frozenset()) -> None:
        self.app = app
        self.settings = settings
        self.extra_hosts = extra_hosts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        hosts = [value.decode("latin-1") for name, value in scope.get("headers", []) if name == b"host"]
        if len(hosts) != 1 or not is_allowed_request_host(
            hosts[0], base_domain=self.settings.base_domain, extra=self.extra_hosts
        ):
            await _reject(send, 400, "invalid_host", "Unknown host.")
            return
        await self.app(scope, receive, send)


class BodyLimitMiddleware:
    """Hard cap on request bodies (declared AND streamed)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                if not value.isdigit() or int(value) > self.max_bytes:
                    await _reject(send, 413, "payload_too_large", "Request body too large.")
                    return
        received = 0
        too_large = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    too_large = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if too_large and not response_started:
                response_started = True
                start, body = _json_error(
                    413, "payload_too_large", "Request body too large.", correlation_id_var.get()
                )
                await send(start)
                await send(body)
                return
            if too_large:
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)


class BrowserOriginGuardMiddleware:
    """Header-level CSRF guard (Fetch Metadata + Origin/Referer) for every unsafe non-protocol request.
    The per-session token is verified additionally inside each route (see security/authz.py)."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET") in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        path: str = scope.get("path", "")
        if path.startswith(PROTOCOL_PREFIXES):
            await self.app(scope, receive, send)
            return
        try:
            check_request_origin(Request(scope), self.settings)
        except CSRFError as exc:
            log.warning("csrf rejected", extra={"path": path, "reason": exc.code})
            await _reject(send, 403, exc.code, "Cross-site request rejected.")
            return
        await self.app(scope, receive, send)
