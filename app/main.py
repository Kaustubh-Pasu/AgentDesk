"""Application assembly.

One image, four roles (``SERVICE_ROLE``):
  all          development / single-host demo: everything in one process
  desk|runtime public web UI + A2A/MCP endpoints (no GoDaddy credential when CONTROLPLANE_URL is set)
  controlplane private: ANS registration + keys (holds the GoDaddy credential); only /internal/ans/step
  scraper      private: website crawler only; no DB, no Redis, no secrets

Middleware order (outermost first): correlation/access-log → security headers → trusted host → body limit →
protocol/proof rate limits → browser origin guard (CSRF headers) → routes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.agents.llm import LLMClient, build_llm
from app.agents.registry import AgentRegistry
from app.agents.runtime import AgentRuntime
from app.agents.seed import seed_demo_agent
from app.ans.certs import KeyStore
from app.ans.client import AnsClient
from app.ans.evidence import ProofService
from app.ans.registration import RegistrationFlow, RegistrationService
from app.ans.verifier import TlsProbe, Verifier
from app.controlplane.api import LocalRegistrar, Registrar, RemoteRegistrar, controlplane_routes
from app.controlplane.tenants import TenantService
from app.find.service import FindDeskBackend, FindService
from app.ingestion.scraper_service import Crawler, build_crawler, scraper_routes
from app.logging_config import configure_logging, correlation_id_var, get_logger
from app.models.db import Database
from app.protocols.a2a_server import create_a2a_routes
from app.protocols.mcp_server import McpProtocolServer
from app.protocols.remote_http import RemoteHttp
from app.security.headers import SecurityHeadersMiddleware
from app.security.kv import KV, build_kv
from app.security.middleware import (
    BodyLimitMiddleware,
    BrowserOriginGuardMiddleware,
    CorrelationMiddleware,
    TrustedHostMiddleware,
    _json_error,
    client_ip_from_scope,
)
from app.security.rate_limit import RateLimiter
from app.security.ssrf import Resolver, system_resolver
from app.settings import Settings, get_settings

log = get_logger("app")
STATIC_DIR = Path(__file__).parent / "web" / "static"


@dataclass
class Overrides:
    """Test seams for the network edge ONLY (never settable from configuration or requests)."""

    ans_transport: Any = None
    remote_http: RemoteHttp | None = None
    resolver: Resolver | None = None
    tls_probe: TlsProbe | None = None
    crawler: Crawler | None = None
    llm: LLMClient | None = None
    kv: KV | None = None
    db: Database | None = None


@dataclass
class Services:
    settings: Settings
    db: Database
    kv: KV
    limiter: RateLimiter
    registry: AgentRegistry
    runtime: AgentRuntime
    ans: AnsClient
    verifier: Verifier
    proof: ProofService
    find: FindService
    tenants: TenantService
    registrar: Registrar
    mcp: McpProtocolServer


def build_services(settings: Settings, overrides: Overrides | None = None) -> Services:
    o = overrides or Overrides()
    db = o.db or Database(settings.database_url)
    kv = o.kv or build_kv(settings.redis_url)
    limiter = RateLimiter(kv)
    llm = o.llm or build_llm(settings, kv)
    registry = AgentRegistry(db, settings)
    ans = AnsClient(settings, transport=o.ans_transport)
    http = o.remote_http or RemoteHttp(settings)
    verifier = Verifier(settings, ans, http, db, resolver=o.resolver or system_resolver, tls_probe=o.tls_probe)
    find = FindService(settings, ans, verifier, http, limiter, db)
    runtime = AgentRuntime(registry, settings, llm=llm, desk_backend=FindDeskBackend(find))
    tenants = TenantService(db, settings, registry, limiter, o.crawler or build_crawler(settings), llm)
    registrar: Registrar
    if settings.controlplane_url and settings.service_role != "controlplane":
        registrar = RemoteRegistrar(settings)
    else:
        flow = RegistrationFlow(ans, KeyStore(settings.keys_path, settings.base_domain), settings)
        registrar = LocalRegistrar(RegistrationService(db, flow, registry, kv, settings))
    return Services(settings, db, kv, limiter, registry, runtime, ans, verifier, ProofService(settings, verifier), find,
                    tenants, registrar, McpProtocolServer(runtime, settings))


class PublicRateLimitMiddleware:
    """Shared (Redis) per-IP limits for the anonymous surfaces. Fails closed if the limiter backend is down."""

    def __init__(self, app: ASGIApp, settings: Settings, limiter: RateLimiter) -> None:
        self.app, self.settings, self.limiter = app, settings, limiter

    def _bucket(self, path: str, method: str) -> tuple[str, int] | None:
        s = self.settings
        if path.startswith(("/a2a", "/mcp")):
            return "protocol", s.rl_protocol_per_min
        if path in ("/proof", "/api/proof") or path.startswith("/.well-known/"):
            return "proof", s.rl_proof_per_min
        if path in ("/find", "/api/find") and method == "POST":
            return "anon-query", s.rl_anon_query_per_min
        return None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            bucket = self._bucket(scope.get("path", ""), scope.get("method", "GET"))
            if bucket is not None:
                result = await self.limiter.hit(bucket[0], client_ip_from_scope(scope, self.settings), limit=bucket[1], window_s=60)
                if not result.allowed:
                    start, body = _json_error(429, "rate_limited", "Too many requests.", correlation_id_var.get(),
                                              [(b"retry-after", str(max(1, result.retry_after_s)).encode())])
                    await send(start)
                    await send(body)
                    return
        await self.app(scope, receive, send)


class SafeErrorMiddleware:
    """Last line of defence: an exception never escapes to the server (whose default page/log we do not control).
    Starlette re-raises after running the 500 handler; if the safe response already went out, that is the end of it."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Any) -> None:
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            if started:
                return  # the registered handler already logged it (redacted) and answered with a safe 500
            log.exception("unhandled error before response start", extra={"path": scope.get("path", "")})
            start, body = _json_error(500, "internal_error", "Something went wrong.", correlation_id_var.get())
            await send(start)
            await send(body)


async def _healthz(_: Any) -> JSONResponse:
    return JSONResponse({"status": "ok"})  # liveness only: no dependency or version detail


def _wrap(app: ASGIApp, settings: Settings, limiter: RateLimiter | None, *, browser: bool) -> ASGIApp:
    app = SafeErrorMiddleware(app)
    if browser:
        app = BrowserOriginGuardMiddleware(app, settings)
    if limiter is not None:
        app = PublicRateLimitMiddleware(app, settings, limiter)
    app = BodyLimitMiddleware(app, settings.max_request_body_bytes)
    if browser:
        app = TrustedHostMiddleware(app, settings)
        app = SecurityHeadersMiddleware(app, hsts=settings.hsts_enabled and settings.public_scheme == "https")
    return CorrelationMiddleware(app, settings)


def create_app(settings: Settings | None = None, overrides: Overrides | None = None) -> ASGIApp:
    return build_app(settings, overrides)[0]


def build_app(settings: Settings | None = None, overrides: Overrides | None = None) -> tuple[ASGIApp, Services | None]:
    settings = settings or get_settings()
    configure_logging(settings.log_level, settings.secret_values())

    if settings.service_role == "scraper":
        inner = Starlette(routes=[Route("/healthz", _healthz), *scraper_routes(settings)])
        return _wrap(inner, settings, None, browser=False), None

    services = build_services(settings, overrides)
    configure_logging(settings.log_level, settings.secret_values())  # the MCP SDK may touch logging on construction

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        if not services.db.is_postgres:
            await services.db.create_all()  # development/test convenience; PostgreSQL uses Alembic migrations
        if settings.service_role in ("all", "runtime", "desk"):
            if await seed_demo_agent(services.db, settings):
                log.info("seeded demo agent", extra={"agent_host": settings.demo_host})
        async with services.mcp.lifespan():
            yield
        await services.kv.close()
        await services.db.dispose()

    if settings.service_role == "controlplane":
        assert isinstance(services.registrar, LocalRegistrar)
        inner = Starlette(routes=[Route("/healthz", _healthz), *controlplane_routes(settings, services.registrar)], lifespan=lifespan)
        return _wrap(inner, settings, None, browser=False), services

    from app.web.routes import register_web  # imported late: templates are not needed by the private roles

    app = FastAPI(title="Agent Desk", docs_url=None, redoc_url=None, openapi_url=None, debug=False, lifespan=lifespan)
    app.state.services = services
    app.router.redirect_slashes = False  # no implicit redirects: unknown paths are plain 404s
    app.router.routes.extend([Route("/healthz", _healthz), *create_a2a_routes(services.runtime, settings), *services.mcp.routes()])
    register_web(app, services)
    return _wrap(app, settings, services.limiter, browser=True), services


def app_factory() -> ASGIApp:  # uvicorn --factory app.main:app_factory
    return create_app()
