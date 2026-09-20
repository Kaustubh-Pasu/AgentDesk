"""Public, server-rendered pages + JSON twins. Jinja2 autoescape is ON and no template uses ``|safe``.

Everything that came from a website, an LLM, ANS or a remote agent reaches a template as a plain string and is
escaped at render time; remote agent replies are additionally shown inside a labelled "untrusted" block.
Absolute URLs are built from configured origins, never from request headers. Redirects go to fixed internal paths.
"""

from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from jinja2 import Environment, FileSystemLoader, StrictUndefined
from pydantic import ValidationError
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.staticfiles import StaticFiles

from app.agents.registry import ServedAgent
from app.agents.runtime import skills_for
from app.ans.client import AnsApiError
from app.ans.evidence import SecretLeak
from app.ans.registration import RegistrationError
from app.controlplane.tenants import TenantError
from app.logging_config import correlation_id_var, get_logger
from app.models.db import User
from app.models.schemas import FindInput, LoginInput
from app.protocols.mcp_server import MCP_METADATA_PATH, mcp_metadata
from app.security import audit, breakers, csrf, sessions
from app.security.authz import AuthRequired, Forbidden, current_session
from app.security.idempotency import IdempotencyConflict
from app.security.middleware import client_ip
from app.security.passwords import needs_rehash, hash_password, verify_password
from app.security.rate_limit import RateLimitExceeded

if TYPE_CHECKING:
    from app.main import Services

log = get_logger("web")
WEB_DIR = Path(__file__).parent
env = Environment(loader=FileSystemLoader(WEB_DIR / "templates"), autoescape=True, undefined=StrictUndefined,  # noqa: S701 - autoescape IS on
                  trim_blocks=True, lstrip_blocks=True)

_STATUS_TEXT = {400: "Bad request", 403: "Forbidden", 404: "Not found", 405: "Method not allowed", 409: "Conflict",
                413: "Payload too large", 422: "Invalid input", 429: "Too many requests", 500: "Something went wrong",
                503: "Temporarily unavailable"}


def render(request: Request, template: str, *, status: int = 200, **context: Any) -> HTMLResponse:
    services: Services = request.app.state.services
    base = {"settings_view": {"desk_origin": services.settings.desk_origin, "demo_origin": services.settings.origin_for(services.settings.demo_host),
                              "desk_host": services.settings.desk_host, "demo_host": services.settings.demo_host,
                              "environment": services.settings.ans_environment},
            "principal": getattr(request.state, "principal", None), "correlation_id": correlation_id_var.get()}
    return HTMLResponse(env.get_template(template).render(**base, **context), status_code=status)


def wants_json(request: Request) -> bool:
    return request.url.path.startswith(("/api/", "/a2a", "/mcp", "/.well-known/", "/internal/"))


def error_response(request: Request, status: int, code: str, message: str = "", headers: dict[str, str] | None = None) -> Response:
    message = message or _STATUS_TEXT.get(status, "Error")
    if wants_json(request):
        return JSONResponse({"error": {"code": code, "message": message, "correlation_id": correlation_id_var.get()}}, status, headers=headers)
    response = render(request, "error.html", status=status, code=code, message=message, title=_STATUS_TEXT.get(status, "Error"))
    response.headers.update(headers or {})
    return response


async def served_agent(request: Request) -> ServedAgent:
    agent = await request.app.state.services.registry.resolve(request.headers.get("host", ""))
    if agent is None:
        raise StarletteHTTPException(404)
    return agent


async def desk_only(request: Request) -> None:
    if (await served_agent(request)).kind != "desk":
        raise StarletteHTTPException(404)  # the admin/UI surface does not exist on tenant hosts


def register_web(app: FastAPI, services: Services) -> None:
    from app.web.admin import register_admin

    settings = services.settings
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    # ------------------------------------------------------------------ error handling (safe codes + correlation id only)
    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        return error_response(request, exc.status_code, f"http_{exc.status_code}")

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> Response:
        return error_response(request, 422, "invalid_input")  # never echo the offending input back

    @app.exception_handler(ValidationError)
    async def _pydantic(request: Request, exc: ValidationError) -> Response:
        fields = sorted({".".join(str(p) for p in e["loc"])[:60] for e in exc.errors()})[:8]
        return error_response(request, 422, "invalid_input", "Invalid input: " + ", ".join(fields))

    @app.exception_handler(AuthRequired)
    async def _auth(request: Request, exc: AuthRequired) -> Response:
        if wants_json(request):
            return error_response(request, 401, "authentication_required", "Authentication required.")
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(Forbidden)
    async def _forbidden(request: Request, exc: Forbidden) -> Response:
        await audit.record_independent(services.db, action=audit.CSRF_REJECTED if exc.code.startswith("csrf") else audit.AUTHZ_DENIED,
                                       outcome="denied", actor_type="ip", actor_id=client_ip(request, settings), metadata={"code": exc.code, "path": request.url.path})
        return error_response(request, 403, exc.code)

    @app.exception_handler(TenantError)
    async def _tenant(request: Request, exc: TenantError) -> Response:
        return error_response(request, exc.status, exc.code, exc.message)

    @app.exception_handler(RateLimitExceeded)
    async def _rate(request: Request, exc: RateLimitExceeded) -> Response:
        return error_response(request, 429, "rate_limited", headers={"Retry-After": str(exc.retry_after_s)})

    @app.exception_handler(breakers.FeatureDisabled)
    async def _breaker(request: Request, exc: breakers.FeatureDisabled) -> Response:
        return error_response(request, 503, exc.code, "This feature is temporarily disabled by the operator.")

    @app.exception_handler(IdempotencyConflict)
    async def _idem(request: Request, exc: IdempotencyConflict) -> Response:
        return error_response(request, 409, exc.code, "This request was already submitted.")

    @app.exception_handler(RegistrationError)
    async def _registration(request: Request, exc: RegistrationError) -> Response:
        return error_response(request, 404 if exc.code == "not_found" else 409, exc.code, str(exc)[:200])

    @app.exception_handler(AnsApiError)
    async def _ans(request: Request, exc: AnsApiError) -> Response:
        return error_response(request, 502, "ans_" + exc.code.lower(), "GoDaddy ANS did not accept the request: " + (exc.message or exc.code))

    @app.exception_handler(SecretLeak)
    async def _leak(request: Request, exc: SecretLeak) -> Response:
        log.error("evidence export refused: secret-shaped content")
        return error_response(request, 500, "evidence_refused")

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> Response:
        log.exception("unhandled error", extra={"path": request.url.path})
        return error_response(request, 500, "internal_error")

    # ------------------------------------------------------------------ pages available on EVERY served host
    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request) -> Response:
        agent = await served_agent(request)
        request.state.principal = await current_session(request, services.db, settings) if agent.kind == "desk" else None
        if agent.kind == "desk":
            return render(request, "home.html", breakers=breakers.snapshot(settings))
        origin = settings.origin_for(agent.host)
        return render(request, "agent_home.html", agent=agent, skills=skills_for(agent), origin=origin)

    @app.get(MCP_METADATA_PATH)
    async def mcp_json(request: Request) -> Response:
        agent = await served_agent(request)
        return JSONResponse(mcp_metadata(agent.kind, agent.host, settings), headers={"Cache-Control": "public, max-age=60"})

    async def _proof(request: Request) -> dict[str, Any]:
        agent = await served_agent(request)
        probe = "get_hours" if agent.kind == "business" else "about_agent_desk"
        return await services.proof.proof_for(agent.host, probe_tool=probe)

    @app.get("/api/proof")
    async def api_proof(request: Request) -> Response:
        return JSONResponse(await _proof(request), headers={"Cache-Control": "no-store"})

    @app.get("/proof", response_class=HTMLResponse)
    async def proof_page(request: Request) -> Response:
        return render(request, "proof.html", proof=await _proof(request))

    # ------------------------------------------------------------------ desk-only public pages
    @app.get("/security", response_class=HTMLResponse)
    async def security_page(request: Request) -> Response:
        await desk_only(request)
        return render(request, "security.html", breakers=breakers.snapshot(settings))

    @app.get("/find", response_class=HTMLResponse)
    async def find_page(request: Request) -> Response:
        await desk_only(request)
        return render(request, "find.html", outcome=None, form={"query": "", "exact_host": "", "question": ""})

    @app.post("/find", response_class=HTMLResponse)
    async def find_submit(request: Request) -> Response:
        await desk_only(request)
        form = await request.form()
        values = {k: str(form.get(k, ""))[:600] for k in ("query", "exact_host", "question")}
        data = FindInput(query=values["query"], exact_host=values["exact_host"], question=values["question"], connect=True)
        outcome = await services.find.find(data, principal=f"ip:{client_ip(request, settings)}")
        return render(request, "find.html", outcome=outcome.to_public_dict(), form=values)

    @app.post("/api/find")
    async def api_find(request: Request) -> Response:
        await desk_only(request)
        try:
            data = FindInput.model_validate(await request.json())
        except ValueError as exc:
            if isinstance(exc, ValidationError):
                raise
            return error_response(request, 400, "invalid_json")
        outcome = await services.find.find(data, principal=f"ip:{client_ip(request, settings)}")
        return JSONResponse(outcome.to_public_dict(), headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------------ login / logout
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        await desk_only(request)
        if await current_session(request, services.db, settings) is not None:
            return RedirectResponse("/create", status_code=303)
        holder = Response()
        token = csrf.issue_login_csrf(holder, settings)  # signed double-submit token bound to a fresh nonce cookie
        response = render(request, "login.html", error="", csrf_token=token)
        response.raw_headers.extend(h for h in holder.raw_headers if h[0] == b"set-cookie")
        return response

    @app.post("/login")
    async def login_submit(request: Request) -> Response:
        await desk_only(request)
        form = await request.form()
        try:
            csrf.check_login_csrf(request, settings, str(form.get(csrf.CSRF_FORM_FIELD, "")))
        except csrf.CSRFError as exc:
            raise Forbidden(exc.code) from exc
        ip = client_ip(request, settings)
        try:
            data = LoginInput(email=str(form.get("email", "")), password=str(form.get("password", "")))
        except ValidationError:
            data = None
        email = data.email.lower() if data else "invalid"
        who = f"{email}|{ip}"
        failures = await services.limiter.peek("login-fail", who)
        if failures >= settings.rl_login_failures:
            raise RateLimitExceeded("login", settings.rl_login_window_s)
        if settings.login_progressive_delay and failures:
            await asyncio.sleep(min(2 ** (failures - 1) * 0.25, 4.0))
        async with services.db.session() as session:
            user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none() if data else None
            ok = verify_password(user.password_hash if user else None, data.password if data else secrets.token_urlsafe(8))
            ok = bool(ok and user is not None and user.disabled_at is None)
            if not ok:
                await services.limiter.hit("login-fail", who, limit=settings.rl_login_failures, window_s=settings.rl_login_window_s)
                await audit.record(session, action=audit.LOGIN_FAILURE, outcome="denied", actor_type="ip", actor_id=ip)
                await session.commit()
                response = render(request, "login.html", status=401, error="Invalid email or password.", csrf_token=csrf.login_token_for(request, settings) or "")
                return response
            assert user is not None and data is not None
            if needs_rehash(user.password_hash):
                user.password_hash = hash_password(data.password)
            old = await sessions.load_session(session, settings, request.cookies.get(sessions.SESSION_COOKIE))
            if old is not None:
                await sessions.destroy_session(session, old)  # never keep a pre-login session alive (fixation)
            token, _row = await sessions.create_session(session, settings, user, request.headers.get("user-agent", ""))
            await audit.record(session, action=audit.LOGIN_SUCCESS, outcome="ok", actor_type="user", actor_id=str(user.id))
            await session.commit()
        await services.limiter.reset("login-fail", who)
        response = RedirectResponse("/create", status_code=303)
        sessions.set_session_cookie(response, settings, token)
        response.delete_cookie(csrf.LOGIN_CSRF_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return response

    register_admin(app, services, render)
