"""Authenticated owner workflows (desk host only): create → import → preview/confirm → publish → ANS registration.

Every POST here requires: a valid server-side session, the per-session CSRF token, the header-level origin guard
(middleware), an idempotency key bound to actor + operation + payload, and owner-scoped data access. Revocation-class
actions additionally require recent re-authentication. No route accepts a URL, hostname, DNS name or file path to act
on: the only inputs are the tenant UUID (owner-checked) and enum-like step names.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, Request
from sqlalchemy import select
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse, RedirectResponse, Response

from app.models.db import ANSRegistration
from app.models.schemas import (
    BusinessCategory,
    BusinessProfile,
    Capability,
    ProfileConfirmInput,
    TenantCreateInput,
)
from app.security import audit, idempotency, sessions
from app.security.authz import Forbidden, Principal, require_csrf, require_user
from app.security.passwords import verify_password

if TYPE_CHECKING:
    from app.main import Services

Render = Callable[..., HTMLResponse]
ANS_STEPS = ("submit", "refresh", "verify_acme", "verify_dns")


def _lines(form: FormData, name: str, width: int, limit: int) -> list[list[str]]:
    rows = []
    for line in str(form.get(name, "")).splitlines()[: limit * 2]:
        cells = [c.strip() for c in line.split("|")]
        if any(cells):
            rows.append((cells + [""] * width)[:width])
    return rows[:limit]


def profile_from_form(form: FormData) -> BusinessProfile:
    """Owner edits arrive as plain text fields and are validated by the SAME strict schema as model output."""
    category = str(form.get("category", "other"))
    return BusinessProfile.model_validate(
        {
            "business_name": str(form.get("business_name", "")),
            "description": str(form.get("description", "")),
            "category": category if category in {c.value for c in BusinessCategory} else "other",
            "address": str(form.get("address", "")),
            "contact": {"phone": str(form.get("phone", "")), "email": str(form.get("email", ""))},
            "hours": [{"days": d, "hours": h} for d, h in _lines(form, "hours", 2, 14)],
            "services": [
                {"name": n, "description": d, "price": p} for n, d, p in _lines(form, "services", 3, 50)
            ],
            "menu_items": [
                {"name": n, "description": d, "price": p, "section": s}
                for n, d, p, s in _lines(form, "menu_items", 4, 100)
            ],
            "faq": [{"question": q, "answer": a} for q, a in _lines(form, "faq", 2, 30)],
        }
    )


def profile_to_form(profile: dict[str, Any]) -> dict[str, str]:
    def join(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> str:
        return "\n".join(" | ".join(str(r.get(k, "")) for k in keys).rstrip(" |") for r in rows)

    contact = profile.get("contact") or {}
    return {
        "business_name": profile.get("business_name", ""),
        "description": profile.get("description", ""),
        "category": profile.get("category", "other"),
        "address": profile.get("address", ""),
        "phone": contact.get("phone", ""),
        "email": contact.get("email", ""),
        "hours": join(profile.get("hours", []), ("days", "hours")),
        "services": join(profile.get("services", []), ("name", "description", "price")),
        "menu_items": join(profile.get("menu_items", []), ("name", "description", "price", "section")),
        "faq": join(profile.get("faq", []), ("question", "answer")),
    }


def register_admin(app: FastAPI, services: Services, render: Render) -> None:
    from app.web.routes import desk_only

    settings = services.settings

    async def owner(request: Request) -> Principal:
        await desk_only(request)
        principal = await require_user(request, services.db, settings)
        request.state.principal = principal
        return principal

    async def guarded_form(
        request: Request, principal: Principal, operation: str, payload: Any
    ) -> tuple[FormData, idempotency.IdempotencyOutcome]:
        form = await request.form()
        await require_csrf(request, principal)
        outcome = await idempotency.begin(
            services.db,
            actor_id=principal.id,
            operation=operation,
            key=str(form.get("idempotency_key", "")),
            payload=payload,
        )
        return form, outcome

    def tenant_uuid(raw: str) -> uuid.UUID:
        try:
            return uuid.UUID(raw)
        except ValueError:
            raise StarletteHTTPException(404) from None

    def back(tenant_id: uuid.UUID | None = None) -> Response:
        return RedirectResponse(f"/admin/tenants/{tenant_id}" if tenant_id else "/create", status_code=303)

    # ------------------------------------------------------------------ pages
    @app.get("/create", response_class=HTMLResponse)
    async def create_page(request: Request) -> Response:
        principal = await owner(request)
        return render(
            request,
            "create.html",
            tenants=await services.tenants.list_for(principal.user.id),
            csrf_token=principal.session.csrf_token,
            idempotency_key=idempotency.new_idempotency_key(),
            base_domain=settings.base_domain,
        )

    @app.get("/admin/tenants/{tenant_id}", response_class=HTMLResponse)
    async def tenant_page(request: Request, tenant_id: str) -> Response:
        principal = await owner(request)
        view = await services.tenants.view(principal.user.id, tenant_uuid(tenant_id))
        async with services.db.session() as session:
            registration = (
                (
                    await session.execute(
                        select(ANSRegistration)
                        .where(ANSRegistration.tenant_id == view.tenant.id)
                        .order_by(ANSRegistration.created_at.desc())
                    )
                )
                .scalars()
                .first()
            )
        shown = view.draft or view.published
        return render(
            request,
            "tenant.html",
            tenant=view.tenant,
            has_draft=view.draft is not None,
            published=view.published,
            form=profile_to_form(shown.profile) if shown else None,
            selected=set(shown.allowed_capabilities) if shown else set(),
            capabilities=[c.value for c in Capability],
            categories=[c.value for c in BusinessCategory],
            registration=registration,
            origin=settings.origin_for(view.tenant.agent_host),
            csrf_token=principal.session.csrf_token,
            keys=[idempotency.new_idempotency_key() for _ in range(8)],
            ans_configured=settings.ans_credential_configured or bool(settings.controlplane_url),
            environment=settings.ans_environment,
        )

    # ------------------------------------------------------------------ mutations
    @app.post("/admin/tenants")
    async def tenant_create(request: Request) -> Response:
        principal = await owner(request)
        raw = await request.form()
        data = TenantCreateInput(
            display_name=str(raw.get("display_name", "")),
            source_url=str(raw.get("source_url", "")),
            agent_label=str(raw.get("agent_label", "")),
        )
        _, outcome = await guarded_form(request, principal, "tenant.create", data.model_dump())
        if outcome.replayed:
            return back(tenant_uuid(str((outcome.response or {}).get("tenant_id", ""))))
        try:
            tenant = await services.tenants.create(principal.user.id, data)
        except Exception:
            await idempotency.abandon(services.db, outcome.key_hash)
            raise
        await idempotency.complete(services.db, outcome.key_hash, {"tenant_id": str(tenant.id)})
        try:
            await services.tenants.run_import(principal.user.id, tenant.id)
        except (
            Exception
        ) as exc:  # the tenant exists; the owner sees the import error on its page and can retry
            request.state.import_error = getattr(exc, "code", "import_failed")
        return back(tenant.id)

    @app.post("/admin/tenants/{tenant_id}/import")
    async def tenant_import(request: Request, tenant_id: str) -> Response:
        principal = await owner(request)
        tid = tenant_uuid(tenant_id)
        _, outcome = await guarded_form(request, principal, "tenant.import", {"tenant": str(tid)})
        if not outcome.replayed:
            try:
                await services.tenants.run_import(principal.user.id, tid)
            except Exception:
                await idempotency.abandon(services.db, outcome.key_hash)
                raise
            await idempotency.complete(services.db, outcome.key_hash, {"ok": True})
        return back(tid)

    @app.post("/admin/tenants/{tenant_id}/publish")
    async def tenant_publish(request: Request, tenant_id: str) -> Response:
        principal = await owner(request)
        tid = tenant_uuid(tenant_id)
        raw = await request.form()
        row_version = str(raw.get("row_version", ""))
        data = ProfileConfirmInput(
            profile=profile_from_form(raw),
            capabilities=[
                Capability(c) for c in raw.getlist("capabilities") if c in {x.value for x in Capability}
            ],
            row_version=int(row_version) if row_version.isdigit() else 0,
            confirm=raw.get("confirm") == "yes",
        )
        _, outcome = await guarded_form(
            request, principal, "tenant.publish", {"tenant": str(tid), "data": data.model_dump(mode="json")}
        )
        if not outcome.replayed:
            try:
                await services.tenants.confirm_and_publish(principal.user.id, tid, data)
            except Exception:
                await idempotency.abandon(services.db, outcome.key_hash)
                raise
            await idempotency.complete(services.db, outcome.key_hash, {"ok": True})
        return back(tid)

    @app.post("/admin/tenants/{tenant_id}/ans/{step}")
    async def tenant_ans(request: Request, tenant_id: str, step: str) -> Response:
        principal = await owner(request)
        tid = tenant_uuid(tenant_id)
        if step not in ANS_STEPS:
            raise StarletteHTTPException(404)
        _, outcome = await guarded_form(request, principal, f"ans.{step}", {"tenant": str(tid)})
        if not outcome.replayed:
            try:
                await services.registrar.run(tid, principal.user.id, step)
            except Exception:
                await idempotency.abandon(services.db, outcome.key_hash)
                raise
            await idempotency.complete(services.db, outcome.key_hash, {"ok": True})
        return back(tid)

    @app.post("/admin/tenants/{tenant_id}/disable")
    async def tenant_disable(request: Request, tenant_id: str) -> Response:
        principal = await owner(request)
        tid = tenant_uuid(tenant_id)
        form, outcome = await guarded_form(request, principal, "tenant.disable", {"tenant": str(tid)})
        if not outcome.replayed:
            # high-impact: require the password again unless the session re-authenticated very recently
            if not sessions.recently_reauthenticated(principal.session, settings) and not verify_password(
                principal.user.password_hash, str(form.get("password", ""))[:256]
            ):
                await idempotency.abandon(services.db, outcome.key_hash)
                raise Forbidden("reauthentication_required")
            try:
                await services.tenants.disable(principal.user.id, tid)
            except Exception:
                await idempotency.abandon(services.db, outcome.key_hash)
                raise
            await idempotency.complete(services.db, outcome.key_hash, {"ok": True})
        return back(tid)

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        principal = await owner(request)
        await require_csrf(request, principal)
        async with services.db.session() as session:
            row = await sessions.load_session(session, settings, request.cookies.get(sessions.SESSION_COOKIE))
            if row is not None:
                await sessions.destroy_session(session, row)
            await audit.record(
                session, action=audit.LOGOUT, outcome="ok", actor_type="user", actor_id=principal.id
            )
            await session.commit()
        response = RedirectResponse("/", status_code=303)
        sessions.clear_session_cookie(response)
        return response
