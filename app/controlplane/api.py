"""Privileged control plane: the ONLY process that holds the GoDaddy credential and the ANS private keys.

In production the public desk never sees the PAT. It sends typed, already-authorized requests
(``tenant_id``, ``owner_id``, ``step``) over the private network with a bearer token that only these two services
share; the control plane re-checks ownership itself (``RegistrationService`` is owner-scoped) and performs the ANS
call. There is no generic "call this URL" or "write this DNS record" operation. With ``CONTROLPLANE_URL`` empty
(development / role ``all``) the same service object is used in-process.
"""

from __future__ import annotations

import hmac
import uuid
from datetime import datetime
from typing import Any, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.ans.client import AnsApiError
from app.ans.registration import RegistrationError, RegistrationService, RegistrationSnapshot
from app.security.breakers import FeatureDisabled
from app.settings import Settings

STEPS = ("submit", "refresh", "verify_acme", "verify_dns")


class Registrar(Protocol):
    async def run(self, tenant_id: uuid.UUID, owner_id: uuid.UUID, step: str) -> RegistrationSnapshot: ...


class LocalRegistrar:
    def __init__(self, service: RegistrationService) -> None:
        self._service = service

    async def run(self, tenant_id: uuid.UUID, owner_id: uuid.UUID, step: str) -> RegistrationSnapshot:
        if step == "submit":
            return await self._service.submit(tenant_id, owner_id)
        return await self._service.advance(tenant_id, owner_id, step)


class _Command(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: uuid.UUID
    owner_id: uuid.UUID
    step: str


def controlplane_routes(settings: Settings, registrar: LocalRegistrar) -> list[Route]:
    expected = settings.controlplane_token.get_secret_value()

    async def ans_step(request: Request) -> JSONResponse:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not expected or not hmac.compare_digest(supplied.encode(), expected.encode()):
            return JSONResponse({"error": {"code": "unauthorized"}}, 401)
        try:
            command = _Command.model_validate(await request.json())
        except (ValueError, ValidationError):
            return JSONResponse({"error": {"code": "bad_request"}}, 400)
        if command.step not in STEPS:
            return JSONResponse({"error": {"code": "step_invalid"}}, 400)
        try:
            snapshot = await registrar.run(command.tenant_id, command.owner_id, command.step)
        except (RegistrationError, AnsApiError, FeatureDisabled) as exc:
            return JSONResponse({"error": {"code": exc.code, "details": getattr(exc, "details", {})}}, 422)
        return JSONResponse(snapshot.to_public_dict())

    return [Route("/internal/ans/step", ans_step, methods=["POST"])]


class RemoteRegistrar:
    """Desk-side client. Holds the shared service token, NOT the GoDaddy credential."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings, self._transport = settings, transport

    async def run(self, tenant_id: uuid.UUID, owner_id: uuid.UUID, step: str) -> RegistrationSnapshot:
        headers = {"Authorization": f"Bearer {self._settings.controlplane_token.get_secret_value()}"}
        body = {"tenant_id": str(tenant_id), "owner_id": str(owner_id), "step": step}
        try:
            async with httpx.AsyncClient(timeout=60, trust_env=False, follow_redirects=False, transport=self._transport) as client:
                response = await client.post(f"{self._settings.controlplane_url.rstrip('/')}/internal/ans/step", json=body, headers=headers)
            data: dict[str, Any] = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RegistrationError("controlplane_unavailable") from exc
        if response.status_code != 200:
            error = data.get("error", {}) if isinstance(data, dict) else {}
            raise RegistrationError(str(error.get("code", "controlplane_error"))[:64])
        try:
            data["checked_at"] = datetime.fromisoformat(data["checked_at"])
            return RegistrationSnapshot(**data)
        except (KeyError, TypeError, ValueError) as exc:
            raise RegistrationError("controlplane_bad_response") from exc
