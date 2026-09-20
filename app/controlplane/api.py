"""Privileged control plane: the ONLY process that holds the GoDaddy credential and the ANS private keys.

In production the public desk never sees the PAT. It sends typed, already-authorized requests
(``tenant_id``, ``owner_id``, ``step``) over the private network with a bearer token that only these two services
share; the control plane re-checks ownership itself (``RegistrationService`` is owner-scoped) and performs the ANS
call. There is no generic "call this URL" or "write this DNS record" operation. With ``CONTROLPLANE_URL`` empty
(development / role ``all``) the same service object is used in-process.

Two further narrow operations exist for the same reason — the desk needs a result that only the credential or
the ANS private key can produce, and must not hold either:

- ``/internal/ans/certificates`` returns the PUBLIC identity certificate of one agent id. The desk's verifier
  needs it for checks 8-10; the certificate is public material, the credential that fetches it is not.
- ``/internal/ans/sign-card`` returns a detached JWS over one Agent Card, made with that agent's ANS identity
  key. The key never leaves this process; only the signature comes back.

Both take a typed, bounded request and expose no way to choose a URL, a key file or an output format.
"""

from __future__ import annotations

import hmac
import uuid
from datetime import datetime
from typing import Any, Protocol

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.ans.card_signature import CardSigner, sign_card
from app.ans.certs import CertError, KeyStore, load_certificates
from app.ans.client import AnsApiError, AnsClient, CertificateResponse, CertificateSource
from app.ans.registration import RegistrationError, RegistrationService, RegistrationSnapshot
from app.models.schemas import ans_name_for
from app.security.breakers import FeatureDisabled
from app.security.hosts import HostPolicyError, validate_agent_host
from app.settings import Settings

STEPS = ("submit", "refresh", "verify_acme", "verify_dns")
MAX_CARD_BYTES = 256 * 1024


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


class _CertificateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: uuid.UUID


class _SignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_host: str = Field(max_length=253)
    version: str = Field(max_length=40)
    card: dict[str, Any]


# --------------------------------------------------------------------------- identity certificates
class RemoteCertificates:
    """Desk-side client. Holds the shared service token, NOT the GoDaddy credential."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings, self._transport = settings, transport

    @property
    def configured(self) -> bool:
        return bool(self._settings.controlplane_url and self._settings.controlplane_token.get_secret_value())

    async def get_identity_certificates(self, agent_id: str) -> list[CertificateResponse]:
        data = await _post_internal(
            self._settings, "/internal/ans/certificates", {"agent_id": str(agent_id)}, self._transport
        )
        items = data.get("certificates", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            raise AnsApiError(0, "CONTROLPLANE_BAD_RESPONSE")
        return [CertificateResponse.model_validate(item) for item in items[:8] if isinstance(item, dict)]


# --------------------------------------------------------------------------- card signing
class NullCardSigner:
    """No ANS key reachable (e.g. the scraper role, or a deployment that never registered). Serve unsigned."""

    async def sign(self, agent_host: str, version: str, card: dict[str, Any]) -> dict[str, str] | None:
        return None


class LocalCardSigner:
    """Signs with the ANS identity key, but only after proving that key matches the certificate ANS issued."""

    def __init__(self, settings: Settings, ans: AnsClient, keystore: KeyStore) -> None:
        self._settings, self._ans, self._keystore = settings, ans, keystore
        self._certificates: dict[tuple[str, str], Certificate] = {}

    async def _certificate(self, agent_host: str, version: str) -> Certificate:
        cached = self._certificates.get((agent_host, version))
        if cached is not None:
            return cached
        agents = await self._ans.find_my_agent(agent_host, version)
        if not agents:
            raise AnsApiError(404, "AGENT_NOT_OWNED")
        certs = await self._ans.get_identity_certificates(agents[0].agent_id)
        if not certs:
            raise AnsApiError(404, "NO_IDENTITY_CERTIFICATE")
        leaf = load_certificates(certs[-1].certificate_pem, limit=1)[0]
        if len(self._certificates) < 64:
            self._certificates[(agent_host, version)] = leaf
        return leaf

    async def sign(self, agent_host: str, version: str, card: dict[str, Any]) -> dict[str, str] | None:
        if not self._ans.configured:
            return None
        try:
            host = validate_agent_host(agent_host, self._settings.base_domain)
            key = self._keystore.load(host, version, "identity")
            if key is None:
                return None
            certificate = await self._certificate(host, version)
            certified = certificate.public_key()
            if (
                not isinstance(certified, rsa.RSAPublicKey)
                or certified.public_numbers() != key.public_key().public_numbers()
            ):
                return None  # the registry certified a different key: never sign with a key it does not know
            return sign_card(key, certificate, ans_name_for(host, version), card)
        except (AnsApiError, CertError, HostPolicyError, ValueError, FeatureDisabled):
            return None  # fail closed: an unsigned card is INCOMPLETE, never a wrong signature


class RemoteCardSigner:
    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings, self._transport = settings, transport

    async def sign(self, agent_host: str, version: str, card: dict[str, Any]) -> dict[str, str] | None:
        body = {"agent_host": agent_host, "version": version, "card": card}
        try:
            data = await _post_internal(self._settings, "/internal/ans/sign-card", body, self._transport)
        except AnsApiError:
            return None
        signature = data.get("signature") if isinstance(data, dict) else None
        return signature if isinstance(signature, dict) and signature.get("signature") else None


async def _post_internal(
    settings: Settings, path: str, body: dict[str, Any], transport: httpx.AsyncBaseTransport | None
) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {settings.controlplane_token.get_secret_value()}"}
    try:
        async with httpx.AsyncClient(
            timeout=30, trust_env=False, follow_redirects=False, transport=transport
        ) as client:
            response = await client.post(
                f"{settings.controlplane_url.rstrip('/')}{path}", json=body, headers=headers
            )
        data: dict[str, Any] = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AnsApiError(0, "CONTROLPLANE_UNAVAILABLE") from exc
    if response.status_code != 200:
        error = data.get("error", {}) if isinstance(data, dict) else {}
        raise AnsApiError(
            int(error.get("status", response.status_code) or response.status_code),
            str(error.get("code", "CONTROLPLANE_ERROR"))[:64],
        )
    return data


def controlplane_routes(
    settings: Settings,
    registrar: LocalRegistrar,
    certificates: CertificateSource | None = None,
    signer: CardSigner | None = None,
) -> list[Route]:
    expected = settings.controlplane_token.get_secret_value()

    def authorized(request: Request) -> bool:
        supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        return bool(expected) and hmac.compare_digest(supplied.encode(), expected.encode())

    async def ans_step(request: Request) -> JSONResponse:
        if not authorized(request):
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

    async def ans_certificates(request: Request) -> JSONResponse:
        """Public identity certificate of ONE agent id. The credential stays here; the PEM is public."""
        if not authorized(request):
            return JSONResponse({"error": {"code": "unauthorized"}}, 401)
        if certificates is None or not certificates.configured:
            return JSONResponse({"error": {"code": "ANS_CREDENTIAL_MISSING", "status": 0}}, 422)
        try:
            query = _CertificateRequest.model_validate(await request.json())
        except (ValueError, ValidationError):
            return JSONResponse({"error": {"code": "bad_request"}}, 400)
        try:
            found = await certificates.get_identity_certificates(str(query.agent_id))
        except (AnsApiError, FeatureDisabled) as exc:
            return JSONResponse({"error": {"code": exc.code, "status": getattr(exc, "status", 0)}}, 422)
        return JSONResponse(
            {
                "certificates": [
                    {"certificatePEM": c.certificate_pem, "chainPEM": c.chain_pem} for c in found[:8]
                ]
            }
        )

    async def sign_agent_card(request: Request) -> JSONResponse:
        """Detached JWS over one Agent Card, made with that agent's ANS identity key. The key stays here."""
        if not authorized(request):
            return JSONResponse({"error": {"code": "unauthorized"}}, 401)
        body = await request.body()
        if len(body) > MAX_CARD_BYTES:
            return JSONResponse({"error": {"code": "card_too_large"}}, 400)
        try:
            query = _SignRequest.model_validate_json(body)
        except (ValueError, ValidationError):
            return JSONResponse({"error": {"code": "bad_request"}}, 400)
        signature = None if signer is None else await signer.sign(query.agent_host, query.version, query.card)
        return JSONResponse({"signature": signature})

    return [
        Route("/internal/ans/step", ans_step, methods=["POST"]),
        Route("/internal/ans/certificates", ans_certificates, methods=["POST"]),
        Route("/internal/ans/sign-card", sign_agent_card, methods=["POST"]),
    ]


class RemoteRegistrar:
    """Desk-side client. Holds the shared service token, NOT the GoDaddy credential."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings, self._transport = settings, transport

    async def run(self, tenant_id: uuid.UUID, owner_id: uuid.UUID, step: str) -> RegistrationSnapshot:
        headers = {"Authorization": f"Bearer {self._settings.controlplane_token.get_secret_value()}"}
        body = {"tenant_id": str(tenant_id), "owner_id": str(owner_id), "step": step}
        try:
            async with httpx.AsyncClient(
                timeout=60, trust_env=False, follow_redirects=False, transport=self._transport
            ) as client:
                response = await client.post(
                    f"{self._settings.controlplane_url.rstrip('/')}/internal/ans/step",
                    json=body,
                    headers=headers,
                )
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
