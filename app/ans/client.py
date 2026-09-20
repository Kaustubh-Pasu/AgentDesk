"""GoDaddy ANS REST client (contract: docs/research/ANS_API_NOTES.md, researched live 2026-09-19).

Security properties
- The credential is sent ONLY to the configured GoDaddy API origin (allow-listed in settings). Redirects are
  never followed (an unauthenticated ``/v1/agents`` call 302s to SSO), and ``links[].href`` values returned by
  the registry are never dereferenced with the credential.
- Public discovery (``/v1/ans/*``) is called WITHOUT the credential: least privilege for the FIND path.
- Responses are size-capped and parsed through lenient-but-bounded models; raw bodies are never logged.
- Errors surface as ``AnsApiError`` with a safe code; the credential can never appear in one.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import uuid
from datetime import datetime
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.logging_config import get_logger
from app.settings import Settings

log = get_logger("ans.client")

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,127}\Z")
_RETRY_STATUS = frozenset({429, 502, 503, 504})
REVOCATION_REASONS = frozenset(
    {"KEY_COMPROMISE", "CESSATION_OF_OPERATION", "AFFILIATION_CHANGED", "CERTIFICATE_HOLD", "PRIVILEGE_WITHDRAWN",
     "AA_COMPROMISE"}
)
TERMINAL_STATUSES = frozenset({"ACTIVE", "FAILED", "EXPIRED", "REVOKED"})
CONNECTABLE_STATUSES = frozenset({"ACTIVE"})


class AnsApiError(Exception):
    def __init__(self, status: int, code: str, message: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(f"ANS API {status} {code}")
        self.status = status
        self.code = code[:64]
        self.message = message[:300]
        self.details = details or {}


class AnsNotConfigured(AnsApiError):
    def __init__(self) -> None:
        super().__init__(0, "ANS_CREDENTIAL_MISSING", "no GoDaddy ANS credential is configured")


# --------------------------------------------------------------------------- response models (lenient, bounded)
class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class AnsFunction(_Model):
    id: str = Field(max_length=128)
    name: str = Field("", max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=20)


class AnsEndpoint(_Model):
    agent_url: str = Field(alias="agentUrl", max_length=2048)
    protocol: str = Field(max_length=20)
    meta_data_url: str | None = Field(None, alias="metaDataUrl", max_length=2048)
    meta_data_hash: str | None = Field(None, alias="metaDataHash", max_length=200)
    transports: list[str] = Field(default_factory=list, max_length=10)
    functions: list[AnsFunction] = Field(default_factory=list, max_length=100)


class DnsRecord(_Model):
    name: str = Field(max_length=300)
    type: str = Field(max_length=10)
    value: str = Field(max_length=1024)
    purpose: str = Field("", max_length=40)
    required: bool = True
    ttl: int = 3600
    priority: int | None = None


class Challenge(_Model):
    type: str = Field("", max_length=20)
    http_path: str | None = Field(None, alias="httpPath", max_length=300)
    dns_record: DnsRecord | None = Field(None, alias="dnsRecord")
    expires_at: str | None = Field(None, alias="expiresAt", max_length=64)
    # token / keyAuthorization are deliberately NOT modelled: we never need them for DNS-01 and never store them.


class NextStep(_Model):
    action: str = Field("", max_length=40)
    description: str = Field("", max_length=300)


class RegistrationPending(_Model):
    status: str = Field("", max_length=40)
    agent_id: str | None = Field(None, alias="agentId", max_length=128)
    ans_name: str | None = Field(None, alias="ansName", max_length=300)
    challenges: list[Challenge] = Field(default_factory=list, max_length=10)
    challenge: Challenge | None = None  # the [SPEC] example uses the singular form
    dns_records: list[DnsRecord] = Field(default_factory=list, alias="dnsRecords", max_length=20)
    next_steps: list[NextStep] = Field(default_factory=list, alias="nextSteps", max_length=10)
    expires_at: str | None = Field(None, alias="expiresAt", max_length=64)

    def all_challenges(self) -> list[Challenge]:
        return [*self.challenges, *([self.challenge] if self.challenge else [])]


class AgentDetails(_Model):
    agent_id: str = Field(alias="agentId", max_length=128)
    agent_status: str = Field("", alias="agentStatus", max_length=40)
    ans_name: str = Field("", alias="ansName", max_length=300)
    agent_host: str = Field("", alias="agentHost", max_length=253)
    version: str = Field("", max_length=32)
    agent_display_name: str = Field("", alias="agentDisplayName", max_length=200)
    endpoints: list[AnsEndpoint] = Field(default_factory=list, max_length=10)
    registration_pending: RegistrationPending | None = Field(None, alias="registrationPending")
    dns_records: list[DnsRecord] = Field(default_factory=list, alias="dnsRecords", max_length=20)

    @field_validator("agent_status", mode="before")
    @classmethod
    def _status(cls, v: Any) -> Any:
        # the SDK documents agentStatus as EITHER a string or {status, phase, ...}
        return v.get("status", "") if isinstance(v, dict) else v

    def pending_dns_records(self) -> list[DnsRecord]:
        return self.dns_records or (self.registration_pending.dns_records if self.registration_pending else [])


class AgentStatus(_Model):
    status: str = Field("", max_length=40)
    phase: str = Field("", max_length=40)
    pending_steps: list[str] = Field(default_factory=list, alias="pendingSteps", max_length=10)


class CertificateResponse(_Model):
    certificate_pem: str = Field(alias="certificatePEM", max_length=32_768)
    chain_pem: str | None = Field(None, alias="chainPEM", max_length=65_536)
    certificate_valid_from: str | None = Field(None, alias="certificateValidFrom", max_length=64)
    certificate_valid_to: str | None = Field(None, alias="certificateValidTo", max_length=64)


class RevocationResponse(_Model):
    agent_id: str = Field("", alias="agentId", max_length=128)
    status: str = Field("", max_length=40)
    revoked_at: str | None = Field(None, alias="revokedAt", max_length=64)
    dns_records_to_remove: list[DnsRecord] = Field(default_factory=list, alias="dnsRecordsToRemove", max_length=20)


class _Lifecycle(_Model):
    status: str = Field("", max_length=40)


class _Scores(_Model):
    trust_score: float | None = Field(None, alias="trustScore")
    relevance: float | None = None


class DiscoveredAgent(_Model):
    """One hit of the public discovery API. ``agent_version`` is v-prefixed there; ``version`` strips it."""

    agent_id: str = Field(alias="agentId", max_length=128)
    agent_host: str = Field("", alias="agentHost", max_length=253)
    ans_name: str = Field("", alias="ansName", max_length=300)
    agent_display_name: str = Field("", alias="agentDisplayName", max_length=200)
    agent_description: str = Field("", alias="agentDescription", max_length=1000)
    agent_version: str = Field("", alias="agentVersion", max_length=33)
    lifecycle: _Lifecycle = Field(default_factory=_Lifecycle)
    scores: _Scores = Field(default_factory=_Scores)
    endpoints: list[AnsEndpoint] = Field(default_factory=list, max_length=10)

    @property
    def version(self) -> str:
        return self.agent_version.removeprefix("v")

    @property
    def status(self) -> str:
        return self.lifecycle.status


class Badge(_Model):
    """Transparency-Log badge, flattened to the fields the verifier compares."""

    status: str = Field("", max_length=40)
    ans_name: str = Field("", max_length=300)
    agent_host: str = Field("", max_length=253)
    identity_fingerprint: str = Field("", max_length=100)
    server_fingerprint: str = Field("", max_length=100)

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> Badge:
        def dig(node: Any, *keys: str) -> Any:
            for key in keys:
                node = node.get(key) if isinstance(node, dict) else None
            return node

        event = dig(data, "payload", "producer", "event") or {}
        return cls(
            status=str(data.get("status") or ""),
            ans_name=str(dig(event, "ansName") or ""),
            agent_host=str(dig(event, "agent", "host") or ""),
            identity_fingerprint=str(dig(event, "attestations", "identityCert", "fingerprint") or ""),
            server_fingerprint=str(dig(event, "attestations", "serverCert", "fingerprint") or ""),
        )


def parse_timestamp(value: str | None) -> datetime | None:
    """Lenient RFC 3339 (space separator, ``Z``, nanoseconds) → aware datetime, or None."""
    if not value:
        return None
    text = value.strip().replace(" ", "T", 1)
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


# --------------------------------------------------------------------------- client
class AnsClient:
    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None,
                 max_retries: int = 2, backoff_s: float = 0.5) -> None:
        self._settings = settings
        self._transport = transport
        self._max_retries = min(max_retries, 2)
        self._backoff_s = backoff_s

    @property
    def environment(self) -> str:
        return self._settings.ans_environment

    @property
    def configured(self) -> bool:
        return self._settings.ans_credential_configured

    def _auth_header(self) -> str:
        s = self._settings
        if not s.ans_credential_configured:
            raise AnsNotConfigured()
        if s.ans_auth_scheme == "bearer":
            return f"Bearer {s.godaddy_pat.get_secret_value()}"
        return f"sso-key {s.godaddy_api_key.get_secret_value()}:{s.godaddy_api_secret.get_secret_value()}"

    @staticmethod
    def _error(response: httpx.Response, raw: bytes) -> AnsApiError:
        code, message, details = f"HTTP_{response.status_code}", "", {}
        if response.status_code in (301, 302, 303, 307, 308):
            code = "UNAUTHENTICATED_REDIRECT"  # the gateway redirects unauthenticated calls to SSO
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
            if isinstance(body, dict):
                code = str(body.get("code") or body.get("name") or code)  # [LIVE] /v1/ans/* errors use "name"
                message = str(body.get("message") or "")
                if isinstance(body.get("details"), dict):
                    details = {str(k)[:40]: str(v)[:200] for k, v in list(body["details"].items())[:10]}
                for key in ("missingRecords", "incorrectRecords"):
                    if isinstance(body.get(key), list):
                        details[key] = body[key][:20]
        except (ValueError, UnicodeDecodeError, RecursionError):
            pass
        return AnsApiError(response.status_code, code, message, details)

    async def _call(self, method: str, path: str, *, auth: bool, params: dict[str, Any] | None = None,
                    body: dict[str, Any] | None = None, retry: bool = False, base: str | None = None) -> Any:
        headers = {"Accept": "application/json", "Content-Type": "application/json",
                   "X-Request-Id": str(uuid.uuid4())}
        if auth:
            headers["Authorization"] = self._auth_header()
        if base is not None and auth:
            raise AnsApiError(0, "CREDENTIAL_SCOPE")  # the credential only ever goes to the RA API origin
        url = f"{base or self._settings.godaddy_api_base}{path}"
        attempts = 1 + (self._max_retries if retry else 0)
        async with httpx.AsyncClient(timeout=self._settings.ans_request_timeout_s, follow_redirects=False,
                                     trust_env=False, transport=self._transport) as client:
            for attempt in range(attempts):
                try:
                    async with client.stream(method, url, headers=headers, params=params,
                                             content=json.dumps(body).encode() if body is not None else None) as response:
                        raw = b""
                        async for chunk in response.aiter_bytes():
                            raw += chunk
                            if len(raw) > MAX_RESPONSE_BYTES:
                                raise AnsApiError(response.status_code, "RESPONSE_TOO_LARGE")
                except httpx.HTTPError as exc:
                    if attempt + 1 < attempts:
                        await asyncio.sleep(self._backoff_s * 2**attempt + random.uniform(0, 0.1))  # noqa: S311
                        continue
                    raise AnsApiError(0, "ANS_UNREACHABLE", type(exc).__name__) from exc
                if response.status_code in _RETRY_STATUS and attempt + 1 < attempts:
                    delay = self._backoff_s * 2**attempt + random.uniform(0, 0.1)  # noqa: S311
                    reset = response.headers.get("ratelimit-reset", "")
                    if reset.isdigit():
                        delay = min(max(delay, float(reset)), 10.0)
                    await asyncio.sleep(delay)
                    continue
                if response.status_code not in (200, 202, 204):
                    error = self._error(response, raw)
                    log.warning("ans api error", extra={"path_template": re.sub(r"[0-9a-f-]{36}", "{id}", path),
                                                        "status": error.status, "code": error.code})
                    raise error
                if not raw:
                    return {}
                try:
                    return json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError, RecursionError) as exc:
                    raise AnsApiError(response.status_code, "INVALID_JSON") from exc
        raise AnsApiError(0, "ANS_UNREACHABLE")

    @staticmethod
    def _parse(model: type[Any], data: Any) -> Any:
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            raise AnsApiError(200, "UNEXPECTED_RESPONSE_SHAPE", f"{exc.error_count()} violation(s)") from exc

    @staticmethod
    def _id(agent_id: str) -> str:
        if not _AGENT_ID.match(agent_id):
            raise AnsApiError(0, "AGENT_ID_INVALID")
        return agent_id

    # ------------------------------------------------------------------ lifecycle (authenticated)
    async def register(self, payload: dict[str, Any]) -> RegistrationPending:
        return self._parse(RegistrationPending, await self._call("POST", "/v1/agents/register", auth=True, body=payload))

    async def get_agent(self, agent_id: str) -> AgentDetails:
        data = await self._call("GET", f"/v1/agents/{self._id(agent_id)}", auth=True, retry=True)
        return self._parse(AgentDetails, data)

    async def verify_acme(self, agent_id: str) -> AgentStatus:
        data = await self._call("POST", f"/v1/agents/{self._id(agent_id)}/verify-acme", auth=True, body={})
        return self._parse(AgentStatus, data)

    async def verify_dns(self, agent_id: str) -> AgentStatus:
        data = await self._call("POST", f"/v1/agents/{self._id(agent_id)}/verify-dns", auth=True, body={})
        return self._parse(AgentStatus, data)

    async def revoke(self, agent_id: str, reason: str, comments: str = "") -> RevocationResponse:
        if reason not in REVOCATION_REASONS:
            raise AnsApiError(0, "REVOCATION_REASON_INVALID")
        body = {"reason": reason, **({"comments": comments[:200]} if comments else {})}
        data = await self._call("POST", f"/v1/agents/{self._id(agent_id)}/revoke", auth=True, body=body)
        return self._parse(RevocationResponse, data)

    async def _certs(self, agent_id: str, kind: str) -> list[CertificateResponse]:
        data = await self._call("GET", f"/v1/agents/{self._id(agent_id)}/certificates/{kind}", auth=True, retry=True)
        if not isinstance(data, list):
            raise AnsApiError(200, "UNEXPECTED_RESPONSE_SHAPE")
        return [self._parse(CertificateResponse, item) for item in data[:10]]

    async def get_identity_certificates(self, agent_id: str) -> list[CertificateResponse]:
        return await self._certs(agent_id, "identity")

    async def get_server_certificates(self, agent_id: str) -> list[CertificateResponse]:
        return await self._certs(agent_id, "server")

    async def find_my_agent(self, agent_host: str, version: str | None = None) -> list[AgentDetails]:
        """``GET /v1/agents?agentHost=…&status=ALL`` — recover an agentId (e.g. after a 409)."""
        params: dict[str, Any] = {"agentHost": agent_host, "status": "ALL", "limit": 20}
        if version:
            params["version"] = version
        data = await self._call("GET", "/v1/agents", auth=True, params=params, retry=True)
        agents = data.get("agents", []) if isinstance(data, dict) else []
        hits = [self._parse(AgentDetails, a) for a in agents[:20] if isinstance(a, dict)]
        return [a for a in hits if a.agent_host.lower() == agent_host.lower()]  # API match may be partial

    # ------------------------------------------------------------------ public discovery (NO credential sent)
    async def discover(self, *, query: str = "", agent_host: str = "", protocols: tuple[str, ...] = (),
                       statuses: tuple[str, ...] = ("ACTIVE",), page_size: int = 10) -> list[DiscoveredAgent]:
        body: dict[str, Any] = {"pageSize": max(1, min(page_size, 25)), "statuses": list(statuses)}
        if query:
            body["query"] = query[:256]
        if agent_host:
            body["agentDomains"] = [agent_host]
        if protocols:
            body["protocols"] = list(protocols)
        data = await self._call("POST", "/v1/ans/search-registered-agents", auth=False, body=body, retry=True)
        items = data.get("items", []) if isinstance(data, dict) else []
        return [self._parse(DiscoveredAgent, item) for item in items[:25] if isinstance(item, dict)]

    async def get_registered_agent(self, agent_id: str) -> DiscoveredAgent:
        data = await self._call("GET", f"/v1/ans/registered-agents/{self._id(agent_id)}", auth=False, retry=True)
        return self._parse(DiscoveredAgent, data)

    async def get_badge(self, agent_id: str) -> Badge:
        """Public Transparency-Log badge (the ANS revocation channel). No credential; fixed official origin."""
        data = await self._call("GET", f"/v1/agents/{self._id(agent_id)}", auth=False, retry=True,
                                base=self._settings.transparency_log_base)
        if not isinstance(data, dict):
            raise AnsApiError(200, "UNEXPECTED_RESPONSE_SHAPE")
        return self._parse(Badge, Badge.from_wire(data).model_dump())
