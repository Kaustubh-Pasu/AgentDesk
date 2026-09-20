"""ANS registration state machine.

    NOT_SUBMITTED → (register) → PENDING_VALIDATION → (verify-acme) → [PENDING_CERTS] → PENDING_DNS
                  → (verify-dns) → ACTIVE          terminal failures: FAILED / EXPIRED / REVOKED

Rules enforced here
- The stored status is ALWAYS the string GoDaddy last reported. Nothing in this module can write ``ACTIVE``
  (or any other status) that did not come out of a live API response.
- DNS records are taken verbatim from the API but must match the exact-name policy for THIS agent host;
  anything else is reported, never acted on. This module itself performs no DNS writes.
- Only public material is persisted: DNS record name/type/value. ACME token / keyAuthorization are not
  even parsed. Private keys stay in the KeyStore.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select

from app.agents.registry import AgentRegistry, ServedAgent
from app.agents.runtime import ALL_SKILLS, skills_for
from app.ans.certs import CsrBundle, KeyStore
from app.ans.http01 import publish_http01_challenges
from app.logging_config import get_logger
from app.models.db import ANSRegistration, Database, Tenant, TenantState, utcnow
from app.models.schemas import ans_name_for
from app.protocols.a2a_server import A2A_RPC_PATH, AGENT_CARD_PATH
from app.protocols.mcp_server import MCP_METADATA_PATH, MCP_PATH, TOOLS_BY_KIND
from app.security import audit
from app.security.breakers import Feature, require
from app.security.kv import KV
from app.settings import Settings

log = get_logger("ans.registration")

PENDING_STATUSES = frozenset({"PENDING_VALIDATION", "PENDING_CERTS", "PENDING_DNS"})


class RegistrationError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


# --------------------------------------------------------------------------- payload
def _functions(skill_ids: tuple[str, ...]) -> list[dict[str, Any]]:
    return [
        {"id": s.id[:64], "name": s.name[:64], "tags": [t[:20] for t in s.tags[:5]]}
        for s in (ALL_SKILLS[i] for i in skill_ids)
    ]


def build_registration_payload(agent: ServedAgent, settings: Settings, csrs: CsrBundle) -> dict[str, Any]:
    """Current-schema ``AgentRegistrationRequest``. Every URL is https on ``agent.host`` (ANS requires both)."""
    origin = f"https://{agent.host}"
    return {
        "agentDisplayName": agent.display_name[:64],
        "agentDescription": agent.description[:150],
        "agentHost": agent.host,
        "version": agent.version,
        "endpoints": [
            {
                "agentUrl": f"{origin}{A2A_RPC_PATH}",
                "metaDataUrl": f"{origin}{AGENT_CARD_PATH}",
                "protocol": "A2A",
                "transports": ["JSON-RPC"],
                "functions": _functions(tuple(s.id for s in skills_for(agent))),
            },
            {
                "agentUrl": f"{origin}{MCP_PATH}",
                "metaDataUrl": f"{origin}{MCP_METADATA_PATH}",
                "protocol": "MCP",
                "transports": ["STREAMABLE-HTTP"],
                "functions": _functions(TOOLS_BY_KIND[agent.kind]),
            },
        ],
        "identityCsrPEM": csrs.identity_csr_pem,  # raw PEM text, NOT base64-of-PEM (notes §0.3)
        "serverCsrPEM": csrs.server_csr_pem,
    }


# --------------------------------------------------------------------------- DNS record policy
def _fqdn(name: str) -> str:
    return name.strip().lower().rstrip(".")


def acme_challenge_records(pending: RegistrationPending | None, agent_host: str) -> list[DnsRecord]:
    """DNS-01 TXT records, accepted ONLY at exactly ``_acme-challenge.<agent_host>``."""
    if pending is None:
        return []
    expected = f"_acme-challenge.{agent_host}"
    out = []
    for challenge in pending.all_challenges():
        record = challenge.dns_record
        if challenge.type.upper().replace("-", "_") != "DNS_01" or record is None:
            continue
        if _fqdn(record.name) != expected or record.type.upper() != "TXT":
            log.warning(
                "ignoring ACME challenge outside the exact-name policy", extra={"agent_host": agent_host}
            )
            continue
        out.append(record)
    return out


def allowed_dns_record(record: DnsRecord, agent_host: str) -> bool:
    """Permanent ANS records we are willing to publish: exact names under THIS host, expected types only."""
    name, rtype = _fqdn(record.name), record.type.upper()
    txt_names = {
        f"_ans.{agent_host}",
        f"_ans-badge.{agent_host}",
        f"_ra-badge.{agent_host}",
        f"_acme-challenge.{agent_host}",
    }
    if rtype == "TXT":
        return name in txt_names
    if rtype == "TLSA":
        return name == f"_443._tcp.{agent_host}"
    if rtype == "HTTPS":
        return name == agent_host
    return False


# --------------------------------------------------------------------------- snapshot
@dataclass
class RegistrationSnapshot:
    agent_host: str
    version: str
    environment: str
    status: str  # exactly as reported by GoDaddy
    agent_id: str | None = None
    ans_name: str | None = None
    acme_records: list[dict[str, Any]] = field(default_factory=list)
    dns_records: list[dict[str, Any]] = field(default_factory=list)
    rejected_records: list[dict[str, Any]] = field(default_factory=list)
    next_action: str = ""
    http01_ready: bool = False
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def active(self) -> bool:
        return self.status == "ACTIVE"

    def to_public_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["checked_at"] = self.checked_at.isoformat()
        return data


def _record_dict(record: DnsRecord) -> dict[str, Any]:
    return {
        "name": _fqdn(record.name),
        "type": record.type.upper(),
        "value": record.value,
        "ttl": record.ttl,
        "required": record.required,
        "purpose": record.purpose,
    }


def _next_action(status: str, acme: list[Any], dns: list[Any]) -> str:
    if status == "PENDING_VALIDATION":
        return "publish_acme_txt_then_verify_acme" if acme else "verify_acme"
    if status == "PENDING_CERTS":
        return "wait_for_certificate_issuance"
    if status == "PENDING_DNS":
        return "publish_dns_records_then_verify_dns" if dns else "wait_for_dns_records"
    if status == "ACTIVE":
        return "none"
    if status in TERMINAL_STATUSES:
        return "register_new_version"
    return "refresh"


class RegistrationFlow:
    """Stateless driver around the ANS client. Used by the DB-backed service AND the go-live CLI script."""

    def __init__(self, client: AnsClient, keystore: KeyStore, settings: Settings) -> None:
        self.client = client
        self._keystore = keystore
        self._settings = settings

    def _snapshot(
        self,
        agent_host: str,
        version: str,
        *,
        status: str,
        agent_id: str | None,
        ans_name: str | None,
        pending: RegistrationPending | None,
        dns: list[DnsRecord],
    ) -> RegistrationSnapshot:
        acme = acme_challenge_records(pending, agent_host)
        good = [r for r in dns if allowed_dns_record(r, agent_host)]
        bad = [r for r in dns if not allowed_dns_record(r, agent_host)]
        http01_ready = bool(pending and publish_http01_challenges(pending, self._settings.artifacts_path))
        return RegistrationSnapshot(
            agent_host=agent_host,
            version=version,
            environment=self.client.environment,
            status=status or "UNKNOWN",
            agent_id=agent_id,
            ans_name=ans_name,
            acme_records=[_record_dict(r) for r in acme],
            dns_records=[_record_dict(r) for r in good],
            rejected_records=[_record_dict(r) for r in bad],
            next_action=_next_action(status, acme, good),
            http01_ready=http01_ready,
        )

    def _from_details(self, details: AgentDetails, agent_host: str, version: str) -> RegistrationSnapshot:
        if details.agent_host and details.agent_host.lower() != agent_host:
            raise RegistrationError("host_mismatch", "registry record belongs to a different host")
        return self._snapshot(
            agent_host,
            version,
            status=details.agent_status,
            agent_id=details.agent_id,
            ans_name=details.ans_name or None,
            pending=details.registration_pending,
            dns=details.pending_dns_records(),
        )

    async def submit(self, agent: ServedAgent) -> RegistrationSnapshot:
        csrs = self._keystore.csr_bundle(agent.host, agent.version)
        payload = build_registration_payload(agent, self._settings, csrs)
        try:
            pending = await self.client.register(payload)
        except AnsApiError as exc:
            if exc.status != 409:
                raise
            # ANSName already exists: adopt it ONLY if the registry says it is ours (authenticated search).
            existing = await self.client.find_my_agent(agent.host, agent.version)
            if not existing:
                raise RegistrationError(
                    "ans_name_taken", "this host+version is already registered; bump the version"
                ) from exc
            return self._from_details(existing[0], agent.host, agent.version)
        if not pending.agent_id:
            found = await self.client.find_my_agent(agent.host, agent.version)
            if not found:
                raise RegistrationError(
                    "agent_id_missing", "registration accepted but no agentId could be recovered"
                )
            return self._from_details(found[0], agent.host, agent.version)
        expected_name = ans_name_for(agent.host, agent.version)
        if pending.ans_name and pending.ans_name != expected_name:
            raise RegistrationError("ans_name_mismatch", "registry returned an unexpected ANS name")
        return self._snapshot(
            agent.host,
            agent.version,
            status=pending.status,
            agent_id=pending.agent_id,
            ans_name=pending.ans_name or expected_name,
            pending=pending,
            dns=pending.dns_records,
        )

    async def refresh(self, agent_id: str, agent_host: str, version: str) -> RegistrationSnapshot:
        return self._from_details(await self.client.get_agent(agent_id), agent_host, version)

    async def trigger_acme(self, agent_id: str, agent_host: str, version: str) -> RegistrationSnapshot:
        await self.client.verify_acme(agent_id)
        return await self.refresh(agent_id, agent_host, version)

    async def trigger_dns(self, agent_id: str, agent_host: str, version: str) -> RegistrationSnapshot:
        await self.client.verify_dns(agent_id)
        return await self.refresh(agent_id, agent_host, version)

    async def poll_until(
        self,
        agent_id: str,
        agent_host: str,
        version: str,
        *,
        until: frozenset[str],
        timeout_s: float = 600.0,
        interval_s: float = 5.0,
    ) -> RegistrationSnapshot:
        """Poll live status with capped exponential backoff until it is in ``until`` or terminal, or time is up."""
        deadline = time.monotonic() + timeout_s
        delay = interval_s
        while True:
            snapshot = await self.refresh(agent_id, agent_host, version)
            if (
                snapshot.status in until
                or snapshot.status in TERMINAL_STATUSES
                or time.monotonic() + delay > deadline
            ):
                return snapshot
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 30.0)


# --------------------------------------------------------------------------- DB-backed service (tenants)
def tenant_state_for(status: str, current: TenantState) -> TenantState:
    if status == "ACTIVE":
        return TenantState.ACTIVE
    if status in PENDING_STATUSES:
        return TenantState.PENDING_VALIDATION
    if status in ("FAILED", "EXPIRED"):
        return TenantState.FAILED
    if status == "REVOKED":
        return TenantState.REVOKED
    return current  # unknown status strings never change local state


class RegistrationService:
    def __init__(
        self, db: Database, flow: RegistrationFlow, registry: AgentRegistry, kv: KV, settings: Settings
    ) -> None:
        self._db = db
        self._flow = flow
        self._registry = registry
        self._kv = kv
        self._settings = settings

    async def _persist(
        self, tenant_id: uuid.UUID, snapshot: RegistrationSnapshot, *, actor_id: str, action: str
    ) -> None:
        async with self._db.session() as session:
            tenant = (await session.execute(select(Tenant).where(Tenant.id == tenant_id))).scalar_one()
            row = (
                await session.execute(
                    select(ANSRegistration).where(
                        ANSRegistration.tenant_id == tenant_id, ANSRegistration.version == snapshot.version
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                row = ANSRegistration(
                    tenant_id=tenant_id, version=snapshot.version, agent_host=snapshot.agent_host
                )
                session.add(row)
            previous = row.status
            row.agent_id, row.ans_name = snapshot.agent_id, snapshot.ans_name
            row.status, row.environment = snapshot.status, snapshot.environment  # verbatim from the live API
            row.challenge = {
                "acme": snapshot.acme_records,
                "dns": snapshot.dns_records,
                "next_action": snapshot.next_action,
            }
            row.last_checked_at, row.last_error = snapshot.checked_at, None
            tenant.state = tenant_state_for(snapshot.status, tenant.state)
            meta = {
                "status": snapshot.status,
                "previous": previous,
                "environment": snapshot.environment,
                "agent_id": snapshot.agent_id,
            }
            await audit.record(
                session,
                action=action,
                outcome="ok",
                actor_type="user",
                actor_id=actor_id,
                target_type="tenant",
                target_id=str(tenant_id),
                metadata=meta,
            )
            if snapshot.active and previous != "ACTIVE":
                await audit.record(
                    session,
                    action=audit.ANS_ACTIVE,
                    outcome="ok",
                    actor_type="system",
                    target_type="tenant",
                    target_id=str(tenant_id),
                    metadata=meta,
                )
            await session.commit()
        self._registry.invalidate(snapshot.agent_host)

    async def _fail(
        self, tenant_id: uuid.UUID, version: str, agent_host: str, code: str, actor_id: str, action: str
    ) -> None:
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(ANSRegistration).where(
                        ANSRegistration.tenant_id == tenant_id, ANSRegistration.version == version
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                row = ANSRegistration(tenant_id=tenant_id, version=version, agent_host=agent_host)
                session.add(row)
            row.last_error, row.last_checked_at = code[:80], utcnow()
            await audit.record(
                session,
                action=action,
                outcome="error",
                actor_type="user",
                actor_id=actor_id,
                target_type="tenant",
                target_id=str(tenant_id),
                metadata={"code": code},
            )
            await session.commit()

    async def _agent_and_row(
        self, tenant_id: uuid.UUID, owner_id: uuid.UUID
    ) -> tuple[ServedAgent, ANSRegistration | None]:
        async with self._db.session() as session:
            tenant = (
                await session.execute(  # owner-scoped: another owner's tenant is indistinguishable from none
                    select(Tenant).where(Tenant.id == tenant_id, Tenant.owner_id == owner_id)
                )
            ).scalar_one_or_none()
            if tenant is None:
                raise RegistrationError("not_found")
            row = (
                await session.execute(
                    select(ANSRegistration).where(
                        ANSRegistration.tenant_id == tenant_id,
                        ANSRegistration.version == tenant.current_version,
                    )
                )
            ).scalar_one_or_none()
        self._registry.invalidate(tenant.agent_host)
        agent = await self._registry.resolve(tenant.agent_host)
        if agent is None:
            raise RegistrationError("not_deployed", "publish the agent before registering it")
        return agent, row

    async def submit(self, tenant_id: uuid.UUID, owner_id: uuid.UUID) -> RegistrationSnapshot:
        require(self._settings, Feature.WRITES)
        agent, row = await self._agent_and_row(tenant_id, owner_id)
        if row is not None and row.agent_id:
            raise RegistrationError(
                "already_submitted", "this version is already registered; refresh instead"
            )
        lock = f"ans:register:{tenant_id}:{agent.version}"
        if not await self._kv.set_nx(lock, 120):  # single-flight per tenant+version
            raise RegistrationError("in_progress", "a registration for this agent is already running")
        try:
            snapshot = await self._flow.submit(agent)
        except (AnsApiError, RegistrationError) as exc:
            await self._fail(
                tenant_id, agent.version, agent.host, exc.code, str(owner_id), audit.ANS_REGISTER
            )
            raise
        finally:
            await self._kv.delete(lock)
        await self._persist(tenant_id, snapshot, actor_id=str(owner_id), action=audit.ANS_REGISTER)
        return snapshot

    async def advance(self, tenant_id: uuid.UUID, owner_id: uuid.UUID, step: str) -> RegistrationSnapshot:
        """``step``: refresh | verify_acme | verify_dns. Always ends with a live status read."""
        agent, row = await self._agent_and_row(tenant_id, owner_id)
        if row is None or not row.agent_id:
            raise RegistrationError("not_submitted")
        if step not in ("refresh", "verify_acme", "verify_dns"):
            raise RegistrationError("step_invalid")
        if step != "refresh":
            require(self._settings, Feature.WRITES)
        call = {
            "refresh": self._flow.refresh,
            "verify_acme": self._flow.trigger_acme,
            "verify_dns": self._flow.trigger_dns,
        }[step]
        action = audit.ANS_STATUS_CHANGE if step == "refresh" else audit.ANS_DNS_VALIDATION
        try:
            snapshot = await call(row.agent_id, agent.host, agent.version)
        except (AnsApiError, RegistrationError) as exc:
            await self._fail(tenant_id, agent.version, agent.host, exc.code, str(owner_id), action)
            raise
        await self._persist(tenant_id, snapshot, actor_id=str(owner_id), action=action)
        return snapshot
