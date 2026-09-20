"""Validated Host → served agent mapping.

The ONLY way a request selects an agent is its (already TrustedHost-checked) Host header, looked up in
the database. There is no filesystem path, no dynamic import and no per-tenant code: every tenant is a
row of validated data served by the same trusted runtime.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError
from sqlalchemy import select

from app.logging_config import get_logger
from app.models.db import SERVING_STATES, AgentConfig, Database, Tenant
from app.models.schemas import BusinessProfile, Capability
from app.security.hosts import host_without_port
from app.settings import Settings

log = get_logger("agents.registry")

AgentKind = Literal["desk", "business"]


@dataclass(frozen=True)
class ServedAgent:
    host: str
    kind: AgentKind
    display_name: str
    description: str
    version: str
    profile: BusinessProfile | None = None
    capabilities: tuple[Capability, ...] = ()
    tenant_id: uuid.UUID | None = None


DESK_DESCRIPTION = (
    "Agent Desk discovers agents in the GoDaddy Agent Name Service, verifies their live ANS identity "
    "evidence, and relays read-only questions to verified agents."
)


class AgentRegistry:
    def __init__(self, db: Database, settings: Settings, *, ttl_s: float = 15.0) -> None:
        self._db = db
        self._settings = settings
        self._ttl_s = ttl_s
        self._cache: dict[str, tuple[float, ServedAgent | None]] = {}

    def desk_agent(self) -> ServedAgent:
        return ServedAgent(
            host=self._settings.desk_host,
            kind="desk",
            display_name="Agent Desk",
            description=DESK_DESCRIPTION,
            version=self._settings.ans_agent_version,
        )

    def invalidate(self, host: str | None = None) -> None:
        if host is None:
            self._cache.clear()
        else:
            self._cache.pop(host, None)

    async def resolve(self, host_header: str) -> ServedAgent | None:
        host = host_without_port(host_header)
        if host == self._settings.desk_host:
            return self.desk_agent()
        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and cached[0] > now:
            return cached[1]
        agent = await self._load(host)
        if len(self._cache) > 2048:
            self._cache.clear()
        self._cache[host] = (now + self._ttl_s, agent)
        return agent

    async def _load(self, host: str) -> ServedAgent | None:
        async with self._db.session() as session:
            row = (
                await session.execute(
                    select(Tenant, AgentConfig)
                    .join(
                        AgentConfig,
                        (AgentConfig.tenant_id == Tenant.id)
                        & (AgentConfig.version == Tenant.current_version),
                    )
                    .where(
                        Tenant.agent_host == host,
                        Tenant.state.in_(SERVING_STATES),
                        AgentConfig.published_at.is_not(None),
                    )
                )
            ).first()
        if row is None:
            return None
        tenant, config = row
        try:
            profile = BusinessProfile.model_validate(config.profile)
            capabilities = tuple(Capability(c) for c in config.allowed_capabilities)
        except (ValidationError, ValueError):
            # Stored config no longer satisfies the schema: refuse to serve rather than serve unvalidated data.
            log.error("stored agent config failed validation", extra={"agent_host": host})
            return None
        return ServedAgent(
            host=tenant.agent_host,
            kind="business",
            display_name=tenant.display_name,
            description=(profile.description or f"Read-only business assistant for {profile.business_name}.")[
                :400
            ],
            version=config.version,
            profile=profile,
            capabilities=capabilities,
            tenant_id=tenant.id,
        )
