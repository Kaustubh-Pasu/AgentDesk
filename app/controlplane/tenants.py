"""Tenant lifecycle for CREATE: create → import (draft) → owner confirms → publish. Every query is owner-scoped.

BOLA/IDOR: a tenant that belongs to someone else is indistinguishable from one that does not exist (404).
Mass assignment: only ``TenantCreateInput`` / ``ProfileConfirmInput`` fields are ever read from a request.
Concurrency: optimistic ``row_version`` — a stale confirmation is rejected instead of overwriting.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError

from app.agents.llm import LLMClient
from app.agents.registry import AgentRegistry
from app.ingestion.extraction_model import ExtractionFailed, ExtractionResult, extract_profile
from app.ingestion.safe_fetch import FetchError
from app.ingestion.scraper_service import Crawler
from app.logging_config import get_logger
from app.models.db import AgentConfig, Database, ImportJob, ImportStatus, Tenant, TenantState, utcnow
from app.models.schemas import BusinessProfile, ProfileConfirmInput, TenantCreateInput, bump_patch, canonical_json
from app.security import audit
from app.security.breakers import Feature, require
from app.security.hosts import HostPolicyError, agent_host_for_label
from app.security.rate_limit import RateLimiter
from app.security.ssrf import SSRFBlocked
from app.settings import Settings

log = get_logger("controlplane.tenants")
MAX_TENANTS_PER_OWNER = 10


class TenantError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


@dataclass
class TenantView:
    tenant: Tenant
    draft: AgentConfig | None
    published: AgentConfig | None


class TenantService:
    def __init__(self, db: Database, settings: Settings, registry: AgentRegistry, limiter: RateLimiter, crawler: Crawler,
                 llm: LLMClient | None) -> None:
        self._db, self._settings, self._registry = db, settings, registry
        self._limiter, self._crawler, self._llm = limiter, crawler, llm

    # ------------------------------------------------------------------ reads (owner-scoped)
    async def list_for(self, owner_id: uuid.UUID) -> list[Tenant]:
        async with self._db.session() as session:
            rows = await session.execute(select(Tenant).where(Tenant.owner_id == owner_id).order_by(Tenant.created_at.desc()))
            return list(rows.scalars())

    async def view(self, owner_id: uuid.UUID, tenant_id: uuid.UUID) -> TenantView:
        async with self._db.session() as session:
            tenant = (await session.execute(select(Tenant).where(Tenant.id == tenant_id, Tenant.owner_id == owner_id))).scalar_one_or_none()
            if tenant is None:
                raise TenantError("not_found", "No such agent.", 404)
            configs = list((await session.execute(select(AgentConfig).where(AgentConfig.tenant_id == tenant_id))).scalars())
        draft = next((c for c in configs if c.published_at is None), None)
        published = next((c for c in configs if c.published_at is not None and c.version == tenant.current_version), None)
        return TenantView(tenant, draft, published)

    # ------------------------------------------------------------------ create
    async def create(self, owner_id: uuid.UUID, data: TenantCreateInput) -> Tenant:
        require(self._settings, Feature.AGENT_CREATION)
        try:
            agent_host = agent_host_for_label(data.agent_label, self._settings.base_domain)
        except HostPolicyError as exc:
            raise TenantError(exc.code, str(exc), 422) from exc
        if agent_host in (self._settings.desk_host, self._settings.demo_host):
            raise TenantError("label_reserved", "that subdomain is reserved", 422)
        async with self._db.session() as session:
            count = len(list((await session.execute(select(Tenant.id).where(Tenant.owner_id == owner_id))).scalars()))
            if count >= MAX_TENANTS_PER_OWNER:
                raise TenantError("tenant_quota", "Agent limit reached for this account.", 429)
            tenant = Tenant(owner_id=owner_id, display_name=data.display_name, source_url=data.source_url,
                            source_domain=(urlsplit(data.source_url).hostname or "").lower(), agent_host=agent_host)
            session.add(tenant)
            try:
                await session.flush()
            except IntegrityError as exc:
                raise TenantError("host_taken", "That agent hostname is already in use.", 409) from exc
            await audit.record(session, action=audit.TENANT_CREATE, outcome="ok", actor_type="user", actor_id=str(owner_id),
                               target_type="tenant", target_id=str(tenant.id), metadata={"agent_host": agent_host})
            await session.commit()
            return tenant

    # ------------------------------------------------------------------ import
    async def run_import(self, owner_id: uuid.UUID, tenant_id: uuid.UUID) -> ExtractionResult:
        require(self._settings, Feature.AGENT_CREATION)
        require(self._settings, Feature.EXTERNAL_FETCH)
        view = await self.view(owner_id, tenant_id)
        owner = str(owner_id)
        if not await self._limiter.acquire_once("import-active", owner, 180):
            raise TenantError("import_in_progress", "An import is already running for this account.", 409)
        try:
            await self._limiter.enforce("import", owner, limit=self._settings.rl_import_per_hour, window_s=3600)
            async with self._db.session() as session:
                job = ImportJob(tenant_id=tenant_id, owner_id=owner_id)
                session.add(job)
                await audit.record(session, action=audit.IMPORT_START, outcome="ok", actor_type="user", actor_id=owner,
                                   target_type="tenant", target_id=str(tenant_id), metadata={"source_domain": view.tenant.source_domain})
                await session.commit()
            try:
                crawl = await self._crawler.crawl(view.tenant.source_url)
                result = await extract_profile(crawl.pages, self._llm, principal=f"user:{owner}")
            except (SSRFBlocked, FetchError, ExtractionFailed) as exc:
                await self._finish_job(job.id, ImportStatus.FAILED, error=exc.code)
                blocked = isinstance(exc, SSRFBlocked)
                await audit.record_independent(self._db, action=audit.SSRF_BLOCKED if blocked else audit.IMPORT_FAILED, outcome="blocked" if blocked else "error",
                                               actor_type="user", actor_id=owner, target_type="tenant", target_id=str(tenant_id), metadata={"code": exc.code})
                raise TenantError(exc.code, "The website could not be imported safely.", 422) from exc
            await self._store_draft(view.tenant, result, crawl.bytes_fetched)
            await self._finish_job(job.id, ImportStatus.DONE, pages=len(crawl.pages), size=crawl.bytes_fetched, mode=result.mode)
            return result
        finally:
            await self._limiter.release("import-active", owner)

    async def _finish_job(self, job_id: uuid.UUID, status: ImportStatus, *, error: str | None = None, pages: int = 0,
                          size: int = 0, mode: str = "") -> None:
        async with self._db.session() as session:
            job = (await session.execute(select(ImportJob).where(ImportJob.id == job_id))).scalar_one()
            job.status, job.error_code, job.pages_fetched, job.bytes_fetched = status, error, pages, size
            job.extraction_mode, job.finished_at = mode, utcnow()
            if status is ImportStatus.DONE:
                await audit.record(session, action=audit.IMPORT_DONE, outcome="ok", target_type="tenant", target_id=str(job.tenant_id),
                                   metadata={"pages": pages, "bytes": size, "mode": mode})
            await session.commit()

    async def _store_draft(self, tenant: Tenant, result: ExtractionResult, size: int) -> None:
        """Only the normalized profile is stored — never the fetched HTML."""
        profile = result.output.profile
        version = bump_patch(tenant.current_version) if tenant.current_version else self._settings.ans_agent_version
        source_hash = hashlib.sha256(canonical_json({"urls": profile.source_urls, "bytes": size}).encode()).hexdigest()
        async with self._db.session() as session:
            draft = (await session.execute(select(AgentConfig).where(AgentConfig.tenant_id == tenant.id, AgentConfig.published_at.is_(None)))).scalar_one_or_none()
            if draft is None:
                draft = AgentConfig(tenant_id=tenant.id, version=version, profile={}, allowed_capabilities=[], content_hash="")
                session.add(draft)
            draft.version, draft.profile = version, profile.model_dump(mode="json")
            draft.allowed_capabilities = [c.value for c in result.output.capabilities]
            draft.content_hash, draft.source_hash = profile.content_hash(), source_hash
            row = (await session.execute(select(Tenant).where(Tenant.id == tenant.id))).scalar_one()
            if row.state is TenantState.DRAFT:
                row.state = TenantState.INGESTED
            await session.commit()

    # ------------------------------------------------------------------ confirm + publish
    async def confirm_and_publish(self, owner_id: uuid.UUID, tenant_id: uuid.UUID, data: ProfileConfirmInput) -> AgentConfig:
        require(self._settings, Feature.WRITES)
        view = await self.view(owner_id, tenant_id)
        if view.draft is None:
            raise TenantError("no_draft", "Import the website before publishing.", 409)
        if view.tenant.state in (TenantState.DISABLED, TenantState.REVOKED):
            raise TenantError("tenant_disabled", "This agent is disabled.", 409)
        profile: BusinessProfile = data.profile.model_copy(update={"source_urls": view.draft.profile.get("source_urls", [])})
        supported = set(profile.derived_capabilities())
        capabilities = [c for c in data.capabilities if c in supported]  # can only narrow what the content supports
        if not capabilities:
            raise TenantError("no_capabilities", "Select at least one capability the content supports.", 422)
        async with self._db.session() as session:
            tenant = (await session.execute(select(Tenant).where(Tenant.id == tenant_id, Tenant.owner_id == owner_id))).scalar_one()
            if tenant.row_version != data.row_version:
                raise TenantError("stale_version", "This agent changed in another session. Reload and try again.", 409)
            draft = (await session.execute(select(AgentConfig).where(AgentConfig.id == view.draft.id))).scalar_one()
            draft.profile, draft.allowed_capabilities = profile.model_dump(mode="json"), [c.value for c in capabilities]
            draft.content_hash, draft.published_at = profile.content_hash(), utcnow()
            tenant.current_version, tenant.display_name = draft.version, profile.business_name
            if tenant.state in (TenantState.DRAFT, TenantState.INGESTED, TenantState.FAILED):
                tenant.state = TenantState.DEPLOYED
            await audit.record(session, action=audit.CONFIG_PUBLISH, outcome="ok", actor_type="user", actor_id=str(owner_id), target_type="tenant",
                               target_id=str(tenant_id), metadata={"version": draft.version, "content_hash": draft.content_hash})
            try:
                await session.commit()
            except StaleDataError as exc:
                raise TenantError("stale_version", "This agent changed in another session. Reload and try again.", 409) from exc
        self._registry.invalidate(view.tenant.agent_host)
        return draft

    async def disable(self, owner_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        require(self._settings, Feature.WRITES)
        view = await self.view(owner_id, tenant_id)
        async with self._db.session() as session:
            tenant = (await session.execute(select(Tenant).where(Tenant.id == tenant_id, Tenant.owner_id == owner_id))).scalar_one()
            tenant.state = TenantState.DISABLED
            await audit.record(session, action=audit.TENANT_DISABLE, outcome="ok", actor_type="user", actor_id=str(owner_id),
                               target_type="tenant", target_id=str(tenant_id))
            await session.commit()
        self._registry.invalidate(view.tenant.agent_host)
