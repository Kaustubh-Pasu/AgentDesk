"""SQLAlchemy 2 models + async engine helpers.

Design notes
- Portable column types (``Uuid``, ``JSON``→``JSONB`` on PostgreSQL, non-native enums) so the exact same
  models run on PostgreSQL in production and SQLite in unit tests.
- ``AuditEvent`` is append-only (ORM guard here + a PostgreSQL trigger in the migration).
- ``AgentConfig`` is immutable once published (ORM guard); a new publication creates a new version row.
- No model ever stores a private key, PAT, or raw session token.
"""

from __future__ import annotations

import enum
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    event,
    inspect,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.pool import StaticPool
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Always store/return timezone-aware UTC datetimes (SQLite drops tzinfo otherwise)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime is not allowed")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


JSONType = JSON().with_variant(JSONB(), "postgresql")


def _enum(py_enum: type[enum.Enum]) -> Enum:
    return Enum(py_enum, native_enum=False, length=40, validate_strings=True, create_constraint=True)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- enums
class Role(enum.StrEnum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"


class TenantState(enum.StrEnum):
    DRAFT = "DRAFT"
    INGESTED = "INGESTED"
    DEPLOYED = "DEPLOYED"
    REGISTRATION_SUBMITTED = "REGISTRATION_SUBMITTED"
    PENDING_VALIDATION = "PENDING_VALIDATION"
    ACTIVE = "ACTIVE"
    FAILED = "FAILED"
    REVOKED = "REVOKED"
    DISABLED = "DISABLED"


# States in which the public runtime serves the tenant.
SERVING_STATES = frozenset(
    {
        TenantState.DEPLOYED,
        TenantState.REGISTRATION_SUBMITTED,
        TenantState.PENDING_VALIDATION,
        TenantState.ACTIVE,
        TenantState.FAILED,  # ANS registration failed, but the published agent itself is still healthy
    }
)


class CertType(enum.StrEnum):
    IDENTITY = "IDENTITY"
    SERVER = "SERVER"
    TLS_OBSERVED = "TLS_OBSERVED"


class CheckStatus(enum.StrEnum):
    PASS = "PASS"  # noqa: S105 - verification status, not a password
    FAIL = "FAIL"
    INCOMPLETE = "INCOMPLETE"


class ImportStatus(enum.StrEnum):
    RUNNING = "RUNNING"
    DONE = "DONE"
    FAILED = "FAILED"


class IdempotencyState(enum.StrEnum):
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"


# --------------------------------------------------------------------------- tables
class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[Role] = mapped_column(_enum(Role), nullable=False, default=Role.OWNER)
    mfa_state: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    tenants: Mapped[list[Tenant]] = relationship(back_populates="owner")


class UserSession(Base):
    """Opaque server-side session. Only an HMAC of the cookie token is stored."""

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)
    reauth_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    user_agent: Mapped[str] = mapped_column(String(200), nullable=False, default="")

    user: Mapped[User] = relationship()

    __table_args__ = (Index("ix_sessions_user_id", "user_id"),)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    source_url: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    source_domain: Mapped[str] = mapped_column(String(253), nullable=False, default="")
    agent_host: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    state: Mapped[TenantState] = mapped_column(_enum(TenantState), nullable=False, default=TenantState.DRAFT)
    current_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # optimistic-lock counter: concurrent edits cannot silently overwrite each other
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)

    owner: Mapped[User] = relationship(back_populates="tenants")
    configs: Mapped[list[AgentConfig]] = relationship(back_populates="tenant", cascade="all, delete-orphan")

    __mapper_args__ = {"version_id_col": row_version}
    __table_args__ = (Index("ix_tenants_owner_id", "owner_id"),)


class AgentConfig(Base):
    __tablename__ = "agent_configs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    profile: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    allowed_capabilities: Mapped[list[str]] = mapped_column(JSONType, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="configs")

    __table_args__ = (UniqueConstraint("tenant_id", "version", name="uq_agent_configs_tenant_version"),)


class ANSRegistration(Base):
    __tablename__ = "ans_registrations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    agent_host: Mapped[str] = mapped_column(String(253), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ans_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Status string exactly as last reported by GoDaddy ANS. Never set to ACTIVE locally.
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="NOT_SUBMITTED")
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    challenge: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        UniqueConstraint("tenant_id", "version", name="uq_ans_registrations_tenant_version"),
        Index("ix_ans_registrations_agent_host", "agent_host"),
    )


class CertificateEvidence(Base):
    __tablename__ = "certificate_evidence"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    agent_host: Mapped[str] = mapped_column(String(253), nullable=False)
    agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    cert_type: Mapped[CertType] = mapped_column(_enum(CertType), nullable=False)
    public_pem: Mapped[str | None] = mapped_column(Text, nullable=True)  # PUBLIC certificate only
    issuer: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    subject: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    san: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    serial: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    chain_status: Mapped[CheckStatus] = mapped_column(
        _enum(CheckStatus), nullable=False, default=CheckStatus.INCOMPLETE
    )
    chain_reason: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    __table_args__ = (Index("ix_certificate_evidence_host_type", "agent_host", "cert_type"),)


class AuditEvent(Base):
    """Append-only semantic audit trail. Metadata is redacted before insert."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, default="-")
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    target_id: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    meta: Mapped[dict[str, Any]] = mapped_column("metadata", JSONType, nullable=False, default=dict)

    __table_args__ = (Index("ix_audit_events_ts", "ts"), Index("ix_audit_events_action", "action"))


class IdempotencyRecord(Base):
    """Replay ledger for state-changing operations (key is bound to actor + operation + payload hash)."""

    __tablename__ = "idempotency_keys"

    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[IdempotencyState] = mapped_column(_enum(IdempotencyState), nullable=False)
    response: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False)


class ImportJob(Base):
    __tablename__ = "import_jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    owner_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[ImportStatus] = mapped_column(
        _enum(ImportStatus), nullable=False, default=ImportStatus.RUNNING
    )
    pages_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    extraction_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    __table_args__ = (Index("ix_import_jobs_owner_status", "owner_id", "status"),)


class CardObservation(Base):
    """Last verified A2A Agent Card hash per remote agent; drift forces re-verification + audit."""

    __tablename__ = "card_observations"

    agent_host: Mapped[str] = mapped_column(String(253), primary_key=True)
    ans_name: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    card_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    drift_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # set when drift was observed; cleared only by an explicit owner/admin re-approval
    drift_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class BlockedAgent(Base):
    """Local deny-list: wins over whatever the remote registry says."""

    __tablename__ = "blocked_agents"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    agent_host: Mapped[str] = mapped_column(String(253), unique=True, nullable=False)
    reason: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)


# --------------------------------------------------------------------------- ORM guards
@event.listens_for(AuditEvent, "before_update")
def _audit_no_update(*_: Any) -> None:
    raise PermissionError("audit_events is append-only")


@event.listens_for(AuditEvent, "before_delete")
def _audit_no_delete(*_: Any) -> None:
    raise PermissionError("audit_events is append-only")


_IMMUTABLE_AFTER_PUBLISH = ("profile", "allowed_capabilities", "content_hash", "version", "tenant_id")


@event.listens_for(AgentConfig, "before_update")
def _config_immutable_after_publish(_mapper: Any, _conn: Any, target: AgentConfig) -> None:
    state = inspect(target)
    published_hist = state.attrs.published_at.history
    was_published = bool(published_hist.unchanged and published_hist.unchanged[0] is not None) or bool(
        published_hist.deleted and published_hist.deleted[0] is not None
    )
    if not was_published:
        return
    for name in (*_IMMUTABLE_AFTER_PUBLISH, "published_at"):
        if state.attrs[name].history.has_changes():
            raise PermissionError("published AgentConfig is immutable; publish a new version instead")


# --------------------------------------------------------------------------- engine helpers
class Database:
    def __init__(self, url: str, *, echo: bool = False) -> None:
        kwargs: dict[str, Any] = {"echo": echo, "future": True}
        if url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in url or url.endswith("://"):
                kwargs["poolclass"] = StaticPool
        else:
            kwargs.update(pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=1800)
        self.url = url
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        if url.startswith("sqlite"):

            @event.listens_for(self.engine.sync_engine, "connect")
            def _fk_pragma(dbapi_conn: Any, _rec: Any) -> None:
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    @property
    def is_postgres(self) -> bool:
        return self.engine.dialect.name == "postgresql"

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as session:
            try:
                yield session
            except BaseException:
                await session.rollback()
                raise

    async def create_all(self) -> None:
        """Development/test convenience. Production uses Alembic migrations."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()
