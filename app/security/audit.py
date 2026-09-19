"""Append-only semantic audit trail. Every event is also emitted to the structured log."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import correlation_id_var, get_logger
from app.models.db import AuditEvent, Database
from app.security.redaction import clean_text, redact_obj

log = get_logger("audit")

# Canonical action names (kept here so tests and dashboards agree).
LOGIN_SUCCESS = "auth.login.success"
LOGIN_FAILURE = "auth.login.failure"
LOGOUT = "auth.logout"
REAUTH = "auth.reauth"
SESSIONS_REVOKED = "auth.sessions.revoked"
AUTHZ_DENIED = "authz.denied"
CSRF_REJECTED = "csrf.rejected"
TENANT_CREATE = "tenant.create"
TENANT_DISABLE = "tenant.disable"
IMPORT_START = "import.start"
IMPORT_DONE = "import.done"
IMPORT_FAILED = "import.failed"
SSRF_BLOCKED = "ssrf.blocked"
CONFIG_EDIT = "config.edit"
CONFIG_PUBLISH = "config.publish"
ANS_REGISTER = "ans.register"
ANS_DNS_VALIDATION = "ans.dns_validation"
ANS_STATUS_CHANGE = "ans.status_change"
ANS_ACTIVE = "ans.active"
ANS_REVOKE = "ans.revoke"
KEY_ROTATION = "key.rotation"
VERIFY_FAILURE = "verify.failure"
VERIFY_SUCCESS = "verify.success"
CARD_DRIFT = "verify.card_drift"
REMOTE_CONNECT = "remote.connect"
UNSUPPORTED_OPERATION = "policy.unsupported_operation"
CIRCUIT_BREAKER = "circuit_breaker.state"
RATE_LIMITED = "rate_limit.exceeded"


def _build(
    *,
    action: str,
    outcome: str,
    actor_type: str,
    actor_id: str,
    target_type: str,
    target_id: str,
    metadata: dict[str, Any] | None,
) -> AuditEvent:
    meta = redact_obj(metadata or {})
    return AuditEvent(
        id=uuid.uuid4(),
        correlation_id=correlation_id_var.get()[:64],
        actor_type=clean_text(actor_type, max_len=32),
        actor_id=clean_text(actor_id, max_len=64),
        action=clean_text(action, max_len=64),
        target_type=clean_text(target_type, max_len=32),
        target_id=clean_text(target_id, max_len=300),
        outcome=clean_text(outcome, max_len=32),
        meta=meta if isinstance(meta, dict) else {},
    )


async def record(
    session: AsyncSession,
    *,
    action: str,
    outcome: str,
    actor_type: str = "system",
    actor_id: str = "",
    target_type: str = "",
    target_id: str = "",
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    """Add an audit event to ``session`` (caller commits – the event shares the operation's transaction)."""
    event = _build(
        action=action,
        outcome=outcome,
        actor_type=actor_type,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        metadata=metadata,
    )
    session.add(event)
    log.info(
        "audit",
        extra={
            "audit_action": event.action,
            "audit_outcome": event.outcome,
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "meta": event.meta,
        },
    )
    return event


async def record_independent(db: Database, **kwargs: Any) -> None:
    """Persist an audit event in its OWN transaction (for failures where the main transaction rolls back)."""
    try:
        async with db.session() as session:
            await record(session, **kwargs)
            await session.commit()
    except Exception:  # auditing must never take the request down, but must be loud
        log.exception("failed to persist audit event", extra={"audit_action": kwargs.get("action")})
