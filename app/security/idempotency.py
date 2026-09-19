"""Replay protection / idempotency for state-changing operations.

A key is bound to ``actor + operation + canonical payload hash``. The ledger row is inserted with the key
hash as PRIMARY KEY, so two concurrent identical requests race on a unique constraint and exactly one wins
(atomic on both PostgreSQL and SQLite). Replays either get the stored result (DONE) or a conflict
(IN_PROGRESS / same key reused with a different payload).
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from app.models.db import Database, IdempotencyRecord, IdempotencyState, utcnow
from app.models.schemas import canonical_json

_KEY_SHAPE = re.compile(r"^[A-Za-z0-9_\-:.]{8,128}\Z")
DEFAULT_TTL = timedelta(hours=24)


class IdempotencyConflict(Exception):
    """Same key, different payload – or the first request is still running."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class IdempotencyOutcome:
    replayed: bool
    response: dict[str, Any] | None
    key_hash: str


def new_idempotency_key() -> str:
    return secrets.token_urlsafe(24)


def payload_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def _key_hash(actor_id: str, operation: str, key: str) -> str:
    return hashlib.sha256(f"{actor_id}\x1f{operation}\x1f{key}".encode()).hexdigest()


async def begin(
    db: Database, *, actor_id: str, operation: str, key: str, payload: Any, ttl: timedelta = DEFAULT_TTL
) -> IdempotencyOutcome:
    """Claim ``key``. Returns ``replayed=True`` with the stored response for a completed duplicate."""
    if not _KEY_SHAPE.match(key):
        raise IdempotencyConflict("idempotency_key_invalid")
    key_hash = _key_hash(actor_id, operation, key)
    p_hash = payload_hash(payload)
    now = utcnow()
    async with db.session() as session:
        await session.execute(delete(IdempotencyRecord).where(IdempotencyRecord.expires_at < now))
        session.add(
            IdempotencyRecord(
                key_hash=key_hash,
                actor_id=actor_id[:64],
                operation=operation[:64],
                payload_hash=p_hash,
                state=IdempotencyState.IN_PROGRESS,
                expires_at=now + ttl,
            )
        )
        try:
            await session.commit()
            return IdempotencyOutcome(replayed=False, response=None, key_hash=key_hash)
        except IntegrityError:
            await session.rollback()
        existing = (
            await session.execute(select(IdempotencyRecord).where(IdempotencyRecord.key_hash == key_hash))
        ).scalar_one_or_none()
    if existing is None:  # expired between the two statements – extremely unlikely; fail closed
        raise IdempotencyConflict("idempotency_retry")
    if existing.payload_hash != p_hash:
        raise IdempotencyConflict("idempotency_key_reused_with_different_payload")
    if existing.state is IdempotencyState.IN_PROGRESS:
        raise IdempotencyConflict("idempotency_in_progress")
    return IdempotencyOutcome(replayed=True, response=existing.response or {}, key_hash=key_hash)


async def complete(db: Database, key_hash: str, response: dict[str, Any]) -> None:
    async with db.session() as session:
        record = await session.get(IdempotencyRecord, key_hash)
        if record is not None:
            record.state = IdempotencyState.DONE
            record.response = response
            await session.commit()


async def abandon(db: Database, key_hash: str) -> None:
    """The operation failed before any side effect: release the key so the client may retry."""
    async with db.session() as session:
        await session.execute(delete(IdempotencyRecord).where(IdempotencyRecord.key_hash == key_hash))
        await session.commit()
