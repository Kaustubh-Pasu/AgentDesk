"""Opaque server-side sessions.

- Cookie ``__Host-agentdesk_session``: Secure; HttpOnly; SameSite=Strict; Path=/; NO Domain attribute,
  so generated tenant subdomains can never receive the admin session.
- Only ``HMAC-SHA256(SESSION_SECRET, token)`` is stored server-side; a database leak does not yield usable
  cookies.
- A brand-new token is minted at login (no fixation) and the row is deleted at logout (no reuse).
- Idle timeout + absolute lifetime; ``revoke_all`` for forced sign-out.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from starlette.responses import Response

from app.models.db import User, UserSession, utcnow
from app.settings import Settings

SESSION_COOKIE = "__Host-agentdesk_session"
_TOKEN_BYTES = 32
_TOUCH_INTERVAL = timedelta(seconds=60)


def _hash_token(settings: Settings, token: str) -> str:
    return hmac.new(
        settings.session_secret.get_secret_value().encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def _looks_like_token(token: str) -> bool:
    return 40 <= len(token) <= 64 and all(ch.isalnum() or ch in "-_" for ch in token)


async def create_session(
    db: AsyncSession, settings: Settings, user: User, user_agent: str = ""
) -> tuple[str, UserSession]:
    """Mint a fresh session (always a NEW token – never reuse a pre-login identifier)."""
    token = secrets.token_urlsafe(_TOKEN_BYTES)
    now = utcnow()
    row = UserSession(
        id=uuid.uuid4(),
        token_hash=_hash_token(settings, token),
        user_id=user.id,
        csrf_token=secrets.token_urlsafe(32),
        created_at=now,
        last_seen_at=now,
        reauth_at=now,
        expires_at=now + timedelta(hours=settings.session_absolute_hours),
        user_agent=user_agent[:200],
    )
    db.add(row)
    await db.flush()
    return token, row


async def load_session(db: AsyncSession, settings: Settings, token: str | None) -> UserSession | None:
    if not token or not _looks_like_token(token):
        return None
    row = (
        await db.execute(
            select(UserSession)
            .options(joinedload(UserSession.user))
            .where(UserSession.token_hash == _hash_token(settings, token))
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    now = utcnow()
    idle_deadline = row.last_seen_at + timedelta(minutes=settings.session_idle_minutes)
    if now >= row.expires_at or now >= idle_deadline or row.user.disabled_at is not None:
        await db.delete(row)
        await db.commit()
        return None
    if now - row.last_seen_at >= _TOUCH_INTERVAL:
        row.last_seen_at = now
        await db.commit()
    return row


async def destroy_session(db: AsyncSession, row: UserSession) -> None:
    await db.delete(row)
    await db.flush()


async def revoke_all(db: AsyncSession, user_id: uuid.UUID, *, except_session: uuid.UUID | None = None) -> int:
    stmt = delete(UserSession).where(UserSession.user_id == user_id)
    if except_session is not None:
        stmt = stmt.where(UserSession.id != except_session)
    result = await db.execute(stmt)
    return int(result.rowcount or 0)  # type: ignore[attr-defined]


async def purge_expired(db: AsyncSession, now: datetime | None = None) -> int:
    result = await db.execute(delete(UserSession).where(UserSession.expires_at < (now or utcnow())))
    return int(result.rowcount or 0)  # type: ignore[attr-defined]


def mark_reauthenticated(row: UserSession) -> None:
    row.reauth_at = utcnow()


def recently_reauthenticated(row: UserSession, settings: Settings) -> bool:
    return utcnow() - row.reauth_at <= timedelta(minutes=settings.reauth_window_minutes)


def set_session_cookie(response: Response, settings: Settings, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_absolute_hours * 3600,
        path="/",
        domain=None,  # __Host- prefix forbids Domain; host-only cookie
        secure=True,
        httponly=True,
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        SESSION_COOKIE, path="/", domain=None, secure=True, httponly=True, samesite="strict"
    )
