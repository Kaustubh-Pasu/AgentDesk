"""Server-side authentication/authorization helpers for cookie-authenticated browser routes.

- ``current_session``: opaque server-side session from the ``__Host-`` cookie (idle + absolute timeouts enforced
  by ``sessions.load_session``). Disabled users lose access immediately.
- ``require_csrf``: the per-session synchronizer token, in addition to the header-level Origin/Fetch-Metadata
  guard that the middleware already applied.
- Role checks are made here on the server; templates hiding a button is never the control.
"""

from __future__ import annotations

from dataclasses import dataclass

from starlette.requests import Request

from app.models.db import Database, Role, User, UserSession
from app.security import csrf, sessions
from app.settings import Settings


class AuthRequired(Exception):
    """No valid session → browser is redirected to the login page (a fixed internal path)."""


class Forbidden(Exception):
    def __init__(self, code: str = "forbidden") -> None:
        super().__init__(code)
        self.code = code


@dataclass
class Principal:
    user: User
    session: UserSession

    @property
    def id(self) -> str:
        return str(self.user.id)


async def current_session(request: Request, db: Database, settings: Settings) -> Principal | None:
    token = request.cookies.get(sessions.SESSION_COOKIE)
    if not token:
        return None
    async with db.session() as session:
        row = await sessions.load_session(session, settings, token)
        if row is None:
            return None
        user = await session.get(User, row.user_id)
        await session.commit()  # persists the last_seen touch
    if user is None or user.disabled_at is not None:
        return None
    return Principal(user=user, session=row)


async def require_user(request: Request, db: Database, settings: Settings, *, role: Role | None = None) -> Principal:
    principal = await current_session(request, db, settings)
    if principal is None:
        raise AuthRequired()
    if role is not None and principal.user.role is not role:
        raise Forbidden("role_required")
    return principal


async def require_csrf(request: Request, principal: Principal) -> None:
    try:
        csrf.check_token(await csrf.supplied_token(request), principal.session.csrf_token)
    except csrf.CSRFError as exc:
        raise Forbidden(exc.code) from exc
