"""Operator CLI (never reachable from HTTP).

python -m app.cli create-owner     # one-time owner seeding from OWNER_EMAIL / OWNER_PASSWORD (env or prompt)
python -m app.cli revoke-sessions  # revoke every session of OWNER_EMAIL (incident response)
"""

from __future__ import annotations

import asyncio
import getpass
import sys

from sqlalchemy import select

from app.models.db import Database, Role, User
from app.security import sessions
from app.security.passwords import WeakPasswordError, check_password_strength, hash_password
from app.settings import get_settings


async def _create_owner() -> int:
    settings = get_settings()
    email = (settings.owner_email or input("Owner email: ")).strip().lower()  # noqa: ASYNC250 - one-shot interactive CLI
    password = settings.owner_password.get_secret_value() or getpass.getpass(
        "Owner password (min 12 chars): "
    )
    try:
        check_password_strength(password)
    except WeakPasswordError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    db = Database(settings.database_url)
    if not db.is_postgres:
        await db.create_all()
    async with db.session() as session:
        if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none() is not None:
            print("owner already exists; nothing changed")
            return 0
        session.add(User(email=email, password_hash=hash_password(password), role=Role.OWNER))
        await session.commit()
    print(f"owner {email} created. Unset OWNER_PASSWORD now.")
    return 0


async def _revoke_sessions() -> int:
    settings = get_settings()
    db = Database(settings.database_url)
    async with db.session() as session:
        user = (
            await session.execute(select(User).where(User.email == settings.owner_email.lower()))
        ).scalar_one_or_none()
        if user is None:
            print("no such user", file=sys.stderr)
            return 1
        count = await sessions.revoke_all(session, user.id)
        await session.commit()
    print(f"revoked {count} session(s)")
    return 0


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "create-owner":
        return asyncio.run(_create_owner())
    if command == "revoke-sessions":
        return asyncio.run(_revoke_sessions())
    print(__doc__)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
