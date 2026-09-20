#!/usr/bin/env python3
"""Interactive or CLI setup for deployment secrets."""

from __future__ import annotations

import argparse
import os
import secrets
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate secrets files for Agent Desk")
    parser.add_argument("--key", help="GoDaddy API Key", default="")
    parser.add_argument("--secret", help="GoDaddy API Secret", default="")
    parser.add_argument("--pat", help="GoDaddy Personal Access Token (PAT)", default="")
    args = parser.parse_args()

    key = args.key
    secret = args.secret
    pat = args.pat

    if not pat and (not key or not secret):
        print("=== GoDaddy ANS Authentication Setup ===")
        print("1. Classic API Key + Secret (default)")
        print("2. Personal Access Token (PAT)")
        choice = input("Select auth method [1/2, default: 1]: ").strip() or "1"
        if choice == "2":
            pat = input("Enter GoDaddy PAT: ").strip()
        else:
            key = input("Enter GoDaddy API Key: ").strip()
            secret = input("Enter GoDaddy API Secret: ").strip()

    repo_root = Path(__file__).resolve().parents[1]
    secrets_dir = repo_root / "secrets"
    artifacts_dir = repo_root / "artifacts"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    pg_pass = secrets.token_urlsafe(32)
    app_pass = secrets.token_urlsafe(32)
    session_sec = secrets.token_urlsafe(32)
    csrf_sec = secrets.token_urlsafe(32)
    cp_token = secrets.token_urlsafe(32)

    # 1. postgres.env
    (secrets_dir / "postgres.env").write_text(
        f"""POSTGRES_USER=postgres_admin
POSTGRES_PASSWORD={pg_pass}
POSTGRES_DB=agentdesk
APP_DB_PASSWORD={app_pass}
DATABASE_URL=postgresql+asyncpg://postgres_admin:{pg_pass}@postgres:5432/agentdesk
"""
    )

    # 2. desk.env
    (secrets_dir / "desk.env").write_text(
        f"""SESSION_SECRET={session_sec}
CSRF_SECRET={csrf_sec}
CONTROLPLANE_TOKEN={cp_token}
DATABASE_URL=postgresql+asyncpg://agentdesk_app:{app_pass}@postgres:5432/agentdesk
REDIS_URL=redis://redis:6379/0
LLM_PROVIDER=none
"""
    )

    # 3. controlplane.env
    if pat:
        ans_config = f"""ANS_AUTH_SCHEME=bearer
GODADDY_PAT={pat}
"""
    else:
        ans_config = f"""ANS_AUTH_SCHEME=sso-key
GODADDY_API_KEY={key}
GODADDY_API_SECRET={secret}
"""

    (secrets_dir / "controlplane.env").write_text(
        f"""SESSION_SECRET={session_sec}
CSRF_SECRET={csrf_sec}
CONTROLPLANE_TOKEN={cp_token}
DATABASE_URL=postgresql+asyncpg://agentdesk_app:{app_pass}@postgres:5432/agentdesk
{ans_config}"""
    )

    for env_file in secrets_dir.glob("*.env"):
        os.chmod(env_file, 0o600)

    print(f"\n[SUCCESS] Generated secrets in {secrets_dir} (chmod 600):")
    print(" - postgres.env")
    print(" - desk.env")
    print(" - controlplane.env")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
