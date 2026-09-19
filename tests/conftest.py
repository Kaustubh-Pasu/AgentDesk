from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

# Make sure no developer .env / real credentials leak into the test process.
for _name in list(os.environ):
    if _name.upper() in {
        "GODADDY_PAT",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "DATABASE_URL",
        "REDIS_URL",
    }:
        os.environ.pop(_name)

from app.models.db import Database  # noqa: E402
from app.security.kv import MemoryKV  # noqa: E402
from app.settings import Settings  # noqa: E402

TEST_BASE_DOMAIN = "example.test"
DESK_HOST = f"desk.{TEST_BASE_DOMAIN}"
DEMO_HOST = f"demo.{TEST_BASE_DOMAIN}"
DESK_ORIGIN = f"https://{DESK_HOST}"


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "env": "test",
        "base_domain": TEST_BASE_DOMAIN,
        "database_url": "sqlite+aiosqlite:///:memory:",
        "redis_url": "",
        "session_secret": "test-session-secret-0123456789abcdef0123456789",
        "csrf_secret": "test-csrf-secret-0123456789abcdef0123456789abcd",
        "api_token_secret": "test-api-token-secret-0123456789abcdef012345",
        "login_progressive_delay": False,
        "llm_provider": "none",
        "keys_dir": "/nonexistent-set-by-fixture",
        "artifacts_dir": "/nonexistent-set-by-fixture",
        "trusted_proxy_cidrs": "127.0.0.1/32",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


@pytest.fixture
def settings(tmp_path: object) -> Settings:
    return make_settings(keys_dir=str(tmp_path / "keys"), artifacts_dir=str(tmp_path / "artifacts"))  # type: ignore[operator]


@pytest_asyncio.fixture
async def db() -> AsyncIterator[Database]:
    database = Database("sqlite+aiosqlite:///:memory:")
    await database.create_all()
    try:
        yield database
    finally:
        await database.dispose()


@pytest.fixture
def kv() -> MemoryKV:
    return MemoryKV()
