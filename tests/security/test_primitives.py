"""Security tests 19, 24, 25, 26, 27, 29, 30 at the primitive level (HTTP-level variants live elsewhere)."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import time

import jwt
import pytest

from app.logging_config import JsonFormatter, RedactionFilter
from app.models.db import AuditEvent, Database
from app.security import audit, breakers, idempotency, state_handles
from app.security.kv import MemoryKV
from app.security.passwords import WeakPasswordError, hash_password, verify_password
from app.security.rate_limit import RateLimiter, RateLimitExceeded
from app.security.redaction import REDACTED, clear_registered_secrets, redact_obj, register_secrets
from app.security.tokens import Scope, TokenError, bearer_from_header, mint_token, verify_token
from tests.conftest import make_settings


# ------------------------------------------------------------------ 29. canary secret never reaches logs
@pytest.fixture
def captured_log() -> tuple[logging.Logger, io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    logger = logging.getLogger("canary-test")
    logger.handlers[:] = [handler]
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    return logger, stream


def test_canary_secret_absent_from_logs(captured_log: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured_log
    canary = "CANARY-pat-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
    register_secrets([canary])
    try:
        logger.info("calling ANS with token %s", canary)
        logger.info(
            "headers",
            extra={
                "headers": {
                    "Authorization": f"Bearer {canary}",
                    "Cookie": f"__Host-agentdesk_session={canary}",
                }
            },
        )
        logger.warning("nested", extra={"ctx": {"deep": [{"godaddy_pat": canary}, f"url?api_key={canary}"]}})
        logger.error("f-string style " + canary + " suffix")
        try:
            raise RuntimeError(f"boom with {canary}")
        except RuntimeError:
            logger.exception("exception path")
    finally:
        clear_registered_secrets()
    output = stream.getvalue()
    assert output.count("\n") == 5
    assert canary not in output
    assert REDACTED in output


def test_unregistered_secret_shapes_are_still_redacted(
    captured_log: tuple[logging.Logger, io.StringIO],
) -> None:
    logger, stream = captured_log
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    token = jwt.encode({"sub": "x"}, "k" * 32, algorithm="HS256")
    logger.info("key %s", pem)
    logger.info("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
    logger.info("jwt %s", token)
    logger.info(
        "extra", extra={"password": "hunter2hunter2", "csrf_token": "abc", "session_id": "zzz", "path": "/ok"}
    )
    output = stream.getvalue()
    assert "MIIEvQIBADANBg" not in output and "abcdefghijklmnopqrstuvwxyz012345" not in output
    assert token not in output and "hunter2hunter2" not in output
    assert '"path": "/ok"' in output  # harmless fields survive


def test_log_injection_is_neutralised(captured_log: tuple[logging.Logger, io.StringIO]) -> None:
    logger, stream = captured_log
    logger.info("user=%s", 'eve\r\n{"level":"INFO","msg":"forged admin login"}')
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["msg"].startswith("user=eve\\r\\n")


def test_redact_obj_key_matching_is_word_based() -> None:
    out = redact_obj(
        {
            "pat": "x" * 10,
            "path": "/a",
            "dispatch": "ok",
            "X-Api-Key": "k" * 10,
            "privateKey": "p" * 10,
            "tokens_in": 5,
        }
    )
    assert out == {
        "pat": REDACTED,
        "path": "/a",
        "dispatch": "ok",
        "X-Api-Key": REDACTED,
        "privateKey": REDACTED,
        "tokens_in": 5,
    }


# ------------------------------------------------------------------ passwords
def test_argon2id_hashing() -> None:
    h = hash_password("correct horse battery staple")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct horse battery staple")
    assert not verify_password(h, "wrong password entirely")
    assert not verify_password(None, "anything")  # unknown user path still runs a verification
    assert not verify_password("not-a-hash", "x")
    for weak in ["short", "aaaaaaaaaaaaaaaa"]:
        with pytest.raises(WeakPasswordError):
            hash_password(weak)


# ------------------------------------------------------------------ 19. rate limits
async def test_rate_limiter_enforces_and_isolates_principals(kv: MemoryKV) -> None:
    limiter = RateLimiter(kv)
    for _ in range(3):
        await limiter.enforce("t", "1.2.3.4", limit=3, window_s=60)
    with pytest.raises(RateLimitExceeded) as exc:
        await limiter.enforce("t", "1.2.3.4", limit=3, window_s=60)
    assert exc.value.retry_after_s >= 1
    await limiter.enforce("t", "5.6.7.8", limit=3, window_s=60)  # other principal unaffected


async def test_rate_limiter_backend_failure_policy() -> None:
    class Broken(MemoryKV):
        async def incr(self, *a: object, **k: object) -> tuple[int, int]:
            raise ConnectionError("redis down")

        async def set_nx(self, *a: object, **k: object) -> bool:
            raise ConnectionError("redis down")

    limiter = RateLimiter(Broken())
    assert (await limiter.hit("login", "x", limit=5, window_s=60, fail_closed=True)).allowed is False
    assert (await limiter.hit("proof", "x", limit=5, window_s=60, fail_closed=False)).allowed is True
    assert await limiter.acquire_once("import", "owner", 60) is False


async def test_single_flight(kv: MemoryKV) -> None:
    limiter = RateLimiter(kv)
    assert await limiter.acquire_once("import", "owner-1", 60) is True
    assert await limiter.acquire_once("import", "owner-1", 60) is False
    await limiter.release("import", "owner-1")
    assert await limiter.acquire_once("import", "owner-1", 60) is True


# ------------------------------------------------------------------ 24. state handle bound to principal
async def test_state_handle_is_bound_to_principal_and_purpose(kv: MemoryKV) -> None:
    handle = await state_handles.issue(
        kv, principal="user:alice", purpose="find.connect", data={"host": "a.example.org"}
    )
    assert (await state_handles.resolve(kv, handle=handle, principal="user:alice", purpose="find.connect"))[
        "host"
    ] == "a.example.org"
    for principal, purpose in [
        ("user:bob", "find.connect"),
        ("user:alice", "tenant.publish"),
        ("anon:1.2.3.4", "find.connect"),
    ]:
        with pytest.raises(state_handles.HandleError):
            await state_handles.resolve(kv, handle=handle, principal=principal, purpose=purpose)
    for junk in ["", "short", "A" * 43 + "!", "../../etc/passwd", "A" * 500]:
        with pytest.raises(state_handles.HandleError):
            await state_handles.resolve(kv, handle=junk, principal="user:alice", purpose="find.connect")
    await state_handles.resolve(
        kv, handle=handle, principal="user:alice", purpose="find.connect", consume=True
    )
    with pytest.raises(state_handles.HandleError):
        await state_handles.resolve(kv, handle=handle, principal="user:alice", purpose="find.connect")


async def test_state_handle_expires(kv: MemoryKV) -> None:
    handle = await state_handles.issue(kv, principal="u", purpose="p", data={}, ttl_s=0)
    await asyncio.sleep(0.01)
    with pytest.raises(state_handles.HandleError):
        await state_handles.resolve(kv, handle=handle, principal="u", purpose="p")


# ------------------------------------------------------------------ 25 + 27. token audience / scope / corrupt input
def test_token_happy_path_and_scope_enforcement() -> None:
    s = make_settings()
    token = mint_token(s, subject="ci-bot", scopes=[Scope.TENANTS_READ])
    assert verify_token(s, token, required_scope=Scope.TENANTS_READ).subject == "ci-bot"
    with pytest.raises(TokenError) as exc:
        verify_token(s, token, required_scope=Scope.FIND_EXECUTE)
    assert exc.value.code == "insufficient_scope"


def test_token_wrong_audience_rejected() -> None:
    s = make_settings()
    token = mint_token(
        s, subject="x", scopes=[Scope.TENANTS_READ], audience="https://some-other-service.example.org"
    )
    with pytest.raises(TokenError):
        verify_token(s, token, required_scope=Scope.TENANTS_READ)


def _forge(s, **claim_overrides):  # type: ignore[no-untyped-def]
    now = int(time.time())
    claims = {
        "ver": 1,
        "iss": "agentdesk",
        "aud": s.desk_origin,
        "sub": "x",
        "scope": "tenants:read",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": "j",
    }
    claims.update(claim_overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, s.api_token_secret.get_secret_value(), algorithm="HS256")


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": "*"},
        {"scope": "tenants:read all"},
        {"scope": "full-access"},
        {"scope": "tenants:write"},
        {"scope": ""},
        {"ver": 0},  # superseded format
        {"ver": 2},  # unknown future format
        {"ver": None},
        {"iss": "someone-else"},
        {"exp": int(time.time()) - 3600},
        {"exp": int(time.time()) + 90 * 24 * 3600},  # absurd lifetime
        {"jti": None},
        {"sub": None},
        {"aud": None},
        {"aud": ["https://other.example.org"]},
    ],
)
def test_token_claim_policy(overrides: dict) -> None:
    s = make_settings()
    with pytest.raises(TokenError):
        verify_token(s, _forge(s, **overrides), required_scope=Scope.TENANTS_READ)


def test_token_unknown_key_alg_none_and_corrupt_input_fail_closed() -> None:
    s = make_settings()
    good = mint_token(s, subject="x", scopes=[Scope.TENANTS_READ])
    header, payload, sig = good.split(".")
    unknown_key = jwt.encode(
        jwt.decode(good, options={"verify_signature": False}), "z" * 40, algorithm="HS256"
    )
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    candidates = [
        unknown_key,
        f"{none_header}.{payload}.",
        f"{header}.{payload}.{sig[:-4]}AAAA",
        f"{header}.{payload[:-6]}AAAAAA.{sig}",
        f"{header}.{payload}",
        "....",
        "a.b.c",
        "",
        "x" * 10_000,
        "\x00\x01\x02",
        good + ".extra",
    ]
    for candidate in candidates:
        with pytest.raises(TokenError):
            verify_token(s, candidate, required_scope=Scope.TENANTS_READ)


def test_token_auth_disabled_without_secret() -> None:
    s = make_settings(api_token_secret="")
    with pytest.raises(TokenError):
        verify_token(s, "a.b.c", required_scope=Scope.TENANTS_READ)


def test_bearer_header_parsing() -> None:
    assert bearer_from_header("Bearer abc.def.ghi") == "abc.def.ghi"
    for bad in [None, "", "Basic abc", "Bearer", "Bearer a b", "abc.def.ghi"]:
        assert bearer_from_header(bad) is None


# ------------------------------------------------------------------ 26. idempotency ledger
async def test_idempotency_blocks_duplicates_and_detects_payload_swap(db: Database) -> None:
    key = idempotency.new_idempotency_key()
    first = await idempotency.begin(
        db, actor_id="u1", operation="tenant.publish", key=key, payload={"tenant": "t1"}
    )
    assert first.replayed is False
    with pytest.raises(idempotency.IdempotencyConflict) as exc:
        await idempotency.begin(
            db, actor_id="u1", operation="tenant.publish", key=key, payload={"tenant": "t1"}
        )
    assert exc.value.code == "idempotency_in_progress"
    await idempotency.complete(db, first.key_hash, {"version": "1.0.0"})
    replay = await idempotency.begin(
        db, actor_id="u1", operation="tenant.publish", key=key, payload={"tenant": "t1"}
    )
    assert replay.replayed is True and replay.response == {"version": "1.0.0"}
    with pytest.raises(idempotency.IdempotencyConflict) as exc2:
        await idempotency.begin(
            db, actor_id="u1", operation="tenant.publish", key=key, payload={"tenant": "OTHER"}
        )
    assert exc2.value.code == "idempotency_key_reused_with_different_payload"
    # a different actor / operation with the same key string is an independent key
    assert (
        await idempotency.begin(db, actor_id="u2", operation="tenant.publish", key=key, payload={})
    ).replayed is False


async def test_idempotency_concurrent_claims_have_exactly_one_winner(tmp_path) -> None:  # type: ignore[no-untyped-def]
    database = Database(f"sqlite+aiosqlite:///{tmp_path / 'idem.db'}")
    await database.create_all()
    key = idempotency.new_idempotency_key()

    async def claim() -> str:
        try:
            await idempotency.begin(
                database, actor_id="u", operation="ans.register", key=key, payload={"a": 1}
            )
            return "won"
        except idempotency.IdempotencyConflict:
            return "lost"

    results = await asyncio.gather(*[claim() for _ in range(8)])
    await database.dispose()
    assert results.count("won") == 1 and results.count("lost") == 7


@pytest.mark.parametrize("key", ["", "short", "has space in it", "x" * 200, "semi;colon-key-1234"])
async def test_idempotency_key_shape(db: Database, key: str) -> None:
    with pytest.raises(idempotency.IdempotencyConflict):
        await idempotency.begin(db, actor_id="u", operation="op", key=key, payload={})


# ------------------------------------------------------------------ audit trail is append-only + redacted
async def test_audit_is_append_only_and_redacted(db: Database) -> None:
    async with db.session() as session:
        event = await audit.record(
            session,
            action=audit.LOGIN_FAILURE,
            outcome="denied",
            actor_type="anonymous",
            metadata={
                "password": "hunter2hunter2",
                "note": "line1\nline2",
                "authorization": "Bearer abcdefghijklmnop",
            },
        )
        await session.commit()
        assert event.meta["password"] == REDACTED and event.meta["authorization"] == REDACTED
        assert event.meta["note"] == "line1\\nline2"
        event_id = event.id
        event.outcome = "success"
        with pytest.raises(PermissionError):
            await session.commit()
        await session.rollback()
        stored = await session.get(AuditEvent, event_id)
        assert stored is not None
        await session.delete(stored)
        with pytest.raises(PermissionError):
            await session.commit()


# ------------------------------------------------------------------ 30. circuit breakers (flag logic)
def test_circuit_breaker_flags() -> None:
    assert all(v for k, v in breakers.snapshot(make_settings(llm_provider="anthropic")).items())
    s = make_settings(
        disable_agent_creation=True,
        disable_external_fetch=True,
        disable_remote_agent_calls=True,
        disable_llm=True,
    )
    assert breakers.snapshot(s) == {
        "agent_creation": False,
        "external_fetch": False,
        "remote_agent_calls": False,
        "llm": False,
        "writes": True,
    }
    ro = make_settings(read_only_mode=True)
    assert not breakers.is_enabled(ro, breakers.Feature.WRITES) and not breakers.is_enabled(
        ro, breakers.Feature.AGENT_CREATION
    )
    with pytest.raises(breakers.FeatureDisabled) as exc:
        breakers.require(ro, breakers.Feature.WRITES)
    assert exc.value.code == "feature_disabled_writes"
