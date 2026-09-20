from __future__ import annotations

import json
import logging

import httpx
import pytest
from sqlalchemy import select

from app.agents.registry import AgentRegistry
from app.agents.seed import seed_demo_agent
from app.ans.certs import KeyStore
from app.ans.client import AnsApiError, AnsClient, AnsNotConfigured, parse_timestamp
from app.ans.registration import (
    RegistrationError,
    RegistrationFlow,
    RegistrationService,
    allowed_dns_record,
    build_registration_payload,
)
from app.ans.client import DnsRecord
from app.models.db import ANSRegistration, AuditEvent, Database, Tenant, TenantState, User
from app.security.kv import MemoryKV
from app.security.passwords import hash_password
from tests.ans.conftest import PAT
from tests.ans.fake_ans import FakeANS
from tests.conftest import DEMO_HOST, TEST_BASE_DOMAIN, make_settings


def client_for(fake: FakeANS, settings) -> AnsClient:  # type: ignore[no-untyped-def]
    return AnsClient(settings, transport=fake.transport, backoff_s=0)


# --------------------------------------------------------------------------- client contract
async def test_bearer_and_sso_key_auth_headers(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    agent_id = fake_ans.add_active_agent(DEMO_HOST)
    assert (await client_for(fake_ans, ans_settings).get_agent(agent_id)).agent_status == "ACTIVE"
    assert fake_ans.requests[-1].headers["authorization"] == f"Bearer {PAT}"
    sso = make_settings(ans_auth_scheme="sso-key", godaddy_api_key="testkey0001", godaddy_api_secret="testsecret0001")
    await client_for(fake_ans, sso).get_agent(agent_id)
    assert fake_ans.requests[-1].headers["authorization"] == "sso-key testkey0001:testsecret0001"
    assert fake_ans.requests[-1].url.host == "api.godaddy.com"


async def test_missing_or_bad_credential(fake_ans: FakeANS) -> None:
    agent_id = fake_ans.add_active_agent(DEMO_HOST)
    with pytest.raises(AnsNotConfigured):
        await client_for(fake_ans, make_settings()).get_agent(agent_id)
    with pytest.raises(AnsApiError) as excinfo:
        await client_for(fake_ans, make_settings(godaddy_pat="gd_pat_wrong_value_123")).get_agent(agent_id)
    assert excinfo.value.status == 401 and "gd_pat" not in str(excinfo.value)


def test_api_base_is_allow_listed() -> None:
    assert make_settings(godaddy_api_base="https://api.ote-godaddy.com/").ans_environment == "ote"
    for bad in ("https://evil.example", "http://api.godaddy.com", "https://api.godaddy.com.evil.example"):
        with pytest.raises(ValueError):
            make_settings(godaddy_api_base=bad)


async def test_public_discovery_sends_no_credential(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    fake_ans.add_active_agent("cafe.example.org", name="Cafe")
    fake_ans.add_active_agent("gone.example.org", status="REVOKED")
    hits = await client_for(fake_ans, ans_settings).discover(query="coffee")
    assert [h.agent_host for h in hits] == ["cafe.example.org"] and hits[0].version == "1.0.0" and hits[0].status == "ACTIVE"
    assert "authorization" not in fake_ans.requests[-1].headers


async def test_redirect_is_not_followed_and_errors_are_lenient(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    client = client_for(fake_ans, ans_settings)
    for response, code in [(httpx.Response(302, headers={"location": "https://evil.example/steal"}), "UNAUTHENTICATED_REDIRECT"),
                           (httpx.Response(401), "HTTP_401"), (httpx.Response(400, content=b"<html>oops"), "HTTP_400"),
                           (httpx.Response(403, json={"code": "ACCESS_DENIED", "message": "scope"}), "ACCESS_DENIED"),
                           (httpx.Response(200, content=b"{not json"), "INVALID_JSON"),
                           (httpx.Response(200, json={"unexpected": True}), "UNEXPECTED_RESPONSE_SHAPE")]:
        fake_ans.fail_next = [response]
        with pytest.raises(AnsApiError) as excinfo:
            await client.get_agent("550e8400-e29b-41d4-a716-446655440000")
        assert excinfo.value.code == code
    assert all(r.url.host == "api.godaddy.com" for r in fake_ans.requests)


async def test_retries_are_bounded_and_only_for_reads(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    agent_id = fake_ans.add_active_agent(DEMO_HOST)
    client = client_for(fake_ans, ans_settings)
    fake_ans.fail_next = [httpx.Response(429), httpx.Response(503)]
    assert (await client.get_agent(agent_id)).agent_id == agent_id
    fake_ans.fail_next = [httpx.Response(429)] * 3
    with pytest.raises(AnsApiError):
        await client.get_agent(agent_id)
    fake_ans.fail_next, before = [httpx.Response(503)], len(fake_ans.requests)
    with pytest.raises(AnsApiError):
        await client.verify_dns(agent_id)  # a state-changing POST is never auto-retried
    assert len(fake_ans.requests) == before + 1


@pytest.mark.parametrize("agent_id", ["../register", "a/b", "", "x" * 200, "id?status=ALL"])
async def test_agent_id_cannot_alter_the_path(fake_ans: FakeANS, ans_settings, agent_id: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(AnsApiError, match="AGENT_ID_INVALID"):
        await client_for(fake_ans, ans_settings).get_agent(agent_id)
    assert fake_ans.requests == []


async def test_status_object_form_and_timestamps(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    agent_id = fake_ans.add_active_agent(DEMO_HOST)
    fake_ans.agents[agent_id]["agentStatus"] = {"status": "PENDING_DNS", "phase": "DNS_PROVISIONING"}
    assert (await client_for(fake_ans, ans_settings).get_agent(agent_id)).agent_status == "PENDING_DNS"
    for text in ("2025-11-13 16:30:00+00:00", "2025-11-13T16:30:00Z", "2026-09-18T07:52:32.212734855Z"):
        assert parse_timestamp(text) is not None
    assert parse_timestamp("garbage") is None and parse_timestamp(None) is None


async def test_revocation_reason_allow_list(fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    agent_id = fake_ans.add_active_agent(DEMO_HOST)
    client = client_for(fake_ans, ans_settings)
    with pytest.raises(AnsApiError, match="REVOCATION_REASON_INVALID"):
        await client.revoke(agent_id, "SUPERSEDED")
    assert (await client.revoke(agent_id, "KEY_COMPROMISE", "demo")).status == "REVOKED"


# --------------------------------------------------------------------------- registration flow
async def make_flow(db: Database, fake: FakeANS, settings):  # type: ignore[no-untyped-def]
    await seed_demo_agent(db, settings)
    registry = AgentRegistry(db, settings, ttl_s=0)
    flow = RegistrationFlow(client_for(fake, settings), KeyStore(settings.keys_path, TEST_BASE_DOMAIN), settings)
    return registry, flow


async def test_registration_payload_matches_contract(db: Database, fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    registry, _ = await make_flow(db, fake_ans, ans_settings)
    agent = await registry.resolve(DEMO_HOST)
    assert agent is not None
    csrs = KeyStore(ans_settings.keys_path, TEST_BASE_DOMAIN).csr_bundle(DEMO_HOST, "1.0.0")
    payload = build_registration_payload(agent, ans_settings, csrs)
    assert payload["agentHost"] == DEMO_HOST and payload["version"] == "1.0.0" and len(payload["agentDisplayName"]) <= 64
    assert {e["protocol"] for e in payload["endpoints"]} == {"A2A", "MCP"}
    for endpoint in payload["endpoints"]:
        assert endpoint["agentUrl"].startswith(f"https://{DEMO_HOST}/") and endpoint["metaDataUrl"].startswith("https://")
        assert all(len(f["id"]) <= 64 and len(f["tags"]) <= 5 and all(len(t) <= 20 for t in f["tags"]) for f in endpoint["functions"])
    assert payload["endpoints"][1]["transports"] == ["STREAMABLE-HTTP"]
    assert payload["identityCsrPEM"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    assert "PRIVATE KEY" not in json.dumps(payload)


@pytest.mark.parametrize("singular", [False, True])
async def test_full_flow_to_active(db: Database, ans_settings, singular: bool) -> None:  # type: ignore[no-untyped-def]
    fake = FakeANS(singular_challenge=singular)
    registry, flow = await make_flow(db, fake, ans_settings)
    agent = await registry.resolve(DEMO_HOST)
    assert agent is not None
    snap = await flow.submit(agent)
    assert snap.status == "PENDING_VALIDATION" and snap.environment == "production" and not snap.active
    assert snap.acme_records == [{"name": f"_acme-challenge.{DEMO_HOST}", "type": "TXT", "value": "acme-value-123",
                                  "ttl": 3600, "required": True, "purpose": ""}]
    assert snap.next_action == "publish_acme_txt_then_verify_acme"
    assert "SECRETISH" not in json.dumps(snap.to_public_dict())  # ACME token/keyAuthorization never kept

    snap = await flow.trigger_acme(snap.agent_id, DEMO_HOST, "1.0.0")  # type: ignore[arg-type]
    assert snap.status == "PENDING_DNS" and snap.next_action == "publish_dns_records_then_verify_dns"
    assert {r["name"] for r in snap.dns_records} == {f"_ans.{DEMO_HOST}", f"_ans-badge.{DEMO_HOST}", f"_443._tcp.{DEMO_HOST}"}
    assert [r["name"] for r in snap.rejected_records] == ["unrelated.victim.example"]

    fake.dns_ok = False
    with pytest.raises(AnsApiError) as excinfo:
        await flow.trigger_dns(snap.agent_id, DEMO_HOST, "1.0.0")  # type: ignore[arg-type]
    assert excinfo.value.status == 422 and "missingRecords" in excinfo.value.details
    assert (await flow.refresh(snap.agent_id, DEMO_HOST, "1.0.0")).status == "PENDING_DNS"  # type: ignore[arg-type]

    fake.dns_ok = True
    snap = await flow.trigger_dns(snap.agent_id, DEMO_HOST, "1.0.0")  # type: ignore[arg-type]
    assert snap.active and snap.next_action == "none"


async def test_conflict_adopts_only_our_own_record(db: Database, fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    registry, flow = await make_flow(db, fake_ans, ans_settings)
    agent = await registry.resolve(DEMO_HOST)
    assert agent is not None
    first = await flow.submit(agent)
    again = await flow.submit(agent)  # 409 → recovered through the authenticated search
    assert again.agent_id == first.agent_id and again.status == "PENDING_VALIDATION"
    fake_ans.agents[first.agent_id]["agentHost"] = "someone-else.example.org"  # type: ignore[index]
    fake_ans.fail_next = [httpx.Response(409, json={"code": "ANS_NAME_TAKEN", "message": "x", "status": "ERROR"})]
    with pytest.raises(RegistrationError, match="already registered"):
        await flow.submit(agent)


async def test_refresh_rejects_record_for_other_host(db: Database, fake_ans: FakeANS, ans_settings) -> None:  # type: ignore[no-untyped-def]
    _, flow = await make_flow(db, fake_ans, ans_settings)
    other = fake_ans.add_active_agent("other.example.org")
    with pytest.raises(RegistrationError, match="different host"):
        await flow.refresh(other, DEMO_HOST, "1.0.0")


def test_dns_record_policy_is_exact_name() -> None:
    def rec(name: str, rtype: str = "TXT") -> DnsRecord:
        return DnsRecord(name=name, type=rtype, value="v")

    assert allowed_dns_record(rec(f"_ANS.{DEMO_HOST}."), DEMO_HOST)
    assert allowed_dns_record(rec(f"_443._tcp.{DEMO_HOST}", "TLSA"), DEMO_HOST)
    assert allowed_dns_record(rec(DEMO_HOST, "HTTPS"), DEMO_HOST)
    for name, rtype in [(DEMO_HOST, "TXT"), (f"_ans.evil.{TEST_BASE_DOMAIN}", "TXT"), (TEST_BASE_DOMAIN, "TXT"),
                        (DEMO_HOST, "A"), (f"www.{DEMO_HOST}", "CNAME"), (f"_ans.{DEMO_HOST}.evil.com", "TXT")]:
        assert not allowed_dns_record(rec(name, rtype), DEMO_HOST)


# --------------------------------------------------------------------------- DB-backed service
async def test_service_persists_only_live_status_and_is_owner_scoped(db: Database, fake_ans: FakeANS, ans_settings, caplog) -> None:  # type: ignore[no-untyped-def]
    registry, flow = await make_flow(db, fake_ans, ans_settings)
    service = RegistrationService(db, flow, registry, MemoryKV(), ans_settings)
    async with db.session() as session:
        tenant = (await session.execute(select(Tenant))).scalar_one()
        intruder = User(email="intruder@example.org", password_hash=hash_password("correct horse battery staple"))
        session.add(intruder)
        await session.commit()
    with pytest.raises(RegistrationError, match="not_found"):
        await service.submit(tenant.id, intruder.id)  # BOLA: someone else's tenant looks like no tenant
    assert fake_ans.requests == []

    with caplog.at_level(logging.DEBUG):
        snap = await service.submit(tenant.id, tenant.owner_id)
    assert PAT not in caplog.text and "PRIVATE KEY" not in caplog.text
    async with db.session() as session:
        row = (await session.execute(select(ANSRegistration))).scalar_one()
        assert row.status == "PENDING_VALIDATION" and row.agent_id == snap.agent_id and row.environment == "production"
        assert "SECRETISH" not in json.dumps(row.challenge)
        assert (await session.execute(select(Tenant))).scalar_one().state is TenantState.PENDING_VALIDATION
    with pytest.raises(RegistrationError, match="already registered"):
        await service.submit(tenant.id, tenant.owner_id)  # duplicate submit cannot register twice

    await service.advance(tenant.id, tenant.owner_id, "verify_acme")
    fake_ans.dns_ok = False
    with pytest.raises(AnsApiError):
        await service.advance(tenant.id, tenant.owner_id, "verify_dns")
    async with db.session() as session:
        row = (await session.execute(select(ANSRegistration))).scalar_one()
        assert row.status == "PENDING_DNS" and row.last_error == "VALIDATION_ERROR"  # failure never became ACTIVE
    fake_ans.dns_ok = True
    assert (await service.advance(tenant.id, tenant.owner_id, "verify_dns")).active
    async with db.session() as session:
        assert (await session.execute(select(Tenant))).scalar_one().state is TenantState.ACTIVE
        actions = [e.action for e in (await session.execute(select(AuditEvent))).scalars()]
    assert "ans.register" in actions and "ans.active" in actions

    # live revocation upstream flows back on the next refresh
    fake_ans.agents[snap.agent_id]["agentStatus"] = "REVOKED"  # type: ignore[index]
    assert (await service.advance(tenant.id, tenant.owner_id, "refresh")).status == "REVOKED"
    async with db.session() as session:
        assert (await session.execute(select(Tenant))).scalar_one().state is TenantState.REVOKED


async def test_read_only_mode_blocks_registration(db: Database, fake_ans: FakeANS, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from app.security.breakers import FeatureDisabled

    settings = make_settings(godaddy_pat=PAT, read_only_mode=True, keys_dir=str(tmp_path / "k"))
    registry, flow = await make_flow(db, fake_ans, settings)
    async with db.session() as session:
        tenant = (await session.execute(select(Tenant))).scalar_one()
    with pytest.raises(FeatureDisabled):
        await RegistrationService(db, flow, registry, MemoryKV(), settings).submit(tenant.id, tenant.owner_id)
