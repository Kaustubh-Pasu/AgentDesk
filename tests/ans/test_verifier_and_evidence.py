"""Gate 5 (local): the 15-point checklist against OUR real A2A/MCP servers + a fake ANS registry."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import pytest
from sqlalchemy import select
from starlette.applications import Starlette

from app.agents.registry import AgentRegistry
from app.agents.runtime import AgentRuntime
from app.agents.seed import seed_demo_agent
from app.ans.certs import TrustAnchors, fingerprint_sha256
from app.ans.client import AnsClient
from app.ans.evidence import ProofService, SecretLeak, assert_no_secrets, build_proof, gate_summary, write_evidence_bundle
from app.ans.verifier import Verifier, make_tls_probe
from app.models.db import AuditEvent, BlockedAgent, Database
from app.models.schemas import TlsEvidence
from app.protocols.a2a_server import create_a2a_routes
from app.protocols.mcp_server import McpProtocolServer
from app.security.ssrf import GlobalOnlyPolicy
from tests.ans.conftest import PAT, FakePKI, pem
from tests.ans.fake_ans import FakeANS
from tests.conftest import make_settings
from tests.helpers import FakeResolver, LoopbackRemoteHttp, serve_app

BASE = "agentdesk-demo.org"  # must satisfy the PRODUCTION url policy (".test" is special-use and rejected)
DEMO = f"demo.{BASE}"
PUBLIC_IP = "93.184.216.34"


async def fake_tls(host: str) -> TlsEvidence:
    return TlsEvidence(status="PASS", detail="test probe", version="TLSv1.3", hostname_verified=True, leaf_sha256="ab" * 32)


@dataclass
class World:
    settings: object
    db: Database
    ans: FakeANS
    port: int
    agent_id: str

    def verifier(self, *, anchors: TrustAnchors | None = None, resolver: FakeResolver | None = None, settings=None) -> Verifier:  # type: ignore[no-untyped-def]
        s = settings or self.settings
        return Verifier(s, AnsClient(s, transport=self.ans.transport, backoff_s=0),  # type: ignore[arg-type]
                        LoopbackRemoteHttp(s, self.port, [DEMO]), self.db, anchors=anchors,  # type: ignore[arg-type]
                        resolver=resolver or FakeResolver({DEMO: [PUBLIC_IP]}), tls_probe=fake_tls)


@asynccontextmanager
async def world(db: Database, tmp_path) -> AsyncIterator[World]:  # type: ignore[no-untyped-def]
    settings = make_settings(base_domain=BASE, godaddy_pat=PAT, artifacts_dir=str(tmp_path / "artifacts"))
    await seed_demo_agent(db, settings)
    runtime = AgentRuntime(AgentRegistry(db, settings), settings)
    mcp = McpProtocolServer(runtime, settings)
    app = Starlette(routes=[*create_a2a_routes(runtime, settings), *mcp.routes()])
    ready, stop = asyncio.Event(), asyncio.Event()

    async def hold() -> None:
        async with mcp.lifespan():
            ready.set()
            await stop.wait()

    task = asyncio.create_task(hold())
    await ready.wait()
    try:
        async with serve_app(app) as port:
            fake = FakeANS()
            yield World(settings, db, fake, port, fake.add_active_agent(DEMO, name="Hokie Bean Cafe (demo)"))
    finally:
        stop.set()
        await task


def by_id(result) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {c.id: c.status for c in result.checks}


async def test_active_agent_verifies_with_honest_incompletes(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        result = await w.verifier().verify(DEMO, probe_tool="get_hours")
    checks = by_id(result)
    assert len(checks) == 15
    assert result.verified and result.decision == "PASS"
    assert result.ans.status == "ACTIVE" and result.ans.environment == "production" and result.ans.agent_id == w.agent_id
    assert result.a2a.card_valid and "get_hours" in result.a2a.skills and len(result.a2a.card_sha256) == 64
    assert result.mcp.handshake and result.mcp.probe_ok and "get_business_info" in result.mcp.tools
    # no certificate for this agent + no trust anchor: those checks are INCOMPLETE, never PASS
    assert checks["identity_certificate_retrieved"] == checks["identity_chain_trust_anchor"] == "INCOMPLETE"
    assert any("INCOMPLETE" in r for r in result.reasons)
    mandatory_pass = [c for c in result.checks if c.mandatory]
    assert all(c.status == "PASS" for c in mandatory_pass)


async def test_identity_certificate_chain_and_binding(db: Database, tmp_path, pki: FakePKI) -> None:  # type: ignore[no-untyped-def]
    bundle = tmp_path / "anchor.pem"
    bundle.write_text(pem(pki.root))
    anchors = TrustAnchors.load(str(bundle), set())
    async with world(db, tmp_path) as w:
        leaf = pki.identity_cert(DEMO)
        w.ans.certs[w.agent_id] = {"identity": [{"certificatePEM": pem(leaf), "chainPEM": pem(pki.intermediate) + pem(pki.root), "csrId": "x"}]}
        w.ans.identity_fingerprints[w.agent_id] = "SHA256:" + fingerprint_sha256(leaf)
        good = await w.verifier(anchors=anchors).verify(DEMO)
        assert good.verified and good.identity_certificate is not None
        assert good.identity_certificate.chain_status == "PASS" and good.identity_certificate.binding_status == "PASS"
        assert f"URI:ans://v1.0.0.{DEMO}" in good.identity_certificate.san

        no_anchor = await w.verifier().verify(DEMO)
        assert no_anchor.identity_certificate.chain_status == "INCOMPLETE"  # type: ignore[union-attr]

        # registry-supplied chain from a DIFFERENT root must not be trusted just because it was sent along
        attacker = FakePKI("Attacker")
        forged = attacker.identity_cert(DEMO)
        w.ans.certs[w.agent_id] = {"identity": [{"certificatePEM": pem(forged), "chainPEM": pem(attacker.intermediate) + pem(attacker.root), "csrId": "x"}]}
        w.ans.identity_fingerprints[w.agent_id] = "SHA256:" + fingerprint_sha256(forged)
        bad = await w.verifier(anchors=anchors).verify(DEMO)
        assert not bad.verified and by_id(bad)["identity_chain_trust_anchor"] == "FAIL"

        # certificate for another host / fingerprint not attested by the transparency log
        w.ans.certs[w.agent_id] = {"identity": [{"certificatePEM": pem(pki.identity_cert("evil." + BASE)), "chainPEM": pem(pki.intermediate), "csrId": "x"}]}
        assert by_id(await w.verifier(anchors=anchors).verify(DEMO))["identity_certificate_binding"] == "FAIL"
        w.ans.certs[w.agent_id] = {"identity": [{"certificatePEM": pem(leaf), "chainPEM": pem(pki.intermediate), "csrId": "x"}]}
        w.ans.identity_fingerprints[w.agent_id] = "SHA256:" + "00" * 32
        assert by_id(await w.verifier(anchors=anchors).verify(DEMO))["identity_certificate_binding"] == "FAIL"


@pytest.mark.parametrize("status", ["REVOKED", "EXPIRED", "DEPRECATED", "PENDING_DNS", ""])
async def test_revoked_or_inactive_candidate_rejected(db: Database, tmp_path, status: str) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.agents[w.agent_id]["agentStatus"] = status
        result = await w.verifier().verify(DEMO)
    assert not result.verified and result.decision == "FAIL"


async def test_unregistered_host_fails_closed(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.agents.clear()
        result = await w.verifier().verify(DEMO)
        assert not result.verified and by_id(result)["ans_status_active"] == "FAIL"
        # …but live protocol evidence for OUR OWN host is still gathered for the proof page
        assert result.a2a.status == "PASS" and result.mcp.status == "PASS"
        foreign = await w.verifier().verify("agent.example.com")
        assert not foreign.verified and foreign.a2a.status == "INCOMPLETE"


async def test_registry_outage_is_incomplete_not_pass(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import httpx

    async with world(db, tmp_path) as w:
        w.ans.fail_next = [httpx.Response(503)] * 3
        result = await w.verifier().verify(DEMO)
    assert result.decision == "INCOMPLETE" and not result.verified


@pytest.mark.parametrize(
    ("mutate", "check"),
    [
        (lambda a: a["endpoints"][0].update(agentUrl="https://evil.example.com/a2a"), "endpoint_host_binding"),
        (lambda a: a["endpoints"][0].update(agentUrl=f"http://{DEMO}/a2a"), "endpoints_https"),
        (lambda a: a["endpoints"][0].update(agentUrl=f"https://{DEMO}/other-rpc"), "metadata_schema"),
        (lambda a: a["endpoints"][1].update(agentUrl=f"https://{DEMO}:8443/mcp"), "endpoint_network_policy"),
        (lambda a: a.update(endpoints=[{"agentUrl": f"https://{DEMO}/api", "protocol": "HTTP-API"}]), "supported_protocol"),
        (lambda a: a.update(ansName="ans://v1.0.0.someone-else.org"), "canonical_agent_host"),
        (lambda a: a["endpoints"][0].update(metaDataHash="sha256:" + "11" * 32), "metadata_integrity"),
    ],
)
async def test_endpoint_mismatches_rejected(db: Database, tmp_path, mutate, check: str) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        mutate(w.ans.agents[w.agent_id])
        result = await w.verifier().verify(DEMO)
    assert not result.verified and by_id(result)[check] == "FAIL", result.reasons


async def test_remote_private_endpoint_rejected_before_any_request(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        result = await w.verifier(resolver=FakeResolver({DEMO: ["10.0.0.5"]})).verify(DEMO)
    checks = by_id(result)
    assert checks["endpoint_network_policy"] == "FAIL" and checks["metadata_fetch"] == "FAIL"
    assert result.a2a.card_sha256 == "" and not result.mcp.handshake  # nothing was fetched


async def test_real_tls_probe_refuses_private_destinations() -> None:
    probe = make_tls_probe(GlobalOnlyPolicy(), FakeResolver({"internal.example.com": ["169.254.169.254"]}))
    evidence = await probe("internal.example.com")
    assert evidence.status == "FAIL" and "blocked" in evidence.detail


async def test_search_detail_and_transparency_contradictions(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.detail_overrides = {"lifecycle": {"status": "REVOKED"}}
        assert by_id(await w.verifier().verify(DEMO))["ans_record_consistency"] == "FAIL"
        w.ans.detail_overrides = {}
        w.ans.badge_overrides = {"status": "REVOKED"}  # the transparency log is the revocation channel
        revoked = await w.verifier().verify(DEMO)
        assert not revoked.verified and by_id(revoked)["ans_record_consistency"] == "FAIL"
        w.ans.badge_overrides = {}
        w.ans.badge_down = True
        down = await w.verifier().verify(DEMO)
        assert down.decision == "INCOMPLETE" and not down.verified


async def test_card_drift_audits_and_forces_reverification(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from app.models.db import CardObservation

    async with world(db, tmp_path) as w:
        assert (await w.verifier().verify(DEMO)).verified
        async with db.session() as session:
            row = (await session.execute(select(CardObservation))).scalar_one()
            row.card_sha256 = "f" * 64  # what we verified last time differs from what is served now
            await session.commit()
        drifted = await w.verifier().verify(DEMO)
        assert not drifted.verified and drifted.a2a.drift and by_id(drifted)["card_hash_drift"] == "FAIL"
        async with db.session() as session:
            events = [e for e in (await session.execute(select(AuditEvent))).scalars() if e.action == "verify.card_drift"]
            assert len(events) == 1 and events[0].meta["previous"] == "f" * 64
        assert (await w.verifier().verify(DEMO)).verified  # full re-verification against the new card


async def test_local_blocklist_wins(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        async with db.session() as session:
            session.add(BlockedAgent(agent_host=DEMO, reason="test"))
            await session.commit()
        result = await w.verifier().verify(DEMO)
    assert not result.verified and by_id(result)["local_blocklist"] == "FAIL"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "demo.agentdesk-demo.org/../x", "a" * 300, "exa mple.com", ""])
async def test_bad_host_input_fails_cleanly(db: Database, tmp_path, host: str) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        result = await w.verifier().verify(host)
    assert result.decision == "FAIL" and w.ans.requests == []


# --------------------------------------------------------------------------- evidence / proof
async def test_proof_document_gates_and_redaction(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        service = ProofService(w.settings, w.verifier())  # type: ignore[arg-type]
        proof = await service.proof_for(DEMO, probe_tool="get_hours")
        again = await service.proof_for(DEMO)
        assert proof["cached"] is False and again["cached"] is True
        gates = {g["gate"]: g["status"] for g in proof["gates"]}
        assert gates == {1: "PASS", 2: "PASS", 3: "PASS", 4: "PASS", 5: "PASS"}
        text = json.dumps(proof)
        assert PAT not in text and "PRIVATE KEY" not in text and w.settings.session_secret.get_secret_value() not in text  # type: ignore[attr-defined]
        path = write_evidence_bundle(proof, tmp_path / "artifacts", name="proof-demo")
        assert json.loads(path.read_text())["agent_host"] == DEMO

        w.ans.agents.clear()
        unregistered = build_proof(await w.verifier().verify(DEMO), w.settings)  # type: ignore[arg-type]
        gates = {g["gate"]: g["status"] for g in unregistered["gates"]}
        assert gates[1] == "PASS" and gates[4] == "INCOMPLETE" and gates[5] == "FAIL" and gates[3] == "INCOMPLETE"


async def test_ote_active_is_not_gate4_pass(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        ote = make_settings(base_domain=BASE, godaddy_api_base="https://api.ote-godaddy.com")
        result = await w.verifier(settings=ote).verify(DEMO)
        gate4 = gate_summary(result, ote)[3]
    assert result.ans.environment == "ote" and gate4["status"] == "INCOMPLETE"


def test_placeholder_domain_never_passes_gate3() -> None:
    from app.models.schemas import AnsEvidence, VerificationResult
    from app.models.db import utcnow

    settings = make_settings()
    result = VerificationResult(agent_host="demo.example.test", generated_at=utcnow(), tls=TlsEvidence(status="PASS"),
                                ans=AnsEvidence(status="ACTIVE", environment="production"))
    assert gate_summary(result, settings)[2]["status"] == "INCOMPLETE"


@pytest.mark.parametrize("leak", ["-----BEGIN RSA PRIVATE KEY-----\nabc", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
                                  "gd_pat_abcdef123456", "sso-key k3y:s3cret", "test-session-secret-0123456789abcdef0123456789"])
def test_secret_shaped_evidence_is_refused(leak: str) -> None:
    with pytest.raises(SecretLeak):
        assert_no_secrets(json.dumps({"note": leak}), make_settings())


def test_bundle_name_is_not_a_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    for name in ("../evil", "a/b", "", "X" * 200, ".hidden"):
        with pytest.raises(ValueError):
            write_evidence_bundle({}, tmp_path, name=name)
