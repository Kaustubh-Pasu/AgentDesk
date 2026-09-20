"""FIND: discover (fake ANS) → verify (real verifier) → communicate (our real A2A/MCP servers over loopback)."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app.ans.client import AnsClient
from app.find.intent import IntentTag, normalize_query
from app.find.service import FindDeskBackend, FindService
from app.models.db import AuditEvent, Database
from app.models.schemas import FindInput
from app.security.kv import MemoryKV
from app.security.rate_limit import RateLimiter, RateLimitExceeded
from tests.ans.test_verifier_and_evidence import BASE, DEMO, World, world
from tests.conftest import make_settings
from tests.helpers import LoopbackRemoteHttp


def service_for(w: World, **overrides: object) -> FindService:
    settings = make_settings(base_domain=BASE, remote_timeout_s=5.0, **overrides) if overrides else w.settings
    http = LoopbackRemoteHttp(settings, w.port, [DEMO])  # type: ignore[arg-type]
    ans = AnsClient(settings, transport=w.ans.transport, backoff_s=0)  # type: ignore[arg-type]
    return FindService(settings, ans, w.verifier(settings=settings), http, RateLimiter(MemoryKV()), w.db)  # type: ignore[arg-type]


def test_intent_is_bounded_enum_tags_and_keywords_only() -> None:
    request = normalize_query("Please find me an agent that knows COFFEE shop opening hours near https://evil.example/x?y=1 ; rm -rf /")
    assert IntentTag.HOURS in request.tags and IntentTag.MENU in request.tags
    assert "coffee" in request.keywords and len(request.keywords) <= 12 and len(request.search_text) <= 256
    assert all(k.isascii() and "/" not in k and ":" not in k for k in request.keywords)
    assert normalize_query("!!!").tags == (IntentTag.GENERAL,)


async def test_discover_verify_communicate(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.add_active_agent("gone.example.org", status="REVOKED")
        outcome = await service_for(w).find(FindInput(query="coffee shop hours", question="When are you open on Saturday?"), principal="ip:1.2.3.4")
    assert outcome.error == "" and outcome.chosen is not None and outcome.chosen.agent_host == DEMO
    assert [c.agent_host for c in outcome.candidates] == [DEMO]  # REVOKED agents are never candidates
    assert outcome.reply_protocol == "A2A" and "Saturday" in outcome.reply
    public = outcome.to_public_dict()
    assert public["remote_reply"]["untrusted"] is True and len(public["candidates"][0]["checks"]) == 15
    async with db.session() as session:
        actions = [e.action for e in (await session.execute(select(AuditEvent))).scalars()]
    assert "verify.success" in actions and "remote.connect" in actions


async def test_exact_host_path_and_mcp_fallback(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        agent = w.ans.agents[w.agent_id]
        agent["endpoints"] = [e for e in agent["endpoints"] if e["protocol"] == "MCP"]
        outcome = await service_for(w).find(FindInput(query="exact lookup", exact_host=DEMO, question="Do you have wifi?"), principal="p")
    assert outcome.chosen is not None and outcome.reply_protocol == "MCP" and "wifi" in outcome.reply.lower()


async def test_unverified_candidate_is_never_contacted(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.badge_overrides = {"status": "REVOKED"}
        before = len(w.ans.requests)
        outcome = await service_for(w).find(FindInput(query="coffee", question="hello?"), principal="p")
    assert outcome.chosen is None and outcome.reply == "" and len(w.ans.requests) > before
    assert "Nothing was contacted" in " ".join(outcome.steps)
    assert outcome.to_public_dict()["candidates"][0]["decision"] == "FAIL"


async def test_high_trust_score_grants_nothing(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        w.ans.agents[w.agent_id]["endpoints"][0]["agentUrl"] = "https://evil.example.com/a2a"
        outcome = await service_for(w).find(FindInput(query="coffee", question="hi"), principal="p")
    assert outcome.candidates[0].trust_score == 70 and outcome.chosen is None and outcome.reply == ""


async def test_remote_calls_breaker_still_verifies(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        outcome = await service_for(w, disable_remote_agent_calls=True).find(FindInput(query="coffee", question="hi"), principal="p")
    assert outcome.reply == ""  # with the breaker on, even metadata fetches are refused, so nothing verifies and nothing is contacted
    assert outcome.chosen is None


async def test_ans_outage_and_rate_limit(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        service = service_for(w, rl_ans_search_per_min=2)
        w.ans.fail_next = [httpx.Response(503)] * 3
        assert "ANS search failed" in (await service.find(FindInput(query="coffee"), principal="p")).error
        await service.find(FindInput(query="tea"), principal="p")
        with pytest.raises(RateLimitExceeded):
            await service.find(FindInput(query="cake"), principal="p")
        assert "Rate limit" in await FindDeskBackend(service).find("cake", principal="p")
        assert (await service.find(FindInput(query="cake"), principal="someone-else")).error == ""


async def test_search_results_are_cached_briefly(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        service = service_for(w)
        await service.find(FindInput(query="coffee", connect=False), principal="a")
        searches = sum(r.url.path.endswith("search-registered-agents") and b"query" in r.content for r in w.ans.requests)
        await service.find(FindInput(query="coffee", connect=False), principal="b")
        assert sum(r.url.path.endswith("search-registered-agents") and b"query" in r.content for r in w.ans.requests) == searches


async def test_desk_backend_text_summaries(db: Database, tmp_path) -> None:  # type: ignore[no-untyped-def]
    async with world(db, tmp_path) as w:
        backend = FindDeskBackend(service_for(w))
        found = await backend.find("coffee shop hours", principal="ip:9.9.9.9")
        verified = await backend.verify(DEMO, principal="ip:9.9.9.9")
        bad = await backend.verify("169.254.169.254", principal="ip:9.9.9.9")
    assert DEMO in found and "verification PASS" in found and "untrusted" in found
    assert verified.startswith(f"Verification of {DEMO}: PASS") and "FAIL" in bad
