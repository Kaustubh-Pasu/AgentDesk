"""Gate 5: proof evidence. Turns a live ``VerificationResult`` into the 5-gate view and redacted bundles.

Nothing here is ever pre-filled: every gate status is derived from checks that were actually run (or from a
short-lived cache of them). A gate without live evidence is INCOMPLETE/WAITING, never PASS.
Bundles are scanned before they leave the process: private-key PEM, bearer/PAT shapes or any configured secret
value abort the export instead of being published.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from app.ans.verifier import Verifier
from app.logging_config import get_logger
from app.models.schemas import Status, VerificationResult
from app.security.redaction import redact_obj
from app.settings import Settings

log = get_logger("ans.evidence")

_SECRET_SHAPES = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|gd_pat_[A-Za-z0-9_\-]{6,}|\bsso-key\s+\S+:\S+|\bBearer\s+[A-Za-z0-9._\-]{16,}"
    r"|__Host-agentdesk_session=", re.IGNORECASE)
_PLACEHOLDER_DOMAINS = frozenset({"localhost", "example.com", "example.test", "example.org"})


class SecretLeak(Exception):
    """Raised instead of emitting evidence that contains secret-shaped material."""


def assert_no_secrets(text: str, settings: Settings) -> None:
    if _SECRET_SHAPES.search(text):
        raise SecretLeak("evidence contains secret-shaped material")
    for value in settings.secret_values():
        if value in text:
            raise SecretLeak("evidence contains a configured secret value")


def _gate(number: int, title: str, status: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"gate": number, "title": title, "status": status, "detail": detail,
            "evidence": {k: v for k, v in evidence.items() if v not in (None, "", [])}}


def _both(a: Status, b: Status) -> Status:
    if "FAIL" in (a, b):
        return "FAIL"
    return "PASS" if a == b == "PASS" else "INCOMPLETE"


def gate_summary(result: VerificationResult, settings: Settings) -> list[dict[str, Any]]:
    host, ans, tls = result.agent_host, result.ans, result.tls
    own = host.endswith("." + settings.base_domain)
    placeholder = settings.base_domain in _PLACEHOLDER_DOMAINS
    active_prod = ans.status == "ACTIVE" and ans.environment == "production"
    if placeholder or not own:
        g3 = ("INCOMPLETE", "BASE_DOMAIN is a placeholder; set it to the MLH domain you own" if placeholder
              else "host is not under BASE_DOMAIN")
    elif tls.status == "PASS" and ans.status == "ACTIVE":
        g3 = ("PASS", "host is under BASE_DOMAIN, serves valid public TLS, and ANS validated control of its DNS (ACME DNS-01)")
    elif tls.status == "PASS":
        g3 = ("INCOMPLETE", "host under BASE_DOMAIN serves valid public TLS; DNS control is proven once ANS reports ACTIVE")
    else:
        g3 = ("INCOMPLETE", "no live evidence yet that this host is publicly served")
    if active_prod:
        g4 = ("PASS", "GoDaddy production ANS reports ACTIVE (live lookup)")
    elif ans.status == "ACTIVE":
        g4 = ("INCOMPLETE", f"ACTIVE in the '{ans.environment}' environment, not production")
    elif ans.status:
        g4 = ("INCOMPLETE", f"GoDaddy ANS reports {ans.status}")
    else:
        g4 = ("INCOMPLETE", "no ANS registration found by the live lookup")
    return [
        _gate(1, "Reachable agent endpoint (A2A + MCP)", _both(result.a2a.status, result.mcp.status),
              f"A2A: {result.a2a.detail or result.a2a.status}; MCP: {result.mcp.detail or result.mcp.status}",
              agent_card=result.a2a.card_url, card_sha256=result.a2a.card_sha256, skills=result.a2a.skills,
              mcp_url=result.mcp.url, mcp_tools=result.mcp.tools),
        _gate(2, "Public HTTPS", tls.status, tls.detail, tls_version=tls.version, leaf_sha256=tls.leaf_sha256,
              issuer=tls.issuer, not_after=tls.not_after.isoformat() if tls.not_after else None),
        _gate(3, "Owned MLH domain", g3[0], g3[1], base_domain=None if placeholder else settings.base_domain, agent_host=host),
        _gate(4, "Production ANS registration ACTIVE", g4[0], g4[1], agent_id=ans.agent_id, ans_name=ans.ans_name,
              ans_status=ans.status, environment=ans.environment, checked_at=ans.checked_at.isoformat() if ans.checked_at else None),
        _gate(5, "Verification evidence", result.decision,
              "all mandatory checks passed" if result.verified else "; ".join(result.reasons[:3]) or "not verified",
              checks_passed=sum(c.status == "PASS" for c in result.checks), checks_total=len(result.checks),
              identity_sha256=result.identity_certificate.sha256 if result.identity_certificate else None),
    ]


def build_proof(result: VerificationResult, settings: Settings) -> dict[str, Any]:
    """Public, redacted proof document. Raises ``SecretLeak`` rather than returning something unsafe."""
    document = redact_obj({
        "agent_host": result.agent_host,
        "generated_at": result.generated_at.isoformat(),
        "environment": settings.ans_environment,
        "verified": result.verified,
        "decision": result.decision,
        "gates": gate_summary(result, settings),
        "verification": result.model_dump(mode="json"),
        "notes": ["Statuses are derived from live checks only; INCOMPLETE means 'could not be proven', never 'assumed fine'.",
                  "An ANS identity identifies an agent; it does not make the agent's output trusted."],
    })
    assert_no_secrets(json.dumps(document, default=str), settings)
    return document


class ProofService:
    """Cheap cached live evidence for ``/proof`` and ``/api/proof`` (single-flight per host)."""

    def __init__(self, settings: Settings, verifier: Verifier) -> None:
        self._settings = settings
        self._verifier = verifier
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._locks: dict[str, Any] = {}

    async def proof_for(self, agent_host: str, *, probe_tool: str | None = None) -> dict[str, Any]:
        import asyncio

        now = time.monotonic()
        cached = self._cache.get(agent_host)
        if cached and cached[0] > now:
            return {**cached[1], "cached": True}
        lock = self._locks.setdefault(agent_host, asyncio.Lock())
        async with lock:
            cached = self._cache.get(agent_host)
            if cached and cached[0] > time.monotonic():
                return {**cached[1], "cached": True}
            result = await self._verifier.verify(agent_host, probe_tool=probe_tool)
            document = build_proof(result, self._settings)
            if len(self._cache) > 256:
                self._cache.clear()
            self._cache[agent_host] = (time.monotonic() + self._settings.proof_cache_ttl_s, document)
            return {**document, "cached": False}


def write_evidence_bundle(document: dict[str, Any], artifacts_dir: Path, *, name: str) -> Path:
    """Write a redacted evidence JSON under the NON-secret artifacts directory (name is server-generated)."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,80}", name):
        raise ValueError("invalid bundle name")
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")
    path = artifacts_dir / f"{name}-{stamp}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True, default=str)
    return path
