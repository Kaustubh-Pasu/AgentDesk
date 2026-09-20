"""Verification engine: the 15-point candidate checklist (spec §26.1) → typed ``VerificationResult``.

Semantics
- Every check is PASS / FAIL / INCOMPLETE. Uncertainty is NEVER rounded up: a check that could not be performed
  (no trust anchor provisioned, certificate API not available for foreign agents, registry unreachable) stays
  INCOMPLETE with the reason.
- Decision: any FAIL → FAIL. Otherwise any MANDATORY check INCOMPLETE → INCOMPLETE. Otherwise PASS.
  Only ``decision == PASS`` sets ``verified`` and permits communication. Optional INCOMPLETE checks are listed in
  ``reasons`` so the caller always sees what was not proven.
- A verified ANS identity says WHO the agent is, not that it is honest: callers keep treating its output as
  untrusted data and grant it no local capability, whatever its trust score.
- All registry data is live (public discovery + detail + Transparency-Log badge). Nothing a remote agent sends
  (certificates, roots, card contents) is used as a trust input.
"""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography import x509
from sqlalchemy import select

from app.ans.certs import CertError, TrustAnchors, check_binding, fingerprint_sha256, load_certificates, summarize, verify_chain
from app.ans.client import CONNECTABLE_STATUSES, AnsApiError, AnsClient, AnsEndpoint, Badge, DiscoveredAgent
from app.logging_config import get_logger
from app.models.db import BlockedAgent, CardObservation, Database, utcnow
from app.models.schemas import (
    A2AEvidence,
    AnsEvidence,
    CheckResult,
    EndpointCheck,
    McpEvidence,
    Status,
    TlsEvidence,
    VerificationResult,
    parse_semver,
)
from app.protocols.a2a_client import A2AClient, FetchedCard
from app.protocols.mcp_client import McpClient
from app.protocols.remote_http import RemoteHttp, RemoteProtocolError
from app.security import audit
from app.security.breakers import FeatureDisabled
from app.security.ssrf import (
    REMOTE_AGENT_URL_POLICY,
    AddressPolicy,
    GlobalOnlyPolicy,
    Resolver,
    SSRFBlocked,
    canonical_hostname,
    resolve_and_validate,
    strict_ssl_context,
    system_resolver,
    validate_url,
)
from app.settings import Settings

log = get_logger("ans.verifier")

TlsProbe = Callable[[str], Awaitable[TlsEvidence]]
BADGE_CONNECTABLE = frozenset({"ACTIVE", "WARNING", "DEPRECATED"})
SUPPORTED_PROTOCOLS = frozenset({"A2A", "MCP"})


def _same_url(a: str, b: str) -> bool:
    return a.rstrip("/").lower() == b.rstrip("/").lower()


def make_tls_probe(address_policy: AddressPolicy, resolver: Resolver, timeout_s: float = 8.0) -> TlsProbe:
    async def probe(host: str) -> TlsEvidence:
        """TLS handshake to a VALIDATED, pinned address with full hostname + chain verification."""
        try:
            addresses = await resolve_and_validate(host, 443, address_policy, resolver)
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(str(addresses[0]), 443, ssl=strict_ssl_context(), server_hostname=host), timeout_s)
        except SSRFBlocked as exc:
            return TlsEvidence(status="FAIL", detail=f"destination blocked: {exc.code}")
        except ssl.SSLCertVerificationError as exc:
            return TlsEvidence(status="FAIL", detail=f"certificate verification failed: {exc.verify_message}"[:200])
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            return TlsEvidence(status="FAIL", detail=f"TLS connection failed: {type(exc).__name__}")
        try:
            sslobj = writer.get_extra_info("ssl_object")
            der = sslobj.getpeercert(True)
            cert = x509.load_der_x509_certificate(der)
            summary = summarize(cert)
            cipher = sslobj.cipher()
            return TlsEvidence(status="PASS", detail="hostname and chain verified against the public WebPKI",
                               version=sslobj.version() or "", cipher=cipher[0] if cipher else "", hostname_verified=True,
                               leaf_sha256=hashlib.sha256(der).hexdigest(), issuer=summary.issuer, subject=summary.subject,
                               san=summary.san, not_after=summary.valid_to)
        finally:
            writer.close()

    return probe


class Verifier:
    def __init__(self, settings: Settings, ans: AnsClient, http: RemoteHttp, db: Database | None, *,
                 anchors: TrustAnchors | None = None, address_policy: AddressPolicy | None = None,
                 resolver: Resolver = system_resolver, tls_probe: TlsProbe | None = None) -> None:
        self._settings = settings
        self._ans = ans
        self._db = db
        self._a2a = A2AClient(http)
        self._mcp = McpClient(http)
        self._anchors = anchors or TrustAnchors.load(settings.ans_trust_anchor_path, settings.trust_anchor_fingerprints)
        self._policy = address_policy or GlobalOnlyPolicy()
        self._resolver = resolver
        self._tls_probe = tls_probe or make_tls_probe(self._policy, resolver)

    # ------------------------------------------------------------------ entry point
    async def verify(self, agent_host: str, *, candidate: DiscoveredAgent | None = None, version: str | None = None,
                     probe_tool: str | None = None) -> VerificationResult:
        """Run the full checklist for ``agent_host``. ``candidate`` is an optional (untrusted-until-checked) search hit."""
        result = VerificationResult(agent_host=agent_host[:253], generated_at=utcnow())
        checks: list[CheckResult] = []

        def add(id_: str, label: str, status: Status, detail: str = "", *, mandatory: bool = True, **evidence: object) -> Status:
            checks.append(CheckResult(id=id_, label=label, status=status, detail=detail[:300], mandatory=mandatory,
                                      evidence={k: v for k, v in evidence.items() if v not in (None, "", [])}))
            return status

        # 2. canonical host (done first: everything else keys off it)
        try:
            host = canonical_hostname(agent_host.strip().lower())
            validate_url(f"https://{host}/", REMOTE_AGENT_URL_POLICY)
        except SSRFBlocked as exc:
            add("canonical_agent_host", "Canonical agent host", "FAIL", f"not a public DNS name ({exc.code})")
            return self._finish(result, checks)
        result.agent_host = host

        # 1. lifecycle ACTIVE from live ANS data
        live, lookup_problem = await self._lookup(host, version)
        if live is None:
            status: Status = "INCOMPLETE" if lookup_problem.startswith("registry") else "FAIL"
            add("ans_status_active", "ANS lifecycle is ACTIVE (live)", status, lookup_problem)
            add("canonical_agent_host", "Canonical agent host", "PASS", "host is a canonical public DNS name", observed=host)
            await self._self_evidence(host, result, add)
            return self._finish(result, checks)
        result.ans = AnsEvidence(agent_id=live.agent_id, ans_name=live.ans_name, status=live.status,
                                 environment=self._ans.environment, checked_at=utcnow(), source="GoDaddy ANS public discovery API (live)",
                                 declared_endpoints=[{"protocol": e.protocol, "url": e.agent_url, "transports": e.transports,
                                                      "metadata_url": e.meta_data_url} for e in live.endpoints])
        add("ans_status_active", "ANS lifecycle is ACTIVE (live)",
            "PASS" if live.status in CONNECTABLE_STATUSES else "FAIL", f"registry reports {live.status or 'no status'}",
            agent_id=live.agent_id, ans_name=live.ans_name)
        host_ok = live.agent_host.lower() == host and live.ans_name == f"ans://v{live.version}.{host}"
        add("canonical_agent_host", "Canonical agent host", "PASS" if host_ok else "FAIL",
            "registry agentHost and ANS name match the requested host" if host_ok else "registry host / ANS name mismatch",
            expected=host, observed=live.agent_host)

        # 3-6. endpoints
        endpoints = [e for e in live.endpoints if e.protocol.upper() in SUPPORTED_PROTOCOLS]
        add("supported_protocol", "Supports A2A or MCP", "PASS" if endpoints else "FAIL",
            ", ".join(sorted({e.protocol.upper() for e in endpoints})) or "no A2A/MCP endpoint declared")
        urls = [u for e in endpoints for u in (e.agent_url, e.meta_data_url) if u]
        https_ok = bool(urls) and all(urlsplit(u).scheme == "https" for u in urls)
        bound = bool(urls) and all((urlsplit(u).hostname or "").lower() == host for u in urls)
        result.tls = await self._tls_probe(host) if https_ok and bound else TlsEvidence(detail="not probed")
        add("endpoints_https", "Endpoints are HTTPS with valid TLS",
            "PASS" if https_ok and result.tls.status == "PASS" else "FAIL",
            result.tls.detail if https_ok else "a declared endpoint is not https", tls_version=result.tls.version,
            leaf_sha256=result.tls.leaf_sha256)
        add("endpoint_host_binding", "Endpoints are on the registered host", "PASS" if bound else "FAIL",
            "every endpoint/metadata URL is on the registered agentHost" if bound else "an endpoint is on a different host")
        net_status, net_detail = await self._network_policy(urls)
        add("endpoint_network_policy", "Endpoints pass outbound network policy", net_status, net_detail)

        # 7. registry detail + transparency log agree with the search hit
        badge = await self._consistency(live, candidate, add)

        # 8-10. identity certificate (official API only)
        await self._identity(live, badge, result, add)

        # 11-14. protocol metadata — only contacted if the destination checks passed
        safe = https_ok and bound and net_status == "PASS"
        card = await self._metadata(host, endpoints, safe, probe_tool, result, add)
        await self._drift(host, live.ans_name, card, result, add)

        # 15. local blocklist
        blocked = await self._blocked(host)
        add("local_blocklist", "Not on the local blocklist", "FAIL" if blocked else "PASS",
            "host is blocked by local policy" if blocked else "no local block")
        return self._finish(result, checks)

    # ------------------------------------------------------------------ steps
    async def _lookup(self, host: str, version: str | None) -> tuple[DiscoveredAgent | None, str]:
        try:
            hits = await self._ans.discover(agent_host=host, statuses=("ACTIVE", "WARNING", "DEPRECATED", "EXPIRED", "REVOKED"),
                                            page_size=25)
        except AnsApiError as exc:
            return None, f"registry lookup failed ({exc.code})"
        hits = [h for h in hits if h.agent_host.lower() == host and (version is None or h.version == version)]
        if not hits:
            return None, "no ANS registration found for this host"

        def order(hit: DiscoveredAgent) -> tuple[int, tuple[int, int, int]]:
            try:
                semver = parse_semver(hit.version)
            except ValueError:
                semver = (0, 0, 0)
            return (1 if hit.status == "ACTIVE" else 0, semver)

        return max(hits, key=order), ""

    async def _network_policy(self, urls: list[str]) -> tuple[Status, str]:
        if not urls:
            return "FAIL", "no endpoint to check"
        try:
            for url in urls:
                target = validate_url(url, REMOTE_AGENT_URL_POLICY)
                await resolve_and_validate(target.host, target.port, self._policy, self._resolver)
        except SSRFBlocked as exc:
            return "FAIL", f"blocked by outbound policy: {exc.code}"
        return "PASS", "https/443, public DNS name, every resolved address globally routable"

    async def _consistency(self, live: DiscoveredAgent, candidate: DiscoveredAgent | None, add: Callable[..., Status]) -> Badge | None:
        problems: list[str] = []
        incomplete: list[str] = []
        badge: Badge | None = None

        def endpoint_set(eps: list[AnsEndpoint]) -> set[tuple[str, str]]:
            return {(e.protocol.upper(), e.agent_url.rstrip("/").lower()) for e in eps}

        if candidate is not None and (candidate.agent_id != live.agent_id or candidate.ans_name != live.ans_name
                                      or endpoint_set(candidate.endpoints) != endpoint_set(live.endpoints)):
            problems.append("search result contradicts the live registry record")
        try:
            detail = await self._ans.get_registered_agent(live.agent_id)
            if (detail.agent_host.lower(), detail.ans_name, detail.status) != (live.agent_host.lower(), live.ans_name, live.status) \
                    or endpoint_set(detail.endpoints) != endpoint_set(live.endpoints):
                problems.append("agent detail contradicts the search result")
        except AnsApiError as exc:
            incomplete.append(f"agent detail unavailable ({exc.code})")
        try:
            badge = await self._ans.get_badge(live.agent_id)
            if badge.status not in BADGE_CONNECTABLE:
                problems.append(f"transparency log reports {badge.status or 'no status'}")
            if badge.agent_host.lower() != live.agent_host.lower() or badge.ans_name != live.ans_name:
                problems.append("transparency log entry is for a different agent")
        except AnsApiError as exc:
            incomplete.append(f"transparency log unavailable ({exc.code})")
        status: Status = "FAIL" if problems else "INCOMPLETE" if incomplete else "PASS"
        add("ans_record_consistency", "Registry detail and transparency log agree", status,
            "; ".join(problems or incomplete) or "search hit, agent detail and transparency-log badge are consistent",
            badge_status=badge.status if badge else None)
        return badge

    async def _identity(self, live: DiscoveredAgent, badge: Badge | None, result: VerificationResult, add: Callable[..., Status]) -> None:
        label8, label9, label10 = ("Identity certificate retrieved from ANS", "Identity certificate validity and binding",
                                   "Identity certificate chains to the ANS trust anchor")
        leaf, chain, why = None, [], ""
        if not self._ans.configured:
            why = "no ANS credential configured: the certificate API is authenticated"
        else:
            try:
                certs = await self._ans.get_identity_certificates(live.agent_id)
                if certs:
                    newest = certs[-1]
                    leaf = load_certificates(newest.certificate_pem, limit=1)[0]
                    chain = load_certificates(newest.chain_pem) if newest.chain_pem else []
                else:
                    why = "the registry returned no identity certificate"
            except AnsApiError as exc:
                why = ("certificate API only serves agents owned by the caller" if exc.status in (401, 403, 404)
                       else f"certificate API error ({exc.code})")
            except CertError as exc:
                add("identity_certificate_retrieved", label8, "FAIL", f"unparseable certificate from registry ({exc.code})", mandatory=False)
                add("identity_certificate_binding", label9, "FAIL", "no usable certificate", mandatory=False)
                add("identity_chain_trust_anchor", label10, "FAIL", "no usable certificate", mandatory=False)
                return
        if leaf is None:
            for id_, label in (("identity_certificate_retrieved", label8), ("identity_certificate_binding", label9),
                               ("identity_chain_trust_anchor", label10)):
                add(id_, label, "INCOMPLETE", why, mandatory=False)
            return
        summary = summarize(leaf)
        add("identity_certificate_retrieved", label8, "PASS", "retrieved from the official certificate-management API",
            mandatory=False, sha256=summary.sha256)
        bind_status, bind_reason = check_binding(leaf, live.agent_host.lower(), live.version)
        if bind_status == "PASS" and badge is not None and badge.identity_fingerprint:
            attested = badge.identity_fingerprint.lower().removeprefix("sha256:")
            if attested != fingerprint_sha256(leaf):
                bind_status, bind_reason = "FAIL", "certificate fingerprint differs from the transparency-log attestation"
            else:
                bind_reason += "; fingerprint matches the transparency-log attestation"
        chain_status, chain_reason = verify_chain(leaf, chain, self._anchors)
        summary.binding_status, summary.binding_reason = bind_status, bind_reason
        summary.chain_status, summary.chain_reason = chain_status, chain_reason
        result.identity_certificate = summary
        add("identity_certificate_binding", label9, bind_status, bind_reason, mandatory=False)
        add("identity_chain_trust_anchor", label10, chain_status, chain_reason, mandatory=False)

    async def _metadata(self, host: str, endpoints: list[AnsEndpoint], safe: bool, probe_tool: str | None,
                        result: VerificationResult, add: Callable[..., Status]) -> FetchedCard | None:
        labels = ("Protocol metadata fetched within limits", "Metadata parses and matches the registration",
                  "Metadata signature / hash")
        if not safe:
            for id_, label in zip(("metadata_fetch", "metadata_schema"), labels, strict=False):
                add(id_, label, "FAIL", "not attempted: endpoint safety checks did not pass")
            add("metadata_integrity", labels[2], "INCOMPLETE", "not attempted", mandatory=False)
            return None
        a2a = next((e for e in endpoints if e.protocol.upper() == "A2A"), None)
        mcp = next((e for e in endpoints if e.protocol.upper() == "MCP"), None)
        fetch_problems: list[str] = []
        schema_problems: list[str] = []
        card: FetchedCard | None = None
        if a2a is not None:
            card_url = a2a.meta_data_url or f"https://{host}/.well-known/agent-card.json"
            try:
                card = await self._a2a.fetch_card(card_url)
                rpc_host = (urlsplit(card.rpc_url).hostname or "").lower()
                if rpc_host != host or urlsplit(card.rpc_url).scheme != "https":
                    schema_problems.append("Agent Card JSON-RPC URL is not https on the registered host")
                elif not _same_url(card.rpc_url, a2a.agent_url):
                    schema_problems.append("Agent Card JSON-RPC URL differs from the ANS-registered A2A endpoint")
                result.a2a = A2AEvidence(status="FAIL" if schema_problems else "PASS", detail="; ".join(schema_problems) or "card valid",
                                         card_url=card_url, card_valid=not schema_problems, card_sha256=card.sha256, name=card.name,
                                         version=card.version, protocol_versions=list(card.protocol_versions),
                                         skills=list(card.skills)[:50], rpc_url=card.rpc_url, signed=card.signed)
            except (RemoteProtocolError, SSRFBlocked, FeatureDisabled) as exc:
                code = getattr(exc, "code", "error")
                (schema_problems if code in ("card_invalid", "invalid_json") else fetch_problems).append(f"A2A card: {code}")
                result.a2a = A2AEvidence(status="FAIL", detail=f"Agent Card rejected: {code}", card_url=card_url)
            result.endpoint_checks.append(EndpointCheck(protocol="A2A", url=a2a.agent_url, status=result.a2a.status, detail=result.a2a.detail))
        if mcp is not None:
            try:
                session = await self._mcp.connect(mcp.agent_url)
                result.mcp = McpEvidence(status="PASS", detail="initialize + tools/list succeeded", url=mcp.agent_url, handshake=True,
                                         protocol_version=session.protocol_version, server_name=session.server_name,
                                         tools=[t.name for t in session.tools][:50])
                tool = next((t for t in session.tools if t.name == probe_tool and t.read_only and not t.required), None)
                if tool is not None:
                    await self._mcp.call_tool(session, tool.name, {})
                    result.mcp.probe_tool, result.mcp.probe_ok = tool.name, True
            except (RemoteProtocolError, SSRFBlocked, FeatureDisabled) as exc:
                code = getattr(exc, "code", "error")
                fetch_problems.append(f"MCP: {code}")
                result.mcp = McpEvidence(status="FAIL", detail=f"MCP handshake failed: {code}", url=mcp.agent_url)
            result.endpoint_checks.append(EndpointCheck(protocol="MCP", url=mcp.agent_url, status=result.mcp.status, detail=result.mcp.detail))
        add("metadata_fetch", labels[0], "FAIL" if fetch_problems else "PASS", "; ".join(fetch_problems) or "fetched with time/size/content-type limits")
        add("metadata_schema", labels[1], "FAIL" if schema_problems else "PASS", "; ".join(schema_problems) or "parsed as data; interface matches the registration")
        declared_hash = (a2a.meta_data_hash or "").lower().removeprefix("sha256:") if a2a else ""
        if card is not None and declared_hash:
            ok = declared_hash in (card.raw_sha256, card.sha256)
            add("metadata_integrity", labels[2], "PASS" if ok else "FAIL",
                "card hash equals the ANS metaDataHash" if ok else "card hash differs from the ANS metaDataHash", mandatory=False)
        elif card is not None and card.signed:
            add("metadata_integrity", labels[2], "INCOMPLETE",
                "card carries a signature; its key is published by the agent itself, so it is recorded but not used as a trust input",
                mandatory=False)
        else:
            add("metadata_integrity", labels[2], "INCOMPLETE", "neither ANS nor the card provides a hash/signature to verify", mandatory=False)
        return card

    async def _drift(self, host: str, ans_name: str, card: FetchedCard | None, result: VerificationResult, add: Callable[..., Status]) -> None:
        label = "Agent Card hash is stable (drift watch)"
        if card is None or self._db is None:
            add("card_hash_drift", label, "INCOMPLETE", "no card to compare" if card is None else "no evidence store", mandatory=False)
            return
        async with self._db.session() as session:
            row = (await session.execute(select(CardObservation).where(CardObservation.agent_host == host))).scalar_one_or_none()
            now = utcnow()
            if row is None:
                session.add(CardObservation(agent_host=host, ans_name=ans_name, card_sha256=card.sha256))
                status, detail = "PASS", "first observation recorded"
            elif row.card_sha256 == card.sha256:
                row.last_seen_at, row.drift_blocked = now, False
                status, detail = "PASS", "matches the last verified hash"
            else:
                await audit.record(session, action=audit.CARD_DRIFT, outcome="drift", target_type="agent", target_id=host,
                                   metadata={"previous": row.card_sha256, "observed": card.sha256, "ans_name": ans_name})
                row.card_sha256, row.last_seen_at, row.ans_name = card.sha256, now, ans_name
                row.drift_count, row.drift_blocked = row.drift_count + 1, True
                result.a2a.drift = True
                status, detail = "FAIL", "Agent Card changed since it was last verified: re-verification required before use"
            await session.commit()
        add("card_hash_drift", label, status, detail, card_sha256=card.sha256)

    async def _blocked(self, host: str) -> bool:
        if self._db is None:
            return False
        async with self._db.session() as session:
            return (await session.execute(select(BlockedAgent.id).where(BlockedAgent.agent_host == host))).first() is not None

    async def _self_evidence(self, host: str, result: VerificationResult, add: Callable[..., Status]) -> None:
        """No ANS record (e.g. our own host before Gate 4): still gather live TLS/A2A/MCP evidence for OUR hosts only."""
        if not (host == self._settings.desk_host or host.endswith("." + self._settings.base_domain)):
            return
        net_status, net_detail = await self._network_policy([f"https://{host}/"])
        add("endpoint_network_policy", "Endpoints pass outbound network policy", net_status, net_detail)
        if net_status != "PASS":
            return
        result.tls = await self._tls_probe(host)
        synthetic = [AnsEndpoint(agentUrl=f"https://{host}/a2a", protocol="A2A", metaDataUrl=f"https://{host}/.well-known/agent-card.json"),
                     AnsEndpoint(agentUrl=f"https://{host}/mcp", protocol="MCP")]
        await self._metadata(host, synthetic, result.tls.status == "PASS", None, result, add)

    @staticmethod
    def _finish(result: VerificationResult, checks: list[CheckResult]) -> VerificationResult:
        result.checks = checks
        failed = [c for c in checks if c.status == "FAIL"]
        open_mandatory = [c for c in checks if c.status == "INCOMPLETE" and c.mandatory]
        open_optional = [c for c in checks if c.status == "INCOMPLETE" and not c.mandatory]
        result.decision = "FAIL" if failed else "INCOMPLETE" if open_mandatory else "PASS"
        result.verified = result.decision == "PASS"
        result.reasons = [f"{c.status}: {c.label} — {c.detail}" for c in (*failed, *open_mandatory, *open_optional)][:30]
        result.generated_at = datetime.now(UTC)
        return result
