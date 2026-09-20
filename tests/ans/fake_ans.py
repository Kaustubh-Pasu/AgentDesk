"""In-memory fake of the GoDaddy ANS REST API (httpx.MockTransport), shaped per docs/research/ANS_API_NOTES.md."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx


class FakeANS:
    def __init__(self, *, singular_challenge: bool = False) -> None:
        self.agents: dict[str, dict[str, Any]] = {}
        self.certs: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self.requests: list[httpx.Request] = []
        self.singular_challenge = singular_challenge
        self.fail_next: list[httpx.Response] = []
        self.acme_ok = True
        self.dns_ok = True

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    # ---------------------------------------------------------------- helpers for tests
    def add_active_agent(self, host: str, version: str = "1.0.0", *, status: str = "ACTIVE",
                         endpoints: list[dict[str, Any]] | None = None, name: str = "Agent") -> str:
        agent_id = str(uuid.uuid4())
        self.agents[agent_id] = {
            "agentId": agent_id, "agentHost": host, "version": version, "agentStatus": status,
            "ansName": f"ans://v{version}.{host}", "agentDisplayName": name,
            "endpoints": endpoints if endpoints is not None else [
                {"agentUrl": f"https://{host}/a2a", "metaDataUrl": f"https://{host}/.well-known/agent-card.json",
                 "protocol": "A2A", "transports": ["JSON-RPC"], "functions": [{"id": "get_hours", "name": "Hours"}]},
                {"agentUrl": f"https://{host}/mcp", "protocol": "MCP", "transports": ["STREAMABLE-HTTP"]}],
            "links": [],
        }
        return agent_id

    def _hit(self, a: dict[str, Any]) -> dict[str, Any]:
        return {"agentId": a["agentId"], "agentHost": a["agentHost"], "ansName": a["ansName"],
                "agentDisplayName": a["agentDisplayName"], "agentVersion": f"v{a['version']}",
                "lifecycle": {"status": a["agentStatus"]}, "scores": {"trustScore": 70, "relevance": 1.0},
                "endpoints": a["endpoints"], "indexedAt": "2026-09-18T07:52:32.212734855Z", "leafIndex": 1}

    # ---------------------------------------------------------------- handler
    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail_next:
            return self.fail_next.pop(0)
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}
        if path.startswith("/v1/ans/"):
            if path == "/v1/ans/search-registered-agents":
                statuses = set(body.get("statuses") or ["ACTIVE"])
                domains = body.get("agentDomains")
                items = [self._hit(a) for a in self.agents.values() if a["agentStatus"] in statuses
                         and (not domains or a["agentHost"] in domains)]
                return httpx.Response(200, json={"items": items[: body.get("pageSize", 20)], "links": []})
            agent = self.agents.get(path.rsplit("/", 1)[-1])
            return httpx.Response(200, json=self._hit(agent)) if agent else self._err(404, "NOT_FOUND")
        auth = request.headers.get("authorization", "")
        if not auth:
            return httpx.Response(302, headers={"location": "https://sso.godaddy.com/login"})
        if auth not in ("Bearer gd_pat_test_credential_0001", "sso-key testkey0001:testsecret0001"):
            return httpx.Response(401)
        if path == "/v1/agents/register" and method == "POST":
            return self._register(body)
        if path == "/v1/agents" and method == "GET":
            host = request.url.params.get("agentHost", "")
            agents = [a for a in self.agents.values() if host in a["agentHost"]]
            return httpx.Response(200, json={"agents": agents, "hasMore": False, "limit": 20, "offset": 0,
                                             "returnedCount": len(agents), "totalCount": len(agents)})
        parts = path.split("/")
        agent = self.agents.get(parts[3]) if len(parts) > 3 else None
        if agent is None:
            return self._err(404, "NOT_FOUND")
        tail = "/".join(parts[4:])
        if tail == "" and method == "GET":
            return httpx.Response(200, json=agent)
        if tail == "verify-acme":
            if not self.acme_ok:
                return self._err(422, "VALIDATION_ERROR", "Validation failed")
            agent["agentStatus"] = "PENDING_DNS"
            host, aid = agent["agentHost"], agent["agentId"]
            agent["registrationPending"] = {"status": "PENDING_DNS", "ansName": agent["ansName"], "nextSteps": [], "dnsRecords": [
                {"name": f"_ans.{host}", "type": "TXT", "value": f"v=ans1; version=v{agent['version']}; p=a2a; url=https://{host}/a2a", "purpose": "DISCOVERY"},
                {"name": f"_ans-badge.{host}", "type": "TXT", "value": f"v=ans-badge1; version=v{agent['version']}; url=https://transparency.ans.godaddy.com/v1/agents/{aid}", "purpose": "BADGE"},
                {"name": f"_443._tcp.{host}", "type": "TLSA", "value": "3 0 1 " + "ab" * 32, "required": False},
                {"name": "unrelated.victim.example", "type": "TXT", "value": "evil"}]}
            return httpx.Response(202, json={"status": "PENDING_DNS", "phase": "DNS_PROVISIONING"})
        if tail == "verify-dns":
            if not self.dns_ok:
                return httpx.Response(422, json={"status": "ERROR", "code": "VALIDATION_ERROR", "message": "DNS",
                                                 "missingRecords": [{"name": f"_ans.{agent['agentHost']}", "type": "TXT", "value": "x"}]})
            agent["agentStatus"] = "ACTIVE"
            agent.pop("registrationPending", None)
            return httpx.Response(202, json={"status": "ACTIVE", "phase": "COMPLETED"})
        if tail == "revoke":
            agent["agentStatus"] = "REVOKED"
            return httpx.Response(200, json={"agentId": agent["agentId"], "ansName": agent["ansName"], "status": "REVOKED",
                                             "revokedAt": "2026-09-19T10:00:00Z", "reason": body.get("reason"), "links": []})
        if tail in ("certificates/identity", "certificates/server"):
            return httpx.Response(200, json=self.certs.get(agent["agentId"], {}).get(tail.rsplit("/", 1)[-1], []))
        return self._err(404, "NOT_FOUND")

    def _register(self, body: dict[str, Any]) -> httpx.Response:
        for key in ("agentDisplayName", "agentHost", "version", "endpoints", "identityCsrPEM"):
            if not body.get(key):
                return self._err(422, "VALIDATION_ERROR", f"{key} is required")
        host, version = body["agentHost"], body["version"]
        if any(a["agentHost"] == host and a["version"] == version for a in self.agents.values()):
            return self._err(409, "ANS_NAME_TAKEN")
        agent_id = self.add_active_agent(host, version, status="PENDING_VALIDATION", endpoints=body["endpoints"],
                                         name=body["agentDisplayName"])
        challenge = {"type": "DNS_01", "token": "tok-SECRETISH", "keyAuthorization": "tok-SECRETISH.thumb",
                     "dnsRecord": {"name": f"_acme-challenge.{host}", "type": "TXT", "value": "acme-value-123"}}
        pending: dict[str, Any] = {"status": "PENDING_VALIDATION", "ansName": f"ans://v{version}.{host}", "agentId": agent_id,
                                   "nextSteps": [{"action": "CONFIGURE_DNS", "description": "x"}],
                                   "expiresAt": "2026-09-19 16:30:00+00:00"}
        pending["challenge" if self.singular_challenge else "challenges"] = challenge if self.singular_challenge else [challenge]
        self.agents[agent_id]["registrationPending"] = pending
        return httpx.Response(202, json=pending)

    @staticmethod
    def _err(status: int, code: str, message: str = "") -> httpx.Response:
        return httpx.Response(status, json={"code": code, "message": message or code, "status": "ERROR"})
