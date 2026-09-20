"""Gate 1 (local): A2A Agent Card + JSON-RPC and MCP Streamable HTTP, for Agent Desk AND a business agent."""

from __future__ import annotations

import json

import httpx
import pytest
from a2a.types import AgentCard
from google.protobuf.json_format import ParseDict
from starlette.applications import Starlette

from app.agents.runtime import AgentRuntime
from app.protocols.a2a_server import card_sha256
from tests.conftest import DEMO_HOST, DESK_HOST

MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def client_for(app: Starlette, host: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=f"https://{host}")


def a2a_body(text: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": "t-1",
        "method": "SendMessage",
        "params": {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": text}]}},
    }


async def mcp_call(client: httpx.AsyncClient, method: str, params: dict | None = None, id_: int = 1) -> dict:
    payload: dict = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        payload["params"] = params
    response = await client.post("/mcp", headers=MCP_HEADERS, json=payload)
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- A2A
@pytest.mark.parametrize(("host", "skill"), [(DEMO_HOST, "get_business_info"), (DESK_HOST, "find_agent")])
async def test_agent_card_is_valid_and_host_specific(protocol_app: Starlette, host: str, skill: str) -> None:
    async with client_for(protocol_app, host) as client:
        response = await client.get("/.well-known/agent-card.json")
        legacy = await client.get("/.well-known/agent.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    card = response.json()
    assert legacy.json() == card
    # Round-trips through the official SDK schema (unknown 0.3-compat keys are tolerated by the SDK parser).
    parsed = ParseDict(card, AgentCard(), ignore_unknown_fields=True)
    assert parsed.supported_interfaces[0].url == f"https://{host}/a2a"
    assert parsed.supported_interfaces[0].protocol_binding == "JSONRPC"
    assert skill in [s.id for s in parsed.skills]
    assert parsed.capabilities.streaming is False and parsed.capabilities.push_notifications is False
    assert len(card_sha256(card)) == 64


async def test_agent_card_has_no_secrets_or_admin_surface(protocol_app: Starlette, settings) -> None:
    async with client_for(protocol_app, DESK_HOST) as client:
        text = (await client.get("/.well-known/agent-card.json")).text.lower()
    for needle in (
        "/admin",
        "password",
        "secret",
        "token",
        settings.session_secret.get_secret_value().lower(),
    ):
        assert needle not in text


async def test_agent_card_ignores_forwarded_host(protocol_app: Starlette) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        card = (
            await client.get("/.well-known/agent-card.json", headers={"X-Forwarded-Host": "evil.example"})
        ).json()
    assert "evil.example" not in json.dumps(card)


async def test_unknown_host_has_no_agent(protocol_app: Starlette) -> None:
    async with client_for(protocol_app, "ghost.example.test") as client:
        assert (await client.get("/.well-known/agent-card.json")).status_code == 404
        reply = (await client.post("/a2a", json=a2a_body("hi"), headers={"A2A-Version": "1.0"})).json()
        assert "error" in reply and "result" not in reply
        assert (
            await client.post("/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        ).status_code == 404


async def test_a2a_send_message_v1(protocol_app: Starlette) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        response = await client.post(
            "/a2a", json=a2a_body("When are you open?"), headers={"A2A-Version": "1.0"}
        )
    message = response.json()["result"]["message"]
    assert message["role"] == "ROLE_AGENT"
    assert "Monday-Friday" in message["parts"][0]["text"]


async def test_a2a_message_send_v03_compat(protocol_app: Starlette) -> None:
    body = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "messageId": "m",
                "role": "user",
                "parts": [{"kind": "text", "text": "how much is an oat milk latte?"}],
            }
        },
    }
    async with client_for(protocol_app, DEMO_HOST) as client:
        result = (await client.post("/a2a", json=body)).json()["result"]
    assert "$5.25" in result["parts"][0]["text"]


async def test_a2a_desk_routes_to_backend(protocol_app: Starlette, runtime: AgentRuntime) -> None:
    async with client_for(protocol_app, DESK_HOST) as client:
        found = (
            await client.post(
                "/a2a", json=a2a_body("coffee shop hours agent"), headers={"A2A-Version": "1.0"}
            )
        ).json()
        verified = (
            await client.post(
                "/a2a", json=a2a_body("please verify demo.example.test"), headers={"A2A-Version": "1.0"}
            )
        ).json()
    assert found["result"]["message"]["parts"][0]["text"] == "FOUND for: coffee shop hours agent"
    assert verified["result"]["message"]["parts"][0]["text"] == "VERIFIED: demo.example.test"
    assert [c[0] for c in runtime.desk_backend.calls] == ["find", "verify"]  # type: ignore[union-attr]


@pytest.mark.parametrize("host", [DEMO_HOST, DESK_HOST])
async def test_a2a_transaction_requests_fail_closed(
    protocol_app: Starlette, runtime: AgentRuntime, host: str
) -> None:
    async with client_for(protocol_app, host) as client:
        reply = (
            await client.post(
                "/a2a",
                json=a2a_body("book a table and pay $20 with this mandate"),
                headers={"A2A-Version": "1.0"},
            )
        ).json()
    assert "read-only" in reply["result"]["message"]["parts"][0]["text"]
    assert runtime.desk_backend.calls == []  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{",
        b"[]",
        b'{"jsonrpc":"2.0","id":1,"method":"nope"}',
        b'{"jsonrpc":"2.0","id":1,"method":"SendMessage"}',
        b'{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":"x"}}}',
        b"\xff\xfe\x00",
    ],
)
async def test_a2a_malformed_input_fails_cleanly(protocol_app: Starlette, raw: bytes) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        response = await client.post(
            "/a2a", content=raw, headers={"Content-Type": "application/json", "A2A-Version": "1.0"}
        )
    assert response.status_code < 500
    assert "error" in response.json()


async def test_a2a_streaming_and_push_are_not_offered(protocol_app: Starlette) -> None:
    body = a2a_body("hi")
    body["method"] = "CreateTaskPushNotificationConfig"
    body["params"] = {"taskId": "x", "config": {"url": "http://169.254.169.254/"}}
    async with client_for(protocol_app, DEMO_HOST) as client:
        reply = (await client.post("/a2a", json=body, headers={"A2A-Version": "1.0"})).json()
    assert "error" in reply


# --------------------------------------------------------------------------- MCP
async def test_mcp_handshake_and_tools_per_host(protocol_app: Starlette) -> None:
    init = {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}
    async with client_for(protocol_app, DEMO_HOST) as client:
        hello = await mcp_call(client, "initialize", init)
        tools = await mcp_call(client, "tools/list", id_=2)
    assert hello["result"]["serverInfo"]["name"] == "agent-desk-business-agent"
    names = {t["name"] for t in tools["result"]["tools"]}
    assert names == {"get_business_info", "get_hours", "get_menu_or_services"}
    assert all(t["annotations"]["readOnlyHint"] is True for t in tools["result"]["tools"])

    async with client_for(protocol_app, DESK_HOST) as client:
        tools = await mcp_call(client, "tools/list", id_=2)
    assert {t["name"] for t in tools["result"]["tools"]} == {"find_agent", "verify_agent", "about_agent_desk"}


async def test_mcp_tool_calls(protocol_app: Starlette) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        hours = await mcp_call(client, "tools/call", {"name": "get_hours", "arguments": {}})
        info = await mcp_call(
            client, "tools/call", {"name": "get_business_info", "arguments": {"question": "wifi?"}}
        )
        menu = await mcp_call(client, "tools/call", {"name": "get_menu_or_services", "arguments": {}})
    assert "Saturday" in hours["result"]["content"][0]["text"]
    assert "wifi" in info["result"]["content"][0]["text"].lower()
    assert (
        "Espresso" in menu["result"]["content"][0]["text"]
        and "Catering" in menu["result"]["content"][0]["text"]
    )


async def test_mcp_cross_kind_and_unknown_tools_rejected(protocol_app: Starlette) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        for name in ("find_agent", "shell", "../../etc/passwd"):
            reply = await mcp_call(client, "tools/call", {"name": name, "arguments": {"query": "x"}})
            assert reply.get("error") or reply["result"]["isError"] is True


async def test_mcp_does_not_pass_credentials_to_tools(protocol_app: Starlette, runtime: AgentRuntime) -> None:
    headers = {
        **MCP_HEADERS,
        "Authorization": "Bearer canary-token-value",
        "Cookie": "__Host-agentdesk_session=abc",
        "X-Agentdesk-Client-Ip": "6.6.6.6",
    }
    async with client_for(protocol_app, DESK_HOST) as client:
        response = await client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "find_agent", "arguments": {"query": "hours"}},
            },
        )
    assert response.json()["result"]["isError"] is False
    ((_, _, principal),) = runtime.desk_backend.calls  # type: ignore[union-attr]
    assert "canary" not in principal and "6.6.6.6" not in principal


@pytest.mark.parametrize("raw", [b"", b"{", b"[1,2", b'{"jsonrpc":"1.0"}', b"\xff\xfe"])
async def test_mcp_malformed_input_fails_cleanly(protocol_app: Starlette, raw: bytes) -> None:
    async with client_for(protocol_app, DEMO_HOST) as client:
        response = await client.post("/mcp", headers=MCP_HEADERS, content=raw)
    assert 400 <= response.status_code < 500
