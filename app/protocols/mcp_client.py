"""Outbound MCP client for REMOTE agents (Streamable HTTP; initialize → tools/list → optional tools/call).

The official MCP 2.x client is built on a different HTTP stack that cannot use our pinned SSRF transport,
so this minimal JSON-RPC client runs over ``RemoteHttp`` instead. It sends no credentials, handles JSON and
SSE replies, echoes ``Mcp-Session-Id`` only back to the server that issued it, and treats everything the
server returns as bounded untrusted data. Only tools that the server itself marks read-only are callable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.models.schemas import clean_text
from app.protocols.remote_http import RemoteHttp, RemoteProtocolError

CLIENT_PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_PROTOCOL_VERSIONS = frozenset(
    {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}
)
MAX_TOOLS = 100
MAX_REPLY_CHARS = 4000
_SESSION_ID = re.compile(r"^[\x21-\x7e]{1,256}\Z")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.\-/]{1,128}\Z")


@dataclass(frozen=True)
class McpTool:
    name: str
    description: str
    read_only: bool
    required: tuple[str, ...]
    properties: tuple[str, ...]


@dataclass
class McpSession:
    url: str
    protocol_version: str
    server_name: str
    headers: dict[str, str] = field(default_factory=dict)
    tools: list[McpTool] = field(default_factory=list)


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _result(data: dict[str, Any] | None, what: str) -> dict[str, Any]:
    if data is None:
        raise RemoteProtocolError("invalid_response", f"no response to {what}")
    if "error" in data:
        err = data["error"]
        code = err.get("code") if isinstance(err, dict) else None
        raise RemoteProtocolError("remote_error", f"{what}: JSON-RPC error {code!r}"[:80])
    result = data.get("result")
    if not isinstance(result, dict):
        raise RemoteProtocolError("invalid_response", f"{what}: result is not an object")
    return result


class McpClient:
    def __init__(self, http: RemoteHttp) -> None:
        self._http = http

    async def connect(self, url: str) -> McpSession:
        """initialize + notifications/initialized + tools/list."""
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agent-desk", "version": "1.0.0"},
            },
        }
        data, headers = await self._http.post_jsonrpc(url, init, allow_sse=True)
        result = _result(data, "initialize")
        version = result.get("protocolVersion")
        if not isinstance(version, str) or version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise RemoteProtocolError("protocol_version", "unsupported MCP protocol version")
        info = _obj(result.get("serverInfo"))
        session = McpSession(
            url=url,
            protocol_version=version,
            server_name=clean_text(str(info.get("name", "")))[:120],
            headers={"MCP-Protocol-Version": version},
        )
        session_id = headers.get("mcp-session-id")
        if session_id:
            if not _SESSION_ID.match(session_id):
                raise RemoteProtocolError("invalid_response", "malformed Mcp-Session-Id")
            session.headers["Mcp-Session-Id"] = session_id
        await self._http.post_jsonrpc(
            url,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=session.headers,
            allow_sse=True,
        )
        data, _ = await self._http.post_jsonrpc(
            url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=session.headers, allow_sse=True
        )
        tools = _result(data, "tools/list").get("tools")
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
            raise RemoteProtocolError("invalid_response", "tools/list: bad tool list")
        for tool in tools:
            if (
                not isinstance(tool, dict)
                or not isinstance(tool.get("name"), str)
                or not _TOOL_NAME.match(tool["name"])
            ):
                raise RemoteProtocolError("invalid_response", "tools/list: bad tool entry")
            schema = _obj(tool.get("inputSchema"))
            annotations = _obj(tool.get("annotations"))
            props = _obj(schema.get("properties"))
            raw_required = schema.get("required")
            required = [
                r for r in (raw_required if isinstance(raw_required, list) else []) if isinstance(r, str)
            ][:20]
            session.tools.append(
                McpTool(
                    name=tool["name"],
                    description=clean_text(str(tool.get("description", "")))[:400],
                    read_only=annotations.get("readOnlyHint") is True
                    and annotations.get("destructiveHint") is not True,
                    required=tuple(required),
                    properties=tuple(list(props)[:40]),
                )
            )
        return session

    async def call_tool(self, session: McpSession, name: str, arguments: dict[str, str]) -> str:
        """Call ONE tool that the server declares read-only. Reply is untrusted text: cleaned and bounded."""
        tool = next((t for t in session.tools if t.name == name), None)
        if tool is None:
            raise RemoteProtocolError("unknown_tool", "tool is not offered by the remote server")
        if not tool.read_only:
            raise RemoteProtocolError("tool_not_read_only", "refusing to call a tool not marked read-only")
        if set(tool.required) - set(arguments) or set(arguments) - set(tool.properties):
            raise RemoteProtocolError("tool_arguments", "arguments do not match the tool's input schema")
        payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        data, _ = await self._http.post_jsonrpc(session.url, payload, headers=session.headers, allow_sse=True)
        result = _result(data, "tools/call")
        content = result.get("content")
        texts = [
            c["text"]
            for c in (content if isinstance(content, list) else [])[:50]
            if isinstance(c, dict) and c.get("type") == "text" and isinstance(c.get("text"), str)
        ]
        reply = clean_text("\n".join(texts))[:MAX_REPLY_CHARS]
        if result.get("isError") is True:
            raise RemoteProtocolError("remote_tool_error", reply[:160])
        if not reply:
            raise RemoteProtocolError("empty_reply", "remote tool returned no text")
        return reply
