"""MCP server (official MCP SDK, Streamable HTTP) at ``/mcp``, multi-tenant by Host.

- Public tools are READ-ONLY and map 1:1 to the prewritten runtime skills. There is no admin, DNS, ANS-write,
  fetch-URL, shell or filesystem tool, and none can be added by tenant data.
- Stateless JSON mode: no server-side MCP session state to hijack; every request stands alone.
- No token passthrough: tools never see or forward Authorization/Cookie headers; only the validated Host
  header and the client IP (for rate limiting) are used.
- Two fixed tool sets exist (Agent Desk / business agent); the Host header picks which one a request sees.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.agents.registry import AgentKind
from app.agents.runtime import AgentRuntime, SkillError
from app.logging_config import get_logger
from app.security.middleware import client_ip_from_scope
from app.settings import Settings

log = get_logger("protocols.mcp")

MCP_PATH = "/mcp"
MCP_METADATA_PATH = "/.well-known/mcp.json"
_READ_ONLY = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
)
_READ_ONLY_OPEN = ToolAnnotations(
    readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True
)

#: tool name → argument names, per agent kind. Single source of truth for tools/list, mcp.json and ANS functions.
TOOLS_BY_KIND: dict[AgentKind, tuple[str, ...]] = {
    "desk": ("find_agent", "verify_agent", "about_agent_desk"),
    "business": ("get_business_info", "get_hours", "get_menu_or_services"),
}


class McpProtocolServer:
    """Owns the two SDK servers and dispatches ``/mcp`` requests to one of them by validated Host."""

    def __init__(self, runtime: AgentRuntime, settings: Settings) -> None:
        self._runtime = runtime
        self._settings = settings
        self._servers: dict[AgentKind, MCPServer] = {
            "desk": self._build_desk(),
            "business": self._build_business(),
        }
        # Host validation is done by OUR TrustedHostMiddleware (BASE_DOMAIN children, dynamic tenants); the SDK's
        # static allow-list cannot express that, so its duplicate check is disabled rather than weakened.
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
        self._apps: dict[AgentKind, ASGIApp] = {
            kind: server.streamable_http_app(
                streamable_http_path=MCP_PATH,
                json_response=True,
                stateless_http=True,
                max_request_body_size=settings.max_request_body_bytes,
                transport_security=security,
            )
            for kind, server in self._servers.items()
        }

    # ------------------------------------------------------------------ tool plumbing
    async def _call(self, ctx: Context, kind: AgentKind, skill_id: str, arguments: dict[str, Any]) -> str:
        headers = ctx.headers or {}
        agent = await self._runtime.registry.resolve(headers.get("host", ""))
        if agent is None or agent.kind != kind:
            raise ValueError("No such tool on this host.")
        forwarded = headers.get("x-agentdesk-client-ip", "unknown")
        try:
            return await self._runtime.call_skill(agent, skill_id, arguments, principal=f"ip:{forwarded}")
        except SkillError as exc:
            raise ValueError(exc.message) from exc

    def _build_desk(self) -> MCPServer:
        server = MCPServer(
            name="agent-desk",
            title="Agent Desk",
            instructions="Read-only ANS discovery and verification tools. No tool changes any state.",
            version=self._settings.ans_agent_version,
        )

        @server.tool(
            name="find_agent", title="Find Agent", annotations=_READ_ONLY_OPEN, structured_output=False
        )
        async def find_agent(query: str, ctx: Context) -> str:
            """Search GoDaddy ANS for agents matching a capability and verify each candidate."""
            return await self._call(ctx, "desk", "find_agent", {"query": query})

        @server.tool(
            name="verify_agent", title="Verify Agent", annotations=_READ_ONLY_OPEN, structured_output=False
        )
        async def verify_agent(agent_host: str, ctx: Context) -> str:
            """Run the Agent Desk ANS verification checklist against one agent hostname."""
            return await self._call(ctx, "desk", "verify_agent", {"agent_host": agent_host})

        @server.tool(
            name="about_agent_desk", title="About Agent Desk", annotations=_READ_ONLY, structured_output=False
        )
        async def about_agent_desk(ctx: Context) -> str:
            """Explain what Agent Desk does and which read-only operations it supports."""
            return await self._call(ctx, "desk", "about_agent_desk", {})

        return server

    def _build_business(self) -> MCPServer:
        server = MCPServer(
            name="agent-desk-business-agent",
            title="Business Agent",
            instructions="Read-only answers from one business's owner-approved public profile.",
            version=self._settings.ans_agent_version,
        )

        @server.tool(
            name="get_business_info",
            title="Business Information",
            annotations=_READ_ONLY,
            structured_output=False,
        )
        async def get_business_info(question: str, ctx: Context) -> str:
            """Answer a question about this business from its published, owner-approved profile."""
            return await self._call(ctx, "business", "get_business_info", {"question": question})

        @server.tool(name="get_hours", title="Opening Hours", annotations=_READ_ONLY, structured_output=False)
        async def get_hours(ctx: Context) -> str:
            """Return the published opening hours of this business."""
            return await self._call(ctx, "business", "get_hours", {})

        @server.tool(
            name="get_menu_or_services",
            title="Menu Or Services",
            annotations=_READ_ONLY,
            structured_output=False,
        )
        async def get_menu_or_services(ctx: Context) -> str:
            """Return the published menu and/or list of services of this business."""
            return await self._call(ctx, "business", "get_menu_or_services", {})

        return server

    # ------------------------------------------------------------------ ASGI
    def routes(self) -> list[BaseRoute]:
        """Exact-path routes (a Mount would 307 ``/mcp`` → ``/mcp/`` and break clients that do not follow it)."""
        return [Route(MCP_PATH, endpoint=self), Route(MCP_PATH + "/", endpoint=self)]

    @asynccontextmanager
    async def lifespan(self) -> AsyncIterator[None]:
        async with AsyncExitStack() as stack:
            for server in self._servers.values():
                await stack.enter_async_context(server.session_manager.run())
            yield

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        host = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"host"), "")
        agent = await self._runtime.registry.resolve(host)
        if agent is None:
            response = JSONResponse(
                {"error": {"code": "agent_not_found", "message": "No agent on this host."}}, 404
            )
            await response(scope, receive, send)
            return
        # Strip credentials before the SDK sees the request (no token passthrough, nothing to leak into tools) and
        # hand the proxy-aware client IP to the tool layer through a header only WE can set.
        ip = client_ip_from_scope(scope, self._settings)
        dropped = {b"authorization", b"cookie", b"x-agentdesk-client-ip", b"x-forwarded-for"}
        headers = [(k, v) for k, v in scope.get("headers", []) if k not in dropped]
        headers.append((b"x-agentdesk-client-ip", ip.encode("latin-1")))
        await self._apps[agent.kind](
            {**scope, "path": MCP_PATH, "raw_path": MCP_PATH.encode(), "headers": headers}, receive, send
        )


def mcp_metadata(kind: AgentKind, host: str, settings: Settings) -> dict[str, Any]:
    """Public ``/.well-known/mcp.json`` discovery document (referenced as ANS ``metaDataUrl``)."""
    from app.agents.runtime import ALL_SKILLS

    return {
        "name": "agent-desk" if kind == "desk" else "agent-desk-business-agent",
        "version": settings.ans_agent_version,
        "endpoint": f"{settings.origin_for(host)}{MCP_PATH}",
        "transport": "streamable-http",
        "authentication": {"type": "none"},
        "readOnly": True,
        "tools": [
            {"name": name, "title": ALL_SKILLS[name].name, "description": ALL_SKILLS[name].description}
            for name in TOOLS_BY_KIND[kind]
        ],
    }
