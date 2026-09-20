"""A2A server (official a2a-sdk): public Agent Card + JSON-RPC endpoint, multi-tenant by Host.

- The card is generated from trusted config (``skills_for``) and OUR canonical origin — never from request
  headers, raw model output or imported HTML. It contains no secrets and no admin endpoints.
- ``/a2a`` is the SDK JSON-RPC dispatcher (A2A 1.0, with the SDK's 0.3 compatibility enabled). The tenant
  is selected from the TrustedHost-validated Host header by ``HostContextBuilder``.
- Streaming and push notifications are disabled: no webhook/callback surface exists in the MVP.
"""

from __future__ import annotations

import hashlib
from typing import Any

from a2a.helpers import new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.context import ServerCallContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.request_handlers.response_helpers import agent_card_to_dict
from a2a.server.routes import DefaultServerCallContextBuilder, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentInterface, AgentProvider, AgentSkill, Role
from a2a.utils import TransportProtocol
from a2a.utils.constants import VERSION_HEADER
from a2a.utils.errors import InvalidParamsError, UnsupportedOperationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Route

from app.agents.registry import ServedAgent
from app.agents.runtime import AgentRuntime, SkillError, skills_for
from app.ans.card_signature import SIGNATURE_FIELD, CardSigner
from app.logging_config import get_logger
from app.models.schemas import canonical_json
from app.security.middleware import client_ip
from app.settings import Settings

log = get_logger("protocols.a2a")

A2A_RPC_PATH = "/a2a"
AGENT_CARD_PATH = "/.well-known/agent-card.json"
LEGACY_AGENT_CARD_PATH = "/.well-known/agent.json"  # still probed by the ANS trust-score crawler
_TEXT = "text/plain"


def build_agent_card(agent: ServedAgent, settings: Settings) -> AgentCard:
    origin = settings.origin_for(agent.host)
    return AgentCard(
        name=agent.display_name,
        description=agent.description,
        version=agent.version,
        provider=AgentProvider(organization="Agent Desk", url=settings.desk_origin),
        documentation_url=f"{settings.desk_origin}/proof",
        supported_interfaces=[
            AgentInterface(
                url=f"{origin}{A2A_RPC_PATH}",
                protocol_binding=TransportProtocol.JSONRPC.value,
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=False, push_notifications=False, extended_agent_card=False),
        default_input_modes=[_TEXT],
        default_output_modes=[_TEXT],
        skills=[
            AgentSkill(
                id=s.id,
                name=s.name,
                description=s.description,
                tags=list(s.tags),
                examples=list(s.examples),
                input_modes=[_TEXT],
                output_modes=[_TEXT],
            )
            for s in skills_for(agent)
        ],
    )


def agent_card_json(agent: ServedAgent, settings: Settings) -> dict[str, Any]:
    return agent_card_to_dict(build_agent_card(agent, settings))


async def signed_agent_card_json(
    agent: ServedAgent, settings: Settings, signer: CardSigner | None
) -> dict[str, Any]:
    """The public card, with a detached JWS attached when the ANS identity key can sign it.

    The signature is made by the key in this agent's ANS identity certificate, so a caller can bind the card
    to the registry identity instead of to a key we publish about ourselves. If signing is unavailable the
    card is served unsigned: an unsigned card verifies as INCOMPLETE, a wrong signature would verify as FAIL.
    """
    card = agent_card_json(agent, settings)
    if signer is None:
        return card
    signature = await signer.sign(agent.host, agent.version, card)
    if signature:
        card[SIGNATURE_FIELD] = [signature]
    return card


def card_sha256(card: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(card).encode()).hexdigest()


class HostContextBuilder(DefaultServerCallContextBuilder):
    """Carries ONLY the validated host and client IP into the executor (no raw headers, no tokens)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def build(self, request: Request) -> ServerCallContext:
        context = super().build(request)
        # The SDK's version negotiation reads state['headers']; keep that one header, drop everything else
        # (cookies, authorization) so nothing sensitive can reach the executor.
        version = request.headers.get(VERSION_HEADER)
        context.state["headers"] = {VERSION_HEADER: version} if version else {}
        context.state["agent_host"] = request.headers.get("host", "")
        context.state["client_ip"] = client_ip(request, self._settings)
        return context


class RuntimeExecutor(AgentExecutor):
    def __init__(self, runtime: AgentRuntime) -> None:
        self._runtime = runtime

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        state = context.call_context.state if context.call_context else {}
        agent = await self._runtime.registry.resolve(str(state.get("agent_host", "")))
        if agent is None:
            raise InvalidParamsError(message="No agent is served on this host.")
        principal = f"ip:{state.get('client_ip', 'unknown')}"
        try:
            reply = await self._runtime.handle_text(agent, context.get_user_input(), principal=principal)
        except SkillError as exc:
            reply = exc.message
        await event_queue.enqueue_event(
            new_text_message(
                reply, context_id=context.context_id, task_id=context.task_id, role=Role.ROLE_AGENT
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        raise UnsupportedOperationError(message="Tasks complete immediately and cannot be cancelled.")


def create_a2a_routes(
    runtime: AgentRuntime, settings: Settings, signer: CardSigner | None = None
) -> list[BaseRoute]:
    async def agent_card(request: Request) -> Response:
        agent = await runtime.registry.resolve(request.headers.get("host", ""))
        if agent is None:
            return JSONResponse(
                {"error": {"code": "agent_not_found", "message": "No agent on this host."}}, 404
            )
        return JSONResponse(
            await signed_agent_card_json(agent, settings, signer),
            headers={"Cache-Control": "public, max-age=60", "X-Content-Type-Options": "nosniff"},
        )

    # The handler-level card only drives SDK capability checks (streaming/push off); the public card is per host.
    handler = DefaultRequestHandler(
        agent_executor=RuntimeExecutor(runtime),
        task_store=InMemoryTaskStore(),
        agent_card=build_agent_card(runtime.registry.desk_agent(), settings),
    )
    rpc_routes = create_jsonrpc_routes(
        handler, A2A_RPC_PATH, context_builder=HostContextBuilder(settings), enable_v0_3_compat=True
    )
    return [
        Route(AGENT_CARD_PATH, agent_card, methods=["GET"]),
        Route(LEGACY_AGENT_CARD_PATH, agent_card, methods=["GET"]),
        *rpc_routes,
    ]
