from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest_asyncio
from starlette.applications import Starlette

from app.agents.registry import AgentRegistry
from app.agents.runtime import AgentRuntime
from app.agents.seed import seed_demo_agent
from app.models.db import Database
from app.protocols.a2a_server import create_a2a_routes
from app.protocols.mcp_server import McpProtocolServer
from app.settings import Settings


class StubDeskBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    async def find(self, query: str, *, principal: str) -> str:
        self.calls.append(("find", query, principal))
        return f"FOUND for: {query}"

    async def verify(self, agent_host: str, *, principal: str) -> str:
        self.calls.append(("verify", agent_host, principal))
        return f"VERIFIED: {agent_host}"


@pytest_asyncio.fixture
async def runtime(db: Database, settings: Settings) -> AgentRuntime:
    await seed_demo_agent(db, settings)
    return AgentRuntime(AgentRegistry(db, settings), settings, desk_backend=StubDeskBackend())


@pytest_asyncio.fixture
async def protocol_app(runtime: AgentRuntime, settings: Settings) -> AsyncIterator[Starlette]:
    mcp = McpProtocolServer(runtime, settings)

    @asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with mcp.lifespan():
            yield

    app = Starlette(routes=[*create_a2a_routes(runtime, settings), *mcp.routes()], lifespan=lifespan)
    # anyio task groups must be entered and exited in the SAME task; fixture setup/teardown are not.
    ready, stop = asyncio.Event(), asyncio.Event()

    async def hold_lifespan() -> None:
        async with lifespan(app):
            ready.set()
            await stop.wait()

    task = asyncio.create_task(hold_lifespan())
    await ready.wait()
    try:
        yield app
    finally:
        stop.set()
        await task
