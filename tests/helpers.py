"""Test-only helpers. NOTHING in here is importable from application code.

``LoopbackTestPolicy`` is the ONLY relaxed address policy in the code base and it lives in the test tree:
it behaves exactly like the production ``GlobalOnlyPolicy`` except for ONE exact ``127.0.0.1:<port>`` pair
(the local fixture server), so redirects/rebinding to any other private destination are still blocked.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import ipaddress
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from app.protocols.remote_http import RemoteHttp
from app.security.ssrf import (
    REMOTE_AGENT_URL_POLICY,
    GlobalOnlyPolicy,
    IPAddress,
    SafeClientConfig,
    UrlPolicy,
    validate_url,
)
from app.settings import Settings


class LoopbackTestPolicy(GlobalOnlyPolicy):
    def __init__(self, port: int) -> None:
        self.port = port

    def check(self, ip: IPAddress, port: int) -> None:
        if ip == ipaddress.ip_address("127.0.0.1") and port == self.port:
            return
        super().check(ip, port)


def local_url_policy(port: int) -> UrlPolicy:
    return UrlPolicy(allowed_schemes=frozenset({"http"}), allowed_ports=frozenset({port}))


class FakeResolver:
    """Maps hostnames to scripted answers. A list of lists scripts successive lookups (rebinding)."""

    def __init__(self, table: dict[str, list[str] | list[list[str]]]) -> None:
        self.table = table
        self.calls: list[str] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        entry = self.table.get(host)
        if entry is None:
            return []
        if entry and isinstance(entry[0], list):
            n = sum(1 for h in self.calls if h == host) - 1
            scripted = entry[min(n, len(entry) - 1)]
            assert isinstance(scripted, list)
            return list(scripted)
        return list(entry)  # type: ignore[arg-type]


@dataclass
class Reply:
    status: int = 200
    headers: dict[str, str] = field(default_factory=lambda: {"Content-Type": "text/html; charset=utf-8"})
    body: bytes = b""
    delay_s: float = 0.0
    # stream ``body`` repeatedly this many times without a content-length (oversize simulation)
    repeat: int = 1


Handler = Callable[[str, dict[str, str]], Reply | Awaitable[Reply]]


class TinyServer:
    """Minimal asyncio HTTP/1.1 server for fixtures (no third-party dependency, records every hit)."""

    def __init__(self, routes: dict[str, Reply | Handler]) -> None:
        self.routes = routes
        self.hits: list[tuple[str, dict[str, str]]] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> TinyServer:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()

    def url(self, host: str, path: str = "/") -> str:
        return f"http://{host}:{self.port}{path}"

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode("latin-1").strip()
            if not request_line:
                return
            _method, target, _ = request_line.split(" ", 2)
            headers: dict[str, str] = {}
            while True:
                line = (await reader.readline()).decode("latin-1").strip()
                if not line:
                    break
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
            self.hits.append((target, headers))
            path = target.split("?", 1)[0]
            route = self.routes.get(path)
            if route is None:
                reply = Reply(status=404, body=b"not found")
            elif isinstance(route, Reply):
                reply = route
            else:
                result = route(target, headers)
                reply = await result if asyncio.iscoroutine(result) else result  # type: ignore[assignment]
            if reply.delay_s:
                await asyncio.sleep(reply.delay_s)
            head = [f"HTTP/1.1 {reply.status} X"]
            hdrs = dict(reply.headers)
            if reply.repeat == 1:
                hdrs["Content-Length"] = str(len(reply.body))
            hdrs["Connection"] = "close"
            head += [f"{k}: {v}" for k, v in hdrs.items()]
            writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))
            for _ in range(reply.repeat):
                writer.write(reply.body)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError):
                await writer.wait_closed()


def gzip_bomb(decompressed_size: int) -> bytes:
    return gzip.compress(b"\0" * decompressed_size, compresslevel=9)


@contextlib.asynccontextmanager
async def serve_app(app: object) -> AsyncIterator[int]:
    """Run an ASGI app on a real loopback socket (uvicorn) so OUR outbound clients can be tested end-to-end."""
    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")  # type: ignore[arg-type]
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(500):
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started, "test server did not start"
        yield server.servers[0].sockets[0].getsockname()[1]
    finally:
        server.should_exit = True
        await task


def loopback_client_config(port: int, hosts: list[str]) -> SafeClientConfig:
    """SafeClientConfig that reaches ONLY 127.0.0.1:<port> for the given fixture hostnames (plain http)."""
    return SafeClientConfig(
        url_policy=UrlPolicy(
            allowed_schemes=frozenset({"http"}),
            allowed_ports=frozenset({port}),
            exempt_hosts=frozenset(hosts),
        ),
        address_policy=LoopbackTestPolicy(port),
        resolver=FakeResolver({h: ["127.0.0.1"] for h in hosts}),
    )


class LoopbackRemoteHttp(RemoteHttp):
    """Test double for the network edge ONLY: ``https://<host>/x`` is served by the fixture at
    ``http://<host>:<port>/x``. URL policy, pinned DNS, caps and parsing are the production code paths."""

    def __init__(self, settings: Settings, port: int, hosts: list[str]) -> None:
        super().__init__(settings, loopback_client_config(port, hosts))
        self._port = port

    async def _request(self, method: str, url: str, **kwargs: object):  # type: ignore[no-untyped-def,override]
        validate_url(url, REMOTE_AGENT_URL_POLICY)  # the production policy still applies to the ORIGINAL url
        parts = urlsplit(url)
        return await super()._request(
            method, f"http://{parts.hostname}:{self._port}{parts.path or '/'}", **kwargs
        )  # type: ignore[arg-type]


@contextlib.asynccontextmanager
async def run_lifespan(app: object) -> AsyncIterator[None]:
    """Drive ASGI lifespan startup/shutdown in ONE background task (anyio task-group affinity)."""
    to_app: asyncio.Queue[dict[str, str]] = asyncio.Queue()
    started, stopped = asyncio.Event(), asyncio.Event()
    failure: list[str] = []

    async def receive() -> dict[str, str]:
        return await to_app.get()

    async def send(message: dict[str, str]) -> None:
        if message["type"].endswith("failed"):
            failure.append(message.get("message", "lifespan failed"))
        if message["type"].startswith("lifespan.startup"):
            started.set()
        elif message["type"].startswith("lifespan.shutdown"):
            stopped.set()

    task = asyncio.create_task(app({"type": "lifespan", "asgi": {"version": "3.0"}}, receive, send))  # type: ignore[operator]
    await to_app.put({"type": "lifespan.startup"})
    await asyncio.wait({asyncio.create_task(started.wait()), task}, return_when=asyncio.FIRST_COMPLETED)
    assert started.is_set() and not failure, failure or "lifespan task exited early"
    try:
        yield
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        await asyncio.wait({asyncio.create_task(stopped.wait()), task}, return_when=asyncio.FIRST_COMPLETED)
        await task


class InProcessRemoteHttp(RemoteHttp):
    """Network-edge double for full-app tests: ``https://<our host>/…`` is answered by the ASGI app in-process.
    The production URL policy is still applied to the requested URL first."""

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.app: object = None
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        max_bytes: int,  # type: ignore[override]
        accept: tuple[str, ...],
        expect_body: bool = True,
    ):  # type: ignore[no-untyped-def]
        import httpx

        from app.protocols.remote_http import RemoteProtocolError
        from app.security.breakers import Feature, require

        require(self._settings, Feature.REMOTE_AGENT_CALLS)
        validate_url(url, REMOTE_AGENT_URL_POLICY)
        self.requests.append((method, url, dict(headers)))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app, client=("198.51.100.7", 4444))
        ) as client:  # type: ignore[arg-type]
            response = await client.request(method, url, headers=headers, content=body)
        if not expect_body and response.status_code in (200, 202, 204):
            return response, b""
        if response.status_code != 200:
            raise RemoteProtocolError("http_status", f"HTTP {response.status_code}")
        if response.headers.get("content-type", "").split(";")[0].strip().lower() not in accept:
            raise RemoteProtocolError("content_type_not_allowed")
        if len(response.content) > max_bytes:
            raise RemoteProtocolError("response_too_large")
        return response, response.content
