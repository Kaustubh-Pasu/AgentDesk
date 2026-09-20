"""Shared outbound HTTP for REMOTE (untrusted) agents: pinned SSRF transport, hard caps, no credentials.

Every request made here:
- goes through ``PinnedTransport`` (URL policy + validated/pinned DNS + strict TLS, no proxies);
- carries NO Authorization/Cookie header of ours — an incoming caller token can never be relayed because
  this module has no parameter through which one could be passed;
- has connect/read/total timeouts and a decoded-size cap;
- never follows redirects, except ONE same-origin 307/308 (needed for ``/mcp`` → ``/mcp/``), which is
  re-validated by the transport like any other request.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from typing import Any

import httpx

from app.security.breakers import Feature, require
from app.security.ssrf import (
    REMOTE_AGENT_URL_POLICY,
    SafeClientConfig,
    SSRFBlocked,
    build_safe_client,
    read_capped,
    validate_url,
)
from app.settings import Settings

JSON_TYPES = ("application/json", "application/a2a-agent-card+json")
SSE_TYPE = "text/event-stream"


class RemoteProtocolError(Exception):
    """Safe, user-displayable failure talking to a remote agent. ``code`` is stable; ``detail`` is bounded."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail[:200]


def parse_json_object(raw: bytes) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RemoteProtocolError("invalid_json", "response is not valid UTF-8 JSON") from exc
    if not isinstance(data, dict):
        raise RemoteProtocolError("invalid_json", "response is not a JSON object")
    return data


def _media_type(response: httpx.Response) -> str:
    return response.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _last_sse_json(raw: bytes) -> dict[str, Any]:
    """Return the last JSON-RPC *response* object carried in an SSE body (already size-capped)."""
    found: dict[str, Any] | None = None
    for block in raw.decode("utf-8", errors="replace").replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip() for line in block.split("\n") if line.startswith("data:"))
        if not data:
            continue
        try:
            obj = json.loads(data)
        except (ValueError, RecursionError):
            continue
        if isinstance(obj, dict) and ("result" in obj or "error" in obj):
            found = obj
    if found is None:
        raise RemoteProtocolError("invalid_response", "no JSON-RPC response in event stream")
    return found


class RemoteHttp:
    def __init__(self, settings: Settings, client_config: SafeClientConfig | None = None) -> None:
        self._settings = settings
        base = client_config or SafeClientConfig(url_policy=REMOTE_AGENT_URL_POLICY)
        self._config = replace(
            base,
            connect_timeout_s=min(base.connect_timeout_s, settings.remote_timeout_s),
            read_timeout_s=settings.remote_timeout_s,
            total_timeout_s=settings.remote_timeout_s,
        )

    @property
    def max_bytes(self) -> int:
        return self._settings.remote_max_response_bytes

    def check_url(self, url: str) -> str:
        """Validate against the remote-agent URL policy; returns the canonical URL."""
        return validate_url(url, self._config.url_policy).url

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        max_bytes: int,
        accept: tuple[str, ...],
        expect_body: bool = True,
    ) -> tuple[httpx.Response, bytes]:
        require(self._settings, Feature.REMOTE_AGENT_CALLS)
        origin = validate_url(url, self._config.url_policy).origin
        try:
            async with (
                asyncio.timeout(self._settings.remote_timeout_s),
                build_safe_client(self._config) as client,
            ):
                for _hop in range(2):
                    async with client.stream(method, url, headers=headers, content=body) as response:
                        if response.status_code in (307, 308) and _hop == 0:
                            target = str(response.url.join(response.headers.get("location", "")))
                            if validate_url(target, self._config.url_policy).origin != origin:
                                raise RemoteProtocolError("redirect_not_allowed", "cross-origin redirect")
                            url = target
                            continue
                        if response.is_redirect:
                            raise RemoteProtocolError("redirect_not_allowed", f"HTTP {response.status_code}")
                        if not expect_body and response.status_code in (200, 202, 204):
                            return response, b""  # notification: the body (if any) is ignored, never read
                        if response.status_code != 200:
                            raise RemoteProtocolError("http_status", f"HTTP {response.status_code}")
                        if _media_type(response) not in accept:
                            raise RemoteProtocolError("content_type_not_allowed", _media_type(response)[:60])
                        return response, await read_capped(response, max_bytes)
                raise RemoteProtocolError("redirect_not_allowed", "too many redirects")
        except SSRFBlocked:
            raise
        except TimeoutError as exc:
            raise RemoteProtocolError("timeout", "remote agent did not answer in time") from exc
        except httpx.HTTPError as exc:
            raise RemoteProtocolError("unreachable", type(exc).__name__) from exc

    async def get_json(self, url: str, *, max_bytes: int | None = None) -> tuple[dict[str, Any], bytes]:
        _, raw = await self._request(
            "GET",
            url,
            headers={"Accept": ", ".join(JSON_TYPES)},
            body=None,
            max_bytes=max_bytes or self.max_bytes,
            accept=JSON_TYPES,
        )
        return parse_json_object(raw), raw

    async def post_jsonrpc(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        allow_sse: bool = False,
    ) -> tuple[dict[str, Any] | None, httpx.Headers]:
        """POST one JSON-RPC message. Returns (response object or None for an accepted notification, headers)."""
        send_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream" if allow_sse else "application/json",
            **(headers or {}),
        }
        accept = (*JSON_TYPES, SSE_TYPE) if allow_sse else JSON_TYPES
        response, raw = await self._request(
            "POST",
            url,
            headers=send_headers,
            body=json.dumps(payload).encode(),
            max_bytes=self.max_bytes,
            accept=accept,
            expect_body="id" in payload,
        )
        if "id" not in payload:
            return None, response.headers
        data = _last_sse_json(raw) if _media_type(response) == SSE_TYPE else parse_json_object(raw)
        if data.get("jsonrpc") != "2.0" or ("result" not in data and "error" not in data):
            raise RemoteProtocolError("invalid_response", "not a JSON-RPC 2.0 response")
        if "id" in payload and data.get("id") != payload["id"]:
            raise RemoteProtocolError("invalid_response", "JSON-RPC id mismatch")
        return data, response.headers
