"""Outbound A2A client for REMOTE agents (read-only: fetch Agent Card, send one text message).

Hand-written on top of ``RemoteHttp`` instead of the SDK client so that every byte goes through the pinned
SSRF transport with hard size/time caps. The card is parsed as DATA through a bounded Pydantic model; nothing
in it is executed, and the only URL we will ever call from it is the JSON-RPC interface, which the verifier
additionally binds to the ANS-registered host before use.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.models.schemas import canonical_json, clean_text
from app.protocols.remote_http import RemoteHttp, RemoteProtocolError

MAX_CARD_BYTES = 256 * 1024
MAX_REPLY_CHARS = 4000
_METHOD_NOT_FOUND = -32601
_VERSION_NOT_SUPPORTED = -32009


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class _Interface(_Lenient):
    url: str = Field(max_length=2048)
    protocol_binding: str = Field("", alias="protocolBinding", max_length=40)
    transport: str = Field("", max_length=40)  # 0.3 additionalInterfaces
    protocol_version: str = Field("", alias="protocolVersion", max_length=20)


class _Skill(_Lenient):
    id: str = Field(max_length=128)
    name: str = Field("", max_length=200)
    description: str = Field("", max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=50)


class _Card(_Lenient):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=4000)
    version: str = Field("", max_length=40)
    protocol_version: str = Field("", alias="protocolVersion", max_length=20)
    url: str = Field("", max_length=2048)  # 0.3
    preferred_transport: str = Field("", alias="preferredTransport", max_length=40)
    supported_interfaces: list[_Interface] = Field(
        default_factory=list, alias="supportedInterfaces", max_length=10
    )
    additional_interfaces: list[_Interface] = Field(
        default_factory=list, alias="additionalInterfaces", max_length=10
    )
    skills: list[_Skill] = Field(default_factory=list, max_length=200)
    signatures: list[dict[str, Any]] = Field(default_factory=list, max_length=10)


@dataclass(frozen=True)
class FetchedCard:
    card_url: str
    sha256: str  # canonical-JSON hash (stable across key order/whitespace) used for drift monitoring
    raw_sha256: str
    name: str
    description: str
    version: str
    skills: tuple[str, ...]
    rpc_url: str
    rpc_protocol_version: str
    protocol_versions: tuple[str, ...]
    signed: bool
    #: The card exactly as served, kept so a signature can be checked against the bytes it covers. Data only:
    #: nothing here is ever executed, and no key or certificate inside it is used as a trust input.
    document: dict[str, Any] = field(default_factory=dict)


def _pick_jsonrpc(card: _Card) -> tuple[str, str]:
    for iface in card.supported_interfaces:
        if iface.protocol_binding.upper().replace("-", "") == "JSONRPC":
            return iface.url, iface.protocol_version or card.protocol_version or "1.0"
    if card.url and card.preferred_transport.upper().replace("-", "") in ("", "JSONRPC"):
        return card.url, card.protocol_version or "0.3"
    for iface in card.additional_interfaces:
        if iface.transport.upper().replace("-", "") == "JSONRPC":
            return iface.url, card.protocol_version or "0.3"
    raise RemoteProtocolError("card_invalid", "card declares no JSON-RPC interface")


def parse_agent_card(data: dict[str, Any], raw: bytes, card_url: str) -> FetchedCard:
    try:
        card = _Card.model_validate(data)
    except ValidationError as exc:
        raise RemoteProtocolError("card_invalid", f"{exc.error_count()} schema violation(s)") from exc
    rpc_url, rpc_version = _pick_jsonrpc(card)
    versions = {card.protocol_version, *(i.protocol_version for i in card.supported_interfaces)} - {""}
    return FetchedCard(
        card_url=card_url,
        sha256=hashlib.sha256(canonical_json(data).encode()).hexdigest(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        name=clean_text(card.name),
        description=clean_text(card.description)[:600],
        version=clean_text(card.version),
        skills=tuple(clean_text(s.id) for s in card.skills),
        rpc_url=rpc_url,
        rpc_protocol_version=rpc_version,
        protocol_versions=tuple(sorted(versions)),
        signed=bool(card.signatures),
        document=data,
    )


def _collect_text(node: Any, out: list[str], depth: int = 0) -> None:
    """Pull text parts out of a Message / Task in either wire format. Bounded depth; data only."""
    if depth > 6 or len(out) > 50:
        return
    if isinstance(node, dict):
        parts = node.get("parts")
        if isinstance(parts, list):
            for part in parts[:50]:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    out.append(part["text"])
        for key in ("message", "task", "status", "artifacts"):
            if key in node:
                _collect_text(node[key], out, depth + 1)
    elif isinstance(node, list):
        for item in node[:20]:
            _collect_text(item, out, depth + 1)


class A2AClient:
    def __init__(self, http: RemoteHttp) -> None:
        self._http = http

    async def fetch_card(self, card_url: str) -> FetchedCard:
        data, raw = await self._http.get_json(card_url, max_bytes=MAX_CARD_BYTES)
        return parse_agent_card(data, raw, card_url)

    async def _send(self, rpc_url: str, text: str, modern: bool) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        if modern:
            method, headers = "SendMessage", {"A2A-Version": "1.0"}
            message: dict[str, Any] = {
                "messageId": message_id,
                "role": "ROLE_USER",
                "parts": [{"text": text}],
            }
        else:
            method, headers = "message/send", {}
            message = {
                "kind": "message",
                "messageId": message_id,
                "role": "user",
                "parts": [{"kind": "text", "text": text}],
            }
        payload = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": {"message": message},
        }
        data, _ = await self._http.post_jsonrpc(rpc_url, payload, headers=headers)
        assert data is not None
        return data

    async def send_text(self, rpc_url: str, text: str, *, protocol_version: str = "1.0") -> str:
        """Send ONE read-only text message. The reply is untrusted text: cleaned, bounded, never interpreted."""
        modern = protocol_version.strip().startswith("1")
        data = await self._send(rpc_url, text, modern)
        error = data.get("error")
        if isinstance(error, dict) and error.get("code") in (_METHOD_NOT_FOUND, _VERSION_NOT_SUPPORTED):
            data = await self._send(rpc_url, text, not modern)
            error = data.get("error")
        if error is not None:
            code = error.get("code") if isinstance(error, dict) else None
            raise RemoteProtocolError("remote_error", f"JSON-RPC error {code!r}"[:80])
        texts: list[str] = []
        _collect_text(data.get("result"), texts)
        reply = clean_text("\n".join(texts))[:MAX_REPLY_CHARS]
        if not reply:
            raise RemoteProtocolError("empty_reply", "remote agent returned no text")
        return reply
