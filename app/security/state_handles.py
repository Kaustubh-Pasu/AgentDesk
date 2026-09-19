"""Workflow/state handles (e.g. "connect to candidate #2 of my last search").

The browser never sends a URL to connect to – it sends an opaque handle. The handle is:
- high entropy (256 bits), time-limited, single-purpose;
- bound SERVER-SIDE to the principal that created it. Possession alone is not authorization:
  presenting someone else's handle fails exactly like presenting a non-existent one;
- resolved to data that the SERVER stored (verified endpoint, protocol) – never to client-supplied data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from app.security.kv import KV

HANDLE_TTL_S = 600
_PREFIX = "agentdesk:handle:"


class HandleError(Exception):
    code = "handle_invalid"


def _key(handle: str) -> str:
    return _PREFIX + hashlib.sha256(handle.encode()).hexdigest()


def _principal_tag(principal: str) -> str:
    return hashlib.sha256(principal.encode()).hexdigest()


async def issue(
    kv: KV, *, principal: str, purpose: str, data: dict[str, Any], ttl_s: int = HANDLE_TTL_S
) -> str:
    handle = secrets.token_urlsafe(32)
    record = {"p": _principal_tag(principal), "u": purpose, "d": data}
    await kv.set_value(_key(handle), json.dumps(record), ttl_s)
    return handle


async def resolve(
    kv: KV, *, handle: str, principal: str, purpose: str, consume: bool = False
) -> dict[str, Any]:
    if (
        not isinstance(handle, str)
        or not (40 <= len(handle) <= 64)
        or not all(c.isalnum() or c in "-_" for c in handle)
    ):
        raise HandleError()
    raw = await kv.get_value(_key(handle))
    if raw is None:
        raise HandleError()
    try:
        record = json.loads(raw)
    except ValueError as exc:
        raise HandleError() from exc
    bound_ok = hmac.compare_digest(str(record.get("p", "")), _principal_tag(principal))
    purpose_ok = record.get("u") == purpose
    if not (bound_ok and purpose_ok):
        raise HandleError()  # same error as "not found": no oracle for other users' handles
    if consume:
        await kv.delete(_key(handle))
    data = record.get("d")
    if not isinstance(data, dict):
        raise HandleError()
    return data
