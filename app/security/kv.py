"""Tiny shared key/value abstraction: Redis in production, in-process for development/tests.

Used for rate-limit counters, single-flight locks, replay markers, state handles and short-lived caches.
Nothing secret is ever stored here.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Protocol

_LUA_INCR = """
local current = redis.call('INCRBY', KEYS[1], ARGV[2])
if current == tonumber(ARGV[2]) then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
  ttl = tonumber(ARGV[1])
end
return {current, ttl}
"""


class KV(Protocol):
    async def incr(self, key: str, window_s: int, amount: int = 1) -> tuple[int, int]:
        """Atomically add ``amount`` to a windowed counter → (count, seconds until the window resets)."""

    async def get_int(self, key: str) -> int: ...

    async def delete(self, key: str) -> None: ...

    async def set_nx(self, key: str, ttl_s: int, value: str = "1") -> bool:
        """Set only if absent (single-flight / replay marker)."""

    async def set_value(self, key: str, value: str, ttl_s: int) -> None: ...

    async def get_value(self, key: str) -> str | None: ...

    async def pop_value(self, key: str) -> str | None:
        """Atomically read-and-delete (one-time handles)."""

    async def close(self) -> None: ...


class MemoryKV:
    """Single-process backend. NOT shared across workers – development and tests only."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    def _live(self, key: str, now: float) -> str | None:
        item = self._data.get(key)
        if item is None:
            return None
        if item[1] <= now:
            self._data.pop(key, None)
            return None
        return item[0]

    def _purge(self, now: float) -> None:
        if len(self._data) > 50_000:
            for key in [k for k, (_, exp) in self._data.items() if exp <= now]:
                self._data.pop(key, None)

    async def incr(self, key: str, window_s: int, amount: int = 1) -> tuple[int, int]:
        now = time.monotonic()
        async with self._lock:
            self._purge(now)
            current = self._live(key, now)
            if current is None:
                count, expires = amount, now + window_s
            else:
                count, expires = int(current) + amount, self._data[key][1]
            self._data[key] = (str(count), expires)
            return count, max(1, int(expires - now))

    async def get_int(self, key: str) -> int:
        value = self._live(key, time.monotonic())
        return int(value) if value is not None else 0

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)

    async def set_nx(self, key: str, ttl_s: int, value: str = "1") -> bool:
        now = time.monotonic()
        async with self._lock:
            if self._live(key, now) is not None:
                return False
            self._data[key] = (value, now + ttl_s)
            return True

    async def set_value(self, key: str, value: str, ttl_s: int) -> None:
        now = time.monotonic()
        async with self._lock:
            self._purge(now)
            self._data[key] = (value, now + ttl_s)

    async def get_value(self, key: str) -> str | None:
        return self._live(key, time.monotonic())

    async def pop_value(self, key: str) -> str | None:
        async with self._lock:
            value = self._live(key, time.monotonic())
            self._data.pop(key, None)
            return value

    async def close(self) -> None:
        self._data.clear()


class RedisKV:
    def __init__(self, client: Any) -> None:
        self._redis = client
        self._incr = client.register_script(_LUA_INCR)

    async def incr(self, key: str, window_s: int, amount: int = 1) -> tuple[int, int]:
        count, ttl = await self._incr(keys=[key], args=[window_s, amount])
        return int(count), int(ttl)

    async def get_int(self, key: str) -> int:
        value = await self._redis.get(key)
        return int(value) if value else 0

    async def delete(self, key: str) -> None:
        await self._redis.delete(key)

    async def set_nx(self, key: str, ttl_s: int, value: str = "1") -> bool:
        return bool(await self._redis.set(key, value, nx=True, ex=ttl_s))

    async def set_value(self, key: str, value: str, ttl_s: int) -> None:
        await self._redis.set(key, value, ex=ttl_s)

    async def get_value(self, key: str) -> str | None:
        value = await self._redis.get(key)
        return None if value is None else str(value)

    async def pop_value(self, key: str) -> str | None:
        value = await self._redis.getdel(key)
        return None if value is None else str(value)

    async def close(self) -> None:
        await self._redis.aclose()


def build_kv(redis_url: str) -> KV:
    if not redis_url:
        return MemoryKV()
    import redis.asyncio as aioredis

    client = aioredis.from_url(
        redis_url, encoding="utf-8", decode_responses=True, socket_timeout=2.0, socket_connect_timeout=2.0
    )
    return RedisKV(client)
