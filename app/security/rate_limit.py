"""Shared rate limiting on top of the KV abstraction (Redis in production).

Fixed-window counters keyed by ``<bucket>:<sha256(principal)>``. The Redis path is atomic (one Lua script).
``fail_closed`` decides what happens when the backend is unavailable: expensive / high-risk operations
(login, import, ANS search, remote calls) deny; cheap read-only ones allow.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.logging_config import get_logger
from app.security.kv import KV

log = get_logger(__name__)


@dataclass(frozen=True)
class RateResult:
    allowed: bool
    count: int
    limit: int
    retry_after_s: int


class RateLimitExceeded(Exception):
    def __init__(self, bucket: str, retry_after_s: int) -> None:
        super().__init__(f"rate limit exceeded for {bucket}")
        self.bucket = bucket
        self.retry_after_s = max(1, retry_after_s)


def _key(bucket: str, principal: str) -> str:
    digest = hashlib.sha256(principal.encode("utf-8", "replace")).hexdigest()[:32]
    return f"agentdesk:rl:{bucket}:{digest}"


class RateLimiter:
    def __init__(self, kv: KV) -> None:
        self.kv = kv

    async def hit(
        self,
        bucket: str,
        principal: str,
        *,
        limit: int,
        window_s: int,
        amount: int = 1,
        fail_closed: bool = True,
    ) -> RateResult:
        try:
            count, ttl = await self.kv.incr(_key(bucket, principal), window_s, amount)
        except Exception:
            log.error(
                "rate limiter backend unavailable", extra={"bucket": bucket, "fail_closed": fail_closed}
            )
            if fail_closed:
                return RateResult(False, limit + 1, limit, 30)
            return RateResult(True, 0, limit, 0)
        return RateResult(count <= limit, count, limit, ttl if count > limit else 0)

    async def enforce(
        self,
        bucket: str,
        principal: str,
        *,
        limit: int,
        window_s: int,
        amount: int = 1,
        fail_closed: bool = True,
    ) -> RateResult:
        result = await self.hit(
            bucket, principal, limit=limit, window_s=window_s, amount=amount, fail_closed=fail_closed
        )
        if not result.allowed:
            raise RateLimitExceeded(bucket, result.retry_after_s)
        return result

    async def peek(self, bucket: str, principal: str) -> int:
        try:
            return await self.kv.get_int(_key(bucket, principal))
        except Exception:
            return 0

    async def reset(self, bucket: str, principal: str) -> None:
        try:
            await self.kv.delete(_key(bucket, principal))
        except Exception:
            log.warning("rate limiter reset failed", extra={"bucket": bucket})

    async def acquire_once(self, bucket: str, principal: str, ttl_s: int) -> bool:
        """SET-NX single-flight marker. Fails closed (returns False) if the backend is down."""
        try:
            return await self.kv.set_nx(_key(bucket, principal), ttl_s)
        except Exception:
            log.error("single-flight backend unavailable", extra={"bucket": bucket})
            return False

    async def release(self, bucket: str, principal: str) -> None:
        await self.reset(bucket, principal)
