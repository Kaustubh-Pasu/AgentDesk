"""Unprivileged LLM adapter.

The model is a pure text → text function: requests never declare tools, never carry our secrets other
than the provider key in the auth header, and go only to the fixed provider API host. Every call is
bounded (input chars, output tokens, wall clock) and counted against per-principal and global daily
budgets (denial-of-wallet control). ``LLM_PROVIDER=none`` or ``DISABLE_LLM=true`` → ``build_llm`` is None
and every caller uses its deterministic path.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from app.logging_config import get_logger
from app.security.breakers import Feature, is_enabled
from app.security.kv import KV
from app.settings import Settings

log = get_logger("agents.llm")

_DAY_S = 86_400


class LLMUnavailable(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LLMClient(Protocol):
    async def complete(
        self, *, system: str, user: str, principal: str, max_tokens: int | None = None
    ) -> str: ...


class HttpLLM:
    def __init__(
        self, settings: Settings, kv: KV, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._settings = settings
        self._kv = kv
        self._transport = transport

    async def _spend(self, principal: str) -> None:
        s = self._settings
        global_count, _ = await self._kv.incr("llm:budget:global", _DAY_S)
        if global_count > s.llm_daily_calls_global:
            raise LLMUnavailable("llm_budget_exhausted")
        count, _ = await self._kv.incr(f"llm:budget:p:{principal[:80]}", _DAY_S)
        if count > s.llm_daily_calls_per_principal:
            raise LLMUnavailable("llm_budget_exhausted")

    def _request(self, system: str, user: str, max_tokens: int) -> tuple[str, dict[str, str], dict[str, Any]]:
        s = self._settings
        if s.llm_provider == "anthropic":
            return (
                "https://api.anthropic.com/v1/messages",
                {"x-api-key": s.anthropic_api_key.get_secret_value(), "anthropic-version": "2023-06-01"},
                {
                    "model": s.anthropic_model,
                    "max_tokens": max_tokens,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
        if s.llm_provider == "openai":
            return (
                "https://api.openai.com/v1/chat/completions",
                {"Authorization": f"Bearer {s.openai_api_key.get_secret_value()}"},
                {
                    "model": s.openai_model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                },
            )
        if s.llm_provider == "gemini":
            return (
                f"https://generativelanguage.googleapis.com/v1beta/models/{s.gemini_model}:generateContent",
                {"x-goog-api-key": s.gemini_api_key.get_secret_value()},
                {
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"maxOutputTokens": max_tokens},
                },
            )
        raise LLMUnavailable("llm_disabled")

    @staticmethod
    def _text(provider: str, data: Any) -> str:
        try:
            if provider == "anthropic":
                return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
            if provider == "openai":
                return str(data["choices"][0]["message"]["content"] or "")
            return "".join(p.get("text", "") for p in data["candidates"][0]["content"]["parts"])
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMUnavailable("llm_bad_response") from exc

    async def complete(self, *, system: str, user: str, principal: str, max_tokens: int | None = None) -> str:
        s = self._settings
        if not is_enabled(s, Feature.LLM):
            raise LLMUnavailable("llm_disabled")
        await self._spend(principal)
        user = user[: s.llm_max_input_chars]
        limit = min(max_tokens or s.llm_max_output_tokens, s.llm_max_output_tokens)
        url, headers, body = self._request(system, user, limit)
        try:
            async with httpx.AsyncClient(
                timeout=s.llm_timeout_s, trust_env=False, follow_redirects=False, transport=self._transport
            ) as client:
                response = await client.post(url, headers=headers, json=body)
        except httpx.HTTPError as exc:
            raise LLMUnavailable("llm_unreachable") from exc
        if response.status_code != 200:
            log.warning("llm call failed", extra={"status": response.status_code, "provider": s.llm_provider})
            raise LLMUnavailable("llm_error_status")
        try:
            data = response.json()
        except ValueError as exc:
            raise LLMUnavailable("llm_bad_response") from exc
        return self._text(s.llm_provider, data)


def build_llm(settings: Settings, kv: KV) -> LLMClient | None:
    if settings.llm_provider == "none" or not is_enabled(settings, Feature.LLM):
        return None
    key = {
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
        "gemini": settings.gemini_api_key,
    }[settings.llm_provider].get_secret_value()
    if not key:
        log.warning("LLM provider configured without an API key; using deterministic mode")
        return None
    return HttpLLM(settings, kv)
