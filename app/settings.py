"""Typed application settings.

All configuration comes from environment variables (or a local ``.env`` in development).
Secrets are ``SecretStr`` so they never appear in ``repr()``/logs by accident, and every
secret value is registered with the log-redaction filter at startup.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Env = Literal["development", "test", "production"]
ServiceRole = Literal["all", "desk", "runtime", "scraper", "controlplane"]
LLMProvider = Literal["anthropic", "openai", "gemini", "none"]

#: The PAT/API key is only ever sent to these exact origins (never to a user- or registry-supplied URL).
GODADDY_API_BASES = {
    "https://api.godaddy.com": "production",
    "https://api.ote-godaddy.com": "ote",
}

_PLACEHOLDER_SECRETS = {
    "",
    "changeme",
    "change-me",
    "...",
    "dev-insecure-session-secret",
    "dev-insecure-csrf-secret",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- environment / role -------------------------------------------------
    env: Env = "development"
    service_role: ServiceRole = "all"
    debug: bool = False
    log_level: str = "INFO"

    # --- domain (Gate 3) ----------------------------------------------------
    base_domain: str = "localhost"
    desk_host: str = ""
    demo_host: str = ""
    # Scheme used to build canonical origins. Production is always https.
    public_scheme: Literal["http", "https"] = "https"
    # Optional explicit port for local development origins (e.g. 8000). Never set in production.
    public_port: int | None = None

    # --- storage --------------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./var/agentdesk.db"
    redis_url: str = ""  # empty → in-process limiter (development/test only)

    # --- web security ---------------------------------------------------------
    session_secret: SecretStr = SecretStr("dev-insecure-session-secret")
    csrf_secret: SecretStr = SecretStr("dev-insecure-csrf-secret")
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    reauth_window_minutes: int = 10
    hsts_enabled: bool = True
    # CIDRs of reverse proxies whose X-Forwarded-For we trust (Caddy's private network).
    trusted_proxy_cidrs: str = "127.0.0.1/32,::1/128"
    login_progressive_delay: bool = True
    # Optional machine API (/api/v1/*) bearer tokens. Empty → token auth disabled (endpoints return 401).
    api_token_secret: SecretStr = SecretStr("")

    # --- GoDaddy / ANS (control plane only) -----------------------------------
    godaddy_pat: SecretStr = SecretStr("")
    # Official sources disagree on ANS auth (docs/research/ANS_API_NOTES.md §3): PAT Bearer vs classic sso-key.
    ans_auth_scheme: Literal["bearer", "sso-key"] = "bearer"
    godaddy_api_key: SecretStr = SecretStr("")
    godaddy_api_secret: SecretStr = SecretStr("")
    godaddy_api_base: str = "https://api.godaddy.com"
    ans_agent_version: str = "1.0.0"
    ans_request_timeout_s: float = 20.0
    # Official/pinned ANS trust anchors (PEM bundle path). Never sourced from a remote agent.
    ans_trust_anchor_path: str = ""
    # Optional comma-separated SHA-256 fingerprints (hex) the anchors must match.
    ans_trust_anchor_sha256: str = ""
    keys_dir: str = "./secrets/keys"
    artifacts_dir: str = "./artifacts"

    # --- service wiring -------------------------------------------------------
    scraper_url: str = ""  # empty → in-process fetcher (development/all role)
    controlplane_url: str = ""  # empty → in-process control plane (development/all role)
    controlplane_token: SecretStr = SecretStr("")

    # --- LLM ------------------------------------------------------------------
    llm_provider: LLMProvider = "none"
    anthropic_api_key: SecretStr = SecretStr("")
    openai_api_key: SecretStr = SecretStr("")
    gemini_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-haiku-4-5-20251001"
    openai_model: str = "gpt-4o-mini"
    gemini_model: str = "gemini-2.0-flash"
    llm_max_input_chars: int = 24_000
    llm_max_output_tokens: int = 2_000
    llm_timeout_s: float = 30.0
    llm_daily_calls_per_principal: int = 200
    llm_daily_calls_global: int = 2_000

    # --- circuit breakers -----------------------------------------------------
    disable_agent_creation: bool = False
    disable_external_fetch: bool = False
    disable_remote_agent_calls: bool = False
    disable_llm: bool = False
    read_only_mode: bool = False

    # --- limits ---------------------------------------------------------------
    rl_login_failures: int = 5
    rl_login_window_s: int = 900
    rl_anon_query_per_min: int = 30
    rl_protocol_per_min: int = 60
    rl_import_per_hour: int = 3
    rl_ans_search_per_min: int = 30
    rl_proof_per_min: int = 60
    max_request_body_bytes: int = 256 * 1024
    proof_cache_ttl_s: int = 60
    ans_search_cache_ttl_s: int = 30
    remote_max_response_bytes: int = 1024 * 1024
    remote_timeout_s: float = 15.0
    remote_max_hops: int = 2

    # --- bootstrap (one-time owner seeding via CLI; never hard-coded) ---------
    owner_email: str = ""
    owner_password: SecretStr = SecretStr("")

    # ------------------------------------------------------------------ validators
    @field_validator("base_domain", "desk_host", "demo_host")
    @classmethod
    def _normalize_host(cls, v: str) -> str:
        return v.strip().lower().rstrip(".")

    @field_validator("godaddy_api_base")
    @classmethod
    def _api_base(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if v not in GODADDY_API_BASES:
            raise ValueError("GODADDY_API_BASE must be one of: " + ", ".join(sorted(GODADDY_API_BASES)))
        return v

    @model_validator(mode="after")
    def _derive_and_check(self) -> Settings:
        if not self.desk_host:
            self.desk_host = f"desk.{self.base_domain}"
        if not self.demo_host:
            self.demo_host = f"demo.{self.base_domain}"
        for host in (self.desk_host, self.demo_host):
            if not host.endswith("." + self.base_domain):
                raise ValueError(f"{host!r} must be a child of BASE_DOMAIN {self.base_domain!r}")
        if self.desk_host == self.demo_host:
            raise ValueError("DESK_HOST and DEMO_HOST must differ")
        _ = self.trusted_proxy_networks  # validate CIDRs early (raises ValueError on bad input)
        if self.env == "production":
            self._check_production()
        return self

    def _check_production(self) -> None:
        problems: list[str] = []
        if self.debug:
            problems.append("DEBUG must be false in production")
        if self.public_scheme != "https":
            problems.append("PUBLIC_SCHEME must be https in production")
        if self.public_port is not None:
            problems.append("PUBLIC_PORT must be unset in production")
        if self.base_domain in {"localhost", "example.com", "example.test"}:
            problems.append("BASE_DOMAIN must be your real owned domain in production")
        for name in ("session_secret", "csrf_secret"):
            value = getattr(self, name).get_secret_value()
            if value in _PLACEHOLDER_SECRETS or len(value) < 32:
                problems.append(f"{name.upper()} must be a random value of at least 32 characters")
        if self.session_secret.get_secret_value() == self.csrf_secret.get_secret_value():
            problems.append("SESSION_SECRET and CSRF_SECRET must differ")
        if self.service_role in {"all", "desk", "runtime", "controlplane"} and self.database_url.startswith(
            "sqlite"
        ):
            problems.append("DATABASE_URL must be PostgreSQL in production")
        if self.service_role in {"all", "desk", "runtime"} and not self.redis_url:
            problems.append("REDIS_URL is required in production")
        if self.service_role == "desk" and not self.controlplane_token.get_secret_value():
            problems.append("CONTROLPLANE_TOKEN is required for the desk role in production")
        if problems:
            raise ValueError("Unsafe production configuration: " + "; ".join(problems))

    # ------------------------------------------------------------------ derived
    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def origin_for(self, host: str) -> str:
        """Canonical absolute origin for one of OUR hosts (never derived from request headers)."""
        port = f":{self.public_port}" if self.public_port else ""
        return f"{self.public_scheme}://{host}{port}"

    @property
    def desk_origin(self) -> str:
        return self.origin_for(self.desk_host)

    @property
    def trusted_proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        nets = []
        for part in self.trusted_proxy_cidrs.split(","):
            part = part.strip()
            if part:
                nets.append(ipaddress.ip_network(part, strict=False))
        return nets

    @property
    def ans_environment(self) -> str:
        return GODADDY_API_BASES[self.godaddy_api_base]

    @property
    def transparency_log_base(self) -> str:
        """Official ANS Transparency Log origin for the configured environment (fixed; never from remote data)."""
        if self.ans_environment == "production":
            return "https://transparency.ans.godaddy.com"
        return "https://transparency.ans.ote-godaddy.com"

    @property
    def ans_credential_configured(self) -> bool:
        if self.ans_auth_scheme == "bearer":
            return bool(self.godaddy_pat.get_secret_value())
        return bool(self.godaddy_api_key.get_secret_value() and self.godaddy_api_secret.get_secret_value())

    @property
    def keys_path(self) -> Path:
        return Path(self.keys_dir)

    @property
    def artifacts_path(self) -> Path:
        return Path(self.artifacts_dir)

    @property
    def trust_anchor_fingerprints(self) -> set[str]:
        return {
            p.strip().lower().replace(":", "") for p in self.ans_trust_anchor_sha256.split(",") if p.strip()
        }

    def secret_values(self) -> list[str]:
        """Every configured secret value, for the log-redaction filter. Never log this list."""
        out: list[str] = []
        for name, field in type(self).model_fields.items():
            if field.annotation is SecretStr:
                value = getattr(self, name).get_secret_value()
                if value and len(value) >= 8:
                    out.append(value)
        return out


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


__all__ = ["Settings", "get_settings", "reset_settings_cache"]
