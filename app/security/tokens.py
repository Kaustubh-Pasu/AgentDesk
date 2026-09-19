"""Bearer tokens for the optional machine API (``/api/v1/*``). Verified with PyJWT – no hand-rolled crypto.

Rules enforced on EVERY request:
- fixed algorithm allow-list (HS256 with OUR key) – ``none``/unknown algorithms and unknown keys are refused;
- ``iss``, ``aud``, ``exp``, ``iat``, ``sub``, ``jti`` are all required;
- ``aud`` must equal THIS service's canonical origin (a token minted for another audience is refused);
- per-operation scope check; wildcard-style scopes (``*``, ``all``, ``full-access`` …) are never honoured;
- schema version allow-list (``ver``): superseded/unknown formats are refused, no lenient fallback;
- any parser/signature error → one uniform ``invalid_token`` failure, never a 500.

Inbound bearer tokens are NEVER forwarded to ANS, to remote agents, or to the LLM (no token passthrough).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from enum import StrEnum

import jwt

from app.settings import Settings

ALGORITHMS = ["HS256"]
TOKEN_VERSION = 1
ISSUER = "agentdesk"
MAX_TOKEN_LENGTH = 4096
MAX_LIFETIME_S = 24 * 3600


class Scope(StrEnum):
    TENANTS_READ = "tenants:read"
    FIND_EXECUTE = "find:execute"


FORBIDDEN_SCOPES = frozenset({"*", "all", "full-access", "full_access", "admin", "root", "superuser"})


class TokenError(Exception):
    def __init__(self, code: str = "invalid_token") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TokenPrincipal:
    subject: str
    scopes: frozenset[str]
    token_id: str


def _signing_key(settings: Settings) -> str:
    key = settings.api_token_secret.get_secret_value()
    if len(key) < 32:
        raise TokenError("token_auth_disabled")
    return key


def mint_token(
    settings: Settings, *, subject: str, scopes: list[Scope], ttl_s: int = 3600, audience: str | None = None
) -> str:
    """Used by the admin CLI only. Scopes are validated against the enum; lifetime is capped."""
    if not scopes:
        raise ValueError("at least one scope is required")
    ttl_s = max(60, min(ttl_s, MAX_LIFETIME_S))
    now = int(time.time())
    claims = {
        "ver": TOKEN_VERSION,
        "iss": ISSUER,
        "aud": audience or settings.desk_origin,
        "sub": subject,
        "scope": " ".join(sorted({Scope(s).value for s in scopes})),
        "iat": now,
        "nbf": now,
        "exp": now + ttl_s,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(claims, _signing_key(settings), algorithm="HS256")


def verify_token(settings: Settings, token: str, *, required_scope: Scope) -> TokenPrincipal:
    if not token or len(token) > MAX_TOKEN_LENGTH or token.count(".") != 2:
        raise TokenError()
    try:
        claims = jwt.decode(
            token,
            _signing_key(settings),
            algorithms=ALGORITHMS,
            audience=settings.desk_origin,
            issuer=ISSUER,
            leeway=30,
            options={"require": ["exp", "iat", "aud", "iss", "sub", "jti"], "verify_signature": True},
        )
    except TokenError:
        raise
    except Exception as exc:  # any PyJWT / parsing error → uniform failure, never a crash
        raise TokenError() from exc
    if claims.get("ver") != TOKEN_VERSION:
        raise TokenError("unsupported_token_version")
    if not isinstance(claims.get("sub"), str) or not isinstance(claims.get("scope"), str):
        raise TokenError()
    if claims["exp"] - claims["iat"] > MAX_LIFETIME_S + 60:
        raise TokenError()
    granted = frozenset(claims["scope"].split())
    if granted & FORBIDDEN_SCOPES:
        raise TokenError("forbidden_scope")
    valid = {s.value for s in Scope}
    if not granted or not granted <= valid:
        raise TokenError("unknown_scope")
    if required_scope.value not in granted:
        raise TokenError("insufficient_scope")
    return TokenPrincipal(subject=claims["sub"][:128], scopes=granted, token_id=str(claims["jti"])[:64])


def bearer_from_header(value: str | None) -> str | None:
    if not value:
        return None
    scheme, _, token = value.strip().partition(" ")
    if scheme.lower() != "bearer" or not token or " " in token.strip():
        return None
    return token.strip()
