"""Secret redaction + log-injection sanitisation.

Three independent layers, applied to every log record and audit metadata blob:

1. **Key-name redaction** – values under sensitive keys (``authorization``, ``cookie``, ``password`` …)
   are replaced wholesale.
2. **Exact-value redaction** – every configured secret value (PAT, LLM keys, session secrets …) is
   registered at startup and scrubbed wherever it appears, even inside other strings.
3. **Pattern redaction** – generic shapes of credentials (Bearer tokens, PEM private keys, JWTs,
   ``sk-``-style API keys, our own session cookie) are scrubbed even when the value is unknown.

Control characters (CR/LF etc.) are escaped so attacker-controlled values cannot forge log lines.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "[REDACTED]"

# A key is sensitive when one of its *words* (split on non-alphanumerics) is in this set …
_SENSITIVE_KEY_WORDS = {
    "authorization",
    "cookie",
    "cookies",
    "password",
    "passwd",
    "secret",
    "secrets",
    "token",
    "apikey",
    "privatekey",
    "pat",
    "csrf",
    "sessionid",
    "credential",
    "credentials",
    "prompt",
}
# … or when its normalised form contains one of these multi-word fragments.
_SENSITIVE_KEY_FRAGMENTS = ("api_key", "private_key", "session_id", "set_cookie", "secret", "password")
# keys that contain a sensitive word but are safe/useful to log
_SAFE_KEYS = {"token_count", "max_tokens", "session_count", "token_audience", "token_scopes"}
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\b(bearer|sso-key|basic)\s+[A-Za-z0-9._~+/=:-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"\b(sk|pk|rk|pat|ghp|gho|xox[abp])[-_][A-Za-z0-9_-]{16,}\b"),
    re.compile(r"(?i)(__Host-agentdesk_session|__Host-agentdesk_csrf)=[^;\s,]+"),
    re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)=([^&\s]+)"),
)

_CONTROL_CHARS = re.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f" + chr(0x2028) + chr(0x2029) + "]")

_lock = threading.Lock()
_exact_secrets: list[str] = []


def register_secrets(values: Iterable[str]) -> None:
    """Register exact secret values to scrub. Short values are ignored to avoid over-redaction."""
    with _lock:
        for value in values:
            if value and len(value) >= 8 and value not in _exact_secrets:
                _exact_secrets.append(value)
        _exact_secrets.sort(key=len, reverse=True)


def clear_registered_secrets() -> None:
    with _lock:
        _exact_secrets.clear()


def sanitize_log_text(value: str) -> str:
    """Neutralise CR/LF and other control characters (log-injection defence)."""
    value = value.replace("\r", "\\r").replace("\n", "\\n")
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", value)


def redact_text(value: str) -> str:
    with _lock:
        secrets = list(_exact_secrets)
    for secret in secrets:
        if secret in value:
            value = value.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        value = pattern.sub(REDACTED, value)
    return value


def clean_text(value: str, *, max_len: int = 4000) -> str:
    text = sanitize_log_text(redact_text(value))
    if len(text) > max_len:
        text = text[:max_len] + "…[truncated]"
    return text


def is_sensitive_key(key: str) -> bool:
    normalized = _NON_ALNUM.sub("_", key.lower()).strip("_")
    if normalized in _SAFE_KEYS:
        return False
    if any(fragment in normalized for fragment in _SENSITIVE_KEY_FRAGMENTS):
        return True
    return not _SENSITIVE_KEY_WORDS.isdisjoint(normalized.split("_"))


def redact_obj(obj: Any, *, _depth: int = 0) -> Any:
    """Recursively redact a JSON-like structure (used for log extras and audit metadata)."""
    if _depth > 6:
        return "[depth-limit]"
    if isinstance(obj, Mapping):
        out: dict[str, Any] = {}
        for key, value in list(obj.items())[:100]:
            key_s = clean_text(str(key), max_len=200)
            out[key_s] = REDACTED if is_sensitive_key(str(key)) else redact_obj(value, _depth=_depth + 1)
        return out
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [redact_obj(v, _depth=_depth + 1) for v in list(obj)[:100]]
    if isinstance(obj, (bytes, bytearray)):
        return f"[{len(obj)} bytes]"
    if isinstance(obj, str):
        return clean_text(obj)
    if isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    return clean_text(str(obj))
