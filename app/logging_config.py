"""Structured JSON logging with correlation IDs and mandatory redaction."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

from app.security.redaction import clean_text, redact_obj, register_secrets

correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="-")

_STANDARD_ATTRS = set(logging.LogRecord("x", 0, "x", 0, "", (), None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}


class RedactionFilter(logging.Filter):
    """Scrubs the formatted message and all ``extra`` fields. Attached to every handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed log call must never crash the app
            message = str(record.msg)
        record.msg = clean_text(message)
        record.args = None
        for key, value in list(record.__dict__.items()):
            if key not in _STANDARD_ATTRS:
                record.__dict__[key] = redact_obj({key: value}).get(clean_text(key, max_len=200))
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = clean_text(formatted, max_len=8000)
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = clean_text(record.exc_text, max_len=8000)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "correlation_id": correlation_id_var.get(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_text:
            payload["exc"] = record.exc_text
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging(level: str = "INFO", secrets: list[str] | None = None) -> None:
    if secrets:
        register_secrets(secrets)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Route uvicorn/sqlalchemy/httpx through the same redacting handler.
    for name in (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "sqlalchemy",
        "httpx",
        "aiohttp",
        "mcp",
        "a2a",
    ):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
    # httpx logs full request URLs at INFO; keep them out unless debugging.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # uvicorn's access log duplicates ours and would bypass header policy.
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
