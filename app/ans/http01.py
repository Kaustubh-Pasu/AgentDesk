"""Publish ACME HTTP-01 challenge files under ARTIFACTS_DIR (public tokens, never secrets)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from app.ans.client import RegistrationPending

_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_HTTP_PATH = re.compile(r"^/\.well-known/acme-challenge/([A-Za-z0-9_-]{1,128})$")


def http01_dir(artifacts: Path) -> Path:
    return artifacts / "acme-http01"


def write_http01_challenge(artifacts: Path, token: str, key_authorization: str, http_path: str) -> bool:
    if not _TOKEN.fullmatch(token) or not key_authorization:
        return False
    match = _HTTP_PATH.fullmatch(http_path)
    if match is None or match.group(1) != token:
        return False
    if len(key_authorization) > 300 or any(ch in key_authorization for ch in "\r\n\0"):
        return False
    directory = http01_dir(artifacts)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / token
    path.write_text(key_authorization, encoding="ascii")
    os.chmod(path, 0o644)
    return True


def read_http01_challenge(artifacts: Path, token: str) -> str | None:
    if not _TOKEN.fullmatch(token):
        return None
    path = http01_dir(artifacts) / token
    try:
        text = path.read_text(encoding="ascii")
    except OSError:
        return None
    if not text or any(ch in text for ch in "\r\n\0"):
        return None
    return text


def publish_http01_challenges(pending: RegistrationPending, artifacts: Path) -> int:
    published = 0
    for challenge in pending.all_challenges():
        kind = challenge.type.upper().replace("-", "_")
        if kind != "HTTP_01":
            continue
        if write_http01_challenge(
            artifacts,
            challenge.token,
            challenge.key_authorization or "",
            challenge.http_path or "",
        ):
            published += 1
    return published
