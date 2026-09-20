#!/usr/bin/env python3
"""Publish exact TXT records at Porkbun (the registrar/DNS host for BASE_DOMAIN).

GoDaddy ANS keys cannot write Porkbun DNS. Optional credentials live in secrets/porkbun.env
(chmod 600, gitignored):

    PORKBUN_API_KEY=...
    PORKBUN_SECRET_API_KEY=...
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PORKBUN = "https://api.porkbun.com/api/json/v3"


def load_porkbun_secrets(repo_root: Path) -> tuple[str, str]:
    env_path = repo_root / "secrets" / "porkbun.env"
    values: dict[str, str] = {}
    if env_path.is_file():
        for line in env_path.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    key = os.environ.get("PORKBUN_API_KEY") or values.get("PORKBUN_API_KEY", "")
    secret = os.environ.get("PORKBUN_SECRET_API_KEY") or values.get("PORKBUN_SECRET_API_KEY", "")
    return key, secret


def _call(path: str, key: str, secret: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    body = {"apikey": key, "secretapikey": secret, **(extra or {})}
    req = urllib.request.Request(  # noqa: S310 - fixed https:// origin, never a caller-supplied scheme
        f"{PORKBUN}{path}",
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310 - fixed HTTPS origin
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Porkbun HTTP {exc.code}: {raw}") from exc


def relative_name(fqdn: str, zone: str) -> str:
    host = fqdn.strip(".").lower()
    zone = zone.strip(".").lower()
    if host == zone:
        return ""
    suffix = f".{zone}"
    if not host.endswith(suffix):
        raise ValueError(f"{fqdn} is outside zone {zone}")
    return host[: -len(suffix)]


def upsert_txt(zone: str, fqdn: str, value: str, ttl: int, key: str, secret: str) -> str:
    name = relative_name(fqdn, zone)
    existing = _call(f"/dns/retrieveByNameType/{zone}/TXT/{name}", key, secret)
    records = existing.get("records") if isinstance(existing, dict) else None
    if isinstance(records, list):
        for record in records:
            if str(record.get("content", "")).strip('"') == value:
                return "exists"
    _call(
        f"/dns/create/{zone}",
        key,
        secret,
        extra={"name": name, "type": "TXT", "content": value, "ttl": str(max(600, ttl))},
    )
    return "created"


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: dns_txt.py <zone> <fqdn> <value> [ttl]", file=sys.stderr)
        return 2
    zone, fqdn, value = sys.argv[1], sys.argv[2], sys.argv[3]
    ttl = int(sys.argv[4]) if len(sys.argv) > 4 else 600
    repo = Path(__file__).resolve().parents[1]
    key, secret = load_porkbun_secrets(repo)
    if not key or not secret:
        print("Porkbun API credentials missing (secrets/porkbun.env). [WAITING_FOR_EXTERNAL_INPUT]")
        return 3
    print(upsert_txt(zone, fqdn, value, ttl, key, secret))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
