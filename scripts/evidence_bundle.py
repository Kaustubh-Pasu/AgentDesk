#!/usr/bin/env python3
"""Write a redacted Gate-5 evidence bundle from LIVE checks (never from stored claims).

    python scripts/evidence_bundle.py --host desk.<BASE_DOMAIN> --host demo.<BASE_DOMAIN>

Output: artifacts/evidence-<host>-<timestamp>.json. The export aborts if anything secret-shaped is found in it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ans.client import AnsClient  # noqa: E402
from app.ans.evidence import SecretLeak, build_proof, write_evidence_bundle  # noqa: E402
from app.ans.verifier import Verifier  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.protocols.remote_http import RemoteHttp  # noqa: E402
from app.security.hosts import HostPolicyError, validate_agent_host  # noqa: E402
from app.settings import get_settings  # noqa: E402


async def run(hosts: list[str]) -> int:
    settings = get_settings()
    configure_logging("ERROR", settings.secret_values())
    verifier = Verifier(settings, AnsClient(settings), RemoteHttp(settings), None)
    code = 0
    for raw in hosts:
        try:
            host = validate_agent_host(raw, settings.base_domain)
        except HostPolicyError as exc:
            print(f"refused {raw}: {exc}", file=sys.stderr)
            code = 2
            continue
        probe = "about_agent_desk" if host == settings.desk_host else "get_hours"
        try:
            proof = build_proof(await verifier.verify(host, probe_tool=probe), settings)
            path = write_evidence_bundle(proof, settings.artifacts_path, name=f"evidence-{host}")
        except SecretLeak:
            print(f"{host}: export REFUSED — secret-shaped content detected", file=sys.stderr)
            code = 1
            continue
        summary = ", ".join(f"G{g['gate']}={g['status']}" for g in proof["gates"])
        print(f"{host}: {proof['decision']} ({summary}) → {path}")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", action="append", required=True)
    return asyncio.run(run(parser.parse_args().host))


if __name__ == "__main__":
    raise SystemExit(main())
