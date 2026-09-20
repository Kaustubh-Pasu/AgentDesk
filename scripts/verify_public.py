#!/usr/bin/env python3
"""External gate check for Gates 1–3 (and 4/5 when registered). Run it from a machine OUTSIDE the server.

    python scripts/verify_public.py --host desk.<BASE_DOMAIN> [--host demo.<BASE_DOMAIN>] [--json]

It uses the same hardened clients as the application (public DNS answers only, strict TLS, size/time caps): if this
passes, another agent on the internet can reach the endpoints too. Exit code 0 only if Gates 1 and 2 PASS for every host.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ans.client import AnsClient  # noqa: E402
from app.ans.evidence import build_proof  # noqa: E402
from app.ans.verifier import Verifier  # noqa: E402
from app.logging_config import configure_logging  # noqa: E402
from app.protocols.remote_http import RemoteHttp  # noqa: E402
from app.settings import Settings  # noqa: E402


async def run(hosts: list[str], as_json: bool, api_base: str) -> int:
    base_domain = hosts[0].split(".", 1)[1]
    # a secret-less, database-less settings object: this script needs no credential at all
    settings = Settings(_env_file=None, env="development", base_domain=base_domain, desk_host=f"desk.{base_domain}",  # type: ignore[call-arg]
                        demo_host=f"demo.{base_domain}", godaddy_api_base=api_base)
    configure_logging("ERROR")
    verifier = Verifier(settings, AnsClient(settings), RemoteHttp(settings), None)
    failed = False
    for host in hosts:
        probe = "about_agent_desk" if host == settings.desk_host else "get_hours"
        proof = build_proof(await verifier.verify(host, probe_tool=probe), settings)
        gates = {g["gate"]: g for g in proof["gates"]}
        failed |= gates[1]["status"] != "PASS" or gates[2]["status"] != "PASS"
        if as_json:
            print(json.dumps(proof, indent=2, default=str))
            continue
        print(f"\n== {host} ==  decision: {proof['decision']}   (gate wording assumes {host} is YOUR host under BASE_DOMAIN={base_domain})")
        for number in sorted(gates):
            print(f"  Gate {number} {gates[number]['status']:<10} {gates[number]['title']} — {gates[number]['detail']}")
        for check in proof["verification"]["checks"]:
            print(f"     [{check['status']:<10}] {check['label']}: {check['detail']}")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", action="append", required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--api-base", default="https://api.godaddy.com")
    args = parser.parse_args()
    return asyncio.run(run(args.host, args.json, args.api_base))


if __name__ == "__main__":
    raise SystemExit(main())
