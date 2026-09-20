#!/usr/bin/env python3
"""Generate deployment secrets and (optionally) pre-create ANS keys + CSRs.

    python scripts/generate_keys.py secrets                 # prints NEW random SESSION_SECRET / CSRF_SECRET / tokens ONCE, to your terminal
    python scripts/generate_keys.py csr --host demo.<BASE_DOMAIN> [--version 1.0.0]
                                                            # creates keys under KEYS_DIR (0600) and prints the PUBLIC CSRs only

Nothing is written to the repository. Private keys are never printed.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ans.certs import CertError, KeyStore  # noqa: E402
from app.settings import get_settings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("secrets")
    csr = sub.add_parser("csr")
    csr.add_argument("--host", required=True)
    csr.add_argument("--version", default="")
    args = parser.parse_args()
    if args.command == "secrets":
        if not sys.stdout.isatty():
            print("refusing to print secrets to a non-terminal (pipe/file/CI log)", file=sys.stderr)
            return 2
        for name in ("SESSION_SECRET", "CSRF_SECRET", "API_TOKEN_SECRET", "CONTROLPLANE_TOKEN", "POSTGRES_PASSWORD", "APP_DB_PASSWORD"):
            print(f"{name}={secrets.token_urlsafe(48)}")
        print("\n# paste into secrets/*.env (chmod 600). These values are not stored anywhere else.", file=sys.stderr)
        return 0
    settings = get_settings()
    try:
        bundle = KeyStore(settings.keys_path, settings.base_domain).csr_bundle(args.host, args.version or settings.ans_agent_version)
    except (CertError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"# keys stored under {settings.keys_path}/{args.host}/ (mode 0600). PUBLIC CSRs follow.\n")
    print("# identity CSR (CN + DNS SAN + ans:// URI SAN)\n" + bundle.identity_csr_pem)
    print("# server CSR (CN + DNS SAN)\n" + bundle.server_csr_pem)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
