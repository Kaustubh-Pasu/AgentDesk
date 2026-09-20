#!/usr/bin/env python3
"""Provision the ANS trust anchor bundle for ANS_TRUST_ANCHOR_PATH.

Why an operator has to run this
    GoDaddy publishes no download URL, bundle or fingerprint for the ANS private CA (docs/research/
    ANS_API_NOTES.md §8). The only source that is not a remote agent is ``chainPEM`` from
    ``GET /v1/agents/{agentId}/certificates/identity`` — the authenticated certificate-management API, served
    by api.godaddy.com over the public WebPKI and answering only for agents this credential owns.

    So the anchor is provisioned the way the notes prescribe: fetch the chain for an agent WE registered,
    show the operator exactly what was found, write the self-signed root to a file, and print its SHA-256 so
    it can be pinned with ANS_TRUST_ANCHOR_SHA256. After that the verifier checks every chain against this
    file and nothing else. A root that arrives later in some remote agent's chain is still ignored.

    This is deliberately a one-time, human-reviewed step. Nothing in the running app fetches an anchor.

Usage
    uv run python deploy/ans_trust_anchor.py --host desk.agent-desk.us
    uv run python deploy/ans_trust_anchor.py --host desk.agent-desk.us --out artifacts/ans-trust-anchors.pem

Exit codes: 0 written, 2 nothing to write (no credential, no agent, no self-signed root in the chain).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from app.ans.certs import (  # noqa: E402
    CertError,
    fingerprint_sha256,
    load_certificates,
    summarize,
)
from app.ans.client import AnsApiError, AnsClient  # noqa: E402
from app.settings import get_settings  # noqa: E402

EXIT_OK = 0
EXIT_NOTHING = 2
# artifacts/ is already mounted into every role that verifies agents, and a public root CA belongs there
# rather than beside the credentials in secrets/.
DEFAULT_OUT = "artifacts/ans-trust-anchors.pem"


def say(message: str) -> None:
    print(message, flush=True)


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    client = AnsClient(settings)
    if not client.configured:
        say("No GoDaddy ANS credential is configured. The certificate API is authenticated; nothing to do.")
        return EXIT_NOTHING

    say(f"Environment: {client.environment} ({settings.godaddy_api_base})")
    try:
        agents = await client.find_my_agent(args.host, args.version)
        if not agents:
            say(f"No agent owned by this credential matches {args.host}. Register it first.")
            return EXIT_NOTHING
        certificates = await client.get_identity_certificates(agents[0].agent_id)
    except AnsApiError as exc:
        say(f"Certificate API error ({exc.code}). The API only serves agents this credential owns.")
        return EXIT_NOTHING
    if not certificates:
        say("The registry returned no identity certificate for this agent.")
        return EXIT_NOTHING

    newest = certificates[-1]
    if not newest.chain_pem:
        say("The certificate response carried no chainPEM, so there is no CA to provision.")
        return EXIT_NOTHING
    try:
        leaf = load_certificates(newest.certificate_pem, limit=1)[0]
        chain = load_certificates(newest.chain_pem)
    except CertError as exc:
        say(f"Unparseable certificate material from the registry ({exc.code}).")
        return EXIT_NOTHING

    say(f"\nLeaf      {summarize(leaf).subject}")
    say(f"  issuer  {summarize(leaf).issuer}")
    roots = []
    for cert in chain:
        kind = "ROOT (self-signed)" if cert.issuer == cert.subject else "intermediate"
        say(f"\n{kind}")
        say(f"  subject {cert.subject.rfc4514_string()}")
        say(f"  issuer  {cert.issuer.rfc4514_string()}")
        say(f"  sha256  {fingerprint_sha256(cert)}")
        say(f"  expires {cert.not_valid_after_utc.isoformat()}")
        if cert.issuer == cert.subject:
            roots.append(cert)

    if not roots:
        say("\nNo self-signed root in the chain: nothing to provision as an anchor.")
        return EXIT_NOTHING

    out = Path(args.out if args.out else REPO_ROOT / DEFAULT_OUT)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in roots))
    out.chmod(0o644)  # public certificate material: readable by the app user, writable only by the operator

    pins = ",".join(fingerprint_sha256(c) for c in roots)
    say(f"\nWrote {len(roots)} anchor(s) to {out}")
    say("\nSet these on the services that verify agents (desk / all):")
    say(f"  ANS_TRUST_ANCHOR_PATH={out}   (in the containers: /artifacts/{out.name})")
    say(f"  ANS_TRUST_ANCHOR_SHA256={pins}")
    say(
        "\nThe pin is what makes this safe to keep: if the file is ever swapped for a different CA, "
        "TrustAnchors.load refuses the bundle and the chain check goes back to INCOMPLETE."
    )
    return EXIT_OK


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="an agent host this credential owns")
    parser.add_argument("--version", default="", help="agent version (default: any)")
    parser.add_argument("--out", default="", help=f"output PEM bundle (default: {DEFAULT_OUT})")
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
