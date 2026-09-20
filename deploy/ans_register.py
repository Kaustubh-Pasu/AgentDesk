#!/usr/bin/env python3
"""Production go-live: register one of OUR agent hosts with GoDaddy ANS and drive it to ACTIVE.

This is an operator CLI, never a web endpoint. It is RESUMABLE: every run reads the live registry status and performs
the next step, stopping whenever a human DNS action is required.

    python deploy/ans_register.py --host desk.<BASE_DOMAIN>              # next step (register → verify-acme → verify-dns → certs)
    python deploy/ans_register.py --host demo.<BASE_DOMAIN> --status     # live status only, no changes
    python deploy/ans_register.py --host … --gddy-dns --zone <zone>      # also publish the exact TXT records with `gddy dns add`
                                                                          # (dry-run is shown first; you must confirm each record)

Guarantees
- The credential comes from the environment/secret file (GODADDY_PAT or GODADDY_API_KEY/SECRET). It is never printed,
  never written to artifacts, and only ever sent to the allow-listed GoDaddy API origin.
- Private keys are created with the OS CSPRNG under KEYS_DIR (0600) and never leave it.
- "ACTIVE" is printed/recorded only when GoDaddy's API reports ACTIVE in THIS run. Nothing is simulated.
- DNS: only records the registry returned for THIS host, at exact allow-listed names, TXT only, append-only
  (`gddy dns add`), after an explicit per-record confirmation. TLSA/HTTPS records cannot be created by gddy: they are
  printed for manual entry at your DNS host.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.agents.registry import AgentRegistry
from app.ans.certs import KeyStore, load_certificates, summarize
from app.ans.client import AnsApiError, AnsClient
from app.ans.evidence import assert_no_secrets, write_evidence_bundle
from app.ans.registration import RegistrationError, RegistrationFlow, RegistrationSnapshot
from app.ans.verifier import make_tls_probe
from app.logging_config import configure_logging
from app.models.db import Database
from app.protocols.a2a_client import A2AClient
from app.protocols.mcp_client import McpClient
from app.protocols.remote_http import RemoteHttp, RemoteProtocolError
from app.security.hosts import HostPolicyError, validate_agent_host
from app.security.redaction import redact_text
from app.security.ssrf import GlobalOnlyPolicy, SSRFBlocked, system_resolver
from app.settings import Settings, get_settings

EXIT_OK, EXIT_ACTION_REQUIRED, EXIT_FAILED = 0, 3, 1
PLACEHOLDER_DOMAINS = {"localhost", "example.com", "example.test", "example.org"}


def say(message: str) -> None:
    print(redact_text(message), flush=True)


def state_path(settings: Settings, host: str) -> Path:
    return settings.artifacts_path / f"ans-state-{host}.json"


def load_state(settings: Settings, host: str) -> dict[str, Any]:
    path = state_path(settings, host)
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(settings: Settings, snapshot: RegistrationSnapshot) -> None:
    settings.artifacts_path.mkdir(parents=True, exist_ok=True)
    text = json.dumps(snapshot.to_public_dict(), indent=2, sort_keys=True)
    assert_no_secrets(text, settings)
    state_path(settings, snapshot.agent_host).write_text(text)


# --------------------------------------------------------------------------- step 3: gddy (inspection only)
def gddy_report() -> None:
    gddy = shutil.which("gddy")
    if gddy is None:
        say(
            "gddy: not installed (optional). Install: curl -fsSL https://github.com/godaddy/cli/releases/latest/download/install.sh | bash"
        )
        return
    for args in (["--version"], ["env", "get"], ["auth", "status"]):
        try:  # argument ARRAYS of constants only; no shell; output passes through the secret redactor
            done = subprocess.run([gddy, *args], capture_output=True, text=True, timeout=20, check=False)
            say(
                f"gddy {' '.join(args)} → exit {done.returncode}: {(done.stdout or done.stderr).strip()[:400]}"
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            say(f"gddy {' '.join(args)} failed: {type(exc).__name__}")


def gddy_publish_txt(records: list[dict[str, Any]], zone: str, assume_yes: bool) -> None:
    gddy = shutil.which("gddy")
    if gddy is None:
        say("gddy is not installed; publish the records manually.")
        return
    for record in records:
        name = str(record["name"])
        if record["type"] != "TXT" or not name.endswith("." + zone):
            say(
                f"  skipped (not a TXT record inside zone {zone}; create it manually): {record['type']} {name}"
            )
            continue
        relative = name[: -len(zone) - 1]
        args = [
            gddy,
            "dns",
            "add",
            zone,
            "--type",
            "TXT",
            "--name",
            relative,
            "--data",
            str(record["value"]),
            "--ttl",
            "600",
        ]
        dry = subprocess.run([*args, "--dry-run"], capture_output=True, text=True, timeout=30, check=False)
        say(
            f"  dry-run: gddy dns add {zone} --type TXT --name {relative} --data <value> --ttl 600 → exit {dry.returncode} {dry.stdout.strip()[:300]}"
        )
        if dry.returncode != 0:
            say("  dry-run failed; not applying.")
            continue
        if (
            not assume_yes
            and input(f"  type the record name to CONFIRM creating TXT {name}: ").strip() != name
        ):
            say("  not confirmed; skipped.")
            continue
        done = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
        say(f"  applied → exit {done.returncode} {(done.stdout or done.stderr).strip()[:300]}")


# --------------------------------------------------------------------------- step 2: public reachability
async def check_public(settings: Settings, host: str) -> bool:
    ok = True
    tls = await make_tls_probe(GlobalOnlyPolicy(), system_resolver)(host)
    say(f"  TLS   {tls.status}: {tls.detail} {tls.version} leaf={tls.leaf_sha256[:16]}…")
    ok &= tls.status == "PASS"
    http = RemoteHttp(settings)
    try:
        card = await A2AClient(http).fetch_card(f"https://{host}/.well-known/agent-card.json")
        say(f"  A2A   PASS: card '{card.name}' skills={list(card.skills)} rpc={card.rpc_url}")
        ok &= card.rpc_url == f"https://{host}/a2a"
    except (RemoteProtocolError, SSRFBlocked) as exc:
        say(f"  A2A   FAIL: {exc.code}")
        ok = False
    try:
        session = await McpClient(http).connect(f"https://{host}/mcp")
        say(f"  MCP   PASS: {session.server_name} tools={[t.name for t in session.tools]}")
    except (RemoteProtocolError, SSRFBlocked) as exc:
        say(f"  MCP   FAIL: {exc.code}")
        ok = False
    return ok


def print_records(title: str, records: list[dict[str, Any]]) -> None:
    say(f"\n{title}")
    for r in records:
        flag = "" if r.get("required", True) else "   (optional)"
        say(
            f"  {r['type']:<5} {r['name']}  TTL {max(600, int(r.get('ttl') or 600))}{flag}\n        value: {r['value']}"
        )


async def collect_certificates(
    client: AnsClient, settings: Settings, snapshot: RegistrationSnapshot
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for kind, getter in (
        ("identity", client.get_identity_certificates),
        ("server", client.get_server_certificates),
    ):
        try:
            certs = await getter(snapshot.agent_id or "")
        except AnsApiError as exc:
            out[kind] = {"error": exc.code}
            continue
        if not certs:
            out[kind] = {"error": "none_issued_yet"}
            continue
        leaf = load_certificates(certs[-1].certificate_pem, limit=1)[
            0
        ]  # refuses anything containing a private key
        out[kind] = summarize(leaf).model_dump(mode="json")
        pem_path = settings.artifacts_path / f"{snapshot.agent_host}-{kind}-cert.pem"
        pem_path.write_text(certs[-1].certificate_pem)
        out[kind]["public_pem_file"] = pem_path.name
    return out


async def main_async(args: argparse.Namespace) -> int:
    settings = get_settings()
    configure_logging("WARNING", settings.secret_values())
    # 1. domain + host policy
    if settings.base_domain in PLACEHOLDER_DOMAINS:
        say(
            "BASE_DOMAIN is a placeholder. Set BASE_DOMAIN to the MLH domain you own. [WAITING_FOR_EXTERNAL_INPUT]"
        )
        return EXIT_FAILED
    try:
        host = validate_agent_host(args.host, settings.base_domain)
    except HostPolicyError as exc:
        say(f"refused: {exc}")
        return EXIT_FAILED
    db = Database(settings.database_url)
    agent = await AgentRegistry(db, settings, ttl_s=0).resolve(host)
    if agent is None:
        say(f"{host} is not a published agent in this deployment's database.")
        return EXIT_FAILED
    client = AnsClient(settings)
    say(
        f"Agent {host} v{agent.version} · ANS environment: {client.environment} ({settings.godaddy_api_base}) · auth scheme: {settings.ans_auth_scheme}"
    )
    if not client.configured:
        say(
            "No GoDaddy credential configured (GODADDY_PAT, or GODADDY_API_KEY + GODADDY_API_SECRET with ANS_AUTH_SCHEME=sso-key). [WAITING_FOR_EXTERNAL_INPUT]"
        )
        return EXIT_FAILED
    flow = RegistrationFlow(client, KeyStore(settings.keys_path, settings.base_domain), settings)
    state = load_state(settings, host)

    try:
        if args.status or state.get("agent_id"):
            if not state.get("agent_id"):
                found = await client.find_my_agent(host, agent.version)
                if not found:
                    say("No registration found for this host+version.")
                    return EXIT_OK if args.status else EXIT_FAILED
                state = {"agent_id": found[0].agent_id}
            snapshot = await flow.refresh(state["agent_id"], host, agent.version)
        else:
            if not args.skip_preflight:
                say("\n[2] Public HTTPS / A2A / MCP check (from this machine, through the public internet):")
                if not await check_public(settings, host):
                    say(
                        "Public endpoints are not healthy. Fix Gates 1–3 first; ANS validation would fail. Nothing was registered."
                    )
                    return EXIT_FAILED
            else:
                say("\n[2] Public preflight skipped (--skip-preflight: verified externally).")
            say("\n[3] gddy CLI:")
            gddy_report()
            say("\n[4–5] Generating/loading keys + CSRs and submitting POST /v1/agents/register …")
            snapshot = await flow.submit(agent)
        save_state(settings, snapshot)
        say(
            f"\nLive status from GoDaddy: {snapshot.status}   agentId={snapshot.agent_id}   {snapshot.ans_name}"
        )
        if args.status:
            return EXIT_OK

        if snapshot.status == "PENDING_VALIDATION":
            if snapshot.http01_ready and not args.verify:
                say(
                    "\n[7] HTTP-01 challenge is being served at "
                    f"https://{host}/.well-known/acme-challenge/… — calling verify-acme."
                )
            elif snapshot.acme_records and not args.verify:
                print_records(
                    "[7] Publish this ACME DNS-01 TXT record exactly, wait until it resolves publicly, then re-run with --verify:",
                    snapshot.acme_records,
                )
                if args.gddy_dns:
                    gddy_publish_txt(snapshot.acme_records, args.zone or settings.base_domain, args.yes)
                return EXIT_ACTION_REQUIRED
            say("\n[9] POST verify-acme …")
            snapshot = await flow.trigger_acme(snapshot.agent_id or "", host, agent.version)
            snapshot = await flow.poll_until(
                snapshot.agent_id or "",
                host,
                agent.version,
                until=frozenset({"PENDING_DNS", "ACTIVE"}),
                timeout_s=args.timeout,
            )
            save_state(settings, snapshot)
            say(f"Live status from GoDaddy: {snapshot.status}")
        if snapshot.status == "PENDING_DNS":
            if snapshot.dns_records and not args.verify_dns:
                print_records(
                    "Publish these ANS DNS records exactly (required ones at minimum), then re-run with --verify-dns:",
                    snapshot.dns_records,
                )
                if snapshot.rejected_records:
                    print_records(
                        "IGNORED (outside the exact-name policy for this host — do NOT create):",
                        snapshot.rejected_records,
                    )
                if args.gddy_dns:
                    gddy_publish_txt(snapshot.dns_records, args.zone or settings.base_domain, args.yes)
                return EXIT_ACTION_REQUIRED
            say("\n[9] POST verify-dns …")
            snapshot = await flow.trigger_dns(snapshot.agent_id or "", host, agent.version)
            snapshot = await flow.poll_until(
                snapshot.agent_id or "",
                host,
                agent.version,
                until=frozenset({"ACTIVE"}),
                timeout_s=args.timeout,
            )
            save_state(settings, snapshot)
            say(f"Live status from GoDaddy: {snapshot.status}")
        if snapshot.status != "ACTIVE":
            say(
                f"Not ACTIVE (status {snapshot.status}; next action: {snapshot.next_action}). Re-run this command later."
            )
            return EXIT_ACTION_REQUIRED if snapshot.status.startswith("PENDING") else EXIT_FAILED

        say("\n[11] Retrieving public identity/server certificates …")
        certificates = await collect_certificates(client, settings, snapshot)
        evidence = {
            "gate": 4,
            "observed": "GoDaddy ANS API reported ACTIVE during this run",
            "registration": snapshot.to_public_dict(),
            "api_base": settings.godaddy_api_base,
            "auth_scheme": settings.ans_auth_scheme,
            "certificates": certificates,
        }
        assert_no_secrets(json.dumps(evidence, default=str), settings)
        path = write_evidence_bundle(evidence, settings.artifacts_path, name=f"ans-active-{host}")
        say(f"[12] ACTIVE ✔  Redacted evidence written to {path}")
        say(
            f"     Public cross-checks:  curl -s {settings.godaddy_api_base}/v1/ans/registered-agents/{snapshot.agent_id}"
        )
        say(
            f"                           curl -s {settings.transparency_log_base}/v1/agents/{snapshot.agent_id}"
        )
        say(f"                           https://{host}/proof")
        return EXIT_OK
    except AnsApiError as exc:
        say(
            f"GoDaddy ANS API error: HTTP {exc.status} {exc.code} {exc.message} {json.dumps(exc.details)[:600] if exc.details else ''}"
        )
        if exc.status in (401, 403) or exc.code == "UNAUTHENTICATED_REDIRECT":
            say(
                "The credential was rejected. Official sources disagree on the ANS auth scheme: try ANS_AUTH_SCHEME=sso-key with an API key/secret, or a PAT with ANS access."
            )
        return EXIT_FAILED
    except RegistrationError as exc:
        say(f"Registration refused: {exc.code} — {exc}")
        return EXIT_FAILED
    finally:
        await db.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", required=True, help="agent FQDN (direct child of BASE_DOMAIN)")
    parser.add_argument(
        "--status", action="store_true", help="print the live registry status and exit (no changes)"
    )
    parser.add_argument(
        "--verify", action="store_true", help="the ACME TXT record is published: call verify-acme"
    )
    parser.add_argument(
        "--verify-dns", action="store_true", help="the ANS DNS records are published: call verify-dns"
    )
    parser.add_argument(
        "--gddy-dns",
        action="store_true",
        help="publish exact TXT records with `gddy dns add` (dry-run + confirmation)",
    )
    parser.add_argument("--zone", default="", help="DNS zone managed at GoDaddy (default: BASE_DOMAIN)")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the per-record confirmation prompt (still runs the dry-run first)",
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="skip local preflight check if public reachability was verified externally",
    )
    parser.add_argument("--timeout", type=float, default=600.0, help="seconds to poll for a status change")
    if os.environ.get("ENV") == "production" and os.geteuid() == 0:
        print("refusing to run as root", file=sys.stderr)
        return EXIT_FAILED
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
