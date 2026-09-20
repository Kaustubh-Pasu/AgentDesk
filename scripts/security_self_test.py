#!/usr/bin/env python3
"""Security self-test: runs the REAL automated security tests and prints the spec §40 summary.

    uv run python scripts/security_self_test.py                          # local controls (no network needed)
    uv run python scripts/security_self_test.py --host desk.<BASE_DOMAIN>  # + live ANS evidence for a deployed host

A line is PASS only if every mapped test actually ran and passed in THIS invocation; a label with no executed test is
reported as FAIL (never silently skipped). The ANS EVIDENCE section is filled only from live checks; without --host it
says NOT RUN.
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CONTROLS: list[tuple[str, tuple[str, ...]]] = [
    (
        "HTTPS-only public surface",
        (
            "test_remote_agent_policy_is_https_443_only",
            "test_production_policy_rejects_bad_start_urls_without_any_request",
            "test_health_home_and_security_headers",
        ),
    ),
    ("Trusted-host enforcement", ("test_host_header_poisoning_rejected", "test_request_host_allowlist")),
    (
        "CSRF protection",
        ("test_csrf_missing_bad_and_cross_origin_rejected", "test_get_requests_never_change_state"),
    ),
    (
        "Cross-tenant authorization",
        ("test_cross_tenant_idor_and_mass_assignment", "test_cross_tenant_access_is_404_without_leak"),
    ),
    ("SSRF private IPv4 / IPv6", ("test_non_global_addresses_rejected", "test_localhost_forms_rejected")),
    ("SSRF metadata service", ("test_hostname_resolving_to_metadata_is_blocked",)),
    ("SSRF parser ambiguity / userinfo", ("test_ambiguous_or_disallowed_urls_rejected",)),
    (
        "Redirect-to-private blocked",
        (
            "test_redirect_to_private_address_blocked_by_pinned_dns",
            "test_redirect_to_metadata_address_blocked",
        ),
    ),
    (
        "DNS rebinding simulation blocked",
        (
            "test_dns_rebinding_second_answer_is_blocked_and_never_connected",
            "test_dns_rebinding_cannot_swap_the_address",
        ),
    ),
    (
        "Oversized body / decompression limits",
        ("test_hostile_start_pages_rejected", "test_read_capped_limits", "test_oversized_body_rejected"),
    ),
    (
        "Prompt-injection ingestion cannot call tools",
        ("test_prompt_injection_gains_nothing", "test_static_extraction_drops_active_and_hidden_content"),
    ),
    (
        "Malformed LLM JSON / forbidden capability rejected",
        (
            "test_malformed_or_privileged_model_output_rejected",
            "test_forbidden_or_unknown_capability_rejected",
        ),
    ),
    ("XSS payload encoded", ("test_create_flow_xss_inert_idempotent_and_registered",)),
    (
        "Mass assignment rejected",
        ("test_mass_assignment_rejected", "test_tenant_create_rejects_privileged_fields"),
    ),
    (
        "SQL / command / path injection are data only",
        (
            "test_injection_strings_in_identifiers_are_just_404",
            "test_duplicate_host_and_sql_strings_are_data",
            "test_keystore_never_builds_paths_from_untrusted_text",
            "test_agent_id_cannot_alter_the_path",
        ),
    ),
    ("CORS not open", ("test_cors_is_not_open",)),
    (
        "Session fixation / reuse after logout",
        ("test_session_fixation_is_not_possible", "test_login_logout_and_session_cookie_attributes"),
    ),
    (
        "Rate limits enforced",
        (
            "test_public_rate_limits",
            "test_generic_login_failure_and_rate_limit",
            "test_rate_limiter_enforces_and_isolates_principals",
        ),
    ),
    (
        "Remote agent endpoint safety",
        (
            "test_remote_private_endpoint_rejected_before_any_request",
            "test_remote_private_or_malformed_endpoint_rejected_by_production_policy",
        ),
    ),
    ("Malformed / oversized Agent Card rejected", ("test_malformed_or_oversized_agent_card_rejected",)),
    ("Endpoint mismatch rejected", ("test_endpoint_mismatches_rejected",)),
    (
        "Revoked / inactive candidate rejected",
        ("test_revoked_or_inactive_candidate_rejected", "test_search_detail_and_transparency_contradictions"),
    ),
    ("State handle bound to principal", ("test_state_handle_is_bound_to_principal_and_purpose",)),
    (
        "Token audience / scope enforcement",
        ("test_token_wrong_audience_rejected", "test_token_happy_path_and_scope_enforcement"),
    ),
    (
        "Replay / idempotency behavior",
        (
            "test_idempotency_blocks_duplicates_and_detects_payload_swap",
            "test_idempotency_concurrent_claims_have_exactly_one_winner",
        ),
    ),
    (
        "Corrupt signature / parser input fails safely",
        (
            "test_token_unknown_key_alg_none_and_corrupt_input_fail_closed",
            "test_a2a_malformed_input_fails_cleanly",
            "test_mcp_malformed_input_fails_cleanly",
        ),
    ),
    ("Card hash drift → audit + re-verification", ("test_card_drift_audits_and_forces_reverification",)),
    (
        "No seeded secret in logs / evidence",
        (
            "test_canary_secret_absent_from_logs",
            "test_canary_secret_never_reaches_logs",
            "test_secret_shaped_evidence_is_refused",
        ),
    ),
    (
        "Circuit breakers work",
        (
            "test_circuit_breaker_flags",
            "test_circuit_breakers_through_the_ui",
            "test_remote_calls_circuit_breaker",
        ),
    ),
    (
        "Unsupported transactions fail closed",
        ("test_a2a_transaction_requests_fail_closed", "test_transactions_fail_closed"),
    ),
    (
        "Trust anchor: remote-supplied roots never trusted",
        (
            "test_chain_verification_uses_only_provisioned_anchor",
            "test_identity_certificate_chain_and_binding",
        ),
    ),
]


def run_pytest() -> dict[str, list[str]]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={report}", "tests"],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=900,
        )
        outcomes: dict[str, list[str]] = {}
        if not report.exists():
            return outcomes
        for case in ET.parse(report).getroot().iter("testcase"):  # noqa: S314
            name = case.get("name", "").split("[", 1)[0]
            bad = any(child.tag in ("failure", "error") for child in case)
            skipped = any(child.tag == "skipped" for child in case)
            outcomes.setdefault(name, []).append("fail" if bad else "skip" if skipped else "pass")
        return outcomes


async def live_evidence(host: str) -> list[tuple[str, str, str]]:
    from app.ans.client import AnsClient
    from app.ans.verifier import Verifier
    from app.logging_config import configure_logging
    from app.protocols.remote_http import RemoteHttp
    from app.settings import get_settings

    settings = get_settings()
    configure_logging("ERROR", settings.secret_values())
    result = await Verifier(settings, AnsClient(settings), RemoteHttp(settings), None).verify(
        host, probe_tool="about_agent_desk" if host == settings.desk_host else "get_hours"
    )
    checks = {c.id: c for c in result.checks}

    def line(label: str, check_id: str) -> tuple[str, str, str]:
        check = checks.get(check_id)
        return (
            label,
            check.status if check else "INCOMPLETE",
            check.detail if check else "check did not run",
        )

    cert = result.identity_certificate
    return [
        line("agentHost exact match", "canonical_agent_host"),
        line("lifecycle ACTIVE", "ans_status_active"),
        (
            "identity certificate valid/bound",
            cert.binding_status if cert else "INCOMPLETE",
            cert.binding_reason if cert else "no certificate retrieved",
        ),
        (
            "identity chain to official trust anchor",
            cert.chain_status if cert else "INCOMPLETE",
            cert.chain_reason if cert else "no certificate retrieved",
        ),
        ("public TLS valid", result.tls.status, result.tls.detail),
        ("A2A card valid", result.a2a.status, result.a2a.detail),
        (
            "MCP round-trip valid",
            "PASS"
            if result.mcp.probe_ok
            else result.mcp.status
            if result.mcp.status != "PASS"
            else "INCOMPLETE",
            result.mcp.detail,
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", help="deployed agent host for the live ANS EVIDENCE section")
    args = parser.parse_args()
    outcomes = run_pytest()
    total = sum(len(v) for v in outcomes.values())
    failures = sum(o == "fail" for v in outcomes.values() for o in v)
    print("SECURITY SELF-TEST")
    exit_code = 0
    for label, tests in CONTROLS:
        results = [o for t in tests for o in outcomes.get(t, [])]
        missing = [t for t in tests if t not in outcomes]
        ok = bool(results) and not missing and all(o == "pass" for o in results)
        exit_code |= 0 if ok else 1
        note = (
            f"  ({len(results)} test case(s))"
            if ok
            else f"  ← {'missing: ' + ', '.join(missing) if missing else 'failing test(s)'}"
        )
        print(f"[{'PASS' if ok else 'FAIL'}] {label}{note}")
    print(
        f"\nfull suite: {total - failures}/{total} test cases passed"
        + ("" if total else "  (pytest produced no report!)")
    )
    exit_code |= 1 if failures or not total else 0
    print("\nANS EVIDENCE")
    if not args.host:
        print("[NOT RUN] pass --host <agent host> after deployment; nothing is assumed about live gates.")
    else:
        for label, status, detail in asyncio.run(live_evidence(args.host)):
            print(f"[{status}] {label} — {detail}")
            exit_code |= 0 if status == "PASS" else 2
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
