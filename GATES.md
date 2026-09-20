# GATES.md — GoDaddy "Best Use of ANS" gate tracker

**Rule:** a gate is `PASS` only after the live evidence was actually observed and recorded here.
Nothing in this file is ever pre-filled, simulated, or inferred. Allowed states:
`NOT_STARTED` · `LOCAL_READY` (code + local tests done, nothing live observed) ·
`WAITING_FOR_EXTERNAL_INPUT` · `PASS` · `FAIL`.

_Last updated: 2026-09-19 — all mockable/testable work is complete; every live gate is blocked on the external inputs below._

| # | Gate | Live status | Local status | Blocking dependency |
|---|------|-------------|--------------|---------------------|
| 1 | Reachable agent endpoint (A2A + MCP) for Agent Desk **and** one generated business agent | `WAITING_FOR_EXTERNAL_INPUT` | `LOCAL_READY` — both protocols served for `desk.` and `demo.` hosts; verified in-process, over a real loopback socket with our own hardened clients, and under `uvicorn` | a public host + DNS (Gates 2/3) |
| 2 | Public HTTPS URL | `WAITING_FOR_EXTERNAL_INPUT` | `LOCAL_READY` — Caddyfile, hardened compose stack, firewall script written; **not executed** (no Docker/Caddy on the build machine; compose checked with a YAML parser only) | a public VPS + DNS `A` records |
| 3 | Owned MLH domain | `WAITING_FOR_EXTERNAL_INPUT` | `LOCAL_READY` — `BASE_DOMAIN` policy enforced everywhere; placeholder domains can never show Gate 3 as PASS | `BASE_DOMAIN` value (your MLH domain) |
| 4 | Production GoDaddy credential + `gddy` CLI flow → ANS status `ACTIVE` | `WAITING_FOR_EXTERNAL_INPUT` | `LOCAL_READY` — REST client, CSRs, state machine and the resumable go-live script tested end-to-end against an in-memory fake of the documented API. **No authenticated GoDaddy call has been made.** | production PAT / event credential + ability to create DNS records |
| 5 | Verification evidence the demo can show (`/proof`, `/api/proof`) | `WAITING_FOR_EXTERNAL_INPUT` | `LOCAL_READY` — 15-check verifier + redacted proof; the verifier has additionally been observed working against the **real** production ANS registry for a third-party agent (see evidence log) | Gates 1–4 live |

## What I need from you (only these; everything else is done)

1. `BASE_DOMAIN` — the MLH domain you own (Gate 3).
2. A public Linux host (VPS) IP, with DNS `A` records `desk.<BASE_DOMAIN>`, `demo.<BASE_DOMAIN>` (and `*.<BASE_DOMAIN>` for
   generated tenants) → that IP (Gate 2).
3. The production GoDaddy PAT / event credential, entered by YOU into `secrets/controlplane.env` (or `gddy auth login` /
   `gddy pat add --env prod`) — never pasted into chat (Gate 4). If the event issues a classic key+secret instead, set
   `ANS_AUTH_SCHEME=sso-key` with `GODADDY_API_KEY` / `GODADDY_API_SECRET`.
4. Ability to create DNS records for the agent hosts: one `_acme-challenge` TXT, then `_ans` / `_ans-badge` TXT (and TLSA/HTTPS
   if your DNS host supports them) (Gate 4).
5. The ANS trust anchor for `ANS_TRUST_ANCHOR_PATH`. GoDaddy publishes no bundle, so provision it once from the
   `chainPEM` of an agent you own: `uv run python deploy/ans_trust_anchor.py --host desk.$BASE_DOMAIN`. It prints the
   root and its SHA-256; set `ANS_TRUST_ANCHOR_PATH` + `ANS_TRUST_ANCHOR_SHA256` from that output. Skip it and the
   identity-chain check stays `INCOMPLETE` (by design) while every other check works.

## Exact next commands (in order)

```bash
# on the VPS, in the repository
sudo ./deploy/firewall.sh                                                     # Gate 2 hardening (--dry-run to preview)
python scripts/generate_keys.py secrets                                       # then fill secrets/{postgres,desk,controlplane}.env
export BASE_DOMAIN=<your-mlh-domain> ACME_EMAIL=<you@…>
docker compose -f deploy/docker-compose.yml config -q && caddy validate --config deploy/Caddyfile   # first real validation of both files
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec -e OWNER_EMAIL=<you@…> desk python -m app.cli create-owner

# from a DIFFERENT machine — Gates 1, 2, 3
python scripts/verify_public.py --host desk.$BASE_DOMAIN --host demo.$BASE_DOMAIN

# Gate 4 (inside the control plane; repeat for demo.$BASE_DOMAIN)
CP="docker compose -f deploy/docker-compose.yml exec controlplane python deploy/ans_register.py"
gddy --help; gddy tree; gddy search ans; gddy api --help; gddy auth status; gddy env get      # inspect the installed CLI first
$CP --host desk.$BASE_DOMAIN               # registers, prints the exact _acme-challenge TXT record (exit 3 = action required)
$CP --host desk.$BASE_DOMAIN --verify      # after the TXT resolves publicly → verify-acme → prints ANS DNS records
$CP --host desk.$BASE_DOMAIN --verify-dns  # after those are published → verify-dns → polls to ACTIVE → redacted evidence file

# Gate 5
python scripts/evidence_bundle.py --host desk.$BASE_DOMAIN --host demo.$BASE_DOMAIN
python scripts/security_self_test.py --host desk.$BASE_DOMAIN
```

Then append the redacted outputs to the evidence log below and flip the corresponding rows to `PASS`.

## Evidence log

_Entries are appended only when a real check was run; each records the command, time, and redacted output._

### 2026-09-19 (local) / 2026-09-20 ~00:55 UTC — interoperability observation (NOT a gate pass for this project)

Command (read-only, unauthenticated, from the build machine): `python scripts/verify_public.py --host agent.webmesh.ai`

Observed: decision `PASS` for the third-party agent `agent.webmesh.ai` — live ANS discovery returned
`ans://v1.0.13.agent.webmesh.ai`, agentId `de02d013-138e-4e50-9cae-daa20bc3dc37`, lifecycle `ACTIVE`; agent detail and the
production transparency-log badge were consistent; public TLS verified; the A2A Agent Card parsed and its JSON-RPC interface
matched the ANS-registered endpoint; identity-certificate checks `INCOMPLETE` (no credential / no published trust anchor);
card signature recorded but not used as a trust input.

What this proves: the discovery client, transparency-log check, TLS probe, SSRF-pinned fetchers and the checklist work against
the real production registry. What it does **not** prove: anything about our own hosts — Gates 1–5 above remain unobserved.

The same run surfaced two differences between the live API and the written contract, now fixed and recorded in
`docs/research/ANS_API_NOTES.md` §14: the search endpoint rejects `WARNING`/`DEPRECATED`/`EXPIRED` status filters (422), and
`/v1/ans/*` errors use `name` instead of `code`.

## Local verification summary (2026-09-19)

| Check | Result |
|---|---|
| `uv run pytest` | **478 passed** (no network required) — re-run 2026-09-19 22:55 EDT |
| `uv run python scripts/security_self_test.py` | all control groups PASS (478/478 cases); ANS EVIDENCE section `NOT RUN` (no deployed host) |
| `uv run ruff check .` / `uv run ruff format --check .` | clean |
| `uv run mypy app scripts deploy/ans_register.py` | clean |
| `uv run pip-audit` | no known vulnerabilities |
| `alembic upgrade head` | OK on SQLite; PostgreSQL trigger statements **not executed** here (no PostgreSQL available) |
| App boot under `uvicorn --factory app.main:app_factory` | OK: `/healthz`, Agent Card, MCP tool call, UI, unknown Host → 400 |
| `caddy validate` | **Valid configuration** for `deploy/Caddyfile` as shipped AND with the optional tenant block uncommented — official Caddy v2.11.4 binary (SHA-512 checked against the release checksums), placeholder `BASE_DOMAIN`/`ACME_EMAIL` |
| `docker compose -f deploy/docker-compose.yml config -q` | exit 0 (Compose v2.38.1, placeholder `secrets/*.env` files in a scratch copy) |
| Image build / `docker compose up` | **not run here** — the Docker daemon is not running on the build machine |

## Build log

- 2026-09-19 — Core security layer (settings, redaction/logging, DB models, schemas, SSRF policy + DNS-pinned
  transport, sessions, CSRF, headers, rate limiting, idempotency, tokens, state handles): 243 local tests pass.
- 2026-09-19 — Gate 1 local: generic multi-tenant runtime (Host → tenant from DB, deterministic answers with
  `LLM_PROVIDER=none`), A2A server on a2a-sdk 1.1.4, MCP Streamable HTTP on mcp 2.2.0, outbound A2A/MCP clients on the
  pinned SSRF transport, seeded demo agent.
- 2026-09-19 — Gate 4 local: OS-CSPRNG RSA keys (0600), identity CSR (`ans://` URI SAN) + server CSR, ANS REST client
  (Bearer PAT and `sso-key`, allow-listed API origin, no redirect following), registration state machine.
- 2026-09-19 — Gate 5 local: 15-point verifier, transparency-log badge check, redacted proof/evidence bundles.
- 2026-09-19 — CREATE/FIND: safe crawler, static extraction, quarantined extraction model, owner-scoped tenant lifecycle,
  ANS discover → verify → read-only relay.
- 2026-09-19 — Web: FastAPI assembly + middleware stack, server-rendered UI, `/proof` + `/api/proof`, private control-plane
  and scraper roles.
- 2026-09-19 — Deploy/docs: Alembic migration, Dockerfile, Caddyfile, hardened compose, firewall script, resumable
  `deploy/ans_register.py`, operator scripts, README, SECURITY.md, `.env.example`. Lint/type/audit clean.
- 2026-09-19 (late) — Go-live fixes found while deploying:
  - **Bug fixed:** Caddy's on-demand-TLS `ask` request (`http://desk:8000/internal/tls-ask`, Host = service name) was
    rejected by the trusted-host check with `400 invalid_host`, so no generated tenant could ever obtain a certificate.
    The check now admits the internal service name for exactly `/internal/tls-ask` and `/healthz`, safe methods only,
    and only from loopback / `TRUSTED_PROXY_CIDRS` peers (regression test added; verified failing before the fix).
  - `deploy/Caddyfile` now manages only the two gate hosts by default; the tenant wildcard block is an opt-in
    (commented, validated). The `:443 { tls internal }` catch-all was dropped.
  - `deploy/ans_register.py --skip-preflight` for hosts that cannot reach their own public name (hairpin NAT). It is
    opt-in, announced in the output, and never shortcuts the registry's own validation (tests added).
