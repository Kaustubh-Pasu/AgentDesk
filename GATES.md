# GATES.md — GoDaddy "Best Use of ANS" gate tracker

**Rule:** a gate is `PASS` only after the live evidence was actually observed and recorded here.
Nothing in this file is ever pre-filled, simulated, or inferred. Allowed states:
`NOT_STARTED` · `LOCAL_READY` (code + local tests done, nothing live observed) ·
`WAITING_FOR_EXTERNAL_INPUT` · `PASS` · `FAIL`.

_Last updated: 2026-09-19 (build in progress — see "Build log" at the bottom)._

| # | Gate | Live status | Local status | Blocking dependency |
|---|------|-------------|--------------|---------------------|
| 1 | Reachable agent endpoint (A2A + MCP) for Agent Desk **and** one generated business agent | `NOT_STARTED` | in progress | public host (Gate 2/3) |
| 2 | Public HTTPS URL | `WAITING_FOR_EXTERNAL_INPUT` | not started | a public VPS/host + DNS A records |
| 3 | Owned MLH domain | `WAITING_FOR_EXTERNAL_INPUT` | not started | `BASE_DOMAIN` value (your MLH domain) |
| 4 | Production GoDaddy credential + `gddy` CLI flow → ANS status `ACTIVE` | `WAITING_FOR_EXTERNAL_INPUT` | not started | production PAT / event credential, DNS control |
| 5 | Verification evidence the demo can show (`/proof`, `/api/proof`) | `NOT_STARTED` | not started | Gates 1–4 live |

## What I need from you (only these; everything else proceeds without you)

1. `BASE_DOMAIN` — the MLH domain you own (Gate 3).
2. A public Linux host (VPS) IP, with DNS `A` records `desk.<BASE_DOMAIN>` and `demo.<BASE_DOMAIN>` → that IP (Gate 2).
3. The production GoDaddy PAT / event credential, entered by YOU via `gddy auth login` or the secrets file — never pasted into chat (Gate 4).
4. Ability to create one DNS TXT record for the ANS DNS-01 challenge (Gate 4).

## Evidence log

_No live evidence has been observed yet. Entries are appended here only when a real check was run; each entry
records the command, timestamp, and redacted output._

## Build log

- 2026-09-19 — Core security layer (settings, redaction/logging, DB models, schemas, SSRF policy + DNS-pinned
  transport, sessions, CSRF, headers, rate limiting, idempotency, tokens, state handles): 243 local tests pass.
