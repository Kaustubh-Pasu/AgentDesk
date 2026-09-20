# Security — Agent Desk

No claim of "unhackable" is made. This document states what is protected, by which concrete control, where that control
lives in the code, and which test exercises it. `python scripts/security_self_test.py` prints a PASS/FAIL line per control
from the real test suite.

## 1. Threat model and trust boundaries

Assets: the GoDaddy credential; ANS identity/server private keys; session/CSRF secrets; owner accounts and tenant data; the
integrity of published agent configs and of proof evidence; the server's network position (SSRF); LLM spend.

| # | Boundary | Untrusted side | Rule |
|---|---|---|---|
| B1 | Browser → desk | every request | session + CSRF token + Origin/Fetch-Metadata; strict input models; owner-scoped queries |
| B2 | Internet → A2A/MCP | every caller | read-only skills only; rate limited; no credentials accepted or forwarded |
| B3 | Desk → arbitrary website | DNS, redirects, bytes | pinned-DNS SSRF transport, hard limits, isolated secret-less scraper, egress firewall |
| B4 | Page text → extraction model | the text (prompt injection) | model has no tools/network/secrets; output must fit a strict schema; owner confirms |
| B5 | Desk → ANS | registry responses | bounded lenient parsing; links never dereferenced with the credential; status copied, never invented |
| B6 | Desk → remote agent | card, replies, certificates | verified before contact; replies are inert text; remote roots never trusted |
| B7 | Desk → control plane | the desk itself (if compromised) | typed request + service token; control plane re-checks ownership; no generic URL/DNS operation |
| B8 | Operator → DNS | script input | only exact records returned for the host; TXT; append-only; dry-run + per-record confirmation |

Security zones: **public** (Caddy), **application** (desk/runtime), **privileged** (control plane: PAT + keys),
**hostile-input** (scraper: no secrets, no DB, egress to public addresses only), **data** (PostgreSQL/Redis: internal network).

## 2. Security invariants

1. Website content never becomes code, configuration paths, tool names, URLs to call, or capabilities. It becomes a
   `BusinessProfile` (bounded strings) or nothing.
2. Capabilities are an enum mapped to prewritten read-only handlers. `shell`, `filesystem`, `arbitrary_http`, `dns_write`,
   `ans_write`, `payment`, `purchase`, `send_email`, `account_admin`, `secrets`, `generic_tool_execution` are rejected by name.
3. Every outbound request to a non-allow-listed destination goes through `PinnedTransport`: validated URL, validated DNS
   answers, connection to exactly those answers, strict TLS, no proxies, no automatic redirects.
4. The GoDaddy credential is sent only to the allow-listed API origin, never to a registry-supplied link, the transparency
   log, the public discovery API, an LLM, a log line, a browser or a proof document.
5. Local ANS status is a copy of the last live GoDaddy response. No code path writes `ACTIVE` otherwise.
6. `PASS` requires an observed positive result. Missing material ⇒ `INCOMPLETE`. Any `FAIL` blocks communication.
7. A remote agent's output is data: displayed, never parsed for instructions, never the source of the next URL, never given
   to a privileged component. An ANS identity or a high trust score grants no local capability.
8. Every tenant query carries `owner_id`. Another owner's object is a 404.
9. State-changing browser routes require session + CSRF token + same-origin headers + idempotency key. GET never mutates.
10. Private keys are created by the OS CSPRNG, stored 0600 under a policy-validated path, and no function that feeds an HTTP
    response can read them. Evidence exports are scanned and refuse secret-shaped content.

## 3. SSRF design (`app/security/ssrf.py`, `app/ingestion/safe_fetch.py`, `app/protocols/remote_http.py`)

- **URL policy**: https only, port 443 only, no userinfo, no fragments, no backslashes/control characters/percent-encoded
  authority, no IP literals in any notation (dotted, decimal, hex, octal, IPv6, bracketed), IDNA/UTS-46 canonicalisation,
  single-label and special-use names (`localhost`, `.local`, `.internal`, `.test`, `.onion`, …) refused, and the stdlib parser
  must agree with ours about host and port (parser-differential guard).
- **Address policy**: every A/AAAA answer must be globally routable. Loopback, RFC1918, link-local/metadata
  (`169.254.169.254`, `fd00:ec2::254`), CGNAT, documentation/benchmark ranges, multicast, reserved, v4-mapped, NAT64, 6to4 and
  Teredo are refused. One bad answer rejects the whole lookup.
- **No TOCTOU / rebinding**: `PinnedNetworkBackend` resolves, validates and connects to the validated address itself; the HTTP
  stack never performs a second lookup. Keep-alive is off so every request re-validates. TLS still verifies the hostname.
- **Redirects**: never automatic. Import: ≤3, full URL + DNS policy per hop. Remote agents: one same-origin 307/308 only.
- **Limits**: html/plain only (import), JSON / agent-card JSON / SSE only (agents); 2 MiB/page decoded, 10 MiB/import, 10 pages,
  depth 2, 60 s; 256 KiB Agent Card; 1 MiB remote reply; bounded decompression (gzip/deflate only; bombs rejected).
- **No ambient authority**: `trust_env=False`; no cookies, Authorization or Referer are ever sent.
- **Second layer**: the scraper runs in its own container/network without secrets; `deploy/firewall.sh` drops its egress to
  private/link-local/metadata ranges at the host.

Tests: `tests/security/test_ssrf_policy.py`, `tests/ingestion/test_ingestion.py`, `tests/protocols/test_clients.py`.

## 4. Prompt-injection design (`app/ingestion/extraction_model.py`, `app/agents/`)

Security does **not** depend on telling the model to ignore instructions. The extraction call has no tools, no network, no
secrets and no database handle; its only output is a string that must validate as `ExtractionOutput` (`extra='forbid'`,
bounded fields, https-only URLs, capability enum). Forbidden capability names are rejected explicitly. Output is never
repaired or partially accepted: two failures → a deterministic heuristic draft flagged for review. Server-side facts win over
model claims (source URLs are what we fetched; capabilities ⊆ what the content supports). Hidden text, comments, scripts,
forms and meta tags are removed before the model sees anything. Nothing is public until the owner confirms the preview.
The public Q&A model gets the profile as data with no tools; transactions are refused before the model is called; answers
are length-bounded; a deterministic answer is used when no LLM is configured or the budget is exhausted.
Remote agent replies are never fed to a privileged component. There is no long-term agent memory to poison.
Denial of wallet: per-principal and global daily LLM budgets, bounded input/output, ≤3 verifications + 1 conversation per
FIND request, no agent chaining, hard wall clocks, `DISABLE_LLM` / `DISABLE_REMOTE_AGENT_CALLS` kill switches.

## 5. Web application controls

| Area | Control |
|---|---|
| Authentication | Argon2id; generic failure message; dummy-hash verification for unknown users; 5 failures/15 min per account+IP with progressive delay; no public sign-up; owner seeded by CLI |
| Sessions | opaque random token, only its HMAC stored; `__Host-agentdesk_session`; `Secure; HttpOnly; SameSite=Strict; Path=/`; no Domain; new token at login (fixation); idle 30 min + absolute 12 h; revoke-all CLI; nothing in web storage |
| CSRF | per-session synchronizer token + signed double-submit token for the login form; `Origin`/`Referer` must equal the canonical desk origin; `Sec-Fetch-Site` must be `same-origin`; GET/HEAD/OPTIONS never mutate |
| Authorization | owner-scoped queries everywhere (`TenantService`, `RegistrationService`); 404 for foreign objects; the admin surface does not exist on tenant hosts; re-authentication for disable |
| Mass assignment | dedicated input models with `extra='forbid'`; ORM models are never bound to request data |
| XSS | Jinja2 autoescape on, `StrictUndefined`, no `|safe`, no inline script/style, no `innerHTML`; remote replies rendered as text in a labelled block |
| CSP / headers | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests`, HSTS 2 years, nosniff, `Referrer-Policy: no-referrer`, Permissions-Policy, COOP, `X-Frame-Options: DENY`; `Server` removed; `no-store` on authenticated pages |
| CORS | none. No `Access-Control-*` header is ever emitted |
| SQL injection | SQLAlchemy bound parameters only; identifiers are UUIDs/enums; least-privilege DB role (DML only); audit table append-only by trigger |
| Command / path | no `shell=True`, `eval`, `exec` or dynamic import; the web app never spawns a process; key paths are built only from policy-validated host + semver; no upload feature |
| Host / proxy | `TrustedHostMiddleware` (exactly one Host header, direct child of `BASE_DOMAIN`); absolute URLs from configured origins; `X-Forwarded-For` honoured only from `TRUSTED_PROXY_CIDRS`; Caddy strips client forwarding headers |
| Redirects | fixed internal paths only |
| Errors | safe code + correlation id; no stack traces, SQL, paths or internal addresses; last-resort ASGI guard |
| Limits | body ≤256 KiB (Caddy + app); login, anonymous query 30/min/IP, A2A/MCP 60/min/IP, proof 60/min/IP, import 3/h/owner + single active import, ANS search 30/min/principal; limiter fails closed |
| Replay | idempotency keys bound to actor + operation + payload hash (atomic insert); single-flight ANS registration per tenant+version; optimistic `row_version` |

## 6. MCP, A2A and ANS

- **MCP** (`/mcp`): stateless Streamable HTTP; read-only tools with `readOnlyHint`; no admin/DNS/ANS/fetch tool exists;
  `Authorization`/`Cookie` headers are stripped before the SDK sees the request, so token passthrough is impossible; there is
  no OAuth proxying, hence no confused-deputy surface; state handles (`app/security/state_handles.py`) are high-entropy,
  10-minute, single-use and bound to the principal; optional machine tokens validate issuer, signature (HS256 allow-list),
  expiry, audience and per-operation scope, and refuse `*`/`all`/`full-access` scopes.
- **MCP client**: only tools the remote server marks read-only are callable; arguments must match the tool's schema; protocol
  version allow-list; session id echoed only to its issuer.
- **A2A**: card served at the well-known path from trusted config (no secrets, no admin endpoints, no header-derived URLs);
  streaming and push notifications disabled (no callback SSRF surface); task/context ids are not authorization; malformed
  JSON-RPC fails cleanly. Card signatures are not emitted: the SDK offers no signing helper we could use without inventing a
  scheme, and an agent-hosted key adds no trust beyond TLS.
- **ANS**: identity ≠ behavioural trust. ACTIVE is required (live), `REVOKED`/`EXPIRED`/inactive fail closed, the transparency
  log (the ANS revocation channel) must agree, endpoints must be https on the registered host, certificates are retrieved
  only from the official API, chain verification uses only the operator-provisioned anchor (optionally SHA-256 pinned) and is
  INCOMPLETE without one, card drift is audited and forces re-verification, a local blocklist always wins.

## 7. Secrets and keys

| Secret | Lives in | Never in |
|---|---|---|
| GoDaddy PAT / API key+secret | `secrets/controlplane.env` → control plane only | desk, scraper, LLM prompts, logs, proof, browser, git |
| ANS identity/server private keys | `ans_keys` volume → control plane only, 0600 | any HTTP response, artifacts, logs |
| SESSION/CSRF secrets | `secrets/desk.env` | scraper |
| DB owner password | `secrets/postgres.env` (migrations only) | running services (they use the DML-only role) |
| LLM key | desk only | scraper, control plane |

Logging: JSON, correlation ids, CR/LF neutralised, a redaction filter for sensitive keys (`authorization`, `cookie`,
`set-cookie`, `password`, `secret`, `token`, `api_key`, `private_key`, …), PAT/bearer/PEM shapes and every configured secret
value. Query strings are never logged. Canary tests assert a seeded secret is absent from formatted log output.
Rotation: PAT — revoke at developer.godaddy.com, replace in `controlplane.env`, restart the control plane. Session/CSRF
secret — replace and restart (all sessions end). ANS keys — register a new version (new keys + CSRs) and revoke the old one.

## 8. Webmesh published attack battery — applicability

The Fraud Agent battery targets AP2/x402 travel-supplier **transaction authorization**. Agent Desk has **no payment, booking or
spending authority**; every such request fails closed as unsupported with no side effect
(`test_a2a_transaction_requests_fail_closed`). These cases are therefore *not applicable*, not "passed". The battery was never
run against third parties.

| Case | Status in this MVP | Relevant control that does exist |
|---|---|---|
| `replay_booking` | unsupported (no bookings) | idempotency ledger + single-flight for our own mutations |
| `underpay_booking`, `tamper_mandate`, `underpay_valid_sig` | unsupported | any future signed authorization must be verified **and** separately policy-checked |
| `quote_swap` | unsupported | future authorization must bind the exact object/quote id |
| `wrong_audience` | applicable to our tokens | audience validated on every bearer token (`test_token_wrong_audience_rejected`) |
| `wrong_scope` | applicable to our tokens | per-operation scope; wildcard scopes refused |
| `wrong_dpop_key`, DPoP replay | not implemented | if ever added: vetted library, key + request binding, freshness, unique proof id; no hand-rolled crypto |
| `corrupt_jws` | applicable to parsers | strict parsing; corrupt tokens/JSON-RPC/cards fail closed without 5xx |
| `superseded_format` | applicable | token version allow-list, MCP protocol-version allow-list, `extra='forbid'`; no lenient legacy fallback |
| `unknown_key` | applicable | only configured keys / provisioned trust anchors; `alg=none` and unknown algorithms refused |
| `replay_settled` | unsupported (no settlement) | replay ledger for local mutations |
| `canonicalization_probe` | not applicable (we sign no JSON) | one canonical JSON form is used for hashing (`canonical_json`) |
| `payto_binding` | not applicable | never accept an unsigned settlement destination if payments are ever added |
| `card_drift_watch` | **implemented** | Agent Card hash per host; drift ⇒ audit event + failed verification until re-verified |

Additional cases covered by tests: SSRF via agent endpoints, oversized/malformed cards, hostile MCP tool lists, prompt injection
in replies, Host-header poisoning, registry contradictions, remote-supplied root certificates.

## 9. Supply chain and hosting

Dependencies are pinned in `uv.lock`; official SDKs are used for A2A and MCP; nothing is installed at runtime. Run
`uv run pip-audit` before each deployment (results of the last run are in `GATES.md`). Images: `python:3.12.11-slim-bookworm`,
`caddy:2.10-alpine`, `postgres:16.10-alpine`, `redis:7.4-alpine` — pin digests for a release. Containers: non-root, read-only root
filesystem, tmpfs `/tmp`, all capabilities dropped, `no-new-privileges`, CPU/memory/PID limits, no Docker socket, no host
network, only Caddy publishes ports, data/control/scrape networks are `internal`.

## 10. Incident response

| Situation | Action |
|---|---|
| Suspicious imports / SSRF attempts | `DISABLE_EXTERNAL_FETCH=true` (and `DISABLE_AGENT_CREATION=true`), restart desk; review `ssrf.blocked` audit events |
| Abuse through FIND / remote agents | `DISABLE_REMOTE_AGENT_CALLS=true`; add the host to `blocked_agents` |
| LLM cost spike | `DISABLE_LLM=true` (deterministic answers continue) |
| Anything unclear | `READ_ONLY_MODE=true`: proof, agent cards and read-only answers keep working; all mutations stop |
| Owner account compromise | `python -m app.cli revoke-sessions`; rotate the password; review `auth.*` audit events |
| ANS key compromise | `POST /v1/agents/{id}/revoke` with `KEY_COMPROMISE` (`AnsClient.revoke`), remove `dnsRecordsToRemove`, register a new version with new keys |
| PAT leak | revoke at developer.godaddy.com immediately, rotate, inspect `GET /v1/agents/events` |

Evidence: append-only `audit_events` (login, tenant create, import, publish, ANS register/validation/ACTIVE, verification
failures, card drift, remote connects, CSRF/authz denials) with correlation ids matching the access log.

## 11. Known limitations and residual risk

- Trust-anchor chain verification is INCOMPLETE until an official ANS CA bundle is provisioned; transparency-log badge
  signatures and Merkle proofs are not verified offline.
- No MFA/WebAuthn. Single owner role model (no teams).
- The in-process rate limiter used without Redis is per-process (development only; production refuses to start without Redis).
- The deterministic intent matcher and extractor are simple by design; they trade recall for having no attack surface.
- DNS answers could differ between our resolver and a victim's view; pinning defeats rebinding against *us*, which is the goal.
- The compose/Caddy configuration has not been executed on the build machine. Validate it (`docker compose config`,
  `caddy validate`) and run `scripts/verify_public.py` plus an external port scan after deployment.

Report vulnerabilities privately to the repository owner. Do not test against third-party agents.
