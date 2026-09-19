You are Claude Code acting as a principal security engineer, staff backend engineer, protocol engineer, and DevOps engineer. Your task is to BUILD, TEST, HARDEN, AND PREPARE FOR DEPLOYMENT a production-oriented hackathon project named \*\*Agent Desk\*\* for the VTHacks 14 GoDaddy “Best Use of ANS” track.

DO NOT merely write a plan. Create the repository/files, implement the application, run tests/linters/security checks available in the environment, fix failures, and produce a final concise deployment/gate report. If you lack shell/filesystem access, output the complete repository file-by-file instead. Do not claim a live external gate is passed unless you have actually observed the live evidence.

\======================================================================  
0\. PROJECT MISSION  
\======================================================================

Agent Desk has two user-facing abilities:

1\) CREATE: an authenticated website owner supplies a public website and an agent hostname. The system safely fetches the public site, extracts useful business facts into strict structured data, creates a small read-only AI business assistant using a PREWRITTEN generic agent runtime, exposes that agent on public HTTPS over BOTH A2A and MCP, and registers it with GoDaddy ANS until the registration is ACTIVE.

2\) FIND: a human or another agent asks Agent Desk for a capability. Agent Desk searches GoDaddy ANS, verifies the discovered candidate’s live ANS lifecycle/host/endpoints/identity evidence, applies outbound network safety policy, and then communicates with the verified candidate over A2A or MCP. Remote output is always untrusted data and may NEVER directly trigger privileged local actions.

One-sentence product statement:  
“Agent Desk turns controlled websites into verified, discoverable AI agents, then helps other agents discover, verify, and communicate with them.”

\======================================================================  
1\. HARD EVENT GATES — ALL FIVE ARE REQUIRED  
\======================================================================

Treat these as acceptance criteria, not optional features:

GATE 1 — Reachable agent endpoint:  
\- Agent Desk MUST expose a standards-compliant A2A endpoint and a Streamable-HTTP MCP endpoint.  
\- At least one generated demo business agent MUST expose both A2A and MCP as well.  
\- Publish an A2A Agent Card at \`/.well-known/agent-card.json\`.  
\- Publish appropriate MCP metadata if supported/needed by the current official MCP SDK and ANS registration.

GATE 2 — Public HTTPS:  
\- Production host(s) must be reachable via HTTPS from the public internet.  
\- Use Caddy as reverse proxy/TLS terminator unless the existing environment has an equally secure alternative.  
\- Application/database/Redis/internal ports must not be public.

GATE 3 — Owned MLH domain:  
\- Read \`BASE\_DOMAIN\` from environment. Never invent or purchase a domain.  
\- Defaults: \`desk.${BASE\_DOMAIN}\` for Agent Desk and \`demo.${BASE\_DOMAIN}\` for the first generated business agent.  
\- Only allow generated subdomains that are sanitized children of BASE\_DOMAIN unless an external domain goes through ownership verification.

GATE 4 — production GoDaddy credential \+ CLI flow \+ ANS ACTIVE:  
\- Current public GoDaddy ANS documentation identifies ANS auth as PAT/Bearer. The hackathon may provide a specific production key/credential flow. FOLLOW EVENT INSTRUCTIONS IF THEY DIFFER.  
\- Install/use the current \`gddy\` CLI. Do not invent stale commands. First inspect \`gddy \--help\`, \`gddy tree\`, \`gddy search ans\`, \`gddy api \--help\`, \`gddy auth status\`, and \`gddy env get\`.  
\- Set/use production environment. If a PAT is provided, store it using the supported production credential path or inject as a secret; never print it.  
\- Implement ANS REST client using current official schema/OpenAPI. Registration currently uses \`/v1/agents/register\`; verify this from live docs/spec before calling.  
\- Generate identity CSR and server CSR (or current supported BYOC fields).  
\- Submit host, semantic version, endpoints, protocols/transports, advertised functions, identity CSR, and server certificate material required by current schema.  
\- Handle DNS-01/PENDING\_VALIDATION challenge safely. If GoDaddy manages BASE\_DOMAIN and CLI DNS commands are available, use \`gddy dns\` with exact record name/value. Never expose generic DNS mutation to public HTTP.  
\- Trigger official validation endpoint(s), poll actual agent details, and do not mark local status ACTIVE until GoDaddy reports ACTIVE.  
\- Capture redacted proof: production environment, agentId, ansName, ACTIVE status, timestamps. NEVER fake ACTIVE.

GATE 5 — Verification evidence:  
\- Implement \`/proof\` (human) and \`/api/proof\` (JSON) for the Agent Desk host, plus tenant proof page if feasible.  
\- It must be generated from actual current checks or short-lived cached checks and include no secrets.  
\- Evidence should include: expected host; ANS agentId/ansName/lifecycle; declared endpoints; last live ANS check; public HTTPS check; TLS version/hostname/certificate fingerprint/expiry; A2A Agent Card parse/hash/skills; MCP handshake/tool probe; identity certificate issuer/subject/SAN/serial/fingerprint/validity; verification decision and reasons.  
\- Retrieve ANS identity certificate using the official certificate-management API if available. Validate its chain/binding using an official/pinned trust anchor obtained through approved ANS documentation/provisioning. DO NOT trust a root certificate merely because a remote agent sends it to you.  
\- If exact official trust-anchor verification cannot be completed because the event has not provided required root material, label that specific check INCOMPLETE rather than PASS. All other checks should still work.

\======================================================================  
2\. CURRENT EXTERNAL FACTS TO VERIFY, NOT BLINDLY ASSUME  
\======================================================================

Use live official docs/CLI/OpenAPI available during implementation. The following are expectations from current public documentation, but verify them:  
\- ANS registration accepts agentDisplayName, agentHost, endpoints, version, identityCsrPEM, and server CSR/BYOC fields.  
\- External-domain registration can return status PENDING\_VALIDATION plus a DNS\_01 challenge.  
\- Agent details can return agentStatus ACTIVE.  
\- Search exists for registered agents and may expose lifecycle, host, ANS name, endpoints, functions, and trust/relevance scores.  
\- Resolution exists by agentHost \+ version.  
\- Certificate management exposes identity/server certificate retrieval.  
\- Revocation exists and supports key-compromise/cessation-style reasons.  
\- A2A public Agent Card standard path is \`/.well-known/agent-card.json\`.  
\- MCP Streamable HTTP is appropriate for a public MCP endpoint.

When library/spec versions differ, implement against the currently installed official SDK and record the exact version in README.

\======================================================================  
3\. REQUIRED STACK AND REPOSITORY  
\======================================================================

Prefer this stack unless the existing repository already has a strong reason not to:  
\- Python 3.12  
\- FastAPI / Starlette  
\- Official A2A Python SDK  
\- Official MCP Python SDK  
\- Pydantic v2 strict schemas  
\- SQLAlchemy 2 \+ PostgreSQL  
\- Redis for rate limiting, replay/idempotency, and short-lived caches  
\- \`cryptography\` for keys/CSRs/certificate inspection  
\- \`httpx\` for trusted outbound API calls  
\- a hardened arbitrary-web fetcher using aiohttp/custom resolver or equivalent that can pin validated DNS answers  
\- BeautifulSoup/lxml for static HTML extraction; never execute page JavaScript  
\- Jinja2 server-rendered UI with autoescape \+ static JS/CSS; no frontend bearer tokens in localStorage  
\- Caddy reverse proxy  
\- Docker Compose  
\- pytest \+ pytest-asyncio  
\- ruff \+ mypy if practical  
\- pip-audit or equivalent dependency audit

Create a layout similar to:

agent-desk/  
  app/  
    main.py  
    settings.py  
    models/  
    security/  
    ans/  
    protocols/  
    ingestion/  
    agents/  
    web/  
  tests/  
    security/  
    ans/  
    protocols/  
    integration/  
  deploy/  
    Caddyfile  
    docker-compose.yml  
    firewall.sh  
    ans\_register.py  
  scripts/  
    generate\_keys.py  
    verify\_public.py  
    security\_self\_test.py  
    evidence\_bundle.py  
  .env.example  
  pyproject.toml  
  README.md  
  SECURITY.md

Never commit real secrets, certificates containing private keys, \`.env\`, database files, or CLI credential stores.

\======================================================================  
4\. PRODUCT DATA MODEL  
\======================================================================

Implement explicit models/tables for:

User:  
\- id UUID  
\- username/email  
\- argon2id password\_hash  
\- role enum OWNER/ADMIN  
\- disabled\_at  
\- optional mfa metadata (do not block MVP if MFA library unavailable)

Tenant:  
\- id UUID  
\- owner\_id  
\- display\_name  
\- source\_url/source\_domain  
\- agent\_host  
\- state enum DRAFT/INGESTED/DEPLOYED/REGISTRATION\_SUBMITTED/PENDING\_VALIDATION/ACTIVE/FAILED/REVOKED/DISABLED  
\- current\_version

AgentConfig:  
\- tenant\_id  
\- semantic version  
\- strict normalized BusinessProfile JSON  
\- allowed\_capabilities enum list  
\- content hash  
\- created\_at/published\_at  
\- immutable after publication; new publication creates a new config version

ANSRegistration:  
\- tenant\_id/version  
\- agent\_id  
\- ans\_name  
\- lifecycle/status  
\- challenge metadata excluding secrets where possible  
\- last\_checked\_at  
\- last\_error safe code

CertificateEvidence:  
\- type IDENTITY/SERVER/TLS\_OBSERVED  
\- public PEM if safe  
\- issuer/subject/SAN/serial  
\- SHA-256 fingerprint  
\- valid\_from/valid\_to  
\- chain verification result \+ reason  
\- NEVER private key

AuditEvent:  
\- append-only semantic event  
\- timestamp  
\- correlation\_id  
\- actor id/type  
\- action  
\- target tenant/agent  
\- outcome  
\- redacted metadata

Use migrations. Every tenant-scoped operation must enforce owner\_id/team authorization server-side.

\======================================================================  
5\. CREATE WORKFLOW — IMPLEMENT END TO END  
\======================================================================

A. AUTHENTICATED OWNER INPUT  
\- Admin/owner UI form takes a source HTTPS website and desired agent subdomain/hostname.  
\- Public signup can be disabled by default for hackathon; seed owner credentials through a secure one-time setup command/environment variable. Do not hard-code passwords.  
\- Desired agent hostname must be a sanitized FQDN under BASE\_DOMAIN for the automatic path.  
\- Do not claim ownership from scraping. Scraping a page is not identity proof.

B. SAFE WEBSITE FETCHER  
This is a HIGH-RISK SSRF boundary.

Implement deterministic URL validation:  
\- Accept HTTPS only in production. If allowing HTTP for import convenience, allow only ports 80/443 and treat it as a step toward a validated HTTPS redirect.  
\- Reject schemes other than http/https; production fetch target should end at https.  
\- Reject userinfo, fragments when not needed, control chars, backslash authority ambiguity, malformed IDN/hostnames, unusual ports.  
\- Prefer rejecting IP literal URLs.  
\- Resolve DNS yourself.  
\- For every A/AAAA result, require globally routable addresses and explicitly reject loopback, RFC1918 private, link-local, multicast, unspecified, reserved/documentation/test ranges, carrier-grade NAT, and cloud metadata/link-local ranges including 169.254.169.254.  
\- Protect against DNS rebinding/TOCTOU by pinning the validated resolved address into the actual connection. Do not simply resolve, check, and then let another resolver perform the connection.  
\- \`trust\_env=False\`; do not inherit arbitrary proxy settings.  
\- Manual redirects only, maximum 3; run the full URL \+ DNS/IP validation on every redirect.  
\- Bound connect/read/whole-operation timeouts.  
\- Maximum pages 10, crawl depth 2, max HTML 2 MiB/page, max decompressed/total import 10 MiB.  
\- Accept only text/html and text/plain initially.  
\- Do not execute JavaScript, plugins, media, PDFs, ZIPs, office docs, binaries, or SVG as active content.  
\- Do not forward authorization cookies/headers from Agent Desk to imported site.  
\- Put the scrape worker in a separate container/network with NO GoDaddy PAT, no DB admin credential, no Redis admin credential, no host mounts, and no Docker socket.  
\- Add deployment firewall/egress rules denying private/link-local/metadata networks from the scrape worker as a second layer.

C. HTML/TEXT EXTRACTION  
\- Parse static HTML.  
\- Remove script/style/noscript/template/iframe/object/embed and unsafe metadata.  
\- Extract semantic/visible-ish text: title, headings, nav labels if useful, address/contact, structured data that can be parsed safely, main content.  
\- Bound character counts.  
\- Do not treat HTML comments, scripts, CSS, hidden fields, or meta instructions as trusted instructions.

D. QUARANTINED EXTRACTION MODEL  
\- The extraction LLM has NO TOOLS, NO network tools, NO shell, NO DNS/ANS APIs, NO database admin rights, NO secrets.  
\- It receives untrusted page text and must emit ONLY a strict JSON BusinessProfile.  
\- Security MUST NOT depend on “ignore prompt injection” wording; the absence of privileges is the real control.  
\- BusinessProfile should include bounded fields such as business\_name, description, address, public contact, hours, services, menu\_items, faq, source\_urls.  
\- Explicit capability enum allowlist. Safe MVP: business\_information, hours, location, menu\_catalog, services\_catalog, faq.  
\- Forbidden generated capabilities: shell, filesystem, arbitrary\_http, dns\_write, ans\_write, payment, purchase, send\_email, account\_admin, secrets, generic\_tool\_execution.  
\- Parse and validate with Pydantic \`extra='forbid'\`, length/array bounds, URL validation, enum validation.  
\- If invalid, retry at most once/twice with bounded tokens; otherwise require owner review.  
\- Owner sees a preview and explicitly confirms imported facts before publish.

E. GENERIC AGENT RUNTIME  
\- DO NOT generate executable Python/JS code from website content.  
\- One trusted agent runtime serves many tenants based on validated Host → tenant mapping from DB.  
\- Never use user input as a filesystem config path.  
\- Tenant agent has read-only access to its own config and no cross-tenant access.  
\- Public Q\&A may call the configured LLM provider, but the model has no privileged tools.  
\- Provide an extractive/deterministic fallback answer mode if no LLM key exists so protocol/gate testing still works.

F. DEPLOY/PUBLISH  
\- Once config is approved, make the hostname route reachable through Caddy and generic runtime.  
\- Verify externally from a separate process/client before ANS registration.  
\- A2A card and MCP metadata are generated from trusted config, not raw model HTML.

G. ANS REGISTRATION  
\- Generate private keys securely using OS CSPRNG. Use a broadly supported algorithm accepted by current ANS docs; do not guess unsupported algorithms. Prefer RSA-3072 or current recommended algorithm after checking schema/docs.  
\- Store private keys in service-specific mounted secret directory with restrictive permissions; never return via web API.  
\- Generate identity CSR and server CSR according to current ANS schema. Base64/PEM encode exactly as current API expects.  
\- Register both A2A and MCP endpoints with function/capability metadata.  
\- Handle PENDING\_VALIDATION DNS\_01 challenge.  
\- Only DNS record allowed to be modified automatically is the exact challenge record under the verified base domain/agent host. No generic DNS write endpoint.  
\- If using \`gddy dns\`, pass arguments as subprocess array from trusted server-generated values; never shell-concatenate. Prefer direct GoDaddy DNS REST/CLI administrative script outside request path.  
\- Verify challenge using official endpoint and poll status with timeout/backoff until ACTIVE or terminal failure.  
\- Retrieve public identity/server certificates and store public evidence.

\======================================================================  
6\. FIND / DISCOVER / VERIFY / COMMUNICATE WORKFLOW  
\======================================================================

A. QUERY NORMALIZATION  
\- Human query is converted to a small internal capability request object. The model may classify intent but cannot directly choose arbitrary URLs or issue network/tool calls.  
\- Use bounded enums/tags and safe text.

B. ANS SEARCH  
\- Call current production ANS search endpoint.  
\- Filter/default to ACTIVE.  
\- Support exact FQDN resolution path for demo/interoperability.  
\- Keep raw external response out of logs if it contains unexpected sensitive data; store only needed normalized fields.

C. VERIFY EACH CANDIDATE  
Fail closed if any mandatory check fails:  
1\. lifecycle/status ACTIVE from live or very fresh ANS data.  
2\. canonical agentHost.  
3\. supported protocol MCP or A2A.  
4\. endpoint HTTPS.  
5\. endpoint host relationship matches registration policy.  
6\. endpoint destination passes outbound SSRF/global-address rules.  
7\. retrieve agent detail/resolution; no contradiction with search result.  
8\. retrieve identity certificate from official ANS API when available.  
9\. verify certificate validity and hostname/ANS URI binding.  
10\. verify chain to approved ANS trust anchor; do not trust remote-supplied root automatically.  
11\. fetch A2A Agent Card / MCP metadata with strict time/size/content-type limits.  
12\. parse schema; no code execution.  
13\. verify metadata signature/hash if current standards/ANS record provides one. If the official A2A SDK supports card signatures, use it. Do NOT invent signature fields.  
14\. store card hash. Unexpected drift forces re-resolution/re-verification and audit event.  
15\. check local blocklist/revocation policy.

D. COMMUNICATE  
\- Prefer the verified advertised protocol.  
\- Outbound request time limit and max response size.  
\- NEVER forward the incoming user/MCP bearer token to a remote agent.  
\- If remote auth is required, use an explicit remote credential obtained for that resource, validate scopes/audience, and keep it server-side.  
\- Remote agent response is UNTRUSTED DATA. It cannot call local tools, alter policy, request secrets, or redirect Agent Desk to arbitrary URLs.  
\- If summarizing remote output with an LLM, use an unprivileged summarizer with no tools/secrets.

\======================================================================  
7\. WEB APPLICATION SECURITY — IMPLEMENT CONCRETELY  
\======================================================================

AUTHENTICATION  
\- Use Argon2id password hashing via a reputable package.  
\- Generic login failure messages.  
\- Login rate limiting per account \+ IP; progressive delays.  
\- Optional TOTP/WebAuthn for admin if feasible.  
\- Re-authenticate before revocation/key rotation.

SESSIONS  
\- Opaque server-side sessions.  
\- Cookie name \`\_\_Host-agentdesk\_session\`.  
\- Secure; HttpOnly; SameSite=Strict; Path=/; no Domain attribute.  
\- Rotate on login/role change.  
\- Idle timeout \+ absolute timeout.  
\- Store hashed session token server-side; support revoke-all.  
\- NEVER store auth/access/refresh tokens in localStorage/sessionStorage.

CSRF  
\- Every cookie-authenticated state-changing browser route requires server-generated per-session CSRF token.  
\- Verify Origin/Referer against canonical admin origin.  
\- Enforce Fetch Metadata policy for unsafe browser requests.  
\- GET/HEAD/OPTIONS must have no state changes.

AUTHORIZATION / BOLA / IDOR  
\- Every tenant/config/registration query is filtered by current owner/team membership.  
\- Role checks server-side.  
\- Do not rely on hidden buttons.  
\- Tests must try cross-tenant UUID access and assert 403/404 without data leakage.

MASS ASSIGNMENT  
\- Dedicated Pydantic input models with only writable fields and \`extra='forbid'\`.  
\- Never bind DB model directly to request JSON.

XSS  
\- Jinja autoescape ON.  
\- No raw HTML from user/site/LLM/ANS/remote agent.  
\- No \`innerHTML\` with untrusted values.  
\- If Markdown is added, disable raw HTML and use allowlist sanitizer.  
\- Validate links/schemes.

CSP / HEADERS  
Set via Caddy/app and test:  
\- \`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests\`  
\- HSTS \`max-age=63072000; includeSubDomains\` only after all subdomains are HTTPS-ready.  
\- X-Content-Type-Options nosniff  
\- Referrer-Policy no-referrer  
\- Permissions-Policy camera=(), microphone=(), geolocation=(), payment=()  
\- Cross-Origin-Opener-Policy same-origin  
\- X-Frame-Options DENY as legacy defense-in-depth

CORS  
\- No CORS if same-origin UI/API.  
\- If needed, exact configured HTTPS origins only. Never \`\*\` with credentials. Never reflect arbitrary Origin.

SQL INJECTION  
\- SQLAlchemy/bound params only; no f-string/raw concatenated SQL.  
\- DB account least privilege, not superuser.  
\- Validate sort/filter field names via enums.

COMMAND INJECTION / RCE  
\- No shell=True, eval, exec, dynamic code generation, or untrusted dynamic imports.  
\- Public app must not execute \`gddy\` based on raw request content.  
\- Docker socket never mounted.

PATH TRAVERSAL  
\- No user-controlled file paths.  
\- Config addressed by DB UUID, not filename.  
\- Upload feature omitted from MVP.

HOST HEADER / PROXY TRUST  
\- TrustedHost middleware allows only BASE\_DOMAIN and intended subdomains.  
\- Caddy is only public ingress.  
\- Trust forwarding headers only from Caddy private network.  
\- Generate absolute URLs from configured canonical origin, not arbitrary Host/X-Forwarded-Host.

OPEN REDIRECT  
\- Redirect targets are internal named routes/relative paths, not arbitrary URLs.

ERRORS  
\- DEBUG=false in production.  
\- Safe structured error codes \+ correlation IDs; no stack trace/secrets/internal topology to clients.

\======================================================================  
8\. MCP SECURITY — REQUIRED  
\======================================================================

Follow current official MCP security best practices.  
\- Token passthrough is forbidden. Validate issuer/signature/expiry/audience/scope. Do not relay incoming token downstream.  
\- Prevent confused-deputy behavior: per-client consent where OAuth proxying is involved, exact redirect URIs, state/CSRF checks, no broad consent reuse.  
\- State/workflow handles are high entropy, time-limited, and bound server-side to the authenticated caller; possession is not authorization.  
\- OAuth/auth metadata URLs use the same SSRF-safe fetch policy. Reject javascript/data/file/vbscript and non-HTTPS production auth URLs.  
\- Least-privilege scopes. No \`\*\`, \`all\`, or \`full-access\`. Request/elevate only scopes needed by the specific operation.  
\- Public MCP tools are read-only. Any future high-impact tool must be separate, authenticated, scope-protected, audited, idempotent, and human-confirmed.

\======================================================================  
9\. A2A SECURITY — REQUIRED  
\======================================================================

Follow current official A2A spec/SDK.  
\- HTTPS/TLS production only.  
\- Serve public Agent Card at standard well-known location.  
\- Public card contains no secrets/internal admin endpoints.  
\- If installed SDK supports Agent Card signatures, implement using standard fields/canonicalization and verify on clients. Do not invent proprietary signature fields.  
\- Protected skills declare auth requirements and enforce authz on every request.  
\- Task/context IDs are caller-scoped and not authorization tokens.  
\- Disable push/webhook callbacks in MVP unless SSRF-safe callback validation and authentication are implemented.

\======================================================================  
10\. ANS IDENTITY VS BEHAVIORAL TRUST  
\======================================================================

A verified ANS identity tells us who/what identity is registered; it does not prove the remote agent is honest, bug-free, or authorized for every action.  
\- Treat an ACTIVE ANS agent as externally identified but still untrusted software.  
\- Never grant extra local capabilities solely because trustScore is high.  
\- For every call, enforce our own tool/capability/data policy.  
\- Revocation/expired/inactive status fails closed.  
\- Recheck status before any future high-impact action.

\======================================================================  
11\. WEBMESH INTEROPERABILITY AND ATTACK-BATTERY DEFENSE  
\======================================================================

Public Webmesh index: https://webmesh.ai/.well-known/agents-index.json  
Useful interop endpoints include agent.webmesh.ai, dnsdoc.webmesh.ai, seo.webmesh.ai, auditor.webmesh.ai, rogue-supplier.webmesh.ai, and fraud.webmesh.ai.

IMPORTANT: The published Fraud Agent attack battery is primarily for AP2/x402/travel supplier transaction authorization. OUR MVP DOES NOT IMPLEMENT PAYMENT/BOOKING/SPENDING AUTHORITY. Therefore all such transaction requests MUST fail closed as unsupported and must never cause side effects. Do not pretend a transaction test “passed” if it never targeted our surface; document applicability correctly.

Still implement generic defenses inspired by the battery:  
\- Replay protection/idempotency for our own state-changing endpoints.  
\- Strict schema/version parsing; unknown/superseded auth object formats rejected.  
\- Audience validation on our tokens.  
\- Scope validation per operation.  
\- Unknown signing keys untrusted.  
\- Invalid/corrupt signatures fail cleanly without crashes or permissive fallback.  
\- If signing structured JSON, use the standard canonicalization required by that protocol consistently.  
\- Hash our public A2A Agent Card; unexpected drift triggers audit \+ ANS re-verification.  
\- If a remote ANS agent is valid but policy behavior is bad, do not treat ANS identity as sufficient authorization.

For the specific published Fraud Agent cases, add a SECURITY.md table stating:  
\- replay\_booking → unsupported in MVP; state-changing replay controls exist generally.  
\- underpay\_booking/tamper\_mandate/underpay\_valid\_sig → unsupported; any future signed authorization must be verified AND separately policy-checked.  
\- quote\_swap → future auth must bind exact object/quote ID.  
\- wrong\_audience → validate audience on every bearer/authorization object.  
\- wrong\_scope → per-operation scope enforcement.  
\- wrong\_dpop\_key/replay → if DPoP is ever implemented, use a vetted library, verify key binding/request binding/freshness/unique proof ID; never hand-roll crypto.  
\- corrupt\_jws → strict parser/signature verification; fail closed.  
\- superseded\_format → schema version allowlist; no lenient legacy fallback.  
\- unknown\_key → pinned/authorized trust anchors only.  
\- replay\_settled → no settlement in MVP; idempotency/replay ledger for local mutations.  
\- canonicalization\_probe → one standards-compliant canonicalizer if signed JSON is added.  
\- payto\_binding → not applicable until payment feature exists; never accept unsigned settlement destination.  
\- card\_drift\_watch → implemented by Agent Card hash monitoring \+ re-verification.

Optionally test discovery/communication with \`agent.webmesh.ai\` if protocol interoperability permits, but never send secrets/private URLs or attempt destructive actions against third parties.

\======================================================================  
12\. RATE LIMITS / RESOURCE / DENIAL-OF-WALLET  
\======================================================================

Implement Redis-backed or equivalent shared limits:  
\- login: \~5 failures/15 min/account+IP with progressive delay  
\- anonymous agent queries: \~30/min/IP  
\- A2A/MCP read-only: \~60/min/IP, with body/response limits  
\- create/import: 3/hour/owner and only one active import/owner  
\- ANS search: bounded/cached, \~30/min/principal  
\- proof endpoint: cheap cached live evidence, \~60/min/IP  
\- model calls: max input/output tokens; per-user and global daily budget ceiling  
\- remote agent hops \<= 2  
\- model/tool calls \<= 5 total for a normal user request  
\- retries \<= 2, exponential backoff  
\- hard wall-clock timeout

Add circuit-breaker environment flags:  
\- \`DISABLE\_AGENT\_CREATION\`  
\- \`DISABLE\_EXTERNAL\_FETCH\`  
\- \`DISABLE\_REMOTE\_AGENT\_CALLS\`  
\- \`DISABLE\_LLM\`  
\- \`READ\_ONLY\_MODE\`

When disabled, return clear safe errors and preserve proof/read-only functionality where possible.

\======================================================================  
13\. REPLAY / IDEMPOTENCY / CONCURRENCY  
\======================================================================

\- State-changing owner/admin endpoints accept or generate idempotency keys bound to actor \+ operation \+ canonical payload hash.  
\- Redis/Postgres stores replay key TTL/state atomically.  
\- Duplicate publish/register/revoke calls cannot execute twice.  
\- ANS registration per tenant/version uses a DB/advisory lock/single-flight.  
\- Configuration uses version/optimistic lock so concurrent edits cannot silently overwrite.  
\- DNS challenge cleanup deletes only the exact value created by this registration and never unrelated records.

\======================================================================  
14\. SECRETS AND KEY MANAGEMENT  
\======================================================================

Secrets:  
\- GODADDY\_PAT/event production credential  
\- DNS credential if separate  
\- LLM API key(s)  
\- DB/Redis passwords  
\- session/CSRF signing secret  
\- ANS identity/server private keys

Rules:  
\- never commit or print  
\- never send to LLM  
\- never expose in browser or proof endpoint  
\- never log Authorization/Cookie/private key fields  
\- store outside repo and inject only to necessary service  
\- scraper receives no secrets  
\- generated agent receives no GoDaddy/DNS/deploy credentials  
\- private keys chmod 600 and service-specific mount  
\- add secret-redaction logging filter  
\- write a test that injects a fake canary secret and asserts it does not appear in logs  
\- document rotation/revocation

\======================================================================  
15\. CONTAINER / HOST HARDENING  
\======================================================================

Docker Compose:  
\- Caddy public on 80/443 only  
\- app/control plane/database/Redis on private networks  
\- non-root app containers  
\- read\_only filesystem where feasible  
\- tmpfs for /tmp  
\- \`no-new-privileges:true\`  
\- drop capabilities; no privileged; no host network  
\- CPU/memory/PID limits where Compose version supports  
\- no Docker socket mounts  
\- scraper isolated from control-plane/db network if architecture permits

Host firewall:  
\- allow 80/443  
\- SSH key-only and restrict source if possible  
\- deny public DB/Redis/app ports  
\- deny scrape-worker egress to private/link-local/metadata ranges

Caddy:  
\- reverse proxy with explicit host routes  
\- request body limits  
\- security headers  
\- hide server details where possible  
\- access logging with redaction policy

\======================================================================  
16\. SUPPLY CHAIN  
\======================================================================

\- Pin dependencies with lockfile.  
\- Prefer official SDKs.  
\- Minimize package count.  
\- Run dependency audit and fix high/critical findings or document unavoidable ones.  
\- No packages/plugins installed based on LLM/web/remote agent suggestions at runtime.  
\- Production container base image pinned to specific supported Python image/version.  
\- \`SECURITY.md\` documents dependencies/services and update process.

\======================================================================  
17\. LOGGING / AUDIT / PRIVACY  
\======================================================================

Structured logs with correlation IDs.  
Audit events for login, tenant create, import, publish, ANS register, DNS validation, ACTIVE transition, verification failure, remote connect, owner config edit, revoke, key rotation, circuit-breaker change.

Redact:  
Authorization, Cookie, Set-Cookie, PAT/API keys, CSRF token, passwords, private keys, raw session IDs, sensitive prompts.

Sanitize log fields against CR/LF log injection.  
Do not store full website HTML indefinitely; store normalized business profile and source URLs/hash unless debugging is explicitly enabled.  
Default conversation retention should be short/minimal.

\======================================================================  
18\. PROOF / VERIFICATION IMPLEMENTATION  
\======================================================================

Create a verifier that returns a typed result like:

{  
  "agent\_host": "desk.example.com",  
  "ans": {  
    "agent\_id": "...",  
    "ans\_name": "ans://v1.0.0.desk.example.com",  
    "status": "ACTIVE",  
    "checked\_at": "..."  
  },  
  "endpoint\_checks": \[  
    {"protocol":"A2A","url":"https://...","pass":true,...},  
    {"protocol":"MCP","url":"https://.../mcp","pass":true,...}  
  \],  
  "identity\_certificate": {  
    "issuer":"...",  
    "subject":"...",  
    "san":\[...\],  
    "sha256":"...",  
    "valid\_from":"...",  
    "valid\_to":"...",  
    "chain\_verified":true,  
    "binding\_verified":true  
  },  
  "tls": {...},  
  "a2a": {"card\_valid":true,"card\_sha256":"...","skills":\[...\]},  
  "mcp": {"handshake":true,"tools":\[...\]},  
  "verified": true,  
  "reasons": \[\]  
}

Never return private keys, bearer tokens, raw environment, session cookies, DB details, or internal network addresses.

Verification should distinguish PASS / FAIL / INCOMPLETE. INCOMPLETE is required where the environment lacks an official trust anchor or external credential; never turn uncertainty into PASS.

\======================================================================  
19\. TEST SUITE — REQUIRED BEFORE FINAL REPORT  
\======================================================================

UNIT/INTEGRATION:  
\- BusinessProfile schema  
\- Host/subdomain policy  
\- owner/tenant authorization  
\- protocol metadata/card generation  
\- ANS client mocked contract tests  
\- proof formatting

SECURITY TESTS AGAINST OUR OWN LOCAL/STAGING APP:  
1\. SSRF block localhost IPv4/IPv6  
2\. block RFC1918/private/link-local/metadata  
3\. block userinfo/parser ambiguity  
4\. block redirect-to-private  
5\. simulate DNS rebinding and ensure pinned resolution blocks it  
6\. oversized page/body/decompression limits  
7\. indirect prompt injection page cannot trigger tools/secrets/network  
8\. malformed LLM JSON rejected  
9\. forbidden capability rejected  
10\. XSS payload rendered inert  
11\. CSRF missing/bad/cross-origin rejected  
12\. cross-tenant IDOR/BOLA rejected  
13\. mass assignment (owner\_id/role/status) rejected  
14\. SQL injection strings are data only  
15\. command/path injection cannot spawn process/read file  
16\. Host header poisoning rejected  
17\. CORS not open  
18\. session fixation/reuse after logout fails  
19\. rate limits enforced  
20\. remote private endpoint rejected  
21\. malformed/oversized Agent Card rejected  
22\. endpoint mismatch rejected  
23\. revoked/inactive mocked/live candidate rejected  
24\. state handle bound to principal  
25\. wrong token audience rejected if token auth enabled  
26\. idempotency prevents duplicate mutation  
27\. corrupted signature/parser input fails safely without 500/crash  
28\. card hash drift triggers re-verification/audit  
29\. canary secret absent from logs  
30\. circuit breakers work

Run tests. Fix failures. Include pass/fail summary.

Never perform intrusive tests against third-party endpoints. Public Webmesh agents may be used only for documented interoperability/read-only calls.

\======================================================================  
20\. README / SECURITY / DEPLOYMENT DOCUMENTATION  
\======================================================================

README must contain:  
\- what the product does in 3–4 sentences  
\- architecture diagram in Mermaid or ASCII  
\- Create flow  
\- Find flow  
\- local dev instructions  
\- production deployment instructions  
\- environment variable reference  
\- exact A2A/MCP URLs  
\- exact 5-gate proof checklist  
\- ANS registration flow  
\- how to verify ACTIVE  
\- how to generate evidence bundle  
\- demo script

SECURITY.md must contain:  
\- threat model/trust boundaries  
\- security invariants  
\- SSRF design  
\- prompt injection design  
\- auth/session/CSRF/XSS/CSP controls  
\- MCP/A2A/ANS security  
\- secret/key handling  
\- Webmesh published battery applicability table  
\- incident response and revocation  
\- known limitations / risks

\======================================================================  
21\. ENVIRONMENT VARIABLES  
\======================================================================

Create \`.env.example\` with safe placeholders, including at minimum:  
ENV=development|production  
BASE\_DOMAIN=example.com  
DESK\_HOST=desk.example.com  
DEMO\_HOST=demo.example.com  
DATABASE\_URL=postgresql+asyncpg://...  
REDIS\_URL=redis://...  
SESSION\_SECRET=...  
CSRF\_SECRET=...  
GODADDY\_PAT=...  
GODADDY\_API\_BASE=https://api.godaddy.com  
ANS\_AGENT\_VERSION=1.0.0  
LLM\_PROVIDER=anthropic|openai|gemini|none  
ANTHROPIC\_API\_KEY=  
OPENAI\_API\_KEY=  
GEMINI\_API\_KEY=  
DISABLE\_AGENT\_CREATION=false  
DISABLE\_EXTERNAL\_FETCH=false  
DISABLE\_REMOTE\_AGENT\_CALLS=false  
DISABLE\_LLM=false  
READ\_ONLY\_MODE=false

Do not require all LLM provider keys; select one. With \`none\`, protocol/gates must still be testable using deterministic answers from structured config.

\======================================================================  
22\. USER INTERFACE  
\======================================================================

Keep it simple and judge-friendly.

Home:  
\- two cards: CREATE AGENT and FIND AGENT  
\- small explanation “discover → verify → communicate”

Create page:  
\- website URL  
\- desired agent hostname/subdomain  
\- import progress  
\- extracted data preview  
\- owner confirmation  
\- publish/ANS registration progress  
\- states visibly labeled

Find page:  
\- natural-language capability query  
\- show ANS search steps  
\- candidate list  
\- verification checks with PASS/FAIL  
\- connect button or automatic read-only connect  
\- result

Proof page:  
\- Gate 1 A2A/MCP reachable  
\- Gate 2 HTTPS  
\- Gate 3 owned domain  
\- Gate 4 production ANS ACTIVE  
\- Gate 5 certificate/verification evidence  
\- timestamps and redacted raw identifiers

Security page (optional but useful):  
\- concise architecture/trust controls  
\- no claims of “unhackable”  
\- show security self-test status

No giant SPA required. Prefer secure server-rendered pages.

\======================================================================  
23\. DEMO BUSINESS AGENT  
\======================================================================

Seed a safe demo business config so Gates can be tested before website import works.  
Example capabilities:  
\- get\_business\_info(question)  
\- get\_hours()  
\- get\_menu\_or\_services()

All are read-only.  
The demo agent uses the same generic runtime as generated tenants.

\======================================================================  
24\. PRODUCTION GO-LIVE / ANS REGISTRATION SCRIPT  
\======================================================================

Create an explicit CLI/admin script, NOT a public web endpoint, that:  
1\. validates BASE\_DOMAIN and host  
2\. verifies public HTTPS A2A/MCP availability  
3\. checks \`gddy auth status\` / prod environment if gddy exists  
4\. generates/loads private key \+ CSRs securely  
5\. uses current production ANS API schema to register  
6\. prints only redacted response summary  
7\. if PENDING\_VALIDATION, shows exact DNS TXT challenge  
8\. optionally uses safe \`gddy dns add\` for exact challenge if domain is manageable and user explicitly runs/approves script  
9\. calls verify-acme/verify-dns as current docs require  
10\. polls actual GoDaddy agent status to ACTIVE  
11\. retrieves identity/server public certificates  
12\. writes redacted evidence JSON file under a non-secret artifacts directory  
13\. never prints/stores PAT or private key in artifacts

Before destructive DNS delete/set operations, use dry-run when supported and exact-match only.

\======================================================================  
25\. FINAL ACCEPTANCE — DO NOT STOP UNTIL LOCAL CODE SATISFIES THESE  
\======================================================================

Local/staging acceptance:  
\[ \] app boots from clean checkout with documented setup  
\[ \] DB migrations succeed  
\[ \] secure login/session/CSRF works  
\[ \] CREATE imports a controlled test page safely  
\[ \] prompt injection in import does not gain privileges  
\[ \] generated agent config is data only  
\[ \] A2A Agent Card valid  
\[ \] A2A read-only request works  
\[ \] MCP Streamable HTTP handshake/tool call works  
\[ \] FIND can discover from mocked/local ANS contract and live ANS when credentials exist  
\[ \] verifier rejects endpoint/cert/status mismatches  
\[ \] \`/proof\` and \`/api/proof\` work  
\[ \] security headers tests pass  
\[ \] SSRF tests pass  
\[ \] cross-tenant authorization tests pass  
\[ \] rate/resource limits pass  
\[ \] secret redaction test passes  
\[ \] dependency/security audit run  
\[ \] Docker Compose and Caddy config validate  
\[ \] README and SECURITY.md complete

Live gate acceptance (only mark PASS after actual observation):  
\[ \] Gate 1 external A2A/MCP reachable  
\[ \] Gate 2 public HTTPS valid  
\[ \] Gate 3 owned MLH domain used  
\[ \] Gate 4 production ANS ACTIVE, with redacted CLI/API evidence  
\[ \] Gate 5 live verification/certificate/protocol evidence displayed

If live credentials/domain/network are absent, mark live gate items WAITING\_FOR\_EXTERNAL\_INPUT, give exact commands/checks, and leave the code ready. Never fabricate success.

\======================================================================  
26\. EXECUTION BEHAVIOR FOR YOU, CLAUDE  
\======================================================================

\- Start by inspecting existing files and installed tool/library versions.  
\- If repository is empty, scaffold it.  
\- Use official current protocol/API docs and SDK introspection where possible.  
\- Do not spend the whole run narrating. Implement.  
\- Make reasonable decisions without asking unnecessary questions.  
\- Only stop for a truly external interactive boundary such as browser login, missing domain, or missing production credential. Even then, complete all code/tests that do not require it and output the exact one-line next action.  
\- Never echo secrets back to chat/output.  
\- Never downgrade TLS or disable certificate verification to “make it work.”  
\- Never turn off a security test to make CI green; fix the bug or clearly document a blocked external dependency.  
\- Prefer correctness/security over visual polish.  
\- Ensure the final demo path is reliable and fast.

FINAL REPORT FORMAT:  
1\. What was built  
2\. Architecture  
3\. Security controls implemented  
4\. Test results  
5\. Five gates status: PASS / FAIL / WAITING\_FOR\_EXTERNAL\_INPUT with evidence  
6\. Exact commands to deploy/register/prove any remaining live steps  
7\. Known limitations

Now build Agent Desk end-to-end.