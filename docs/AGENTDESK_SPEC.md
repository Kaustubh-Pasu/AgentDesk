# **Agent Desk**

*Production Build, ANS Gate Compliance, Security Architecture, Threat Model, Test Plan, and Claude One‑Shot Implementation Prompt*

**Purpose: build an ANS-native system that turns a controlled website into a small public AI business agent, registers that agent with GoDaddy ANS, and lets Agent Desk discover, verify, and communicate with registered agents over the open web. Security is defense-in-depth: the LLM is never the authorization, identity, network, or execution boundary.**

Target event: VTHacks 14 — GoDaddy “Best Use of ANS.” The five event gates supplied by the team are treated as hard acceptance criteria. Current public GoDaddy documentation is used where available; event-specific mentor instructions override public docs if they differ.

Important security statement: no architecture can guarantee immunity from every attack. This specification aims to minimize attack surface, fail closed, isolate privileges, make high-impact operations explicit, and provide auditable evidence that controls are working.

# **Document Map**

| Part | What it contains |
| :---- | :---- |
| I. Product | What Agent Desk does; who uses it; what “Create” and “Find” mean. |
| II. ANS Compliance | Exact mapping to Gates 1–5; production registration and evidence. |
| III. Architecture | Services, data model, protocols, routes, flows, deployment topology. |
| IV. Security | Threat model and concrete protections for web, LLM, scraper, ANS, MCP/A2A, data, host, and supply chain. |
| V. Webmesh & Adversarial Tests | How to interoperate with public Webmesh agents and how the system handles the published attack battery. |
| VI. Verification & Runbook | Acceptance tests, security tests, deployment, incident response, and judging demo. |
| VII. Claude One‑Shot Prompt | A copy/paste prompt instructing Claude Code to build the production-oriented MVP and prove all gates. |

# **I. What the Product Actually Does**

## **1\. Plain-English Product Definition**

Agent Desk is an “on-ramp and search engine” for a verified agent web. A website owner provides a website they control. Agent Desk extracts public business information and creates a small AI assistant for that business. The assistant is exposed at a public HTTPS endpoint, speaks MCP and A2A, is registered with GoDaddy ANS, and receives a domain-backed ANS identity. Later, a human or another agent can ask Agent Desk to find an agent for a task; Agent Desk searches ANS, verifies the candidate, and communicates with the verified endpoint.

**One sentence: Agent Desk turns controlled websites into verified, discoverable AI agents, then helps other users and agents discover, verify, and communicate with those agents.**

## **2\. The Two Core Workflows**

### **2.1 CREATE — Website → Mini Agent → ANS Identity**

Owner enters website \+ desired agent hostname

        ↓

Safe website fetcher retrieves public pages

        ↓

Unprivileged extraction model converts text → strict business JSON

        ↓

Schema / policy validator accepts only safe fields and allowed capabilities

        ↓

Generic multi-tenant agent runtime loads that business configuration

        ↓

Public HTTPS A2A \+ MCP endpoints become reachable

        ↓

ANS registration request contains host, endpoints, functions, CSRs, version

        ↓

DNS-01 / event validation is completed

        ↓

ANS status reaches ACTIVE

        ↓

Identity certificate \+ verification evidence are displayed

The implementation does not generate and execute arbitrary Python or JavaScript for each business. “Creating an agent” means creating validated configuration and a new tenant/hostname for a prewritten, trusted runtime. This sharply reduces remote-code-execution and supply-chain risk.

### **2.2 FIND — Need → Discover → Verify → Communicate**

User/agent: “Find a verified restaurant agent that answers menu questions.”

        ↓

Agent Desk normalizes the requested capability

        ↓

Search GoDaddy ANS for ACTIVE candidates

        ↓

For each candidate: verify host, lifecycle, endpoints, certificates, metadata

        ↓

Apply trust policy and reject mismatches/revoked/unreachable candidates

        ↓

Select a verified compatible A2A or MCP endpoint

        ↓

Connect with strict timeouts, size limits, and no credential passthrough

        ↓

Treat remote output as untrusted data; return result to caller

## **3\. Example User Journey**

A local restaurant owner provides \`https://example-restaurant.com\` and requests \`assistant.example-restaurant.com\`. Agent Desk imports hours, menu, contact data, and FAQs. The owner completes ANS/domain verification. The generated assistant becomes ACTIVE and advertises capabilities such as \`business\_information\` and \`menu\_questions\`. A separate AI later asks Agent Desk for a restaurant-information agent; Agent Desk discovers the registration, validates it, and sends the user’s question to the verified endpoint.

## **4\. MVP Scope and Explicit Non-Goals**

The secure hackathon MVP should prioritize read-only information retrieval. Payments, arbitrary purchases, account changes, email sending, shell access, DNS administration from public chat, and autonomous destructive actions are outside the default agent capability set.

* Generated business agents answer questions from a bounded, structured knowledge base.  
* Agent Desk can create/configure tenants, search ANS, verify candidates, and relay read-only requests.  
* Administrative operations require owner authentication and server-side authorization.  
* No public endpoint accepts raw shell commands, SQL, filesystem paths, arbitrary URLs for callbacks, or generic “execute tool” payloads.  
* No generated agent has the GoDaddy PAT, DNS credentials, deployment credentials, database administrator credentials, or host access.  
* If state-changing business tools are added later, each receives a separate authorization design, explicit human confirmation, idempotency, audit records, and narrow scopes.

# **II. The Five GoDaddy Track Gates**

The team supplied the following five gates. This specification treats all five as “must pass” before polish or extra features.

| Gate | Requirement | Concrete implementation | Proof to show judges |
| :---- | :---- | :---- | :---- |
| 1 | Build an agent with a reachable endpoint (A2A, MCP). | Agent Desk exposes both A2A and MCP. At least one generated business agent also exposes both. | External request to A2A; MCP tool call; public agent card and MCP metadata. |
| 2 | Host a public HTTPS URL. | Caddy/reverse proxy terminates modern TLS; only 443 serves application traffic; HTTP redirects to HTTPS. | Open public URL; TLS probe; health endpoint; external protocol call. |
| 3 | Use a free MLH domain you own. | Use BASE\_DOMAIN from the team’s MLH domain. Suggested hosts: \`desk.\<domain\>\` and \`demo.\<domain\>\`. | DNS records \+ browser/public resolver \+ ANS host exact match. |
| 4 | Register a production API key \+ CLI flow → status ACTIVE. | Use production \`gddy\` auth/PAT per current GoDaddy ANS docs/event instructions; register via live ANS API; satisfy DNS validation; poll until ACTIVE. | Redacted \`gddy auth status\`, prod environment, agentId, ANS name, API response with ACTIVE. |
| 5 | Prove it: verification evidence the demo can show. | Create a read-only proof screen/API showing ANS lifecycle, endpoint match, identity certificate summary/fingerprint, live TLS result, A2A/MCP checks, and timestamps. | Live \`/proof\` page \+ JSON evidence bundle \+ direct ANS/API lookup. |

## **5\. Gate 1 — A2A and MCP**

A2A public discovery uses an Agent Card at \`https://{agent-host}/.well-known/agent-card.json\`; current A2A documentation describes the card as the server’s public declaration of identity, capabilities, skills, interfaces, and authentication requirements. Production A2A communication should use HTTPS/TLS and server-side authorization for protected operations. \[S8\]

MCP should be exposed using Streamable HTTP at \`/mcp\`. MCP-specific security guidance explicitly covers confused-deputy risk, token passthrough, SSRF, state-handle hijacking, OAuth URL validation, and least-privilege scopes; this design incorporates those controls. \[S9\]

## **6\. Gate 2 — Public HTTPS**

* Public protocol endpoints are reachable from an external network, not only \`localhost\` or a private tunnel.  
* TLS certificate hostname validation must succeed.  
* Production redirects HTTP to HTTPS and sends HSTS after the domain is stable.  
* Application services bind only to the private Docker/network interface; the reverse proxy is the only public ingress.  
* No development server, database, Redis, metrics, admin debug, or container daemon port is exposed publicly.

## **7\. Gate 3 — Owned MLH Domain**

A safe default topology is \`desk.\<BASE\_DOMAIN\>\` for the main Agent Desk agent and \`demo.\<BASE\_DOMAIN\>\` for the first generated business agent. Additional generated agents may use sanitized labels such as \`\<tenant-slug\>.\<BASE\_DOMAIN\>\`. The application must never let a user select arbitrary DNS records: an agent hostname must be a validated child of \`BASE\_DOMAIN\`, or an externally controlled domain must complete the ANS/domain ownership process before it can be marked verified.

## **8\. Gate 4 — Production ANS Registration**

Current public GoDaddy developer documentation identifies ANS as PAT-authenticated and supports production CLI authentication through \`gddy\`; public docs show \`gddy auth login\`, \`gddy auth status\`, \`gddy env set\`, and PAT storage for non-interactive use. The ANS registration endpoint accepts the agent host, endpoints, functions, semantic version, identity CSR, and server certificate material/CSR. External-domain registration may return a DNS-01 challenge and \`PENDING\_VALIDATION\`; after validation the agent detail response can report \`ACTIVE\`. \[S1\]\[S3\]\[S6\]\[S7\]

**Do not invent ANS CLI syntax. The production build must run \`gddy tree\`, \`gddy search ans\`, and \`gddy api \--help\` against the installed CLI to discover the exact current command surface. If the event provides a specific command or credential type, that event instruction wins. The web app itself should call the documented ANS REST API using a narrowly scoped production credential stored server-side.**

### **8.1 Registration state machine**

DRAFT

  → DEPLOYED\_HTTPS

  → REGISTRATION\_SUBMITTED

  → PENDING\_VALIDATION

  → VALIDATING\_DNS/ACME

  → ACTIVE

 

Failure branches:

  → VALIDATION\_FAILED

  → REGISTRATION\_FAILED

  → REVOKED

  → DISABLED\_LOCAL

### **8.2 Registration payload targets**

The implementation should generate and submit the current-schema equivalents of: display name; exact FQDN; version; MCP endpoint plus metadata URL/functions; A2A endpoint plus Agent Card metadata URL; identity CSR; and server CSR or supported BYOC server certificate fields. The exact JSON should be generated from the live GoDaddy OpenAPI/schema rather than copied forever from a stale example. \[S1\]

## **9\. Gate 5 — Verification Evidence**

Gate 5 should be a visible product feature, not terminal noise. The proof service must be read-only and contain no private keys or bearer tokens.

| Evidence item | What to verify | What to display |
| :---- | :---- | :---- |
| ANS lifecycle | Live GET/search reports the expected agent and ACTIVE status. | agentId, ANS name, lifecycle/status, checked\_at. |
| Host binding | ANS agentHost exactly equals expected FQDN. | Expected host vs observed host. |
| Endpoint binding | Declared endpoint matches the endpoint being called. | Protocol, URL, transport, metadata URL. |
| Identity certificate | Certificate is retrieved from ANS; chain/subject/SAN/validity are checked according to official trust anchor guidance. | Issuer, subject, SAN, valid-from/to, serial/fingerprint; never private key. |
| Public TLS | HTTPS connection validates hostname and certificate chain. | TLS version, hostname check, leaf fingerprint, expiry. |
| A2A | Agent Card parses and advertises expected capability/interface. | Name/version/skills; card hash. |
| MCP | Initialize/handshake succeeds and expected read-only tool responds. | Endpoint, tool list, test result. |
| Revocation freshness | Status rechecked before sensitive use; revoked agents fail closed. | Last checked \+ decision reason. |

GoDaddy’s current certificate-management reference exposes identity and server certificate retrieval for an agent. The identity certificate example binds the hostname and ANS URI in the subject/SAN and returns the certificate chain. ANS also exposes revocation with reasons such as key compromise. \[S4\]\[S5\]

# **III. Production-Oriented Architecture**

## **10\. Component Topology**

Internet

   │

   ▼

\[Caddy / TLS / request limits / security headers\]

   │

   ├── desk.BASE\_DOMAIN ──────► \[Agent Desk API \+ Web UI\]

   │                               │

   │                               ├─► \[ANS Client / Verifier\]

   │                               ├─► \[Safe Fetch Queue\]

   │                               └─► \[Remote Agent Client\]

   │

   ├── demo.BASE\_DOMAIN ──────► \[Generic Business Agent Runtime\]

   │                               │

   │                               └─► \[Tenant knowledge \+ LLM adapter\]

   │

   └── tenant.BASE\_DOMAIN ────► \[Same runtime, different tenant config\]

 

Private-only services:

   \[PostgreSQL\] \[Redis/rate limit \+ replay cache\] \[Scrape worker\]

 

Privileged control-plane service:

   \[ANS registration \+ certificate operations\]

   \- holds GoDaddy PAT

   \- never exposed directly to the internet

   \- only receives typed, authorized internal requests

## **11\. Recommended Stack**

| Layer | Choice | Reason |
| :---- | :---- | :---- |
| Backend/protocols | Python 3.12 \+ FastAPI/Starlette | Strong type validation; A2A/MCP Python SDK integration; async HTTP. |
| A2A | Official A2A Python SDK where compatible | Standards-based Agent Card and request handling. |
| MCP | Official MCP Python SDK, Streamable HTTP | Direct match to gate and current security guidance. |
| Database | PostgreSQL | Tenant, user, config, evidence, audit, replay/idempotency state. |
| Cache/limits | Redis | Shared rate limiting, short-lived nonces, replay/idempotency cache. |
| HTTP client | httpx for trusted destinations; hardened aiohttp resolver for arbitrary website fetches | Separate trusted and untrusted network paths. |
| Crypto | Python \`cryptography\` \+ OpenSSL verification tooling | CSR/key generation and certificate inspection. |
| Web UI | Server-rendered Jinja2 \+ static JS/CSS | Small attack surface; automatic escaping; no bearer tokens in browser storage. |
| Reverse proxy | Caddy | Simple automatic TLS and reverse proxy; can enforce headers and body limits. |
| Packaging | Docker Compose for hackathon VPS; non-root containers | Reproducible deployment and service isolation. |

## **12\. Repository Layout**

agent-desk/

├── app/

│   ├── main.py

│   ├── settings.py

│   ├── security/

│   │   ├── headers.py

│   │   ├── csrf.py

│   │   ├── sessions.py

│   │   ├── authz.py

│   │   ├── rate\_limit.py

│   │   ├── ssrf.py

│   │   └── audit.py

│   ├── ans/

│   │   ├── client.py

│   │   ├── registration.py

│   │   ├── certs.py

│   │   ├── verifier.py

│   │   └── evidence.py

│   ├── protocols/

│   │   ├── a2a\_server.py

│   │   ├── a2a\_client.py

│   │   ├── mcp\_server.py

│   │   └── mcp\_client.py

│   ├── ingestion/

│   │   ├── safe\_fetch.py

│   │   ├── html\_extract.py

│   │   ├── extraction\_model.py

│   │   └── policy.py

│   ├── agents/

│   │   ├── runtime.py

│   │   ├── knowledge.py

│   │   └── registry.py

│   ├── web/

│   │   ├── routes.py

│   │   ├── admin.py

│   │   └── templates/

│   └── models/

│       ├── db.py

│       └── schemas.py

├── tests/

│   ├── security/

│   ├── protocols/

│   ├── ans/

│   └── integration/

├── deploy/

│   ├── Caddyfile

│   ├── docker-compose.yml

│   ├── firewall.sh

│   └── ans\_register.py

├── scripts/

│   ├── generate\_keys.py

│   ├── verify\_public.py

│   ├── security\_self\_test.py

│   └── evidence\_bundle.py

├── .env.example

├── pyproject.toml

├── SECURITY.md

└── README.md

## **13\. Core Data Model**

| Entity | Important fields | Security notes |
| :---- | :---- | :---- |
| User | id, username/email, password\_hash, role, mfa\_state, disabled\_at | Argon2id; owner/admin roles; no plaintext credentials. |
| Tenant | id, owner\_id, display\_name, source\_domain, agent\_host, state | Every query is owner-scoped to prevent IDOR/BOLA. |
| AgentConfig | tenant\_id, version, normalized business JSON, allowed\_capabilities | Strict schema; no executable code; immutable versions after publication. |
| ANSRegistration | tenant\_id, agent\_id, ans\_name, lifecycle, last\_checked\_at | No PAT stored here; state comes from live ANS. |
| CertificateEvidence | agent\_id, type, issuer, subject, serial, fingerprints, validity | Store public certificate metadata/PEM only; private key stored separately. |
| AuditEvent | actor, action, target, result, correlation\_id, metadata | Append-only semantics; redact secrets/PII. |
| RateLimit/Replays | principal, key, expires\_at | Redis preferred; fail safely if high-risk replay store unavailable. |

## **14\. CREATE Workflow — Detailed**

☐ Owner authenticates to administrative UI.

☐ Owner submits source domain/URL and desired agent hostname.

☐ Backend canonicalizes URL and enforces domain/hostname policy.

☐ Safe fetcher validates scheme, port, DNS result, redirect chain, response type, size, and time budget.

☐ HTML extraction removes active content and returns visible/semantic text only.

☐ Quarantined extraction LLM has no tools and no secrets; it produces only strict JSON.

☐ Pydantic schema with \`extra=forbid\`, length limits, enums, and capability allowlist validates output.

☐ Owner previews/edit-confirms imported business facts before publication.

☐ Tenant config is stored as data. Generic runtime is assigned hostname and version.

☐ Public HTTPS A2A/MCP endpoints are health checked externally.

☐ Identity/server key material is generated using OS CSPRNG and secure filesystem permissions.

☐ Production ANS registration is submitted.

☐ DNS validation is performed only for the exact permitted validation record.

☐ Agent is polled until ACTIVE; failure never silently converts to success.

☐ Public identity/server certificate evidence is retrieved and verified.

☐ Proof page is updated; audit event records success.

## **15\. FIND Workflow — Detailed**

☐ Caller supplies a natural-language capability request.

☐ Intent extraction produces a bounded internal capability representation; no network action is directly generated by the model.

☐ ANS search returns candidates; default lifecycle filter is ACTIVE.

☐ For each candidate, host and endpoint URLs pass outbound safety validation.

☐ ANS registration is resolved/retrieved; exact host/version/protocol/endpoint relationships are checked.

☐ Identity certificate evidence is validated using trusted ANS certificate material/official trust anchors.

☐ A2A card or MCP metadata is fetched with time/size limits and parsed as data.

☐ If metadata hash/signature exists, verify it. Any observed drift triggers re-verification before use.

☐ Authorization and trust policy determines whether communication is permitted.

☐ Remote request uses a new credential appropriate for that remote service; incoming tokens are never blindly forwarded.

☐ Remote response is untrusted data and cannot cause local tool execution or privilege escalation.

☐ Result and verification summary are returned with correlation/audit IDs.

## **16\. Protocol Endpoints**

| Path | Purpose | Exposure |
| :---- | :---- | :---- |
| /.well-known/agent-card.json | Public A2A Agent Card. No secrets or internal-only capabilities. | Public GET |
| /a2a or / | A2A JSON-RPC/HTTP interface according to installed SDK version. | Public; auth depends on skill. |
| /.well-known/mcp.json | Public MCP metadata if used by current tooling/ANS registration. | Public GET |
| /mcp | MCP Streamable HTTP. Read-only public tools; protected admin tools must not be exposed here. | Public with rate limits. |
| /proof | Human-readable gate/verification evidence. | Public read-only; redacted. |
| /api/proof | Machine-readable proof evidence. | Public read-only; redacted. |
| /admin/\* | Create/publish/revoke/configure workflows. | Authenticated owner/admin only. |
| /healthz | Minimal liveness. | Public, no sensitive dependency detail. |
| /readyz | Readiness. | Prefer private/monitoring network. |

# **IV. Security Architecture and Threat Model**

## **17\. Core Security Invariants**

**1\.** The LLM is never an authorization, identity, cryptographic-verification, or network-policy boundary.

**2\.** Untrusted website content and remote-agent content never reach a privileged model/tool path with executable authority.

**3\.** Website ingestion can produce data only, never executable source code, shell commands, reverse-proxy configuration, SQL, DNS commands, or deployment instructions.

**4\.** GoDaddy PAT/DNS/deployment secrets exist only in the control plane and are never placed in prompts, browser code, generated tenant configs, logs, or remote-agent requests.

**5\.** Every server-side object access is scoped to the authenticated owner/tenant; knowing an object ID is not authorization.

**6\.** Every state-changing operation is authenticated, authorized, CSRF-protected where browser cookies are used, audited, and idempotent when applicable.

**7\.** Every arbitrary outbound URL path is protected against SSRF, redirects, DNS rebinding, private-address access, cloud metadata, local services, and parser ambiguities.

**8\.** Every remote agent is treated as untrusted software even after ANS identity verification; identity is not behavioral trust.

**9\.** All unsupported high-impact/financial operations fail closed.

**10\.** No security control relies solely on a system prompt.

## **18\. Assets to Protect**

* GoDaddy production PAT/event credential and any DNS-management credential.  
* ANS identity private keys, server private keys, session-signing keys, CSRF keys, database credentials, LLM API keys.  
* Owner accounts and sessions.  
* Tenant configuration and imported business content.  
* ANS identity integrity: hostname, endpoints, advertised capabilities, version, certificate state.  
* Availability and hackathon budget: CPU, RAM, bandwidth, LLM tokens, ANS calls, DNS calls.  
* Audit evidence and verification status.  
* Host/VPS, Docker socket, database, Redis, reverse proxy, CI/CD credentials.

## **19\. Trust Boundaries**

| Boundary | Trust level | Rule |
| :---- | :---- | :---- |
| Browser → web app | Untrusted | Validate, authenticate, authorize, CSRF-check, rate-limit. |
| Website being imported → scrape worker | Hostile by default | SSRF-safe fetch, content/size/time limits, sandbox. |
| Scraped content → LLM | Hostile instructions embedded in data | Quarantined model; no tools/secrets; structured output only. |
| LLM → application | Untrusted suggestion | Schema validation and deterministic policy gate. |
| Public A2A/MCP caller → agent | Untrusted | Protocol validation, authz where needed, rate limits, content limits. |
| ANS registry → Agent Desk | Externally authoritative for ANS registration data, but still parsed defensively | Validate schema, expected host/protocol, certificates, freshness. |
| Remote agent → Agent Desk | Untrusted software with possible verified identity | No instruction-following; data-only responses; narrow client privileges. |
| Web app → control plane | Privileged | Typed internal commands, owner authz, no direct user-controlled shell/URL. |

## **20\. Security Zone Separation**

Use separate processes/containers and credentials for the public web/API, scrape worker, business-agent runtime, and ANS control plane. A compromise of the scraper or a generated tenant agent must not reveal the GoDaddy PAT or enable DNS/ANS mutations. The control plane is not publicly routable.

## **21\. Website & API Security — Concrete Controls**

### **21.1 Authentication**

* Public read-only agent queries may be anonymous, but all owner/admin functions require authentication.  
* Use Argon2id for password hashing with library defaults tuned to the host; never implement password hashing manually.  
* Disable public signup by default for the hackathon unless needed; seed team owner accounts securely or use an invite code stored server-side.  
* Add optional TOTP/WebAuthn for administrator accounts if time permits.  
* Rate-limit login, reset, and invitation endpoints by IP and account identifier; use generic failure messages.  
* Re-authenticate before high-impact operations such as revoking an ANS agent or rotating keys.

### **21.2 Session Security**

* Use opaque server-side sessions, not browser localStorage bearer tokens.  
* Cookie name uses \`\_\_Host-\` prefix and attributes \`Secure; HttpOnly; SameSite=Strict; Path=/\`.  
* Rotate session ID on login/privilege change; invalidate on logout/password reset; short idle timeout and bounded absolute lifetime.  
* Do not set a \`Domain=\` attribute on the admin session cookie, so generated subdomains cannot receive the admin session.  
* Store only a hashed session identifier server-side; support forced revocation.

### **21.3 CSRF**

* All browser state-changing routes require a per-session CSRF token plus strict Origin/Referer verification.  
* Use Fetch Metadata (\`Sec-Fetch-Site\`, mode, destination) as an additional fail-safe for state-changing browser routes.  
* GET/HEAD/OPTIONS are side-effect free.  
* A2A/MCP API endpoints use explicit protocol authentication rather than cookie sessions, avoiding ambient-cookie CSRF.

### **21.4 Authorization / IDOR / BOLA**

* Every database query for a tenant/config/registration includes the authenticated \`owner\_id\` or explicit team membership predicate.  
* Never fetch object by user-supplied UUID and then assume ownership.  
* Admin and owner permissions are separate server-side enums/scopes; the browser cannot assign its own role.  
* Pydantic request models use \`extra="forbid"\` to prevent mass assignment/property injection.  
* ANS registration/revocation routes re-check ownership even if the UI hides controls.

### **21.5 XSS and Content Injection**

* Jinja auto-escaping remains enabled. Never mark scraped content, LLM output, ANS metadata, remote-agent output, error text, or user profile values as safe HTML.  
* No \`innerHTML\` with untrusted data. Render untrusted strings using text nodes/textContent.  
* If Markdown is supported, use an allowlist sanitizer and disable raw HTML.  
* Validate all href/src values; allow only expected HTTPS URLs and internal paths.  
* Set \`X-Content-Type-Options: nosniff\` and return explicit content types.

### **21.6 Content Security Policy and Browser Headers**

Content-Security-Policy:

  default-src 'self';

  script-src 'self';

  style-src 'self';

  img-src 'self' data:;

  connect-src 'self';

  object-src 'none';

  base-uri 'none';

  frame-ancestors 'none';

  form-action 'self';

  upgrade-insecure-requests

 

Strict-Transport-Security: max-age=63072000; includeSubDomains

X-Content-Type-Options: nosniff

Referrer-Policy: no-referrer

Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()

Cross-Origin-Opener-Policy: same-origin

X-Frame-Options: DENY  \# defense-in-depth for older clients

CSP is defense-in-depth rather than a replacement for contextual output encoding. \[S15\]

### **21.7 CORS**

* Default API behavior: no cross-origin browser access.  
* If the UI and API share an origin, do not enable CORS at all.  
* If a separate origin is necessary, allow only exact configured HTTPS origins; never combine credentials with \`\*\`.  
* Never dynamically reflect the Origin header.

### **21.8 SQL/NoSQL Injection**

* Use SQLAlchemy parameter binding/ORM only. No string concatenation or f-string SQL from user/model/remote data.  
* Database role used by web app is not superuser and has only required schema privileges.  
* No generic “query” tool is exposed to an LLM or remote agent.  
* Validate sort fields/filter names against explicit enums instead of inserting arbitrary identifiers.

### **21.9 OS Command Injection / RCE**

* No public input is passed to a shell.  
* Never use \`shell=True\`, \`eval\`, \`exec\`, dynamic import from user/model output, or template evaluation of untrusted code.  
* If deployment scripts call \`gddy\`, call it as an argument array with server-generated values; do not expose that subprocess path to HTTP requests.  
* Generated agents are configuration records, not generated executable code.  
* Docker socket is never mounted into the public application.

### **21.10 Path Traversal / File Access**

* Tenant configuration is stored by database key, not a user-controlled filesystem path.  
* No endpoint accepts arbitrary filenames or directories.  
* Uploads are out of scope for MVP. If added, store under generated UUID names outside the web root and perform MIME/size scanning.  
* Secret/private-key directories are mounted only into the service that requires them and use restrictive permissions.

### **21.11 Request Smuggling, Host Header, Proxy Trust**

* Use one hardened reverse proxy as the only public ingress and keep Uvicorn/ASGI ports private.  
* Reject malformed/conflicting Content-Length/Transfer-Encoding requests at the proxy; keep proxy and app patched.  
* FastAPI/Starlette trusted-host middleware allows only the exact base domain and approved subdomains.  
* Do not trust arbitrary \`X-Forwarded-For\`, \`X-Forwarded-Host\`, or scheme headers; trust forwarding headers only from the local reverse proxy network.  
* Generate absolute URLs from configured canonical origins, not raw Host headers.

### **21.12 Open Redirect / URL Injection**

* Redirect destinations are enum/route identifiers or relative paths, never arbitrary request-supplied URLs.  
* OAuth/authorization URLs are parsed and allowlisted; production must be HTTPS.  
* Never open URLs through a shell command.

### **21.13 Error Handling and Information Disclosure**

* Production \`DEBUG=false\`; no stack traces to clients.  
* Errors return stable machine codes and generic text; correlation ID links to server logs.  
* Do not reveal filesystem paths, SQL, environment variables, tokens, internal hostnames, dependency versions, or private network topology.  
* Protocol parsing errors fail cleanly and do not crash the process.

## **22\. SSRF Protection — Website Import and Remote-Agent Fetching**

This project has two major SSRF surfaces: the owner-supplied website URL and agent/metadata URLs obtained during remote discovery. OWASP and MCP guidance both recommend destination validation, redirect validation, private-address blocking, egress controls, and defenses against DNS rebinding/TOCTOU. \[S9\]\[S12\]

### **22.1 URL acceptance policy**

* Production website ingestion accepts \`https://\` by default; optional \`http://\` may only be used to follow an immediate validated redirect to HTTPS if product requirements demand it.  
* Reject userinfo (\`user@host\`), fragments, non-HTTP schemes, unusual ports, raw control characters, backslashes in authority parsing, and parser-ambiguous URLs.  
* Allowed ports: 443; optionally 80 only for initial HTTP-to-HTTPS upgrade. Never arbitrary ports.  
* Normalize hostname using IDNA; enforce length; reject malformed labels and trailing-dot ambiguity after canonicalization.  
* If an IP literal is provided, require it to be globally routable and not reserved/private/link-local/loopback/multicast/documentation range. Prefer rejecting IP-literal imports entirely.

### **22.2 DNS / IP policy**

Resolve hostname with a resolver controlled by the fetcher.

For every A/AAAA answer:

  \- parse with ipaddress

  \- require is\_global

  \- explicitly deny RFC1918/private, loopback, link-local, multicast,

    unspecified, carrier-grade NAT, documentation/test ranges, and metadata ranges

  \- explicitly deny 169.254.169.254 and IPv6 metadata/link-local equivalents

Pin the validated address for the actual connection so DNS cannot change between check and use.

Re-run the full policy for every redirect hop.

### **22.3 Fetch limits**

| Limit | Recommended default |
| :---- | :---- |
| Redirects | 3 maximum; validate each hop; no automatic blind following. |
| Per-request timeout | 5 seconds connect \+ bounded read timeout. |
| Whole import | 30 seconds wall clock. |
| Pages | 10 maximum. |
| Depth | 2 maximum. |
| HTML response | 2 MiB/page. |
| Total import bytes | 10 MiB. |
| Accepted content | \`text/html\`, \`text/plain\` initially. |
| Decompression | Bound decompressed size; reject bombs. |
| Concurrency | Small per-import and global caps. |

### **22.4 Network-level defense**

* Run the scrape worker in a separate container with no route/credentials to PostgreSQL, Redis, control plane, Docker socket, or host services.  
* Add host/container egress firewall rules that deny private/link-local/metadata destination ranges in addition to application checks.  
* Use no-proxy/trust\_env=false so attacker-controlled environment proxy settings cannot alter routing.  
* Never return raw internal fetch errors/body content to the requester.

## **23\. Prompt Injection and LLM Security**

OWASP states that prompt injection cannot be perfectly prevented by model instructions alone and recommends privilege separation, external validation, least privilege, segregation of untrusted content, and human approval for high-risk actions. \[S10\]\[S11\]

### **23.1 Quarantined extraction model**

* Website text is processed by a model instance with zero tools, zero network access, zero ANS/DNS credentials, zero database credentials, and zero ability to execute code.  
* System instruction says the website is untrusted data, but security does not rely on that instruction. The architectural absence of tools is the real control.  
* The model may emit one JSON object matching the BusinessProfile schema and nothing else.  
* If the output fails JSON parsing, schema validation, content limits, or capability allowlist, discard it and retry with bounded count or require human review.  
* System prompts contain no secrets. A leaked prompt must not grant capabilities.

### **23.2 Capability allowlist**

The model cannot invent agent powers. A server-side allowlist maps safe capability IDs to prewritten handlers. Recommended MVP capabilities are read-only: \`business\_information\`, \`hours\`, \`location\`, \`menu\_catalog\`, \`services\_catalog\`, and \`faq\`. \`shell\`, \`filesystem\`, \`network\_fetch\`, \`dns\_write\`, \`ans\_write\`, \`payment\`, \`send\_email\`, and generic \`http\_request\` do not exist as generated-agent tools.

### **23.3 Remote-agent prompt injection**

* Remote agent output is never concatenated into a privileged system prompt that has tools.  
* Remote responses are parsed according to expected protocol schema and treated as quoted/untrusted content.  
* Instructions such as “ignore previous rules,” “call this URL,” “send your token,” or “run this tool” are data and have no control authority.  
* Agent Desk does not relay internal system prompts, private memory, environment variables, or credentials to remote agents.  
* If an LLM summarizes a remote response, that summarizer has no privileged tools.

### **23.4 Memory poisoning**

* No cross-user long-term memory in MVP.  
* Tenant knowledge can only be changed through authenticated owner workflow, not through public chat responses.  
* Conversation history is bounded and isolated by tenant/session; remote content cannot write into global policy memory.  
* If feedback/memory is added later, provenance, owner approval, TTL, and delete/reset controls are mandatory.

### **23.5 Denial of wallet / agent loops**

| Control | Default |
| :---- | :---- |
| Model calls/request | ≤ 2 for read-only answer; ≤ 3 for create/extract workflow. |
| Remote agent hops | ≤ 2\. |
| Tool calls | ≤ 5\. |
| Retries | ≤ 2 with exponential backoff; no infinite retry. |
| Input tokens | Hard maximum. |
| Output tokens | Hard maximum. |
| Per-user daily LLM budget | Configurable hard ceiling. |
| Global circuit breaker | Disable LLM/remote calls while preserving proof/read-only admin. |

## **24\. MCP Security**

MCP’s current security best-practices document explicitly identifies confused-deputy attacks, token passthrough, SSRF, state-handle hijacking, authorization URL injection, and overbroad scopes. \[S9\]

* Never pass an incoming MCP client bearer token unchanged to a downstream API or remote agent.  
* Validate token issuer, signature, expiry, audience, and scopes for the current server/resource. Acquire a separate downstream credential when needed.  
* Use minimal scopes and step-up authorization only for the exact protected capability. No wildcard/full-access scope.  
* Bind any state/workflow handle to the authenticated principal server-side; a guessed handle cannot access another user’s state.  
* Validate every externally supplied URL used during OAuth/client metadata discovery with the same SSRF policy.  
* Consent and redirect URIs are per-client and exact-match; do not accept broad wildcards.  
* Public MCP tool set is intentionally read-only and narrow.

## **25\. A2A Security**

A2A’s current specification requires encrypted production transport and server-side authorization boundaries for protected operations. Agent Cards are published via the well-known path and may be signed; sensitive extended-card information belongs behind authentication. \[S8\]

* HTTPS/TLS only in production; validate server identity on outbound connections.  
* Public Agent Card contains no secrets, private topology, PATs, internal admin URLs, or owner PII.  
* If Agent Card signing is supported by the installed official SDK, sign using a dedicated signing key/certificate and verify signatures when present. Do not invent non-standard fields.  
* Authentication requirements are declared in the Agent Card; protected skills enforce authorization server-side on every request.  
* A2A task/context identifiers are high-entropy and caller-scoped. Never treat possession of contextId/taskId as authorization.  
* Push/webhook functionality is disabled in MVP unless its callback URLs use the hardened SSRF policy.

## **26\. ANS Identity and Verification Policy**

ANS is used to establish registration identity and discovery metadata, not blanket behavioral trust. A malicious or flawed agent may still be ANS-registered; the supplied Webmesh rogue-supplier example explicitly demonstrates an ANS-registered identity whose transaction behavior is invalid. \[S16\]

### **26.1 Candidate verification checklist**

☐ Live ANS lifecycle is ACTIVE.

☐ Expected ANS name is syntactically valid and version handling follows semver policy.

☐ agentHost is a canonical FQDN and matches the endpoint hostname policy.

☐ Protocol is one we support (MCP/A2A) and transport is allowed.

☐ Endpoint uses HTTPS and passes SSRF/global-address rules.

☐ Agent Card/MCP metadata host and endpoint do not contradict ANS registration.

☐ Identity certificate is within validity period and its hostname/ANS URI semantics match the registration.

☐ Certificate chain verifies to an official/pinned ANS trust anchor obtained through approved documentation/provisioning—not a root supplied by the remote agent itself.

☐ If metadata hash/signature is advertised, it verifies. A mismatch blocks use and triggers re-resolution.

☐ Freshness timestamp is within policy; high-impact calls re-check immediately before execution.

☐ Locally revoked/blocked identities are denied even if remote registry still appears active during propagation.

### **26.2 Revocation and compromise**

* Expose an authenticated owner/admin revoke workflow that calls the ANS revocation endpoint for key compromise/cessation/etc. when applicable. \[S5\]  
* On suspected private-key compromise: disable local agent, stop traffic, revoke ANS registration/certificate, rotate keys, create new version/identity, and invalidate cached verification evidence.  
* Discovery cache TTL should be short; a cached ACTIVE result is never considered permanent.

## **27\. Key and Secret Management**

* GoDaddy PAT, LLM keys, DB/Redis passwords, session secrets, and private keys never enter Git, images, HTML, logs, prompts, screenshots, or proof JSON.  
* Use a host secrets manager if available. Hackathon fallback: root-readable environment file outside repository with \`chmod 600\`, injected into specific containers.  
* Each service receives only the secret it needs. Scraper receives none. Generated agent runtime receives at most the LLM key/limited provider credential and read-only DB access if necessary.  
* Private keys are generated with OS CSPRNG, stored encrypted/permission-restricted, and never returned through web APIs.  
* Proof endpoints expose fingerprints/public cert metadata only.  
* Provide rotation and emergency revocation runbooks. Current GoDaddy PAT docs support revocation and recommend secret-manager storage. \[S6\]\[S15\]

## **28\. TLS and Transport Security**

* Public HTTP redirects to HTTPS; protocols and API are HTTPS-only.  
* TLS 1.2 minimum, prefer TLS 1.3; disable obsolete protocols/ciphers via reverse-proxy defaults/config.  
* Outbound clients verify certificates and hostnames; never \`verify=False\`.  
* Use HSTS only after HTTPS is confirmed for all intended subdomains; \`includeSubDomains\` means every child host must support HTTPS.  
* No mixed-content assets in UI.  
* Admin/private service traffic stays on isolated Docker/private network; database and Redis do not bind public interfaces.

## **29\. Rate Limiting, DoS, and Resource Exhaustion**

OWASP API guidance calls unrestricted resource consumption a major API risk; this is especially important because website fetches, LLM calls, ANS calls, and agent fan-out have direct cost. \[S13\]

| Surface | Suggested starting limit |
| :---- | :---- |
| Login | 5 failures / 15 min / account \+ IP, then progressive delay. |
| Anonymous Q\&A | 30/min/IP \+ global concurrency cap. |
| MCP/A2A anonymous read | 60/min/IP with body and result caps. |
| Create/import | 3/hour/owner; 10 pages/import; one active import/owner. |
| ANS search | Cache short-lived results; 30/min/principal; global breaker. |
| Proof endpoint | 60/min/IP; no expensive live cert operation on every page view—cache briefly. |
| LLM | Per-request token caps \+ daily user/global spend ceilings. |
| Remote agent | 2 hops, strict timeout, response ≤ 1 MiB. |

## **30\. Replay, Idempotency, and Concurrency**

* State-changing API requests accept/generate idempotency keys bound to actor \+ operation \+ payload hash.  
* Nonce/replay entries are stored in Redis/Postgres with TTL; repeated state-changing requests return prior result or reject.  
* Optimistic locking/version fields prevent concurrent owner edits from silently overwriting configuration.  
* ANS registration for a tenant/version is single-flight using a database lock/advisory lock.  
* DNS challenge writes are exact-value and cleanup does not delete unrelated records.

## **31\. Supply Chain and Dependency Security**

* Pin dependency versions and commit a lockfile.  
* Prefer official A2A/MCP SDKs and well-maintained libraries. Minimize dependencies.  
* Run \`pip-audit\` (or equivalent) and dependency/license checks before deployment.  
* Container images use pinned tags/digests where practical and run as non-root.  
* Never automatically install packages suggested by website content, model output, remote agents, or MCP metadata.  
* CI secrets are scoped, masked, and unavailable to pull requests from untrusted forks.  
* Generate SBOM if time permits and document third-party services in \`SECURITY.md\`.

## **32\. Container, Host, and Network Hardening**

* Only ports 80/443 are public; SSH is key-only and ideally source-restricted. Database/Redis/app internal ports are private.  
* Run containers as non-root with read-only root filesystem where feasible, \`no-new-privileges\`, dropped Linux capabilities, memory/CPU/PID limits, and temporary writable tmpfs.  
* No Docker socket in application containers. No \`--privileged\`. No host network mode.  
* Scrape worker and public agent runtime are isolated from control plane networks.  
* Firewall explicitly denies ingress to database/Redis/internal services and egress to private/metadata ranges from scraper network.  
* Automatic security updates/patching where practical; reboot strategy understood.  
* Backups are encrypted and do not include unprotected production private keys unless deliberately secured.

## **33\. Logging, Monitoring, and Incident Evidence**

* Use structured JSON logs with timestamp, correlation ID, actor/tenant ID (non-sensitive), route/tool, decision, latency, and result code.  
* Redact \`Authorization\`, cookies, PATs, API keys, CSRF tokens, private keys, passwords, raw session IDs, and sensitive prompts.  
* Sanitize CR/LF/control characters in user-controlled values before logging to avoid log injection.  
* Audit before and after: login, logout, create tenant, publish, ANS register, DNS validation, ACTIVE transition, revoke, key rotation, verification failure, trust/card drift, authorization denial.  
* Alert/circuit-break on unusual import rates, repeated SSRF blocks, repeated auth failures, high LLM spend, remote-agent verification failures, or sudden Agent Card changes.

## **34\. Data Privacy and Retention**

* Import only public website data needed for the agent; avoid collecting personal data that the owner did not request.  
* Do not scrape authenticated/private pages or bypass access controls.  
* Owner can delete draft/imported data and disable an agent. Define what evidence/audit records remain for security purposes.  
* Conversation logs default to short retention and avoid sensitive content; provide configurable logging off/redaction.  
* Never use scraped business content to train a model unless explicitly authorized by the owner/provider terms.

# **V. Webmesh Interoperability and Adversarial Coverage**

## **35\. What Webmesh Provides**

Webmesh publishes a public fleet of A2A/MCP agents. Its machine-readable index currently lists agents for ANS discovery/verification, DNS/TLS diagnostics, SEO/LLM discoverability, travel authorization/supply/audit, a rogue supplier, and a Fraud Agent attack battery. \[S16\]

| Webmesh service | How Agent Desk should use/treat it |
| :---- | :---- |
| Webmesh Agent | Useful public interoperability target for ANS discovery/verification by FQDN. Treat responses as untrusted data. |
| Domain DNS/SSL Doctor | Optional read-only external diagnostic target. Do not give it internal URLs or secrets. |
| SEO & LLM Discovery Analyzer | Optional public-page analysis target. Never send private/admin pages. |
| Traveler / Supplier / Spending Authority | Out of MVP scope unless implementing transactions. Do not automatically grant transaction authority. |
| Auditor Agent | Useful model for independent evidence verification; optional interop. Do not outsource local authz decisions. |
| Rogue Supplier | Important lesson: ANS identity can be valid while business/authorization behavior is invalid. |
| Fraud Agent | Its published battery is transaction-specific; our MVP blocks unsupported transaction/payment operations by design. |

## **36\. Published Fraud Agent Battery — Required Defensive Posture**

The current Fraud Agent page describes 10 targeted attacks plus 3 structural probes: replayed DPoP proof, tampered/underpaid/signed mandates, quote swap, wrong audience, wrong scope, wrong DPoP key, corrupt JWS, superseded mandate format, unknown signing key, settlement replay, canonicalization drift, pay-to binding, and signed-card drift. \[S16\]

| Published case | MVP response | If transaction features are ever added |
| :---- | :---- | :---- |
| replay\_booking | No AP2/booking/payment tool exists → reject as unsupported; no side effect. | Use one-time proof/nonces and replay store; bind proof to request and caller. |
| underpay\_booking / tamper\_mandate | Reject unsupported authorization object. | Verify signature before trusting any field; independently enforce price/amount policy. |
| underpay\_valid\_sig | Reject unsupported. | A valid signature does not imply sufficient authorization; enforce amount ceiling/floor and object binding. |
| quote\_swap\_attack | Reject unsupported. | Bind authorization to immutable quote/object ID and exact transaction parameters. |
| wrong\_audience\_attack | Reject unsupported. | Validate token/mandate audience equals the exact target service. |
| wrong\_scope\_attack | Reject unsupported. | Check required scope server-side for each operation; no wildcard scopes. |
| wrong\_dpop\_key\_attack | Reject unsupported. | Verify proof key binding to the authorized key/thumbprint using vetted library. |
| corrupt\_jws\_attack | Strict parser rejects malformed/invalid signed objects without crashing. | Fail closed on any signature/parser error; do not “best effort” parse. |
| superseded\_format\_attack | Unknown transaction schema/version is rejected. | Explicit version allowlist and mandatory fields; no lenient legacy fallback. |
| unknown\_key\_mandate | Unknown signing key is untrusted. | Trust only keys chained/pinned through approved authority metadata. |
| replay\_settled | No settlement operation exists. | Idempotency/replay ledger prevents a consumed authorization from executing twice. |
| canonicalization\_probe | No signed transaction JSON in MVP. | Use one canonicalization implementation (e.g., standard required by protocol) before signing/verifying. |
| payto\_binding\_check | No pay-to address exists. | Bind settlement address to signed/verified service metadata; drift requires re-approval. |
| card\_drift\_watch | Hash public Agent Card; unexpected change triggers re-verification and audit event. | For signed cards, verify signature \+ canonicalization; compare against ANS/version/re-registration state. |

## **37\. Additional Attack Matrix for Agent Desk**

| Attack | Primary control | Secondary control / expected result |
| :---- | :---- | :---- |
| Direct prompt injection | Model has no privileged tools for public Q\&A. | Output/schema policy; no secrets in system prompt. |
| Indirect prompt injection in scraped page | Quarantined extraction model with no tools/secrets. | Strict JSON schema \+ human preview; injected instructions become inert data. |
| SSRF to localhost/RFC1918/metadata | IP/range rejection \+ pinned resolution. | Network egress firewall; redirect revalidation. |
| DNS rebinding | Resolve-and-pin checked address for connection. | Egress firewall; revalidate each hop. |
| Redirect SSRF | Manual redirect handling with full policy per hop. | Max 3 redirects; HTTPS/port policy. |
| XSS via website/LLM/agent response | Contextual escaping; no raw HTML. | Strict CSP; nosniff. |
| CSRF on publish/revoke | CSRF token \+ Origin/Fetch-Metadata checks. | SameSite strict \_\_Host cookie. |
| Session theft/fixation | Secure opaque sessions; rotate at login. | Short TTL, revocation, HttpOnly. |
| IDOR/BOLA | Owner/tenant predicate on every object query. | Authorization tests for cross-tenant IDs. |
| Mass assignment | Explicit Pydantic request schemas, extra=forbid. | Separate input/output models. |
| SQL injection | ORM/bound parameters only. | Least-privilege DB role. |
| Command injection | No shell use in request path; no generated code. | gddy only in admin scripts with arg arrays. |
| Path traversal | No user-chosen filesystem paths. | UUID/database storage. |
| Token passthrough/confused deputy | Validate audience/scope; never forward inbound token. | Acquire separate downstream token or anonymous call. |
| MCP state-handle hijack | Handle bound to authenticated principal. | High-entropy handle \+ TTL. |
| Malicious remote Agent Card | Schema/size/HTTPS/SSRF validation; no secrets. | Signature verification when present; card hash drift monitoring. |
| ANS identity valid but agent malicious | Identity treated separately from behavior/authorization. | Capability allowlist, no high-impact operations, policy enforcement. |
| Revoked agent used from cache | Short cache \+ recheck before sensitive call. | Local blocklist/incident switch. |
| Replay/idempotency abuse | Request IDs/nonces/idempotency store. | Atomic DB transactions. |
| DoS/DoW | Rate, body, concurrency, token, time, hop caps. | Circuit breakers and budget alerts. |
| Credential stuffing | Login rate limits \+ strong password hash \+ MFA option. | Generic errors and anomaly logging. |
| Secret leakage in logs | Central redaction filter. | Security tests scan logs for seeded canary secrets. |
| Supply-chain package compromise | Pinned/locked deps, audit, minimal packages. | Non-root/read-only containers. |
| Host header poisoning | TrustedHost \+ configured canonical origin. | Proxy strips spoofed forwarding headers. |
| Clickjacking | CSP frame-ancestors none. | X-Frame-Options DENY. |
| CORS data theft | No CORS by default / exact origins only. | No browser bearer tokens in localStorage. |

# **VI. Verification, Security Testing, and Deployment Runbook**

## **38\. Gate Acceptance Tests**

☐ From an external machine, \`https://desk.BASE\_DOMAIN/.well-known/agent-card.json\` returns a valid A2A Agent Card over trusted TLS.

☐ From an external MCP client, \`https://desk.BASE\_DOMAIN/mcp\` initializes and a read-only tool call succeeds.

☐ At least one generated agent hostname behaves similarly.

☐ \`gddy auth status\` and environment output show production environment without printing token material.

☐ Live ANS agent detail/search returns the exact host/version with ACTIVE state.

☐ Live certificate-management call returns the agent identity certificate; verifier validates expected binding/trust policy.

☐ Proof page reports PASS only from live checks or short-lived cached live evidence; it never hardcodes success.

☐ ANS search from Agent Desk discovers at least one real external or separately registered agent and successfully communicates after verification.

☐ A deliberately invalid/unverified/revoked test candidate is visibly rejected.

## **39\. Automated Security Tests**

Implement these as tests against local/staging instances. They are defensive tests of our own code; do not aim them at third-party systems without authorization.

☐ SSRF: localhost, IPv4/IPv6 private, link-local, metadata IP, encoded/alternate IP forms, userinfo confusion, redirect-to-private, DNS-rebinding test resolver.

☐ Prompt injection: page text containing override/exfiltration/tool-use instructions; output must remain schema-bounded and no privileged action occurs.

☐ XSS: script tags, event handlers, SVG/data URLs, malformed HTML, remote-agent HTML; UI must render as text and CSP remains intact.

☐ CSRF: state-changing request with missing/wrong token, cross-site Origin, and missing Fetch metadata; all rejected.

☐ Authorization: owner A attempts tenant/registration IDs owned by B; all read/write operations denied.

☐ Mass assignment: add role/owner\_id/status/ans\_name fields to public request; rejected/ignored according to schema, never applied.

☐ SQLi and template injection strings in every text field; no query/code execution.

☐ Command/path injection strings in slug/domain fields; validation rejection and no process/file access.

☐ Rate-limit/resource tests: large body, excessive pages, slow response, huge decompression, repeated LLM calls, remote-agent loop; budgets enforced.

☐ MCP: wrong audience token, overbroad scope assumptions, replayed state handle, malicious authorization URL; fail closed.

☐ Agent metadata: malformed Agent Card, oversized card, HTTP/non-HTTPS endpoint, private endpoint, card drift, endpoint mismatch, revoked/expired identity.

☐ Logging: seeded fake secret never appears in application/audit/access logs.

☐ Session: fixation attempt, logout reuse, expired cookie, cookie received by generated subdomain; all fail.

☐ Error handling: malformed signed/JSON/protocol objects return safe 4xx error and process stays healthy.

## **40\. Security Self-Test Output**

SECURITY SELF-TEST

\[PASS\] HTTPS-only public surface

\[PASS\] Trusted-host enforcement

\[PASS\] CSRF protection

\[PASS\] Cross-tenant authorization

\[PASS\] SSRF private IPv4

\[PASS\] SSRF private IPv6

\[PASS\] SSRF metadata service

\[PASS\] Redirect-to-private blocked

\[PASS\] DNS rebinding simulation blocked

\[PASS\] Prompt-injection ingestion cannot call tools

\[PASS\] XSS payload encoded

\[PASS\] Rate limits enforced

\[PASS\] Remote agent endpoint safety

\[PASS\] Token audience enforcement (if auth enabled)

\[PASS\] Replay/idempotency behavior

\[PASS\] No seeded secret in logs

 

ANS EVIDENCE

\[PASS\] agentHost exact match

\[PASS\] lifecycle ACTIVE

\[PASS\] identity certificate valid/bound

\[PASS\] public TLS valid

\[PASS\] A2A card valid

\[PASS\] MCP round-trip valid

## **41\. Deployment Order**

* 1\. Create repository, secrets file outside Git, and production environment configuration.  
* 2\. Point \`desk.BASE\_DOMAIN\` and \`demo.BASE\_DOMAIN\` DNS to the VPS.  
* 3\. Configure firewall; deploy Caddy \+ app \+ private Postgres/Redis.  
* 4\. Verify public HTTPS before ANS registration.  
* 5\. Install \`gddy\`; authenticate to prod; verify \`gddy auth status\` and environment.  
* 6\. Generate Agent Desk identity/server keys and CSRs.  
* 7\. Submit production ANS registration; add exact DNS challenge; verify; poll ACTIVE.  
* 8\. Retrieve identity/server certificate evidence; populate live proof page.  
* 9\. Register demo business agent separately; verify ACTIVE.  
* 10\. Test Agent Desk discover → verify → communicate against demo and at least one external compatible agent.  
* 11\. Run full unit/integration/security suite.  
* 12\. Export redacted evidence bundle/screenshots for judging backup.

## **42\. Incident Response / Kill Switches**

| Incident | Immediate action |
| :---- | :---- |
| GoDaddy PAT suspected leaked | Disable registration/DNS write feature; revoke PAT; rotate; audit every ANS/DNS mutation. |
| ANS private identity key compromise | Disable agent; revoke ANS registration with KEY\_COMPROMISE; rotate key; publish new version/identity. |
| LLM key leaked | Disable LLM calls; rotate provider key; retain read-only static answers/proof. |
| SSRF bypass suspected | Disable website import and remote URL fetch; leave existing verified read-only agents online; inspect egress/audit logs. |
| Generated tenant compromise | Disable that tenant/host; remove route; revoke identity if needed; other tenants stay isolated. |
| Unexpected Agent Card/metadata drift | Block candidate, re-resolve ANS/certificate state, require re-approval before use. |
| DoS/abuse | Raise block/rate controls, disable expensive endpoints, preserve proof/health. |

## **43\. Three-Minute Judging Demo**

0:00–0:25  Problem

“Anyone can claim to be an AI agent for a business. How does another AI find the real one and know where to talk to it?”

 

0:25–1:05  Create

Paste a controlled site → show extracted structured profile → agent becomes reachable.

Show public HTTPS \+ A2A card \+ MCP tool.

 

1:05–1:35  ANS identity / gate proof

Open Proof: production, ACTIVE, ANS name, identity certificate summary, endpoint checks.

 

1:35–2:15  Discover \+ verify

Ask Agent Desk for the capability. Show live ANS search and verification checks.

 

2:15–2:40  Communicate

Agent Desk invokes the remote agent over MCP/A2A and returns the answer.

 

2:40–3:00  Security / rejection

Show a mismatched/unverified or deliberately altered candidate being rejected.

Close: “We built the on-ramp and verification layer for the open agent web.”

# **VII. Claude One‑Shot Production Prompt**

**The following prompt is also delivered as a separate plain-text file for easy copy/paste. It deliberately tells Claude not to fake external gate success and to fail closed at credential/domain boundaries.**

You are Claude Code acting as a principal security engineer, staff backend engineer, protocol engineer, and DevOps engineer. Your task is to BUILD, TEST, HARDEN, AND PREPARE FOR DEPLOYMENT a production-oriented hackathon project named \*\*Agent Desk\*\* for the VTHacks 14 GoDaddy “Best Use of ANS” track.

DO NOT merely write a plan. Create the repository/files, implement the application, run tests/linters/security checks available in the environment, fix failures, and produce a final concise deployment/gate report. If you lack shell/filesystem access, output the complete repository file-by-file instead. Do not claim a live external gate is passed unless you have actually observed the live evidence.

### **0\. PROJECT MISSION**

Agent Desk has two user-facing abilities:

1\) CREATE: an authenticated website owner supplies a public website and an agent hostname. The system safely fetches the public site, extracts useful business facts into strict structured data, creates a small read-only AI business assistant using a PREWRITTEN generic agent runtime, exposes that agent on public HTTPS over BOTH A2A and MCP, and registers it with GoDaddy ANS until the registration is ACTIVE.

2\) FIND: a human or another agent asks Agent Desk for a capability. Agent Desk searches GoDaddy ANS, verifies the discovered candidate’s live ANS lifecycle/host/endpoints/identity evidence, applies outbound network safety policy, and then communicates with the verified candidate over A2A or MCP. Remote output is always untrusted data and may NEVER directly trigger privileged local actions.

One-sentence product statement:

“Agent Desk turns controlled websites into verified, discoverable AI agents, then helps other agents discover, verify, and communicate with them.”

### **1\. HARD EVENT GATES — ALL FIVE ARE REQUIRED**

Treat these as acceptance criteria, not optional features:

GATE 1 — Reachable agent endpoint:

* Agent Desk MUST expose a standards-compliant A2A endpoint and a Streamable-HTTP MCP endpoint.  
* At least one generated demo business agent MUST expose both A2A and MCP as well.  
* Publish an A2A Agent Card at \`/.well-known/agent-card.json\`.  
* Publish appropriate MCP metadata if supported/needed by the current official MCP SDK and ANS registration.

GATE 2 — Public HTTPS:

* Production host(s) must be reachable via HTTPS from the public internet.  
* Use Caddy as reverse proxy/TLS terminator unless the existing environment has an equally secure alternative.  
* Application/database/Redis/internal ports must not be public.

GATE 3 — Owned MLH domain:

* Read \`BASE\_DOMAIN\` from environment. Never invent or purchase a domain.  
* Defaults: \`desk.${BASE\_DOMAIN}\` for Agent Desk and \`demo.${BASE\_DOMAIN}\` for the first generated business agent.  
* Only allow generated subdomains that are sanitized children of BASE\_DOMAIN unless an external domain goes through ownership verification.

GATE 4 — production GoDaddy credential \+ CLI flow \+ ANS ACTIVE:

* Current public GoDaddy ANS documentation identifies ANS auth as PAT/Bearer. The hackathon may provide a specific production key/credential flow. FOLLOW EVENT INSTRUCTIONS IF THEY DIFFER.  
* Install/use the current \`gddy\` CLI. Do not invent stale commands. First inspect \`gddy \--help\`, \`gddy tree\`, \`gddy search ans\`, \`gddy api \--help\`, \`gddy auth status\`, and \`gddy env get\`.  
* Set/use production environment. If a PAT is provided, store it using the supported production credential path or inject as a secret; never print it.  
* Implement ANS REST client using current official schema/OpenAPI. Registration currently uses \`/v1/agents/register\`; verify this from live docs/spec before calling.  
* Generate identity CSR and server CSR (or current supported BYOC fields).  
* Submit host, semantic version, endpoints, protocols/transports, advertised functions, identity CSR, and server certificate material required by current schema.  
* Handle DNS-01/PENDING\_VALIDATION challenge safely. If GoDaddy manages BASE\_DOMAIN and CLI DNS commands are available, use \`gddy dns\` with exact record name/value. Never expose generic DNS mutation to public HTTP.  
* Trigger official validation endpoint(s), poll actual agent details, and do not mark local status ACTIVE until GoDaddy reports ACTIVE.  
* Capture redacted proof: production environment, agentId, ansName, ACTIVE status, timestamps. NEVER fake ACTIVE.

GATE 5 — Verification evidence:

* Implement \`/proof\` (human) and \`/api/proof\` (JSON) for the Agent Desk host, plus tenant proof page if feasible.  
* It must be generated from actual current checks or short-lived cached checks and include no secrets.  
* Evidence should include: expected host; ANS agentId/ansName/lifecycle; declared endpoints; last live ANS check; public HTTPS check; TLS version/hostname/certificate fingerprint/expiry; A2A Agent Card parse/hash/skills; MCP handshake/tool probe; identity certificate issuer/subject/SAN/serial/fingerprint/validity; verification decision and reasons.  
* Retrieve ANS identity certificate using the official certificate-management API if available. Validate its chain/binding using an official/pinned trust anchor obtained through approved ANS documentation/provisioning. DO NOT trust a root certificate merely because a remote agent sends it to you.  
* If exact official trust-anchor verification cannot be completed because the event has not provided required root material, label that specific check INCOMPLETE rather than PASS. All other checks should still work.

### **2\. CURRENT EXTERNAL FACTS TO VERIFY, NOT BLINDLY ASSUME**

Use live official docs/CLI/OpenAPI available during implementation. The following are expectations from current public documentation, but verify them:

* ANS registration accepts agentDisplayName, agentHost, endpoints, version, identityCsrPEM, and server CSR/BYOC fields.  
* External-domain registration can return status PENDING\_VALIDATION plus a DNS\_01 challenge.  
* Agent details can return agentStatus ACTIVE.  
* Search exists for registered agents and may expose lifecycle, host, ANS name, endpoints, functions, and trust/relevance scores.  
* Resolution exists by agentHost \+ version.  
* Certificate management exposes identity/server certificate retrieval.  
* Revocation exists and supports key-compromise/cessation-style reasons.  
* A2A public Agent Card standard path is \`/.well-known/agent-card.json\`.  
* MCP Streamable HTTP is appropriate for a public MCP endpoint.

When library/spec versions differ, implement against the currently installed official SDK and record the exact version in README.

### **3\. REQUIRED STACK AND REPOSITORY**

Prefer this stack unless the existing repository already has a strong reason not to:

* Python 3.12  
* FastAPI / Starlette  
* Official A2A Python SDK  
* Official MCP Python SDK  
* Pydantic v2 strict schemas  
* SQLAlchemy 2 \+ PostgreSQL  
* Redis for rate limiting, replay/idempotency, and short-lived caches  
* \`cryptography\` for keys/CSRs/certificate inspection  
* \`httpx\` for trusted outbound API calls  
* a hardened arbitrary-web fetcher using aiohttp/custom resolver or equivalent that can pin validated DNS answers  
* BeautifulSoup/lxml for static HTML extraction; never execute page JavaScript  
* Jinja2 server-rendered UI with autoescape \+ static JS/CSS; no frontend bearer tokens in localStorage  
* Caddy reverse proxy  
* Docker Compose  
* pytest \+ pytest-asyncio  
* ruff \+ mypy if practical  
* pip-audit or equivalent dependency audit

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

### **4\. PRODUCT DATA MODEL**

Implement explicit models/tables for:

User:

* id UUID  
* username/email  
* argon2id password\_hash  
* role enum OWNER/ADMIN  
* disabled\_at  
* optional mfa metadata (do not block MVP if MFA library unavailable)

Tenant:

* id UUID  
* owner\_id  
* display\_name  
* source\_url/source\_domain  
* agent\_host  
* state enum DRAFT/INGESTED/DEPLOYED/REGISTRATION\_SUBMITTED/PENDING\_VALIDATION/ACTIVE/FAILED/REVOKED/DISABLED  
* current\_version

AgentConfig:

* tenant\_id  
* semantic version  
* strict normalized BusinessProfile JSON  
* allowed\_capabilities enum list  
* content hash  
* created\_at/published\_at  
* immutable after publication; new publication creates a new config version

ANSRegistration:

* tenant\_id/version  
* agent\_id  
* ans\_name  
* lifecycle/status  
* challenge metadata excluding secrets where possible  
* last\_checked\_at  
* last\_error safe code

CertificateEvidence:

* type IDENTITY/SERVER/TLS\_OBSERVED  
* public PEM if safe  
* issuer/subject/SAN/serial  
* SHA-256 fingerprint  
* valid\_from/valid\_to  
* chain verification result \+ reason  
* NEVER private key

AuditEvent:

* append-only semantic event  
* timestamp  
* correlation\_id  
* actor id/type  
* action  
* target tenant/agent  
* outcome  
* redacted metadata

Use migrations. Every tenant-scoped operation must enforce owner\_id/team authorization server-side.

### **5\. CREATE WORKFLOW — IMPLEMENT END TO END**

A. AUTHENTICATED OWNER INPUT

* Admin/owner UI form takes a source HTTPS website and desired agent subdomain/hostname.  
* Public signup can be disabled by default for hackathon; seed owner credentials through a secure one-time setup command/environment variable. Do not hard-code passwords.  
* Desired agent hostname must be a sanitized FQDN under BASE\_DOMAIN for the automatic path.  
* Do not claim ownership from scraping. Scraping a page is not identity proof.

B. SAFE WEBSITE FETCHER

This is a HIGH-RISK SSRF boundary.

Implement deterministic URL validation:

* Accept HTTPS only in production. If allowing HTTP for import convenience, allow only ports 80/443 and treat it as a step toward a validated HTTPS redirect.  
* Reject schemes other than http/https; production fetch target should end at https.  
* Reject userinfo, fragments when not needed, control chars, backslash authority ambiguity, malformed IDN/hostnames, unusual ports.  
* Prefer rejecting IP literal URLs.  
* Resolve DNS yourself.  
* For every A/AAAA result, require globally routable addresses and explicitly reject loopback, RFC1918 private, link-local, multicast, unspecified, reserved/documentation/test ranges, carrier-grade NAT, and cloud metadata/link-local ranges including 169.254.169.254.  
* Protect against DNS rebinding/TOCTOU by pinning the validated resolved address into the actual connection. Do not simply resolve, check, and then let another resolver perform the connection.  
* \`trust\_env=False\`; do not inherit arbitrary proxy settings.  
* Manual redirects only, maximum 3; run the full URL \+ DNS/IP validation on every redirect.  
* Bound connect/read/whole-operation timeouts.  
* Maximum pages 10, crawl depth 2, max HTML 2 MiB/page, max decompressed/total import 10 MiB.  
* Accept only text/html and text/plain initially.  
* Do not execute JavaScript, plugins, media, PDFs, ZIPs, office docs, binaries, or SVG as active content.  
* Do not forward authorization cookies/headers from Agent Desk to imported site.  
* Put the scrape worker in a separate container/network with NO GoDaddy PAT, no DB admin credential, no Redis admin credential, no host mounts, and no Docker socket.  
* Add deployment firewall/egress rules denying private/link-local/metadata networks from the scrape worker as a second layer.

C. HTML/TEXT EXTRACTION

* Parse static HTML.  
* Remove script/style/noscript/template/iframe/object/embed and unsafe metadata.  
* Extract semantic/visible-ish text: title, headings, nav labels if useful, address/contact, structured data that can be parsed safely, main content.  
* Bound character counts.  
* Do not treat HTML comments, scripts, CSS, hidden fields, or meta instructions as trusted instructions.

D. QUARANTINED EXTRACTION MODEL

* The extraction LLM has NO TOOLS, NO network tools, NO shell, NO DNS/ANS APIs, NO database admin rights, NO secrets.  
* It receives untrusted page text and must emit ONLY a strict JSON BusinessProfile.  
* Security MUST NOT depend on “ignore prompt injection” wording; the absence of privileges is the real control.  
* BusinessProfile should include bounded fields such as business\_name, description, address, public contact, hours, services, menu\_items, faq, source\_urls.  
* Explicit capability enum allowlist. Safe MVP: business\_information, hours, location, menu\_catalog, services\_catalog, faq.  
* Forbidden generated capabilities: shell, filesystem, arbitrary\_http, dns\_write, ans\_write, payment, purchase, send\_email, account\_admin, secrets, generic\_tool\_execution.  
* Parse and validate with Pydantic \`extra='forbid'\`, length/array bounds, URL validation, enum validation.  
* If invalid, retry at most once/twice with bounded tokens; otherwise require owner review.  
* Owner sees a preview and explicitly confirms imported facts before publish.

E. GENERIC AGENT RUNTIME

* DO NOT generate executable Python/JS code from website content.  
* One trusted agent runtime serves many tenants based on validated Host → tenant mapping from DB.  
* Never use user input as a filesystem config path.  
* Tenant agent has read-only access to its own config and no cross-tenant access.  
* Public Q\&A may call the configured LLM provider, but the model has no privileged tools.  
* Provide an extractive/deterministic fallback answer mode if no LLM key exists so protocol/gate testing still works.

F. DEPLOY/PUBLISH

* Once config is approved, make the hostname route reachable through Caddy and generic runtime.  
* Verify externally from a separate process/client before ANS registration.  
* A2A card and MCP metadata are generated from trusted config, not raw model HTML.

G. ANS REGISTRATION

* Generate private keys securely using OS CSPRNG. Use a broadly supported algorithm accepted by current ANS docs; do not guess unsupported algorithms. Prefer RSA-3072 or current recommended algorithm after checking schema/docs.  
* Store private keys in service-specific mounted secret directory with restrictive permissions; never return via web API.  
* Generate identity CSR and server CSR according to current ANS schema. Base64/PEM encode exactly as current API expects.  
* Register both A2A and MCP endpoints with function/capability metadata.  
* Handle PENDING\_VALIDATION DNS\_01 challenge.  
* Only DNS record allowed to be modified automatically is the exact challenge record under the verified base domain/agent host. No generic DNS write endpoint.  
* If using \`gddy dns\`, pass arguments as subprocess array from trusted server-generated values; never shell-concatenate. Prefer direct GoDaddy DNS REST/CLI administrative script outside request path.  
* Verify challenge using official endpoint and poll status with timeout/backoff until ACTIVE or terminal failure.  
* Retrieve public identity/server certificates and store public evidence.

### **6\. FIND / DISCOVER / VERIFY / COMMUNICATE WORKFLOW**

A. QUERY NORMALIZATION

* Human query is converted to a small internal capability request object. The model may classify intent but cannot directly choose arbitrary URLs or issue network/tool calls.  
* Use bounded enums/tags and safe text.

B. ANS SEARCH

* Call current production ANS search endpoint.  
* Filter/default to ACTIVE.  
* Support exact FQDN resolution path for demo/interoperability.  
* Keep raw external response out of logs if it contains unexpected sensitive data; store only needed normalized fields.

C. VERIFY EACH CANDIDATE

Fail closed if any mandatory check fails:

### **1\. lifecycle/status ACTIVE from live or very fresh ANS data.**

### **2\. canonical agentHost.**

### **3\. supported protocol MCP or A2A.**

### **4\. endpoint HTTPS.**

### **5\. endpoint host relationship matches registration policy.**

### **6\. endpoint destination passes outbound SSRF/global-address rules.**

### **7\. retrieve agent detail/resolution; no contradiction with search result.**

### **8\. retrieve identity certificate from official ANS API when available.**

### **9\. verify certificate validity and hostname/ANS URI binding.**

### **10\. verify chain to approved ANS trust anchor; do not trust remote-supplied root automatically.**

### **11\. fetch A2A Agent Card / MCP metadata with strict time/size/content-type limits.**

### **12\. parse schema; no code execution.**

### **13\. verify metadata signature/hash if current standards/ANS record provides one. If the official A2A SDK supports card signatures, use it. Do NOT invent signature fields.**

### **14\. store card hash. Unexpected drift forces re-resolution/re-verification and audit event.**

### **15\. check local blocklist/revocation policy.**

D. COMMUNICATE

* Prefer the verified advertised protocol.  
* Outbound request time limit and max response size.  
* NEVER forward the incoming user/MCP bearer token to a remote agent.  
* If remote auth is required, use an explicit remote credential obtained for that resource, validate scopes/audience, and keep it server-side.  
* Remote agent response is UNTRUSTED DATA. It cannot call local tools, alter policy, request secrets, or redirect Agent Desk to arbitrary URLs.  
* If summarizing remote output with an LLM, use an unprivileged summarizer with no tools/secrets.

### **7\. WEB APPLICATION SECURITY — IMPLEMENT CONCRETELY**

AUTHENTICATION

* Use Argon2id password hashing via a reputable package.  
* Generic login failure messages.  
* Login rate limiting per account \+ IP; progressive delays.  
* Optional TOTP/WebAuthn for admin if feasible.  
* Re-authenticate before revocation/key rotation.

SESSIONS

* Opaque server-side sessions.  
* Cookie name \`\_\_Host-agentdesk\_session\`.  
* Secure; HttpOnly; SameSite=Strict; Path=/; no Domain attribute.  
* Rotate on login/role change.  
* Idle timeout \+ absolute timeout.  
* Store hashed session token server-side; support revoke-all.  
* NEVER store auth/access/refresh tokens in localStorage/sessionStorage.

CSRF

* Every cookie-authenticated state-changing browser route requires server-generated per-session CSRF token.  
* Verify Origin/Referer against canonical admin origin.  
* Enforce Fetch Metadata policy for unsafe browser requests.  
* GET/HEAD/OPTIONS must have no state changes.

AUTHORIZATION / BOLA / IDOR

* Every tenant/config/registration query is filtered by current owner/team membership.  
* Role checks server-side.  
* Do not rely on hidden buttons.  
* Tests must try cross-tenant UUID access and assert 403/404 without data leakage.

MASS ASSIGNMENT

* Dedicated Pydantic input models with only writable fields and \`extra='forbid'\`.  
* Never bind DB model directly to request JSON.

XSS

* Jinja autoescape ON.  
* No raw HTML from user/site/LLM/ANS/remote agent.  
* No \`innerHTML\` with untrusted values.  
* If Markdown is added, disable raw HTML and use allowlist sanitizer.  
* Validate links/schemes.

CSP / HEADERS

Set via Caddy/app and test:

* \`Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests\`  
* HSTS \`max-age=63072000; includeSubDomains\` only after all subdomains are HTTPS-ready.  
* X-Content-Type-Options nosniff  
* Referrer-Policy no-referrer  
* Permissions-Policy camera=(), microphone=(), geolocation=(), payment=()  
* Cross-Origin-Opener-Policy same-origin  
* X-Frame-Options DENY as legacy defense-in-depth

CORS

* No CORS if same-origin UI/API.  
* If needed, exact configured HTTPS origins only. Never \`\*\` with credentials. Never reflect arbitrary Origin.

SQL INJECTION

* SQLAlchemy/bound params only; no f-string/raw concatenated SQL.  
* DB account least privilege, not superuser.  
* Validate sort/filter field names via enums.

COMMAND INJECTION / RCE

* No shell=True, eval, exec, dynamic code generation, or untrusted dynamic imports.  
* Public app must not execute \`gddy\` based on raw request content.  
* Docker socket never mounted.

PATH TRAVERSAL

* No user-controlled file paths.  
* Config addressed by DB UUID, not filename.  
* Upload feature omitted from MVP.

HOST HEADER / PROXY TRUST

* TrustedHost middleware allows only BASE\_DOMAIN and intended subdomains.  
* Caddy is only public ingress.  
* Trust forwarding headers only from Caddy private network.  
* Generate absolute URLs from configured canonical origin, not arbitrary Host/X-Forwarded-Host.

OPEN REDIRECT

* Redirect targets are internal named routes/relative paths, not arbitrary URLs.

ERRORS

* DEBUG=false in production.  
* Safe structured error codes \+ correlation IDs; no stack trace/secrets/internal topology to clients.

### **8\. MCP SECURITY — REQUIRED**

Follow current official MCP security best practices.

* Token passthrough is forbidden. Validate issuer/signature/expiry/audience/scope. Do not relay incoming token downstream.  
* Prevent confused-deputy behavior: per-client consent where OAuth proxying is involved, exact redirect URIs, state/CSRF checks, no broad consent reuse.  
* State/workflow handles are high entropy, time-limited, and bound server-side to the authenticated caller; possession is not authorization.  
* OAuth/auth metadata URLs use the same SSRF-safe fetch policy. Reject javascript/data/file/vbscript and non-HTTPS production auth URLs.  
* Least-privilege scopes. No \`\*\`, \`all\`, or \`full-access\`. Request/elevate only scopes needed by the specific operation.  
* Public MCP tools are read-only. Any future high-impact tool must be separate, authenticated, scope-protected, audited, idempotent, and human-confirmed.

### **9\. A2A SECURITY — REQUIRED**

Follow current official A2A spec/SDK.

* HTTPS/TLS production only.  
* Serve public Agent Card at standard well-known location.  
* Public card contains no secrets/internal admin endpoints.  
* If installed SDK supports Agent Card signatures, implement using standard fields/canonicalization and verify on clients. Do not invent proprietary signature fields.  
* Protected skills declare auth requirements and enforce authz on every request.  
* Task/context IDs are caller-scoped and not authorization tokens.  
* Disable push/webhook callbacks in MVP unless SSRF-safe callback validation and authentication are implemented.

### **10\. ANS IDENTITY VS BEHAVIORAL TRUST**

A verified ANS identity tells us who/what identity is registered; it does not prove the remote agent is honest, bug-free, or authorized for every action.

* Treat an ACTIVE ANS agent as externally identified but still untrusted software.  
* Never grant extra local capabilities solely because trustScore is high.  
* For every call, enforce our own tool/capability/data policy.  
* Revocation/expired/inactive status fails closed.  
* Recheck status before any future high-impact action.

### **11\. WEBMESH INTEROPERABILITY AND ATTACK-BATTERY DEFENSE**

Public Webmesh index: https://webmesh.ai/.well-known/agents-index.json

Useful interop endpoints include agent.webmesh.ai, dnsdoc.webmesh.ai, seo.webmesh.ai, auditor.webmesh.ai, rogue-supplier.webmesh.ai, and fraud.webmesh.ai.

IMPORTANT: The published Fraud Agent attack battery is primarily for AP2/x402/travel supplier transaction authorization. OUR MVP DOES NOT IMPLEMENT PAYMENT/BOOKING/SPENDING AUTHORITY. Therefore all such transaction requests MUST fail closed as unsupported and must never cause side effects. Do not pretend a transaction test “passed” if it never targeted our surface; document applicability correctly.

Still implement generic defenses inspired by the battery:

* Replay protection/idempotency for our own state-changing endpoints.  
* Strict schema/version parsing; unknown/superseded auth object formats rejected.  
* Audience validation on our tokens.  
* Scope validation per operation.  
* Unknown signing keys untrusted.  
* Invalid/corrupt signatures fail cleanly without crashes or permissive fallback.  
* If signing structured JSON, use the standard canonicalization required by that protocol consistently.  
* Hash our public A2A Agent Card; unexpected drift triggers audit \+ ANS re-verification.  
* If a remote ANS agent is valid but policy behavior is bad, do not treat ANS identity as sufficient authorization.

For the specific published Fraud Agent cases, add a SECURITY.md table stating:

* replay\_booking → unsupported in MVP; state-changing replay controls exist generally.  
* underpay\_booking/tamper\_mandate/underpay\_valid\_sig → unsupported; any future signed authorization must be verified AND separately policy-checked.  
* quote\_swap → future auth must bind exact object/quote ID.  
* wrong\_audience → validate audience on every bearer/authorization object.  
* wrong\_scope → per-operation scope enforcement.  
* wrong\_dpop\_key/replay → if DPoP is ever implemented, use a vetted library, verify key binding/request binding/freshness/unique proof ID; never hand-roll crypto.  
* corrupt\_jws → strict parser/signature verification; fail closed.  
* superseded\_format → schema version allowlist; no lenient legacy fallback.  
* unknown\_key → pinned/authorized trust anchors only.  
* replay\_settled → no settlement in MVP; idempotency/replay ledger for local mutations.  
* canonicalization\_probe → one standards-compliant canonicalizer if signed JSON is added.  
* payto\_binding → not applicable until payment feature exists; never accept unsigned settlement destination.  
* card\_drift\_watch → implemented by Agent Card hash monitoring \+ re-verification.

Optionally test discovery/communication with \`agent.webmesh.ai\` if protocol interoperability permits, but never send secrets/private URLs or attempt destructive actions against third parties.

### **12\. RATE LIMITS / RESOURCE / DENIAL-OF-WALLET**

Implement Redis-backed or equivalent shared limits:

* login: \~5 failures/15 min/account+IP with progressive delay  
* anonymous agent queries: \~30/min/IP  
* A2A/MCP read-only: \~60/min/IP, with body/response limits  
* create/import: 3/hour/owner and only one active import/owner  
* ANS search: bounded/cached, \~30/min/principal  
* proof endpoint: cheap cached live evidence, \~60/min/IP  
* model calls: max input/output tokens; per-user and global daily budget ceiling  
* remote agent hops \<= 2  
* model/tool calls \<= 5 total for a normal user request  
* retries \<= 2, exponential backoff  
* hard wall-clock timeout

Add circuit-breaker environment flags:

* \`DISABLE\_AGENT\_CREATION\`  
* \`DISABLE\_EXTERNAL\_FETCH\`  
* \`DISABLE\_REMOTE\_AGENT\_CALLS\`  
* \`DISABLE\_LLM\`  
* \`READ\_ONLY\_MODE\`

When disabled, return clear safe errors and preserve proof/read-only functionality where possible.

### **13\. REPLAY / IDEMPOTENCY / CONCURRENCY**

* State-changing owner/admin endpoints accept or generate idempotency keys bound to actor \+ operation \+ canonical payload hash.  
* Redis/Postgres stores replay key TTL/state atomically.  
* Duplicate publish/register/revoke calls cannot execute twice.  
* ANS registration per tenant/version uses a DB/advisory lock/single-flight.  
* Configuration uses version/optimistic lock so concurrent edits cannot silently overwrite.  
* DNS challenge cleanup deletes only the exact value created by this registration and never unrelated records.

### **14\. SECRETS AND KEY MANAGEMENT**

Secrets:

* GODADDY\_PAT/event production credential  
* DNS credential if separate  
* LLM API key(s)  
* DB/Redis passwords  
* session/CSRF signing secret  
* ANS identity/server private keys

Rules:

* never commit or print  
* never send to LLM  
* never expose in browser or proof endpoint  
* never log Authorization/Cookie/private key fields  
* store outside repo and inject only to necessary service  
* scraper receives no secrets  
* generated agent receives no GoDaddy/DNS/deploy credentials  
* private keys chmod 600 and service-specific mount  
* add secret-redaction logging filter  
* write a test that injects a fake canary secret and asserts it does not appear in logs  
* document rotation/revocation

### **15\. CONTAINER / HOST HARDENING**

Docker Compose:

* Caddy public on 80/443 only  
* app/control plane/database/Redis on private networks  
* non-root app containers  
* read\_only filesystem where feasible  
* tmpfs for /tmp  
* \`no-new-privileges:true\`  
* drop capabilities; no privileged; no host network  
* CPU/memory/PID limits where Compose version supports  
* no Docker socket mounts  
* scraper isolated from control-plane/db network if architecture permits

Host firewall:

* allow 80/443  
* SSH key-only and restrict source if possible  
* deny public DB/Redis/app ports  
* deny scrape-worker egress to private/link-local/metadata ranges

Caddy:

* reverse proxy with explicit host routes  
* request body limits  
* security headers  
* hide server details where possible  
* access logging with redaction policy

### **16\. SUPPLY CHAIN**

* Pin dependencies with lockfile.  
* Prefer official SDKs.  
* Minimize package count.  
* Run dependency audit and fix high/critical findings or document unavoidable ones.  
* No packages/plugins installed based on LLM/web/remote agent suggestions at runtime.  
* Production container base image pinned to specific supported Python image/version.  
* \`SECURITY.md\` documents dependencies/services and update process.

### **17\. LOGGING / AUDIT / PRIVACY**

Structured logs with correlation IDs.

Audit events for login, tenant create, import, publish, ANS register, DNS validation, ACTIVE transition, verification failure, remote connect, owner config edit, revoke, key rotation, circuit-breaker change.

Redact:

Authorization, Cookie, Set-Cookie, PAT/API keys, CSRF token, passwords, private keys, raw session IDs, sensitive prompts.

Sanitize log fields against CR/LF log injection.

Do not store full website HTML indefinitely; store normalized business profile and source URLs/hash unless debugging is explicitly enabled.

Default conversation retention should be short/minimal.

### **18\. PROOF / VERIFICATION IMPLEMENTATION**

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

### **19\. TEST SUITE — REQUIRED BEFORE FINAL REPORT**

UNIT/INTEGRATION:

* BusinessProfile schema  
* Host/subdomain policy  
* owner/tenant authorization  
* protocol metadata/card generation  
* ANS client mocked contract tests  
* proof formatting

SECURITY TESTS AGAINST OUR OWN LOCAL/STAGING APP:

### **1\. SSRF block localhost IPv4/IPv6**

### **2\. block RFC1918/private/link-local/metadata**

### **3\. block userinfo/parser ambiguity**

### **4\. block redirect-to-private**

### **5\. simulate DNS rebinding and ensure pinned resolution blocks it**

### **6\. oversized page/body/decompression limits**

### **7\. indirect prompt injection page cannot trigger tools/secrets/network**

### **8\. malformed LLM JSON rejected**

### **9\. forbidden capability rejected**

### **10\. XSS payload rendered inert**

### **11\. CSRF missing/bad/cross-origin rejected**

### **12\. cross-tenant IDOR/BOLA rejected**

### **13\. mass assignment (owner\_id/role/status) rejected**

### **14\. SQL injection strings are data only**

### **15\. command/path injection cannot spawn process/read file**

### **16\. Host header poisoning rejected**

### **17\. CORS not open**

### **18\. session fixation/reuse after logout fails**

### **19\. rate limits enforced**

### **20\. remote private endpoint rejected**

### **21\. malformed/oversized Agent Card rejected**

### **22\. endpoint mismatch rejected**

### **23\. revoked/inactive mocked/live candidate rejected**

### **24\. state handle bound to principal**

### **25\. wrong token audience rejected if token auth enabled**

### **26\. idempotency prevents duplicate mutation**

### **27\. corrupted signature/parser input fails safely without 500/crash**

### **28\. card hash drift triggers re-verification/audit**

### **29\. canary secret absent from logs**

### **30\. circuit breakers work**

Run tests. Fix failures. Include pass/fail summary.

Never perform intrusive tests against third-party endpoints. Public Webmesh agents may be used only for documented interoperability/read-only calls.

### **20\. README / SECURITY / DEPLOYMENT DOCUMENTATION**

README must contain:

* what the product does in 3–4 sentences  
* architecture diagram in Mermaid or ASCII  
* Create flow  
* Find flow  
* local dev instructions  
* production deployment instructions  
* environment variable reference  
* exact A2A/MCP URLs  
* exact 5-gate proof checklist  
* ANS registration flow  
* how to verify ACTIVE  
* how to generate evidence bundle  
* demo script

SECURITY.md must contain:

* threat model/trust boundaries  
* security invariants  
* SSRF design  
* prompt injection design  
* auth/session/CSRF/XSS/CSP controls  
* MCP/A2A/ANS security  
* secret/key handling  
* Webmesh published battery applicability table  
* incident response and revocation  
* known limitations / risks

### **21\. ENVIRONMENT VARIABLES**

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

### **22\. USER INTERFACE**

Keep it simple and judge-friendly.

Home:

* two cards: CREATE AGENT and FIND AGENT  
* small explanation “discover → verify → communicate”

Create page:

* website URL  
* desired agent hostname/subdomain  
* import progress  
* extracted data preview  
* owner confirmation  
* publish/ANS registration progress  
* states visibly labeled

Find page:

* natural-language capability query  
* show ANS search steps  
* candidate list  
* verification checks with PASS/FAIL  
* connect button or automatic read-only connect  
* result

Proof page:

* Gate 1 A2A/MCP reachable  
* Gate 2 HTTPS  
* Gate 3 owned domain  
* Gate 4 production ANS ACTIVE  
* Gate 5 certificate/verification evidence  
* timestamps and redacted raw identifiers

Security page (optional but useful):

* concise architecture/trust controls  
* no claims of “unhackable”  
* show security self-test status

No giant SPA required. Prefer secure server-rendered pages.

### **23\. DEMO BUSINESS AGENT**

Seed a safe demo business config so Gates can be tested before website import works.

Example capabilities:

* get\_business\_info(question)  
* get\_hours()  
* get\_menu\_or\_services()

All are read-only.

The demo agent uses the same generic runtime as generated tenants.

### **24\. PRODUCTION GO-LIVE / ANS REGISTRATION SCRIPT**

Create an explicit CLI/admin script, NOT a public web endpoint, that:

### **1\. validates BASE\_DOMAIN and host**

### **2\. verifies public HTTPS A2A/MCP availability**

### **3\. checks \`gddy auth status\` / prod environment if gddy exists**

### **4\. generates/loads private key \+ CSRs securely**

### **5\. uses current production ANS API schema to register**

### **6\. prints only redacted response summary**

### **7\. if PENDING\_VALIDATION, shows exact DNS TXT challenge**

### **8\. optionally uses safe \`gddy dns add\` for exact challenge if domain is manageable and user explicitly runs/approves script**

### **9\. calls verify-acme/verify-dns as current docs require**

### **10\. polls actual GoDaddy agent status to ACTIVE**

### **11\. retrieves identity/server public certificates**

### **12\. writes redacted evidence JSON file under a non-secret artifacts directory**

### **13\. never prints/stores PAT or private key in artifacts**

Before destructive DNS delete/set operations, use dry-run when supported and exact-match only.

### **25\. FINAL ACCEPTANCE — DO NOT STOP UNTIL LOCAL CODE SATISFIES THESE**

Local/staging acceptance:

* \[ \] app boots from clean checkout with documented setup  
* \[ \] DB migrations succeed  
* \[ \] secure login/session/CSRF works  
* \[ \] CREATE imports a controlled test page safely  
* \[ \] prompt injection in import does not gain privileges  
* \[ \] generated agent config is data only  
* \[ \] A2A Agent Card valid  
* \[ \] A2A read-only request works  
* \[ \] MCP Streamable HTTP handshake/tool call works  
* \[ \] FIND can discover from mocked/local ANS contract and live ANS when credentials exist  
* \[ \] verifier rejects endpoint/cert/status mismatches  
* \[ \] \`/proof\` and \`/api/proof\` work  
* \[ \] security headers tests pass  
* \[ \] SSRF tests pass  
* \[ \] cross-tenant authorization tests pass  
* \[ \] rate/resource limits pass  
* \[ \] secret redaction test passes  
* \[ \] dependency/security audit run  
* \[ \] Docker Compose and Caddy config validate  
* \[ \] README and SECURITY.md complete

Live gate acceptance (only mark PASS after actual observation):

* \[ \] Gate 1 external A2A/MCP reachable  
* \[ \] Gate 2 public HTTPS valid  
* \[ \] Gate 3 owned MLH domain used  
* \[ \] Gate 4 production ANS ACTIVE, with redacted CLI/API evidence  
* \[ \] Gate 5 live verification/certificate/protocol evidence displayed

If live credentials/domain/network are absent, mark live gate items WAITING\_FOR\_EXTERNAL\_INPUT, give exact commands/checks, and leave the code ready. Never fabricate success.

### **26\. EXECUTION BEHAVIOR FOR YOU, CLAUDE**

* Start by inspecting existing files and installed tool/library versions.  
* If repository is empty, scaffold it.  
* Use official current protocol/API docs and SDK introspection where possible.  
* Do not spend the whole run narrating. Implement.  
* Make reasonable decisions without asking unnecessary questions.  
* Only stop for a truly external interactive boundary such as browser login, missing domain, or missing production credential. Even then, complete all code/tests that do not require it and output the exact one-line next action.  
* Never echo secrets back to chat/output.  
* Never downgrade TLS or disable certificate verification to “make it work.”  
* Never turn off a security test to make CI green; fix the bug or clearly document a blocked external dependency.  
* Prefer correctness/security over visual polish.  
* Ensure the final demo path is reliable and fast.

### **FINAL REPORT FORMAT:**

### **1\. What was built**

### **2\. Architecture**

### **3\. Security controls implemented**

### **4\. Test results**

### **5\. Five gates status: PASS / FAIL / WAITING\_FOR\_EXTERNAL\_INPUT with evidence**

### **6\. Exact commands to deploy/register/prove any remaining live steps**

### **7\. Known limitations**

Now build Agent Desk end-to-end.

# **VIII. Sources and Current References**

These are the external sources used to anchor current protocol/API/security details. Event-specific instructions from GoDaddy mentors should override public documentation if the event environment differs.

**\[S1\] GoDaddy ANS Registration —** [https://developer.godaddy.com/en/docs/references/rest/ans/registration](https://developer.godaddy.com/en/docs/references/rest/ans/registration) — Registration schema, PENDING\_VALIDATION DNS-01 example, ACTIVE agent detail.

**\[S2\] GoDaddy ANS Agents/Search —** [https://developer.godaddy.com/en/docs/references/rest/ans/agents](https://developer.godaddy.com/en/docs/references/rest/ans/agents) — Registered-agent search and lifecycle/endpoints/functions/scores.

**\[S3\] GoDaddy ANS Validation —** [https://developer.godaddy.com/en/docs/references/rest/ans/validation](https://developer.godaddy.com/en/docs/references/rest/ans/validation) — verify-acme / verify-dns status flow.

**\[S4\] GoDaddy ANS Certificate Management —** [https://docs.developer.commerce.godaddy.com/en/docs/references/rest/ans/certificate-management](https://docs.developer.commerce.godaddy.com/en/docs/references/rest/ans/certificate-management) — Identity/server certificate retrieval and certificate metadata.

**\[S5\] GoDaddy ANS Revocation —** [https://developer.godaddy.com/en/docs/references/rest/ans/revocation](https://developer.godaddy.com/en/docs/references/rest/ans/revocation) — Agent revocation and compromise reasons.

**\[S6\] GoDaddy Authentication —** [https://developer.godaddy.com/en/docs/api-users/auth/how-to](https://developer.godaddy.com/en/docs/api-users/auth/how-to) — PAT Bearer usage and secret handling.

**\[S7\] GoDaddy CLI workflow reference —** [https://developer.godaddy.com/en/docs/api-users/cli/reference](https://developer.godaddy.com/en/docs/api-users/cli/reference) — gddy auth/env/PAT/API/DNS command families.

**\[S8\] A2A Protocol — current specification —** [https://a2a-protocol.org/dev/specification/](https://a2a-protocol.org/dev/specification/) — Agent Card discovery, HTTPS/TLS, auth/authz, security considerations.

**\[S9\] Model Context Protocol — Security Best Practices —** [https://modelcontextprotocol.io/docs/tutorials/security/security\_best\_practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) — Confused deputy, token passthrough, SSRF, state handles, scope minimization.

**\[S10\] OWASP AI Agent Security Cheat Sheet —** [https://cheatsheetseries.owasp.org/cheatsheets/AI\_Agent\_Security\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) — Agent-specific prompt injection, tool, privilege, memory, DoW and inter-agent risks.

**\[S11\] OWASP Prompt Injection Prevention —** [https://cheatsheetseries.owasp.org/cheatsheets/LLM\_Prompt\_Injection\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — Quarantined model / action screening / least privilege.

**\[S12\] OWASP SSRF Prevention Cheat Sheet —** [https://cheatsheetseries.owasp.org/cheatsheets/Server\_Side\_Request\_Forgery\_Prevention\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — URL/network validation and redirect risk.

**\[S13\] OWASP API Security Top 10 — 2023 —** [https://api-security.owasp.org/editions/2023/en/0x11-t10/](https://api-security.owasp.org/editions/2023/en/0x11-t10/) — BOLA, auth, resource consumption, SSRF, unsafe API consumption.

**\[S14\] OWASP REST Security Cheat Sheet —** [https://cheatsheetseries.owasp.org/cheatsheets/REST\_Security\_Cheat\_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) — Input/content-type validation, errors, CORS, management endpoints, logs.

**\[S15\] OWASP CSP / Session / CSRF / Secrets cheat sheets —** [https://cheatsheetseries.owasp.org/](https://cheatsheetseries.owasp.org/) — Browser, session, CSRF and secret management guidance.

**\[S16\] Webmesh public agent index \+ Fraud/Rogue/Auditor pages —** [https://webmesh.ai/.well-known/agents-index.json](https://webmesh.ai/.well-known/agents-index.json) — Live agent fleet and published adversarial battery/interoperability descriptions.

# **IX. Final Build Priority**

**Build priority: (1) one hand-written public Agent Desk endpoint; (2) production ANS ACTIVE \+ proof; (3) discover/verify/communicate with a second real agent; (4) safe website-to-config ingestion; (5) automatic tenant publishing; (6) polish. Never sacrifice Gates 1–5 for the website-generation wow feature.**

The project is strongest when the demo makes ANS visibly necessary: a caller needs a capability, Agent Desk discovers candidates, verifies the domain-backed identity and current registration evidence, rejects a bad/mismatched candidate, then communicates only with the verified agent.