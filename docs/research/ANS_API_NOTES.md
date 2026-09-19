# GoDaddy ANS REST API + `gddy` CLI — implementation contract

Researched live on **2026-09-19**. Rule used throughout: anything not confirmed from a live official source is tagged `UNVERIFIED`. Where official sources disagree, both are shown and tagged `CONFLICT` (see §11). JSON examples are verbatim in content (whitespace compacted in places; "abridged" where marked).

Source tags used below:

| Tag | Source |
|---|---|
| `[SPEC]` | OpenAPI 3.1.1 "Agent Name Service (ANS) API" v1.0.0, embedded in every `developer.godaddy.com/en/docs/references/rest/ans/*` page (identical hash on all 8 pages + the commerce mirror) |
| `[GDDEV]` | `https://www.godaddy.com/ans/developers` (GoDaddy "Agent Identity" developer docs: Registration Guide, API Reference, Trust Scores) |
| `[PORTAL]` | `developer.godaddy.com` prose docs (via `llms-full.txt`) |
| `[SDK]` | Official SDKs: `github.com/agentnameservice/ans-sdk-go` (v0.1.18, 2026-09-17), `ans-sdk-java`, `ans-sdk-rust` (moved from `github.com/godaddy/*`, old URLs 301) |
| `[ANS-SPEC]` | Open ANS spec `github.com/agentnameservice/ans-registry/spec/*` (ANS-0..6). Describes the open standard / reference RA, **not** guaranteed identical to the GoDaddy-hosted RA |
| `[CLI]` | `github.com/godaddy/cli` (gddy v0.2.20, 2026-09-18) |
| `[LIVE]` | Read-only probes I ran against production/OTE on 2026-09-19 (no credentials) |

---

## 0. Ten things that matter most

1. Base URL prod `https://api.godaddy.com`, OTE `https://api.ote-godaddy.com`. ANS paths are rooted at `/v1/agents/...` (lifecycle) and `/v1/ans/...` (public discovery/trust). No extra prefix.
2. Registration flow: `POST /v1/agents/register` (202, `PENDING_VALIDATION`) -> publish `_acme-challenge` TXT -> `POST /v1/agents/{agentId}/verify-acme` (202) -> poll `GET /v1/agents/{agentId}` until `PENDING_DNS` and DNS records appear -> publish DNS records -> `POST /v1/agents/{agentId}/verify-dns` (202) -> `ACTIVE`.
3. CSR fields (`identityCsrPEM`, `serverCsrPEM`) carry the **raw PEM text** (`-----BEGIN CERTIFICATE REQUEST-----\n...`) as a JSON string. NOT base64-of-PEM. (`[SPEC]` wording "Base64 encoded PEM" is misleading; `[GDDEV]`, `[ANS-SPEC]` example and all three SDKs send raw PEM.)
4. Identity CSR: subject `CN={agentHost}`, SAN `DNS:{agentHost}` + SAN `URI:ans://v{version}.{agentHost}`; key EC P-256 (or RSA 2048/3072/4096). Server CSR: `CN={agentHost}`, SAN `DNS:{agentHost}`; key **RSA 2048 or 4096 only**, signed SHA256withRSA.
5. Auth is `CONFLICT`: portal says ANS uses a PAT (`Authorization: Bearer <PAT>`); `[GDDEV]` and SDK defaults use `Authorization: sso-key <KEY>:<SECRET>`. Make the client support both, selectable by config.
6. Status enum (agent): `PENDING_VALIDATION, PENDING_DNS, ACTIVE, FAILED, EXPIRED, REVOKED` (+ `PENDING_CERTS` only inside the pending-registration object; + `DEPRECATED` in search filter; discovery API uses `ACTIVE, WARNING, DEPRECATED, EXPIRED, REVOKED`).
7. DNS records to publish come back from the API as `dnsRecords[] {name,type,value,purpose,required,ttl,priority}` — publish exactly what is returned; do not synthesize. Live prod agents publish `_ans` TXT, `_ans-badge` TXT, `_443._tcp` TLSA, optional HTTPS RR.
8. Discovery endpoints `/v1/ans/registered-agents*` and `/v1/ans/search-registered-agents` answer **without any auth** `[LIVE]`, rate-limited 60/window.
9. An ANSName (`version`+`agentHost`) is unique; 409 if it exists. Per `[ANS-SPEC]` it is consumed permanently, even by failed attempts -> bump `version` on retry.
10. `gddy` install: `curl -fsSL https://github.com/godaddy/cli/releases/latest/download/install.sh | bash` (binary lands in `~/.local/bin`). gddy has **no ANS commands and no ANS entries in its `gddy api` catalog**; raw paths still work via `gddy api call <path>`. `gddy dns` cannot create TLSA/HTTPS records.

---

## 1. Source log (all fetched 2026-09-19)

| URL | Result |
|---|---|
| `developer.godaddy.com/en/docs/references/rest/ans/{registration,agents,validation,certificate-management,revocation,resolution,search,events}` | 200. Visible HTML is thin (JS accordions); full OpenAPI extracted from the Next.js flight payload (`self.__next_f.push`). Same spec on all pages |
| `docs.developer.commerce.godaddy.com/en/docs/references/rest/ans/{certificate-management,registration}` | 200. Byte-identical spec and identical page list to developer.godaddy.com |
| `developer.godaddy.com/llms.txt`, `/llms-full.txt` | 200. ANS appears only as reference stubs + one line: "ANS API ... Auth: PAT". **No ANS how-to/quickstart guide exists on the portal** |
| `developer.godaddy.com/openapi/ans.json`, `/openapi/ans.yaml` | 404 (no standalone ANS spec published; other APIs have one) |
| `developer.godaddy.com/swagger/swagger_ans.json`, `/doc/endpoint/ans` (still linked from SDK READMEs) | 404 — dead since the July 2026 portal relaunch |
| `developer.godaddy.com/en/docs/api-users/auth/how-to`, `/auth`, `/cli/reference`, `/cli/set-up`, `/cli/agent-skill`, `/rate-limits`, `/errors`, `/concepts/how-godaddy-apis-work` | 200 (read from llms-full.txt) |
| `developer.godaddy.com/personal-access-token` | Redirects to SSO login — scope picker not inspectable |
| `developer.godaddy.com/openapi/domains-v3.json` | 200 (used for DNS record type/TTL limits and env host enum) |
| `www.godaddy.com/ans/developers`, `www.godaddy.com/ans` | 403 to plain curl/WebFetch; 200 with full browser headers. Tab content pulled from JS chunk `app/developers/page-858ab2197e6a651b.js` |
| `github.com/godaddy/{ans-registry,ans-sdk-go,ans-sdk-java,ans-sdk-rust,ans}` | 301 -> `github.com/agentnameservice/*`. READMEs, Go SDK sources, spec docs fetched via raw.githubusercontent.com |
| `github.com/godaddy/cli` | 200. README, `.agents/skills/gddy/*`, guides, `rust/src/{api,env,environments,scopes}` read |
| `ansinfo.ai` (= agentnameregistry.org redirect) | 200, marketing/standards only |
| `transparency.ans.godaddy.com`, `transparency.ans.ote-godaddy.com` | 200 live (`/root-keys`, `/v1/log/checkpoint`, `/v1/agents/{id}`, `/receipt`, `/status-token`, `/v1/log/schema/V1`) |
| `api.godaddy.com/v1/ans/*` (no auth) | 200 live. `api.godaddy.com/v1/agents*` (no auth): 302 to SSO or 401 |
| Wayback Machine | 429, not used |

---

## 2. Base URLs & environments

| Env | Registry Authority (RA) API | Transparency Log (public) |
|---|---|---|
| Production | `https://api.godaddy.com` | `https://transparency.ans.godaddy.com` |
| OTE (test) | `https://api.ote-godaddy.com` | `https://transparency.ans.ote-godaddy.com` |

Sources: `[SPEC]` `servers: https://api.godaddy.com` only; `[GDDEV]` "Production / OTE / Transparency Log / API Version: v1.0.0"; `[SDK]` env table; `[LIVE]` all four hosts answered. `ans-cli` defaults to **OTE**; Go SDK `NewClient` defaults to prod.

- Path prefixes: `/v1/agents` (register, lifecycle, certs, search, resolution, events) and `/v1/ans` (registered-agents discovery + trust). TL uses `/v1/agents/{agentId}`, `/v1/log/*`, `/root-keys`.
- A "V2 lane" `/v2/ans/agents[...]` exists in `[SDK]`/`[ANS-SPEC]` (same shapes + `discoveryProfiles`). `[LIVE]` unauthenticated `GET https://api.godaddy.com/v2/ans/agents` -> 404. Availability on the hosted RA: `UNVERIFIED`. Use V1.
- OTE and prod are separate registries with separate credentials `[PORTAL]` ("OTE credentials" keyword; `gddy pat add --env ote|prod`). Note `[PORTAL]` "How GoDaddy APIs work" says there is "a single production environment", while other portal pages and gddy reference OTE — treat OTE as available but less documented.

---

## 3. Authentication

### 3.1 Header formats

| Scheme | Header | Source |
|---|---|---|
| PAT (portal-recommended) | `Authorization: Bearer <GODADDY_PAT>` — token looks like `gd_pat_...` | `[PORTAL]`, `[CLI]` |
| Classic developer key | `Authorization: sso-key <KEY>:<SECRET>` | `[PORTAL]`, `[GDDEV]`, `[SDK]` |
| OAuth 2.0 access token | `Authorization: Bearer <token>` | `[SDK]` (added v0.1.18, 2026-09-17) |
| Internal JWT | `Authorization: sso-jwt <jwt>` | `[SDK]` "for internal endpoints" — not for us |

`CONFLICT`: `[PORTAL]` REST reference index: "ANS API ... Auth: PAT." `[GDDEV]` shows only `sso-key` for every ANS call and says "create an API key on developer.godaddy.com -> API Keys -> Create New API Key, name it, select the Environment, Next; you receive an API Key and API Secret (secret shown once)". `[SPEC]` declares **no** `securitySchemes` at all. Whether a PAT is accepted on `/v1/agents/*` today: `UNVERIFIED` (needs a real credential). Implement `ANS_AUTH_SCHEME=bearer|sso-key`.

Always send `Content-Type: application/json` and `Accept: application/json` (SDK does on every request, including body-less POSTs). `[GDDEV]` sends `-d '{}'` on verify-acme/verify-dns; SDK sends no body. Both are documented.

Other headers: `X-Request-Id` (optional; events: "UUID V1 as Base58"; `/v1/ans/*`: uuid; echoed back as `x-request-id` `[LIVE]`). `X-Shopper-Id` on register: "Optional. GoDaddy Shopper ID for DNS API authorization" `[GDDEV]` only.

### 3.2 Creating a PAT `[PORTAL]`

1. Sign in at `https://developer.godaddy.com/personal-access-token` -> **+ Generate Token** -> Name, Expiration (days), Scopes -> **Generate Token**. Shown once; revoke via trash icon (instant).
2. `export GODADDY_PAT="..."`; send `Authorization: Bearer ${GODADDY_PAT}`.
3. "The GoDaddy API gateway exchanges the PAT for a short-lived access token and enforces the PAT's scopes" `[CLI]`. Missing scope -> 403.

Scopes: only Domains (`domains.domain:read|create|update|delete`, `domains.dns:update`, `domains.nameserver:update`, `domains.host:update`, `domains.forward:update`, `domains.contact:update`, `domains.transfer:execute|update`) and Commerce scopes are documented. **No ANS scope name is documented anywhere** (portal, gddy scope registry, SDKs) -> `UNVERIFIED`. For DNS automation via API/gddy you need `domains.domain:read` + `domains.dns:update`.

### 3.3 Observed auth failures `[LIVE]`

- No `Authorization` on `GET /v1/agents?limit=1` -> **302** to `https://sso.godaddy.com/login?realm=jomax&app=ra.int&path=%2F` (do not follow redirects; treat as unauthenticated).
- Bogus `Bearer`, `sso-key` or `sso-jwt` on the same path -> **401 with empty body**.
- No auth on `GET /v1/agents/events` -> 401 `{"code":"UNAUTHORIZED","message":"auth: unauthorized"}` (no `status` field).

Hackathon notes: no official hackathon page or special hackathon access path was found (`UNVERIFIED` if one exists). Practical: use OTE first; registration needs a domain whose DNS you control; a failed attempt may burn the version number (§5).

---

## 4. Endpoints

### 4.0 Conventions

Error body `[SPEC]` `ErrorResponse`: `code` (string, required), `message` (string, required), `status` (enum `ERROR`, required), `details` (object, optional). Verbatim 422 example:

```json
{
  "code": "VALIDATION_ERROR",
  "details": {
    "field": "agentDisplayName",
    "reason": "Field is required but was not provided"
  },
  "message": "Invalid registration request: agentDisplayName is required",
  "status": "ERROR"
}
```

Timestamps: `[SPEC]` examples render as `"2025-11-13 16:30:00+00:00"` (space separator), `[GDDEV]` as `"2025-11-13T16:30:00Z"`, and live responses use RFC 3339 with up to nanosecond precision (`"2026-09-18T07:52:32.212734855Z"`) — use a lenient parser (Python < 3.11 `fromisoformat` rejects `Z` and 9-digit fractions).

Reality check `[LIVE]`: gateway-level errors may have an empty body or omit `status`. Platform-wide envelope `[PORTAL]` is `{code, message, fields[]}`. Parse defensively: try JSON, fall back to raw text. Error codes seen in official sources: `VALIDATION_ERROR`, `UNAUTHORIZED`, `ACCESS_DENIED`, `NOT_FOUND`, `INVALID_REQUEST`, `INVALID_FORMAT`, `MALFORMED_REQUEST`, `INVALID_ENCODING`, `RATE_LIMIT_EXCEEDED`, `INTERNAL_SERVER_ERROR`, `BAD_GATEWAY`, `FAILED_DEPENDENCY`, `SERVICE_UNAVAILABLE`, `DEPENDENCY_TIMEOUT`, `GATEWAY_TIMEOUT` `[SPEC]`; `[ANS-SPEC]` adds `ANS_NAME_TAKEN` (409), `DUPLICATE_PROTOCOL`, `ENDPOINT_HOST_MISMATCH`, `INVALID_ENDPOINT`, `DUPLICATE_ENDPOINT`, `CANNOT_CANCEL`, `IDENTITY_CSR_NOT_PERMITTED` (409) — hosted-RA use of those: `UNVERIFIED`.

Endpoint inventory `[SPEC]` (19 operations):

| Method | Path | operationId |
|---|---|---|
| POST | `/v1/agents/register` | registerAgent |
| GET | `/v1/agents/{agentId}` | getAgent |
| POST | `/v1/agents/{agentId}/verify-acme` | validateRegistration |
| POST | `/v1/agents/{agentId}/verify-dns` | verifyDnsRecords |
| POST | `/v1/agents/{agentId}/revoke` | revokeAgent |
| GET / POST | `/v1/agents/{agentId}/certificates/identity` | get.../submitAgentIdentityCsrByAgentId |
| GET | `/v1/agents/{agentId}/certificates/server` | getAgentServerCertificateByAgentId |
| POST / GET / DELETE | `/v1/agents/{agentId}/certificates/server/renewal` | submit/getStatus/cancel ServerCertificateRenewal |
| POST | `/v1/agents/{agentId}/certificates/server/renewal/verify-acme` | verifyAcmeChallenges |
| GET | `/v1/agents/{agentId}/csrs/{csrId}/status` | getAgentCsrStatusByAgentId |
| GET | `/v1/agents` | searchANSName |
| POST | `/v1/agents/resolution` | resolveANSName |
| GET | `/v1/agents/events` | getAgentEvents |
| POST | `/v1/ans/search-registered-agents` | searchRegisteredAgents |
| GET | `/v1/ans/registered-agents` | listRegisteredAgents |
| GET | `/v1/ans/registered-agents/{agentId}` | getRegisteredAgent |

Not in `[SPEC]` but in other official sources: `GET /v1/agents/{agentId}/challenge` (`[SDK]` `GetChallengeDetails`; also the `links[rel=challenge]` href in the register example) -> `{status, challenges[], createdAt, expiresAt}`; `POST /v1/agents/{agentId}/certificates/server` body `{csrPEM}` or `{certificatePEM}` (`[GDDEV]`, `[SDK]` `SubmitServerCSR`). Treat both as `UNVERIFIED` on the hosted RA.

### 4.1 Register agent — `POST /v1/agents/register`

Request `AgentRegistrationRequest` `[SPEC]`:

| Field | Type | Req | Constraints |
|---|---|---|---|
| `agentDisplayName` | string | yes | <= 64 chars (`[GDDEV]` lists it as optional — send it) |
| `agentHost` | string | yes | FQDN, <= 253 |
| `version` | string | yes | `^(0\|[1-9]\d*)\.(0\|[1-9]\d*)\.(0\|[1-9]\d*)$` (bare semver, no `v`, no pre-release) |
| `agentDescription` | string | no | <= 150 |
| `endpoints` | AgentEndpoint[] | yes | minItems 1 (AgentDetails says maxItems 5) |
| `identityCsrPEM` | string | yes | PEM CSR (see §6) |
| `serverCsrPEM` | string | cond. | "Required when not using BYOC" |
| `serverCertificatePEM` | string | cond. | BYOC leaf cert PEM |
| `serverCertificateChainPEM` | string | no | only valid with `serverCertificatePEM` |

`AgentEndpoint`: `agentUrl` (uri, **required**), `protocol` (**required**, enum `A2A | MCP | HTTP-API`), `metaDataUrl` (uri, must be absolute https per SDK changelog), `documentationUrl` (uri), `transports[]` (enum `STREAMABLE-HTTP | SSE | JSON-RPC | GRPC | REST | HTTP`), `functions[]`.
`AgentFunction`: `id` (required, <= 64), `name` (required, <= 64), `tags[]` (<= 5 items, each <= 20 chars). Meaning: MCP tools / A2A skills / HTTP routes.
Extra rules from `[ANS-SPEC]` (hosted enforcement `UNVERIFIED` but follow them): every `agentUrl` hostname must equal `agentHost`; at most one endpoint per protocol; exactly one of `serverCsrPEM` / `serverCertificatePEM`. BYOC is for the server cert only; identity certs are always RA-issued.

Verbatim request example `[SPEC]`:

```json
{
  "agentDisplayName": "Sentiment Analyzer",
  "agentHost": "myagent.example.com",
  "endpoints": [
    {
      "agentUrl": "https://myagent.example.com/mcp",
      "metaDataUrl": "https://myagent.example.com/.well-known/mcp.json",
      "documentationUrl": "https://docs.myagent.example.com",
      "protocol": "MCP",
      "transports": ["STREAMABLE-HTTP"],
      "functions": [
        { "id": "domain_suggest", "name": "Domain Suggest", "tags": ["domain", "suggestion", "availability"] }
      ]
    }
  ],
  "identityCsrPEM": "string",
  "version": "1.2.0"
}
```

`[GDDEV]` shows the CSR fields as `"identityCsrPEM": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"` and the same for `serverCsrPEM`, with header `Authorization: sso-key YOUR_API_KEY:YOUR_API_SECRET`.

Responses: **202** `RegistrationPending`; 401, 403, **409** "Agent ID or ANSName already exists", **422** invalid request, 500. Flows per `[SPEC]` description: (1) GoDaddy-registered domains + CSRs: "synchronous - Returns 202 immediately with wait instruction" (nextStep `WAIT`; `[GDDEV]` FAQ: "GoDaddy domains validated via Shopper ID"); (2) external domains + CSRs (async ACME) or BYOC: 202 with validation requirements.

`RegistrationPending` schema: `status` (required; enum `PENDING_VALIDATION | PENDING_CERTS | PENDING_DNS`), `ansName` (required), `nextSteps[]` (required), `challenges[]` (ChallengeInfo), `dnsRecords[]` (DnsRecord), `expiresAt` (date-time), `links[]` (`{href, rel}`). `agentId` is not in the schema but is in every example and in the SDK model.

- `ChallengeInfo`: `type` (`DNS_01 | HTTP_01`), `token`, `keyAuthorization`, `httpPath` (e.g. `/.well-known/acme-challenge/xyz123`), `dnsRecord {name, type, value}`, `expiresAt`.
- `NextStep`: `action` (`CONFIGURE_DNS | CONFIGURE_HTTP | VERIFY_DNS | VALIDATE_DOMAIN | WAIT`), `description`, `endpoint` (uri).
- `DnsRecord`: `name` (required, full name), `type` (required; `HTTPS | TLSA | TXT`), `value` (required), `purpose` (`DISCOVERY | TRUST | CERTIFICATE_BINDING | BADGE`), `required` (bool, default true), `ttl` (int, default 3600), `priority` (int, HTTPS records).

Verbatim 202 example `[SPEC]`:

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "ansName": "ans://v1.0.0.external-domain.com",
  "challenge": {
    "dnsRecord": {
      "name": "_acme-challenge.external-domain.com",
      "type": "TXT",
      "value": "xyz123abc456"
    },
    "keyAuthorization": "xyz123abc456.thumbprint",
    "token": "xyz123abc456",
    "type": "DNS_01"
  },
  "expiresAt": "2025-11-13 16:30:00+00:00",
  "links": [
    { "href": "https://api.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000/challenge", "rel": "challenge" }
  ],
  "nextSteps": [
    {
      "action": "CONFIGURE_DNS",
      "description": "Configure DNS TXT record for ACME validation",
      "endpoint": "https://api.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000/verify-acme"
    }
  ],
  "status": "PENDING_VALIDATION"
}
```

`CONFLICT`: the example uses singular `challenge` (object) while the schema and the SDK use plural `challenges` (array). **Parse both.** Publish exactly `dnsRecord.name` / `dnsRecord.value` as a TXT record (or serve `keyAuthorization` at `httpPath` for HTTP-01). Challenge expiry: only `expiresAt` is given; no fixed duration documented.

### 4.2 Get agent details — `GET /v1/agents/{agentId}`

200 `AgentDetails`: required `agentId`, `agentStatus`, `ansName`, `agentHost`, `links`, `version`, `endpoints`; optional `agentDisplayName`, `agentDescription`, `registrationTimestamp`, `lastRenewalTimestamp`, `registrationPending` (RegistrationPending — carries `challenges` while `PENDING_VALIDATION` and `dnsRecords` while `PENDING_DNS`). SDK additionally reads a top-level `dnsRecords[]` and accepts `agentStatus` as **either a string or an object** `{status, phase, ...}` — handle both. Errors 401/403/404/500.

Verbatim 200 example `[SPEC]`:

```json
{
  "agentId": "550e8400-e29b-41d4-a716-446655440000",
  "agentDisplayName": "Sentiment Analyzer",
  "agentDescription": "An agent that analyzes sentiment in text",
  "agentHost": "myagent.example.com",
  "ansName": "ans://v1.0.0.myagent.example.com",
  "version": "1.0.0",
  "agentStatus": "ACTIVE",
  "endpoints": [
    { "agentUrl": "https://myagent.example.com/mcp", "protocol": "MCP", "transports": ["STREAMABLE-HTTP"],
      "functions": [ { "id": "analyze_sentiment", "name": "Analyze Sentiment", "tags": ["nlp", "sentiment"] } ] },
    { "agentUrl": "https://myagent.example.com/a2a", "metaDataUrl": "https://myagent.example.com/.well-known/agent-card.json",
      "protocol": "A2A", "transports": ["JSON-RPC"] },
    { "agentUrl": "https://myagent.example.com/api/v1", "protocol": "HTTP-API", "transports": ["REST"],
      "documentationUrl": "https://docs.myagent.example.com/api" }
  ],
  "links": [ { "href": "https://api.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000", "rel": "self" } ]
}
```

`CONFLICT`: the `[GDDEV]` Registration Guide shows a different polling shape (`"status": "PENDING_DNS_VERIFICATION"`, `"requiredDnsRecords": {"_ans": {...}, "_ans-badge": {...}}`) and a verify-acme reply `{"status": "PENDING_CERTIFICATE_ISSUANCE", "message": ...}`. These names appear nowhere in `[SPEC]`/`[SDK]`; the `[GDDEV]` API Reference tab on the same page uses the `[SPEC]` shapes. Treat the guide's names as stale; but do not hard-fail on unknown status strings.

### 4.3 Trigger ACME validation — `POST /v1/agents/{agentId}/verify-acme`

No body (or `{}`). **202** `AgentStatus`; 401/403/404/**422** "Validation failed"/500. "A single domain validation is used for both certificates. The RA will automatically determine which validation method to use."
`AgentStatus`: `status` (AgentLifecycleStatus), `phase` (`INITIALIZATION | DOMAIN_VALIDATION | CERTIFICATE_ISSUANCE | DNS_PROVISIONING | COMPLETED`), `completedSteps[]`, `pendingSteps[]`, `createdAt`, `updatedAt`, `expiresAt`. Verbatim `[GDDEV]`:

```json
{
  "status": "PENDING_VALIDATION",
  "phase": "DOMAIN_VALIDATION",
  "completedSteps": ["INITIALIZATION"],
  "pendingSteps": ["DOMAIN_VALIDATION", "CERTIFICATE_ISSUANCE", "DNS_PROVISIONING"],
  "createdAt": "2025-11-13T15:30:00Z",
  "updatedAt": "2025-11-13T15:30:00Z",
  "expiresAt": "2025-11-13T17:30:00Z"
}
```

Issuance is asynchronous: re-POSTing verify-acme re-drives a pending order `[ANS-SPEC]`; poll `GET /v1/agents/{agentId}` (and `GET .../certificates/*`) until `PENDING_DNS`.

### 4.4 Verify DNS — `POST /v1/agents/{agentId}/verify-dns`

No body (or `{}`). **202** `AgentStatus` ("DNS verified, registration active"); 401/403/404/500; **422** `DnsVerificationError`: `status` (`ERROR`), `missingRecords[]` (DnsRecord), `incorrectRecords[] {record: DnsRecord, expected: string, found: string}`. Final step for external domains. Verbatim success `[GDDEV]`:

```json
{
  "status": "ACTIVE",
  "phase": "COMPLETED",
  "completedSteps": ["INITIALIZATION", "DOMAIN_VALIDATION", "CERTIFICATE_ISSUANCE", "DNS_PROVISIONING"],
  "pendingSteps": [],
  "createdAt": "2025-11-13T15:30:00Z",
  "updatedAt": "2025-11-13T15:35:00Z",
  "expiresAt": "2025-11-13T17:30:00Z"
}
```

### 4.5 State machine

```
register -> PENDING_VALIDATION --verify-acme ok--> (PENDING_CERTS: derived, only in registrationPending.status) --> PENDING_DNS --verify-dns ok--> ACTIVE
PENDING_VALIDATION --challenge window lapses--> EXPIRED          PENDING_DNS / PENDING_CERTS --revoke--> REVOKED (cancel)
ACTIVE --> DEPRECATED (defined, not driven today) ; ACTIVE | DEPRECATED --revoke--> REVOKED ; FAILED = pending-side terminal
```

Terminal: `REVOKED`, `FAILED`, `EXPIRED`. `PENDING_VALIDATION` **cannot** be cancelled via revoke (422); it auto-expires `[SPEC]`. TL-derived read-time statuses: `WARNING` (cert expires within 30 days), `EXPIRED` `[SDK]`.

### 4.6 Certificates

- `GET /v1/agents/{agentId}/certificates/identity` and `GET .../certificates/server` -> 200 **array** of `CertificateResponse`; 401/403/404/500.
- `POST /v1/agents/{agentId}/certificates/identity` body `{"csrPEM": "<PEM CSR>"}` -> **202** `{csrId (uuid, required), message}`; 401/403/404/422/500. Used for identity-cert rotation (ACTIVE agents; additive).
- `GET /v1/agents/{agentId}/csrs/{csrId}/status` -> 200 `{csrId, type: SERVER|IDENTITY, status: PENDING|SIGNED|REJECTED, submittedAt, updatedAt, failureReason (only when REJECTED)}`; 404 if CSR not owned by agent.

`CertificateResponse`: required `certificatePEM`, `certificateValidFrom`, `certificateValidTo`, `csrId`; nullable `certificateIssuer`, `certificateSubject`, `certificateSerialNumber`, `certificatePublicKeyAlgorithm`, `certificateSignatureAlgorithm`, `chainPEM` ("PEM certificate chain (intermediate and root certificates)"). PEM fields are raw PEM text. Verbatim `[GDDEV]`:

```json
[
  {
    "certificateIssuer": "CN=Agent Name Service CA,O=GoDaddy,C=US",
    "certificatePEM": "-----BEGIN CERTIFICATE-----\nCERT DATA\n...truncated...\n-----END CERTIFICATE-----",
    "certificatePublicKeyAlgorithm": "RSA",
    "certificateSerialNumber": "1234567890ABCDEF",
    "certificateSignatureAlgorithm": "SHA256withRSA",
    "certificateSubject": "CN=myagent.example.com,O=Example Corp,C=US,SAN:URI:ans://v1.0.0.myagent.example.com",
    "certificateValidFrom": "2026-01-21T06:29:07.755Z",
    "certificateValidTo": "2026-01-21T06:29:07.755Z",
    "csrId": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
  }
]
```

### 4.7 Server certificate renewal `[SPEC]`

- `POST .../certificates/server/renewal` body: exactly one of `serverCsrPEM` | `serverCertificatePEM` (+ optional `serverCertificateChainPEM`). **202** `RenewalSubmission {renewalType: SERVER_CSR|SERVER_BYOC, status: PENDING_VALIDATION|ISSUING_CERTIFICATE, csrId|null, challenges: {dns01: ChallengeInfo, http01: ChallengeInfo}, expiresAt (7 days), nextStep, links}`. **409** if a pending renewal exists. 422: agent not ACTIVE, neither/both inputs, SAN/CN mismatch, BYOC expired, chain without cert.
- `GET` same path -> 200 `RenewalStatus` (status adds `COMPLETED|FAILED|EXPIRED`; `tlsaDnsRecord`, `failureReason`); 404 if none. `DELETE` -> 204 (422 if already completed).
- `POST .../renewal/verify-acme` -> **200** (BYOC, synchronous, returns `tlsaDnsRecord`) or **202** (CSR path, poll `GET /certificates/server`); `RenewalVerification {status: VERIFIED|ISSUING_CERTIFICATE|COMPLETED, csrId, tlsaDnsRecord, nextStep}`. Checks TXT at `_acme-challenge.{agentHost}` or file at `/.well-known/acme-challenge/{token}`. After renewal the TLSA value changes -> republish.

### 4.8 Revoke — `POST /v1/agents/{agentId}/revoke`

Body: `reason` (required; enum `KEY_COMPROMISE | CESSATION_OF_OPERATION | AFFILIATION_CHANGED | SUPERSEDED | CERTIFICATE_HOLD | PRIVILEGE_WITHDRAWN | AA_COMPROMISE`), `comments` (<= 200). `SUPERSEDED` is "reserved for internal deprecation flow" -> 422. **200** `AgentRevocationResponse`: required `agentId` (uuid), `ansName`, `status`, `revokedAt`, `reason`, `links`; optional `dnsRecordsToRemove[]` (DnsRecord — delete these). 401/403/404/422/500. ans-cli README lists 4 more reasons (`CA_COMPROMISE, EXPIRED_CERT, REMOVE_FROM_CRL, UNSPECIFIED`) not in `[SPEC]` -> avoid.

```json
{ "reason": "CESSATION_OF_OPERATION", "comments": "Service is being retired." }
```

`CONFLICT`: `[GDDEV]` shows a different response `{"status":"SUCCESS","message":...,"revocationTimestamp":...,"crlLocation":"https://api.godaddy.com/v1/crl/ans-ca.crl"}`; that CRL URL returns 404 `[LIVE]`.

### 4.9 Search my/registry agents — `GET /v1/agents`

Query: `agentDisplayName` (<= 64, partial match), `version` (flexible), `agentHost` (`CONFLICT`: `[GDDEV]` "exact FQDN match required", SDK "partial"), `protocol` (`MCP|A2A|HTTP-API`), `limit` (1–100, default 20), `offset` (>= 0, default 0), `status` (array; `[SPEC]` style form/explode=false i.e. `status=ACTIVE,PENDING_DNS`; the Go SDK sends repeated `status=` params; enum `PENDING_DNS | ACTIVE | DEPRECATED | REVOKED | ALL`; default `ACTIVE`; `ALL` overrides others).
200 `AgentSearchResponse`: required `agents[]`, `hasMore`, `limit`, `offset`, `returnedCount`, `totalCount`; optional `searchCriteria {agentHost, agentDisplayName, protocol, version}`. Agent item: required `agentDisplayName, agentId, ansName, agentHost, endpoints, links, version`; optional `agentDescription, registrationTimestamp, ttl` (seconds). 401/403/422/500. Useful for recovering an `agentId`: `?agentHost=<host>&status=ALL`. Whether results are owner-scoped: `UNVERIFIED`.

### 4.10 Resolution — `POST /v1/agents/resolution`

Body: `agentHost` (required, <= 253), `version` (required; semver range: `1.0.0`, `^1.0.0`, `~1.2.3`, `*` or `""` = latest). 200: `ansName` + `links[]` with `rel: agent-details` and `rel: agent-endpoint`. 401/403/404/422/500. Verbatim:

```json
{ "agentHost": "myagent.example.com", "version": "^1.0.0" }
```
```json
{
  "ansName": "ans://v1.0.0.myagent.example.com",
  "links": [
    { "href": "https://api.godaddy.com/v1/agents/550e8400-e29b-41d4-a716-446655440000", "rel": "agent-details" },
    { "href": "https://myagent.example.com/api/v1", "rel": "agent-endpoint" }
  ]
}
```

### 4.11 Events — `GET /v1/agents/events`

Query: `providerId` (optional; omitted = all providers), `lastLogId` (cursor; omitted = start of stream), `limit` (1–200, default 100). Events retained 30 days. 200 `{items: EventItem[], lastLogId}` (`lastLogId` omitted when no more). `EventItem` required: `logId, eventType (AGENT_REGISTERED|AGENT_RENEWED|AGENT_DEPRECATED|AGENT_REVOKED), createdAt, agentId, ansName, agentHost, version`; optional `expiresAt, agentDisplayName, agentDescription, providerId (e.g. "PC_1234567890"), endpoints[]`. 400/401/403/422/**429**/500. Requires auth `[LIVE]`.

### 4.12 Public discovery + trust — `/v1/ans/*` (no auth needed `[LIVE]`)

- `GET /v1/ans/registered-agents` query: `query` (<= 256 chars; <= 4096 with `keywordExtraction=true`), `keywordExtraction` (bool), `keywordAlgorithm` (`RAKE|SIMPLE|TEXTRANK`, default SIMPLE), `profile` (default `default`), `pageSize` (1–100, default 20), `pageToken`, `pageTokenDirection` (`backward|forward`; 422 without `pageToken`), `totalRequired` (bool -> `totalItems`, `totalPages`), repeated array params `providerIds`, `statuses` (`ACTIVE|WARNING|DEPRECATED|EXPIRED|REVOKED`; default excludes REVOKED), `agentDomains` (apex + subdomains), `protocols` (`A2A|ACP|HTTP-API|MCP`), `transports` (`HTTP|REST|SSE|JSON-RPC|STREAMABLE-HTTP`), `tags`, `capabilities` (function names), `scoring.pillarWeights.identity|integrity`, `scoring.thresholds.identity|integrity` (0–100).
- `POST /v1/ans/search-registered-agents`: same criteria as JSON body (`additionalProperties: false`; `scoring: {pillarWeights:{identity,integrity}, thresholds:{...}}`; `profile` cannot be combined with `pillarWeights`). 415 if wrong media type.
- `GET /v1/ans/registered-agents/{agentId}` (+ `profile`): full trust explainability.
- Responses: list `{items: AnsRegisteredAgentHit[], totalItems?, totalPages?, links: [{rel: self|next|prev, method, href}]}`; follow `links[].href` for paging. Item: required `agentId, indexedAt, leafIndex, lifecycle{status}`; plus `agentDisplayName, agentDescription, agentHost, agentVersion` (**`v`-prefixed**, e.g. `v1.0.0`), `ansName, logId, providerId, endpoints[] (+metaDataHash)`, and `scores {trustScore 0-100, textScore 0-100, relevance (raw ES _score)}`. Detail adds `trustScore, trustVector{identity,integrity}, missingness{requiredSignals,missingSignals,penalties}, coverage{computedPillars,coverageRatio}, signals{<name>: {score, missing, pillar, computedAt, evidence}}`. `[LIVE]` also returns undocumented `expiresAt` and `trustScoreExplanation{baseTrustScore, penaltyScore, trustScore, appliedPenalties[]}`.
- Errors: 400/401/403/404/415/422/429/500/502/503/504, all `ErrorResponse`, content type `*/*`.

Live prod sample (abridged to one item, values verbatim) `[LIVE]`:

```json
{
  "items": [{
    "agentId": "121072b1-79d5-4d2f-8eba-298addcb53d3", "providerId": "30",
    "ansName": "ans://v1.0.0.corn-futures.aginttest.net", "agentHost": "corn-futures.aginttest.net",
    "agentDisplayName": "Corn Futures", "agentVersion": "v1.0.0",
    "indexedAt": "2026-09-18T07:52:32.212734855Z", "leafIndex": 10077,
    "logId": "019d1c2f-6035-7786-9709-1146f6503881", "expiresAt": "2026-06-21T17:48:42Z",
    "lifecycle": {"status": "ACTIVE"},
    "scores": {"trustScore": 72, "textScore": 0, "relevance": 71.6},
    "endpoints": [{"agentUrl": "https://corn-futures.aginttest.net/", "metaDataUrl": "https://corn-futures.aginttest.net/.well-known/agent.json",
      "protocol": "A2A", "transports": ["JSON-RPC"], "functions": [{"id": "corn_futures_price", "name": "Corn Futures Price Lookup"}]}]
  }],
  "totalItems": 216898, "totalPages": 216898,
  "links": [{"rel": "self", "method": "GET", "href": "https://api.godaddy.com/v1/ans/registered-agents?pageSize=1&profile=default&totalRequired=true"},
            {"rel": "next", "method": "GET", "href": "https://api.godaddy.com/v1/ans/registered-agents?pageSize=1&pageToken=<opaque>&pageTokenDirection=forward&profile=default&totalRequired=true"}]
}
```

Trust model `[GDDEV]`: pillars Identity 60% (signals `certtype`, `dnssecurity`) and Integrity 40% (`agentage`, `versionstability`, `dnsconsistency`, `httpsrecord`); `agentcard` is a penalty-only signal (serve a valid card at `/.well-known/agent.json`). Tiers: Emerging 1–15, Establishing 16–35, Developing 36–60, Strong 61–80, Verified Leader 81–100. Cheap wins: DNSSEC, TLSA, HTTPS RR, valid agent card, <= 1 version change/month.

### 4.13 Transparency Log (public, no auth) `[SDK]` `[ANS-SPEC]` `[LIVE]`

| Path (on the TL host) | Returns |
|---|---|
| `GET /v1/agents/{agentId}` | "Badge": `{status, schemaVersion, payload{logId, producer{event, keyId, signature}}, signature, merkleProof{leafHash, leafIndex, path[], rootHash, rootSignature, treeSize, treeVersion}}`; header `X-Schema-Version: V1` |
| `GET /v1/agents/{agentId}/audit?offset&limit` | paginated event history with proofs |
| `GET /v1/agents/{agentId}/receipt` | SCITT COSE receipt (`application/scitt-receipt+cose`) |
| `GET /v1/agents/{agentId}/status-token` | signed status (`application/ans-status-token+cbor`, ~1h TTL) |
| `GET /v1/log/checkpoint`, `/v1/log/checkpoint/history`, `/v1/log/schema/{version}` | checkpoint JSON / history / JSON Schema (`V1`) |
| `GET /root-keys` | TL verification keys, text/plain |

Live prod badge `event` (abridged, values verbatim):

```json
{
  "ansId": "1e69ddf7-ba8f-41d5-981d-6791b4430df1",
  "ansName": "ans://v1.0.0.hospital-coding-audit.agentworks.fr",
  "eventType": "AGENT_REGISTERED",
  "agent": {"host": "hospital-coding-audit.agentworks.fr", "name": "Hospital Coding Audit", "version": "v1.0.0"},
  "attestations": {
    "dnsRecordsProvisioned": {
      "_443._tcp.hospital-coding-audit.agentworks.fr": "3 0 1 332915582f29e10e79405d59dab4d2737aed6e30159e4efface8168d28b3de1a",
      "_ans-badge.hospital-coding-audit.agentworks.fr": "v=ans-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/1e69ddf7-ba8f-41d5-981d-6791b4430df1",
      "_ans.hospital-coding-audit.agentworks.fr": "v=ans1; version=v1.0.0; p=mcp; mode=direct; url=https://hospital-coding-audit.agentworks.fr/mcp"
    },
    "domainValidation": "ACME-DNS-01",
    "identityCert": {"fingerprint": "SHA256:aa18adb9a12c90cd0505fa27b27ec7f981845696cec571de898f469e99ee25cf", "type": "X509-OV-CLIENT"},
    "serverCert": {"fingerprint": "SHA256:332915582f29e10e79405d59dab4d2737aed6e30159e4efface8168d28b3de1a", "type": "X509-DV-SERVER"}
  },
  "expiresAt": "2026-10-09T01:31:39.000000Z", "issuedAt": "2026-03-25T01:31:36.208951Z",
  "raId": "gd-ra-us-west-2-prod-main-fb-2831b58c259d4ed49b9a9754865a310a", "timestamp": "2026-03-25T01:33:08.551493Z"
}
```

Badge `status` enum: `ACTIVE, WARNING, DEPRECATED, EXPIRED, REVOKED`; connectable = first three.

---

## 5. ANS name format & version rules

`ans://v{version}.{agentHost}` e.g. `ans://v1.0.0.myagent.example.com` (`[SPEC]`, `[GDDEV]`, `[ANS-SPEC]` ANS-2).

- Scheme always `ans`; protocol (MCP/A2A/HTTP-API) is **not** part of the name.
- `version`: numeric `major.minor.patch`, no pre-release/build metadata; request field is bare (`1.0.0`), the name/DNS records/discovery `agentVersion` carry the `v` prefix (`v1.0.0`).
- `agentHost`: RFC 1123 FQDN, <= 253 octets, labels <= 63 LDH, >= 2 labels `[ANS-SPEC]`.
- Every version is an independent registration with its own `agentId`, certs and DNS rows; versions coexist; no retirement timeline. A version bump = full new registration (new ACME proof). Version churn lowers the trust score.
- Uniqueness across all statuses; FAILED/EXPIRED/cancelled attempts still hold the name `[ANS-SPEC]` (hosted: `UNVERIFIED`, but 409 is documented).

---

## 6. CSR / key requirements

Encoding: a JSON string holding one PEM block `-----BEGIN CERTIFICATE REQUEST-----` ... `-----END CERTIFICATE REQUEST-----` with real newlines (`\n` in JSON). Exactly one block, nothing before/after, no private key in the file `[SDK]` csrvalidation. In Python: `csr.public_bytes(serialization.Encoding.PEM).decode()`.

| | Identity CSR | Server CSR |
|---|---|---|
| Public key | RSA 2048 / 3072 / 4096 **or** EC P-256 (only curve) | RSA 2048 or 4096 **only** (no EC, no 3072) |
| CSR signature | SHA-256/384/512 with RSA or ECDSA | SHA-256 with RSA |
| Subject | `CN={agentHost}` (ans-cli adds `O=<org>`, `C=<country>`; Java SDK uses CN only) | `CN={agentHost}` |
| SAN | `DNS:{agentHost}` **and** `URI:ans://v{version}.{agentHost}` (URI SAN is mandatory; RA rejects mismatch with 422) | `DNS:{agentHost}` (ans-cli also adds the URI SAN; Java SDK does not) |
| Issued cert | ANS private CA; keyUsage digitalSignature, EKU clientAuth; attested type `X509-OV-CLIENT` | GoDaddy public CA (or BYOC); attested type `X509-DV-SERVER` |

ans-cli defaults: identity = EC P-256, server = RSA 2048. Note from `[SDK]`: "EC P-256 identity CSRs require a registry deployment with EC support; a registry without it rejects them with a 422" -> safest portable choice is **RSA 2048 for both**; fall back from EC to RSA on 422. Private keys never leave the client. BYOC server cert: CN or SAN must match `agentHost`, chain to a trusted root, unexpired; pass leaf in `serverCertificatePEM`, intermediates in `serverCertificateChainPEM`.

---

## 7. DNS records the registrant must publish

Authoritative source is always the API's `dnsRecords[]`. Shapes observed on live production and OTE agents `[LIVE]` (and matching `[ANS-SPEC]` ANS-3 / `ANS_TXT` profile, which the V1 lane is pinned to):

```text
; step 2 (temporary) - ACME DNS-01
_acme-challenge.{agentHost}.  TXT   "<challenge.dnsRecord.value>"
; step 5 (permanent)
_ans.{agentHost}.             TXT   "v=ans1; version=v1.0.0; p=mcp; mode=direct; url=https://{agentHost}/mcp"      ; one per endpoint, p = a2a|mcp|http-api
_ans-badge.{agentHost}.       TXT   "v=ans-badge1; version=v1.0.0; url=https://transparency.ans.godaddy.com/v1/agents/{agentId}"
_443._tcp.{agentHost}.        TLSA  3 0 1 <sha256 hex of full DER server certificate>                                ; one per distinct TLS port
{agentHost}.                  HTTPS 1 . alpn=h2
```

- OTE badge URLs point at `transparency.ans.ote-godaddy.com` `[LIVE]`.
- `CONFLICT` on the badge label: `[SPEC]` text says "all four required records (HTTPS, TLSA, _ans, _ra-badge)"; `[GDDEV]` says `_ans-badge`; live agents publish `_ans-badge` and no `_ra-badge`; SDK verifiers read `_ans-badge` first, `_ra-badge` as legacy fallback (format `v=ra-badge1`).
- `CONFLICT` on which are mandatory: `[SPEC]` says all four; `[ANS-SPEC]` marks `_ans` + `_ans-badge` required, TLSA and HTTPS `required=false` (HTTPS impossible behind an apex CNAME; TLSA only enforced when DNSSEC-validated and mismatching); `[GDDEV]` guide lists only the two TXT records; a live ACTIVE prod agent has no HTTPS RR. -> honor each record's `required` flag; publish optional ones when the DNS host allows (they raise the trust score).
- TTL: API default 3600. GoDaddy DNS minimum TTL is 600 `[PORTAL domains-v3]`.
- On revoke, delete `dnsRecordsToRemove[]`. After server-cert renewal, update the TLSA.
- If DNS is hosted at GoDaddy: Domains v3 DNS API (`POST /v3/domains/zones/{zone}/dns-records`, body `{name (relative, @ = apex), type, data (<= 512), ttl 600-86400}`) and `gddy dns` only support `A, AAAA, CNAME, MX, TXT, NS, SRV, SOA, CAA` (+`ALIAS` in gddy). **TLSA and HTTPS cannot be created through them** — TXT records only.

---

## 8. Trust anchors & verifying an agent identity certificate

What is documented:

- Identity certs are "signed by the ANS private CA"; server certs "by the GoDaddy public CA" or BYOC `[GDDEV]`. Example issuer DN: `CN=Agent Name Service CA,O=GoDaddy,C=US` (example value only).
- **No URL, bundle or fingerprint for the ANS private root/intermediate CA is published in any source I could reach.** `[ANS-SPEC]` refers to "the ANS Private CA's published trust anchor" without a location; the Rust SDK just takes `AnsClientCertVerifier::from_pem(&ca_pem)`. The only documented way to obtain the chain is `chainPEM` from `GET /v1/agents/{agentId}/certificates/identity` (authenticated, own agents). Pin that. Everything else: `UNVERIFIED`.
- The CA publishes no CRL/OCSP `[ANS-SPEC]`; the `[GDDEV]` `crlLocation` URL is 404 `[LIVE]`. **The Transparency Log is the revocation channel.**

Documented verification procedure (badge tier; `[SDK]` verify package, `[ANS-SPEC]` ANS-6 §6):

1. (mTLS only) chain-validate the client cert to the pinned ANS private CA.
2. From the cert take CN/DNS SAN = FQDN and URI SAN = `ans://v{ver}.{fqdn}`. No URI SAN -> not an ANS identity cert.
3. `TXT _ans-badge.{fqdn}` (fallback `_ra-badge`); pick the row whose `version=` matches; parse `v=ans-badge1; version=vX.Y.Z; url=https://...`. Require https, no userinfo/fragment, and host in your trusted-TL allowlist (`transparency.ans.godaddy.com`, OTE: `transparency.ans.ote-godaddy.com`).
4. `GET <url>` -> badge. Require `status` in `ACTIVE | WARNING | DEPRECATED`; `payload.producer.event.agent.host == fqdn`; `...event.ansName == URI SAN`; `"SHA256:" + hex(sha256(cert DER))` equals `...attestations.identityCert.fingerprint` (V1 schema) or any of `identityCerts[]` (V2). For a server cert compare with `serverCert.fingerprint` instead.
5. Optional: DANE (`_443._tcp` TLSA `3 0 1`, only meaningful with DNSSEC); SCITT tier (headers `X-SCITT-Receipt` + `X-ANS-Status-Token`, verified offline with `/root-keys`, ES256).

TL verification keys fetched live 2026-09-19 (format `<name>+<key_hash>+<base64 SPKI>`; `key_hash` = first 4 bytes of SHA-256(SPKI DER) = COSE `kid`; list is append-only):

```text
transparency.ans.godaddy.com+c9e2f584+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJiE0eriKUOYbYrXerJlCJv6TZGEglLkPOHo+bEieNtPsL2FjuXfRCZbYF3RCwqF/99iDVxIUHJWTcW3KXqbiCU=
transparency.ans.ote-godaddy.com+7b7c29c1+AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMpcwxnxsuH+svxoM5pS2KmMtbwVrm49Kcio7MbcdIZ10dFqLMj/E9RlXg1BR/s4Yk86sOFuE0r1ix83ROWb4sc=
```

---

## 9. `gddy` CLI

Install `[PORTAL]` `[CLI]` — GitHub release binaries only; **no npm/brew/pip package** for `gddy` (the old TypeScript `@godaddy/cli` on npm is a different tool named `godaddy`):

```bash
curl -fsSL https://github.com/godaddy/cli/releases/latest/download/install.sh | bash   # macOS/Linux/Git Bash -> ~/.local/bin/gddy (PATH not modified)
export PATH="$HOME/.local/bin:$PATH"
irm https://github.com/godaddy/cli/releases/latest/download/install.ps1 | iex           # PowerShell -> %LOCALAPPDATA%\Programs\gddy
bash install.sh --prefix /usr/local/bin --version v1.2.3                                # options when run as a file
gddy --version && gddy --help ; gddy update check ; gddy update apply
```

Auth: `gddy auth login` (browser OAuth; `--scope <s>` repeatable; `--env prod|ote`), `gddy auth status`, `gddy auth scopes`. Non-interactive: `echo 'gd_pat_...' | gddy pat add --env prod "CI token"` (or `--token`), `gddy pat list`, `gddy pat remove --env prod`; stored at `~/.config/gddy/pat.toml` (0600). Env vars `GDDY_PAT_<ENV>` > `GDDY_PAT` > stored PAT > OAuth. PAT is sent as `Authorization: Bearer gd_pat_...`.

Environment: `gddy env list | get | set <prod|ote> | info`; persisted to `~/.gdenv`; default `prod`; one-off `--env <env>`. `gddy env get` -> `{"env":"prod","apiUrl":"https://api.godaddy.com"}`; OTE apiUrl `https://api.ote-godaddy.com`.

Command tree (documented families; run `gddy tree` for the exact list of the installed version): `auth`, `pat`, `env`, `domain (available|suggest|quote|agreements|purchase|contacts init|list|get|nameservers set)`, `dns (list|add|set|delete)`, `api`, `hosting nodejs`, `email`, `payment-methods add`, `update`, `flags`, `completion`, `search <keyword>`, `guide [topic]` (e.g. `auth`, `domain-purchase`), `tree`, `platform ...` (needs `GDDY_MIN_STAGE=experimental`).

DNS (`domains.dns:update` scope; types `A AAAA ALIAS CAA CNAME MX NS SOA SRV TXT`; NS/SOA read-only):

```bash
gddy dns list example.com --type TXT --name _acme-challenge
gddy dns add  example.com --type TXT --name _acme-challenge.myagent --data "<token>" --ttl 600   # append; --data repeatable; ttl default 3600, min 600
gddy dns set  example.com --type TXT --name _ans.myagent --data "v=ans1; ..." --dry-run           # replaces all for type+name; --replace-conflicting-types
gddy dns delete example.com --type TXT --name _acme-challenge.myagent                              # no-op if absent
```

`<DOMAIN>` is the zone; `--name` is relative to it (`@` = apex). Type flags: `--priority` (MX,SRV); `--port --weight --protocol --service` (SRV); `--flag --tag` (CAA). Global flags: `-o json|human|toon` (`--json`), `--fields`, `--filter <jmespath>`, `--expr <jmespath>`, `--limit/--offset`, `--verbose`, `--schema`, `--env`, `--dry-run`, `--credential-store auto|keyring|file`, `--debug <pattern>`, `--timeout 60s`. Non-TTY output defaults to JSON wrapped as `{"data": ...}`.

`gddy api`: `api domain list`, `api operation list --domain <d>`, `api search "<q>"`, `api operation get <id|path> [--method]`, `api parameter|response list|get --operation <id>`, `api schema get <id>`, `api call <path|operationId> -X/--method <M> [-d/--body '<json>'] [-f/--field k=v] [-F/--file body.json] [--param n=v] [-H/--header 'K: V'] [--include] [-s/--scope <s>]`, plus `api graphql ...`.

ANS through `gddy api`: the bundled catalog (`rust/schemas/api/manifest.json`, generated 2026-09-16) has **no ANS domain**, so `api search`/`operation get` will not find ANS operations. `api call` accepts any literal path: on a catalog miss it uses the active env's `apiUrl` and the current credential (source: `rust/src/api/call.rs`). Therefore the following should work but is `UNVERIFIED` (no ANS example exists in official docs; gddy's OAuth client has no ANS scope, so use a PAT):

```bash
gddy api call /v1/agents/register -X POST -F register.json --include        # UNVERIFIED
gddy api call "/v1/agents?agentHost=myagent.example.com&status=ALL"          # UNVERIFIED
gddy api call /v1/ans/registered-agents?pageSize=5                           # public endpoint
```

The purpose-built CLI is `ans-cli` `[SDK]`: `brew install agentnameservice/ans/ans-cli` (or scoop / `go install github.com/agentnameservice/ans-sdk-go/cmd/ans-cli@latest`); env `ANS_API_KEY="key:secret"` (-> `sso-key`), `ANS_OAUTH_TOKEN` (-> `Bearer`, wins if both set), `ANS_BASE_URL` (default OTE), `ANS_API_VERSION`, `ANS_TRANSPARENCY_URL`; commands `generate-csr, register, status, verify-acme, verify-dns, search, resolve, revoke, events, csr-status, submit-identity-csr, submit-server-csr, get-identity-certs, get-server-certs, badge`; `--json`, `--verbose`.

---

## 10. Rate limits / quotas

- `/v1/ans/*`: `x-rate-limit: {requests: 100, period: 60s, scope: "per-api-key, per-client-identity"}` `[SPEC]`. `[LIVE]` unauthenticated response headers: `ratelimit-limit: 60`, `ratelimit-remaining: 58`, `ratelimit-reset: 8`.
- Platform `[PORTAL]`: per-credential windowed limit; headers `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` (seconds) on every response; 429 has **no body** (or `ErrorLimit` with `retryAfterSec` + `Retry-After`). Stated values disagree: llms.txt "60 requests/minute per credential" vs rate-limits page "600 per ~23-minute window"; "subject to change" -> read the headers, back off with jitter.
- Events endpoint documents 429. No per-account cap on number of agents is documented (`UNVERIFIED`). Renewal requests expire after 7 days. Events retained 30 days.

---

## 11. Conflicts between official sources (code defensively)

| Topic | A | B | Recommendation |
|---|---|---|---|
| Auth scheme | `[PORTAL]` PAT Bearer | `[GDDEV]`/`[SDK]` `sso-key key:secret` | configurable; try the credential you have |
| CSR encoding wording | `[SPEC]` "Base64 encoded PEM" | everything else: raw PEM text | raw PEM |
| Register response | example `challenge` (object) | schema `challenges` (array) | accept both |
| Pending status names | `[SPEC]` `PENDING_VALIDATION/PENDING_CERTS/PENDING_DNS` | `[GDDEV]` guide `PENDING_CERTIFICATE_ISSUANCE/PENDING_DNS_VERIFICATION`, `requiredDnsRecords{}` | follow `[SPEC]`, tolerate unknowns |
| Badge label | `[SPEC]` `_ra-badge` | `[GDDEV]`/`[LIVE]` `_ans-badge` | publish what the API returns |
| Required DNS set | `[SPEC]` four records | `[ANS-SPEC]`/`[GDDEV]` two TXT required | use `required` flag |
| Enum spelling | hosted: `HTTP-API`, `STREAMABLE-HTTP`, `JSON-RPC` | `[ANS-SPEC]` V2: `HTTP_API`, `STREAMABLE_HTTP`, `JSON_RPC` | hyphens on `/v1` |
| `agentDisplayName` | `[SPEC]` required | `[GDDEV]` optional | always send |
| Revoke response | `[SPEC]` `AgentRevocationResponse` | `[GDDEV]` `{status: SUCCESS, crlLocation}` | follow `[SPEC]` |
| `status` query style | `[SPEC]` comma-separated | Go SDK repeated params | try comma first |
| Error envelope | `[SPEC]` `{code,message,status,details}` | `[LIVE]` empty body / `{code,message}`; `[PORTAL]` `{code,message,fields}` | lenient parser |

---

## 12. Open questions / UNVERIFIED

1. Whether a PAT (`Bearer gd_pat_...`) is accepted by `/v1/agents/*`, and the name of any ANS PAT scope (none documented; PAT page is behind login).
2. Whether classic `sso-key` keys can still be created on the relaunched portal for ANS ("API Keys" page per `[GDDEV]`), and OTE vs prod key separation for ANS.
3. Location/fingerprints of the ANS private root + intermediate CA (not published anywhere reachable). Only `chainPEM` is documented.
4. Whether the hosted RA accepts EC P-256 identity CSRs (SDK warns some deployments 422).
5. Exact `dnsRecords[]` content returned by the hosted RA for TLSA/HTTPS and whether verify-dns blocks on them; TTL expectations.
6. Challenge/registration expiry durations (only `expiresAt` values are given); whether a failed/expired attempt permanently burns the ANSName on the hosted RA.
7. Existence on the hosted RA of `GET /v1/agents/{agentId}/challenge`, `POST /v1/agents/{agentId}/certificates/server`, and the whole `/v2/ans/agents` lane (`discoveryProfiles`).
8. GoDaddy-registered-domain "synchronous" flow details: what `nextSteps` contains, whether GoDaddy provisions DNS itself, role of `X-Shopper-Id`.
9. Whether `GET /v1/agents` search is owner-scoped or global; `agentHost` exact vs partial match.
10. Whether `gddy api call` works for ANS paths in practice (no ANS in gddy catalog or scope registry).
11. Per-account limits/cost of ANS registration; any hackathon-specific access program.
12. Server certificate lifetime/issuer on the hosted RA (live sample: ~6.5 months between `issuedAt` and `expiresAt`; single data point).

---

## 13. Suggested client flow (derived from the above)

1. Generate identity key + CSR and server key (RSA 2048) + CSR per §6; keep keys local.
2. `POST /v1/agents/register`; persist `agentId`, `ansName`, raw response. On 409 search `GET /v1/agents?agentHost=...&status=ALL`.
3. Read challenge from `challenges[]` or `challenge`; if absent `GET /v1/agents/{id}` -> `registrationPending.challenges` (or `/challenge`). Publish TXT (TTL 600 on GoDaddy DNS); wait until resolvable from public resolvers.
4. `POST .../verify-acme`; on 422 wait and retry; then poll `GET /v1/agents/{id}` with backoff until status `PENDING_DNS` and `dnsRecords` are present (top-level or in `registrationPending`).
5. Download certs (`GET .../certificates/identity|server`), store `certificatePEM` + `chainPEM`.
6. Publish every returned DNS record (at least `required: true`); `POST .../verify-dns`; on 422 print `missingRecords` / `incorrectRecords[].expected|found`, fix, retry.
7. Confirm `ACTIVE`; confirm public visibility via `GET /v1/ans/registered-agents/{agentId}` and TL badge `GET https://transparency.ans.godaddy.com/v1/agents/{agentId}`.
