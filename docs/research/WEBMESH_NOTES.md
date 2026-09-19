# Webmesh public agent fleet - interop research notes

- Research date: **2026-09-19** (all fetches 23:22-23:27 UTC per server `Date` headers).
- Method: read-only HTTP **GET** only. **No POST was sent to any agent. No tool, skill, or attack was invoked.**
- Purpose: let an engineer build a read-only interoperability test (discover -> verify -> communicate over A2A or MCP).

Evidence labels used throughout:

| Label | Meaning |
|---|---|
| `VERIFIED` | Observed directly in a live fetch this session (see source log). "Declared" means the document says so; it does not prove server behaviour. |
| `VERIFIED-LOCAL` | Computed offline from bytes fetched this session (signature / digest checks). |
| `UNVERIFIED` | Not confirmed from a live fetch. Includes anything that would need a POST, and anything recalled from spec knowledge rather than fetched. |

## 0. TL;DR for the test author

1. All six requested hosts answered `200` at `/.well-known/agent-card.json` (the legacy `/.well-known/agent.json` fallback was never needed and was not requested).
2. Every card declares **A2A `protocolVersion: "1.0"`**, a single JSON-RPC interface at the host root, `streaming: false`, `pushNotifications: false`, `noAuth`, and carries **one detached-JWS EdDSA signature**. `VERIFIED`
3. The `agent.webmesh.ai` card signature **verifies** offline with the Ed25519 key from its trust card. `VERIFIED-LOCAL` (the other five are same shape, not cryptographically checked - `UNVERIFIED`).
4. **Best interop target: `agent.webmesh.ai`**, skill/tool **`verify`**.
   - A2A: `POST https://agent.webmesh.ai/` with header `A2A-Version: 1.0`, JSON-RPC method **`SendMessage`** (fallback `message/send`), text `Verify agent.webmesh.ai`.
   - MCP: `POST https://agent.webmesh.ai/mcp/` (note trailing slash), `initialize` -> `tools/list` -> `tools/call` name **`verify`**.
5. Do **not** target `seo.webmesh.ai` (active x402 paywall), `fraud.webmesh.ai` or `rogue-supplier.webmesh.ai` (adversarial; GET their cards only).
6. The cards are **not strictly A2A-1.0 shaped**; a strict parser will trip. See section 9.

## 1. Source log

All requests were plain GETs on 2026-09-19. Tool was `curl` unless noted. Sizes are response body bytes.

| # | URL | Status | Content-Type | Bytes | Notes |
|---|---|---|---|---|---|
| 1 | https://webmesh.ai/.well-known/agents-index.json | 200 | application/json | 5826 | single-line JSON; sha256 `06abedf7e7069a51a727fdbe44d436441e8caab42533ddcb5bac54e4ef9c9429` |
| 2 | https://agent.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 7080 | sha256 `2b6450357e2967e162f5188003f1d46c176613fe95f85fe5608799ff70a0b1fb` |
| 3 | https://dnsdoc.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 5941 | sha256 `7ee632b1efd55359050cbede063ccaabc7c71dfb057f9149b0f835f9bded5cb6` |
| 4 | https://seo.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 6871 | sha256 `71f2b7a4555fa4f6dddfac0cdc8242da981884166a0148f62b332e2b34e4bcb2` |
| 5 | https://auditor.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 4974 | sha256 `4996e7b233456808ffc25dd241f618bd0bd0e4f66105995ef8344c01bff33bdf` |
| 6 | https://rogue-supplier.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 5117 | sha256 `602cfcf609e419a8379aad794498d4c83e90938282bbb125a8775a3591b80e87` |
| 7 | https://fraud.webmesh.ai/.well-known/agent-card.json | 200 | application/a2a-agent-card+json | 12939 | sha256 `52b3088a1a7411b62ad2a30468fca076e7c4b7be09e349c00bfd496e3528b6eb` |
| 8 | https://agent.webmesh.ai/.well-known/mcp.json | 200 | application/json | 1632 | tool names + descriptions, **no `inputSchema`** |
| 9 | https://agent.webmesh.ai/ (Accept: text/html) | 200 | text/html | 8584 | human landing page |
| 10 | https://agent.webmesh.ai/llms.txt | 200 | text/plain | 3007 | says A2A endpoint is "JSON-RPC, 1.0 backward-compatible with 0.3" |
| 11 | https://fraud.webmesh.ai/ (Accept: text/html) | 200 | text/html | 11269 | landing page |
| 12 | https://rogue-supplier.webmesh.ai/ (Accept: text/html) | 200 | text/html | 7728 | landing page |
| 13 | https://fraud.webmesh.ai/.well-known/mcp.json | 200 | application/json | 3876 | 16 tools, no `inputSchema` |
| 14 | https://fraud.webmesh.ai/llms.txt | **404** | - | 0 | landing page links to it, but it does not exist |
| 15 | https://rogue-supplier.webmesh.ai/.well-known/mcp.json | 200 | application/json | 589 | 1 tool `get_quote`, no `inputSchema` |
| 16 | https://dnsdoc.webmesh.ai/.well-known/mcp.json | 200 | application/json | 693 | 1 tool `diagnose`, no `inputSchema` |
| 17 | https://agent.webmesh.ai/.well-known/ans/trust-card.json | 200 | application/json | 6721 | JWK (`keys[]`) used to verify card signature |
| 18 | https://agent.webmesh.ai/.well-known/ai-catalog.json | 200 | application/ai-catalog+json | 9758 | carries sha256 digests of card / mcp.json / agentfacts |
| 19 | https://agent.webmesh.ai/.well-known/ard.json | 200 | application/ai-catalog+json | 9758 | same document as #18, regenerated and re-signed per request (timestamps differ by 2 s) |
| 20 | https://webmesh.ai/ (Accept: text/html) | 200 | text/html | 12419 | fleet landing page, lists the same 10 agents as the index |
| 21 | https://seo.webmesh.ai/.well-known/mcp.json | 200 | application/json | 1997 | **does** include `inputSchema` and an x402 `payment` block |
| 22 | https://auditor.webmesh.ai/.well-known/mcp.json | 200 | application/json | 672 | 1 tool `audit_transaction`, no `inputSchema` |
| 23 | https://agent.webmesh.ai/mcp (Accept: text/event-stream) | **307** | - | 0 | `Location: https://agent.webmesh.ai/mcp/` |
| 24 | https://agent.webmesh.ai/mcp/ (Accept: text/event-stream) | 200 | text/event-stream | 0 | SSE stream opened and held; no events in 8 s; closed by client |
| 25 | https://a2a-protocol.org/latest/specification/ (WebFetch) | 200 (implied: tool returned content, status not exposed) | text/html | - | tool truncated the page; confirmed "Latest Released Version 1.0.0" |
| 26 | https://a2a-protocol.org/latest/specification/ (curl) | 200 | text/html | 617214 | full page, grepped locally for method names / shapes / signing rules |

Budget accounting: **26 GETs total** (24 to `*.webmesh.ai`, 2 to `a2a-protocol.org`), one over the ~25 target; #26 re-downloaded the spec because #25 came back truncated. **0 POSTs.** No Webmesh URL was requested twice, and no path was guessed: every URL came from the task brief, the index, a card, a link on a fetched page, or a redirect `Location` header.

Common response headers on `agent.webmesh.ai` (`VERIFIED`, from #2/#8/#23/#24): `via: 1.1 Caddy`, HSTS, `content-security-policy: default-src 'none'; frame-ancestors 'none'`, `link: </.well-known/ai-catalog.json>; rel="ai-catalog", </.well-known/agent-card.json>; rel="agent-card"`. No `ETag`, `Cache-Control`, or `Last-Modified` on the agent card. No `Access-Control-Allow-Origin` header was seen (requests carried no `Origin` header, so CORS behaviour is `UNVERIFIED`; assume a server-side test client).

## 2. Organization index (verbatim)

Source: `https://webmesh.ai/.well-known/agents-index.json` (#1). The wire response is a single 5826-byte line; it is reproduced below re-indented only (key order and every value unchanged; equality with the wire JSON was asserted programmatically). 118 lines, so not truncated.

```json
{
  "schemaVersion": "0.1",
  "spec": "draft-mozleywilliams-dnsop-dnsaid-02",
  "organization": "webmesh.ai",
  "description": "Organization agent index (DNS-AID use case 2). Resolve each agent's SVCB record at its ownerName for connection details (use case 1).",
  "agents": [
    {
      "name": "Webmesh Agent",
      "ownerName": "agent.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://agent.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://agent.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://agent.webmesh.ai/mcp",
      "a2aEndpoint": "https://agent.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/de02d013-138e-4e50-9cae-daa20bc3dc37",
      "summary": "Verifies, discovers, and interacts with ANS agents by FQDN."
    },
    {
      "name": "Domain Impact Analyzer",
      "ownerName": "impact.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://impact.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://impact.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://impact.webmesh.ai/mcp",
      "a2aEndpoint": "https://impact.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/f406507d-2185-4d34-b667-95eac772f2af",
      "summary": "Scores domains for technical disruption and media impact before removal from DNS."
    },
    {
      "name": "Domain DNS/SSL Doctor",
      "ownerName": "dnsdoc.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://dnsdoc.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://dnsdoc.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://dnsdoc.webmesh.ai/mcp",
      "a2aEndpoint": "https://dnsdoc.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/e1b465ae-e117-43a1-9e55-6ba66b059146",
      "summary": "Diagnoses a domain's DNS, TLS/SSL, HTTP, and email configuration from live probes."
    },
    {
      "name": "SEO & LLM Discovery Analyzer",
      "ownerName": "seo.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://seo.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://seo.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://seo.webmesh.ai/mcp",
      "a2aEndpoint": "https://seo.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/0dd48801-3fab-4243-add8-5a5503c25f69",
      "summary": "Analyzes a web page for SEO and LLM-discovery (LLMO/GEO) optimization from a live fetch."
    },
    {
      "name": "Traveler Agent",
      "ownerName": "traveler.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://traveler.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://traveler.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://traveler.webmesh.ai/mcp",
      "a2aEndpoint": "https://traveler.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/1b0bc6c1-2160-4b24-8261-5b38c97ec7fa",
      "summary": "Books flights within a spending mandate. Finds options, requests authorization, books, leaves an auditable evidence chain."
    },
    {
      "name": "Travel Supplier",
      "ownerName": "supplier.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://supplier.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://supplier.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://supplier.webmesh.ai/mcp",
      "a2aEndpoint": "https://supplier.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/89b08fbc-a12a-4989-9c89-f2050f5a4505",
      "summary": "Issues flight quotes (x402-gated) and books against verified AP2 mandates with DPoP proof. SCITT-anchored receipts."
    },
    {
      "name": "Spending Authority",
      "ownerName": "authority.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://authority.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://authority.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://authority.webmesh.ai/mcp",
      "a2aEndpoint": "https://authority.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/fa76a86a-0543-4c89-85bb-db63291da81e",
      "summary": "Issues RFC 9421 AP2 spending mandates with DPoP key binding. Human spending policy as a machine-verifiable instrument."
    },
    {
      "name": "Auditor Agent",
      "ownerName": "auditor.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://auditor.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://auditor.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://auditor.webmesh.ai/mcp",
      "a2aEndpoint": "https://auditor.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/0c2ed1ce-bdad-4c65-bb98-b12b06e5c3c1",
      "summary": "Independently verifies transactions from public evidence. Walks identity chain, checks mandate and DPoP binding, produces signed report."
    },
    {
      "name": "Rogue Supplier (Adversarial Test)",
      "ownerName": "rogue-supplier.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://rogue-supplier.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://rogue-supplier.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://rogue-supplier.webmesh.ai/mcp",
      "a2aEndpoint": "https://rogue-supplier.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/1fe31038-5cd2-4824-942d-b80d160a2724",
      "summary": "Test agent: ANS-registered agent that skips mandate/DPoP/settlement. Caught by the auditor on mandate_signature and receipt_anchored. For interop security testing."
    },
    {
      "name": "Fraud Agent (Attack Battery)",
      "ownerName": "fraud.webmesh.ai",
      "protocols": ["a2a", "mcp"],
      "agentCard": "https://fraud.webmesh.ai/.well-known/agent-card.json",
      "trustCard": "https://fraud.webmesh.ai/.well-known/ans/trust-card.json",
      "mcpEndpoint": "https://fraud.webmesh.ai/mcp",
      "a2aEndpoint": "https://fraud.webmesh.ai/",
      "tlBadge": "https://transparency.ans.godaddy.com/v1/agents/02afb4ea-11d7-4661-9199-9a815a53d000",
      "summary": "Adversarial attack-battery agent (v2): 10 targeted attacks (mandate forgery, DPoP, authorization binding, on-chain replay) + 3 structural probes (payTo attestation, card drift, canonicalization). run_battery executes all concurrently. Every attack must be BLOCKED."
    }
  ]
}
```

Structure notes (`VERIFIED`):

- Top level: `schemaVersion` ("0.1"), `spec` ("draft-mozleywilliams-dnsop-dnsaid-02"), `organization`, `description`, `agents[]`.
- Each agent entry has exactly: `name`, `ownerName` (the FQDN), `protocols` (always `["a2a","mcp"]`), `agentCard`, `trustCard`, `mcpEndpoint` (`https://<host>/mcp`), `a2aEndpoint` (`https://<host>/`), `tlBadge` (GoDaddy ANS transparency-log URL), `summary`.
- 10 agents: `agent`, `impact`, `dnsdoc`, `seo`, `traveler`, `supplier`, `authority`, `auditor`, `rogue-supplier`, `fraud` (all under `webmesh.ai`).
- The index itself is **not signed** and has no per-entry digest.
- Index `name` differs from the card `name` for two hosts: `rogue-supplier` (index "Rogue Supplier (Adversarial Test)" vs card **"Travel Supplier"**) and `fraud` (index "Fraud Agent (Attack Battery)" vs card "Fraud Test Agent"). Key your test on `ownerName` / host, never on display name.

## 3. Per-agent table (the six requested hosts)

Identical on all six cards (`VERIFIED`, declared): top-level `protocolVersion: "1.0"`; exactly one `supportedInterfaces` entry `{url: "https://<host>", protocolBinding: "jsonrpc", protocolVersion: "1.0"}`; no `preferredTransport` / `additionalInterfaces` fields at all; legacy top-level `url: "https://<host>"` also present; `capabilities = {streaming: false, pushNotifications: false, extendedAgentCard: false, extensions: [...]}`; `securitySchemes = {noAuth, ansIdentityCert (mutualTLS), httpMessageSignatures (http/signature)}`; `securityRequirements: [{"noAuth": []}]`; `defaultInputModes: [text/plain, application/json]`; one entry in `signatures[]`; MCP advertised through a capability extension with `uri: "https://modelcontextprotocol.io"` and `params = {endpoint: "https://<host>/mcp", transport: "streamable-http", protocolVersion: "2025-03-26", discoveryUrl: "https://<host>/.well-known/mcp.json"}`.

| Host | Card `name` / `version` | A2A card URL | A2A JSON-RPC URL | A2A protocol version | Transports | MCP URL | Auth required? | Notable skills (ids) |
|---|---|---|---|---|---|---|---|---|
| agent.webmesh.ai | Webmesh Agent / 1.0.13 | https://agent.webmesh.ai/.well-known/agent-card.json | `POST https://agent.webmesh.ai/` | 1.0 (llms.txt: "1.0 backward-compatible with 0.3") | JSON-RPC only; no streaming, no push | https://agent.webmesh.ai/mcp -> 307 -> `/mcp/`; streamable-http; MCP 2025-03-26 | **No** (declared `noAuth`; landing page: "no credential required") | `verify`, `discover`, `interact` |
| dnsdoc.webmesh.ai | Domain DNS/SSL Doctor / 1.0.6 | https://dnsdoc.webmesh.ai/.well-known/agent-card.json | `POST https://dnsdoc.webmesh.ai/` | 1.0 | JSON-RPC only | https://dnsdoc.webmesh.ai/mcp | **No** for `diagnose`. A separate paid op is declared via extension `https://webmesh.ai/ext/gated-commerce/v1`: scope `purchase:dns_deep_scan`, `mandateRequired: true`, USD 0.50, RFC 9421-signed capability + mandate | `diagnose` (MCP tool is `diagnose` in mcp.json but called `diagnose_domain` in the card's extension text) |
| seo.webmesh.ai | SEO & LLM Discovery Analyzer / 1.0.7 | https://seo.webmesh.ai/.well-known/agent-card.json | `POST https://seo.webmesh.ai/` | 1.0 | JSON-RPC only | https://seo.webmesh.ai/mcp | No HTTP auth, **but payment is declared required**: extension `https://webmesh.ai/ext/x402/v1` `active: true` - $0.01 USDC, network `eip155:84532`, payTo `0xb2F8DcB78321fEd765dA208e9e07eD9180177066`, facilitator `https://x402.org/facilitator`. Declared behaviour: A2A `POST /` answers HTTP 402 with a payment-required header; unpaid MCP `analyze_seo` returns `isError: true` with the x402 challenge in `result.structuredContent`; payment travels in `params._meta["x402/payment"]`. Also gated-commerce `purchase:seo_audit` USD 0.50 | `analyze_seo` (only tool in the fleet with a published `inputSchema`: `url` required, `goal` optional) |
| auditor.webmesh.ai | Auditor Agent / 1.0.3 | https://auditor.webmesh.ai/.well-known/agent-card.json | `POST https://auditor.webmesh.ai/` | 1.0 | JSON-RPC only | https://auditor.webmesh.ai/mcp | **No** (declared) | `audit_transaction` (input `application/json` only: an evidence bundle; 10 checks incl. on-chain EIP-3009 settlement on Base Sepolia; example "Audit booking T-1042") |
| rogue-supplier.webmesh.ai | **Travel Supplier** / 1.0.2 | https://rogue-supplier.webmesh.ai/.well-known/agent-card.json | `POST https://rogue-supplier.webmesh.ai/` | 1.0 | JSON-RPC only | https://rogue-supplier.webmesh.ai/mcp | **No** (declared) | `get_quote` (tags `adversarial`, `test`; example "Rogue quote MAD-SIN") |
| fraud.webmesh.ai | Fraud Test Agent / 1.0.2 | https://fraud.webmesh.ai/.well-known/agent-card.json | `POST https://fraud.webmesh.ai/` | 1.0 | JSON-RPC only | https://fraud.webmesh.ai/mcp | **No** (declared) - anyone can trigger it | `run_battery` + 12 attack skills + 3 probes (section 8) |

"Auth required?" reflects what each card **declares**. Whether the servers enforce anything on POST is `UNVERIFIED` (no POST was sent). Each card also carries `x-security-note`: mTLS (`ansIdentityCert`) "is declared for future ANS-to-ANS production calls but is not currently enforced".

Other hosts in the index, **not fetched** (everything beyond the index line is `UNVERIFIED`): `impact.webmesh.ai` (Domain Impact Analyzer), `traveler.webmesh.ai` (Traveler Agent), `supplier.webmesh.ai` (Travel Supplier, "x402-gated" quotes, AP2 mandates + DPoP), `authority.webmesh.ai` (Spending Authority, RFC 9421 AP2 mandates).

Per-host identity extras (`VERIFIED`, declared in every card): `provider.did = did:web:<host>`; `x-identity.ans.uri = ans://v<version>.<host>`; `x-identity.wimse.spiffeId = spiffe://webmesh.ai/agents/<label>`; `x-discovery.dns_aid_svcb = "<host> IN SVCB 1 . alpn=a2a,h2"`; extension `https://webmesh.ai/ext/ans-trust-stack/v1` pointing at `trust-card.json`, `ard.json`, `agentfacts.json`, `http-message-signatures-directory`.

## 4. Verbatim agent card: agent.webmesh.ai

Source: #2. Re-indented only (content-equal to the wire JSON). The sha256 in the source log is over the **raw wire bytes**, not over this re-indented form.

```json
{
  "name": "Webmesh Agent",
  "url": "https://agent.webmesh.ai",
  "description": "Interrogates other agents by hostname. Verifies whether an agent is what it claims, from its DNS records, DNSSEC signatures, Agent Name Service (ANS) Transparency Log proof, and published agent card. Sends any agent a live A2A message and reports the credential it requires. Searches the ANS registry for agents by capability or protocol. The verify and interact checks run against any agent, whether or not it is ANS-registered; the registry search covers agents registered in ANS.",
  "version": "1.0.13",
  "protocolVersion": "1.0",
  "provider": {
    "organization": "Webmesh",
    "url": "https://webmesh.ai",
    "did": "did:web:agent.webmesh.ai"
  },
  "documentationUrl": "https://agent.webmesh.ai",
  "supportedInterfaces": [
    {
      "url": "https://agent.webmesh.ai",
      "protocolBinding": "jsonrpc",
      "protocolVersion": "1.0"
    }
  ],
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "extendedAgentCard": false,
    "extensions": [
      {
        "uri": "https://modelcontextprotocol.io",
        "description": "MCP server exposing read-only verification tools over streamable-HTTP.",
        "required": false,
        "params": {
          "endpoint": "https://agent.webmesh.ai/mcp",
          "transport": "streamable-http",
          "protocolVersion": "2025-03-26",
          "discoveryUrl": "https://agent.webmesh.ai/.well-known/mcp.json"
        }
      },
      {
        "uri": "https://webmesh.ai/ext/ans-trust-stack/v1",
        "description": "Identity and interoperability stack: ANS Trust Card (x5c chain + stapled SCITT receipt), DNS-AID SVCB with DNSSEC and DANE TLSA, DNSid organizational accountability, ARD / AI-Catalog discovery, and Web Bot Auth (RFC 9421 HTTP Message Signatures) outbound request signing.",
        "required": false,
        "params": {
          "trustCard": "https://agent.webmesh.ai/.well-known/ans/trust-card.json",
          "ard": "https://agent.webmesh.ai/.well-known/ard.json",
          "agentFacts": "https://agent.webmesh.ai/agentfacts.json",
          "httpMessageSignaturesDirectory": "https://agent.webmesh.ai/.well-known/http-message-signatures-directory",
          "identityAnchors": [
            "ans-x509",
            "did:web",
            "dns-aid",
            "dnssec",
            "dane-tlsa",
            "dnsid"
          ],
          "outboundSigning": "web-bot-auth"
        }
      }
    ]
  },
  "securitySchemes": {
    "noAuth": {
      "type": "noAuth",
      "description": "This agent is publicly accessible with no authentication required. All skills are available to any caller."
    },
    "ansIdentityCert": {
      "type": "mutualTLS",
      "description": "ANS Identity Certificate issued by the ANS Registration Authority. The agent presents this cert during the TLS handshake; clients verify against the chain advertised in the Trust Card's keys[].x5c. See https://agent.webmesh.ai/.well-known/ans/trust-card.json"
    },
    "httpMessageSignatures": {
      "type": "http",
      "scheme": "signature",
      "description": "RFC 9421 HTTP Message Signatures over response components, using the Ed25519 key advertised in the Trust Card. Public key directory at https://agent.webmesh.ai/.well-known/http-message-signatures-directory"
    }
  },
  "securityRequirements": [
    {
      "noAuth": []
    }
  ],
  "defaultInputModes": [
    "text/plain",
    "application/json"
  ],
  "defaultOutputModes": [
    "application/json",
    "text/plain"
  ],
  "skills": [
    {
      "id": "verify",
      "name": "Agent Verification",
      "description": "Checks identity and compatibility for an agent at a given FQDN. Returns a four-dimension compatibility verdict (identity / protocol / auth / attestations, each pass/warning/unable-to-check) and a can_traveler_transact summary, plus: A2A protocol version vs our v1.0 baseline, all endpoints (A2A and MCP) with versions, bearer auth forms and mandate authority, SPIFFE ID if present, and the full identity evidence chain (ANS TL proof, DNSSEC, DNS-AID, DNSid). Works for any agent, ANS-registered or not.",
      "tags": [
        "verification",
        "trust",
        "ANS",
        "DNS-AID",
        "DNSSEC",
        "interop"
      ],
      "examples": [
        "Verify agent.webmesh.ai",
        "Is travel.agenthaven.dev compatible with our traveler?",
        "Check the evidence trail for ans://v1.0.2.agent.webmesh.ai",
        "What protocol does bookings.example.com speak?"
      ],
      "inputModes": [
        "text/plain",
        "application/json"
      ],
      "outputModes": [
        "application/json",
        "text/plain"
      ],
      "securityRequirements": [
        {
          "noAuth": []
        }
      ]
    },
    {
      "id": "discover",
      "name": "Agent Discovery",
      "description": "Searches the ANS registry for agents matching a free-text query, a capability description, or a protocol filter. Returns Trust Index-scored candidates. Use this to find agents before verifying or interacting with them.",
      "tags": [
        "discovery",
        "search",
        "ANS"
      ],
      "examples": [
        "Find agents that handle DNS diagnostics",
        "List ANS-registered A2A agents tagged with compliance",
        "Which agents in prod cover IP address management?",
        "Show me MCP agents for infrastructure operations"
      ],
      "inputModes": [
        "text/plain",
        "application/json"
      ],
      "outputModes": [
        "application/json",
        "text/plain"
      ],
      "securityRequirements": [
        {
          "noAuth": []
        }
      ]
    },
    {
      "id": "interact",
      "name": "Agent Interaction",
      "description": "Sends a message to another A2A agent and returns its reply. Reads the target agent card to determine the correct endpoint and authentication requirements. For agents that require OAuth2, reports exactly what credential is needed and where to get it. For open agents, sends the message and returns the response directly.",
      "tags": [
        "interaction",
        "A2A",
        "interconnect"
      ],
      "examples": [
        "Ask ddi-agent.ai.infoblox.com what DNS skills it has",
        "Talk to agent.example.com: what can you do?",
        "Send 'list your skills' to the agent at bookings.example.com"
      ],
      "inputModes": [
        "text/plain",
        "application/json"
      ],
      "outputModes": [
        "application/json",
        "text/plain"
      ],
      "securityRequirements": [
        {
          "noAuth": []
        }
      ]
    }
  ],
  "x-identity": {
    "ans": {
      "uri": "ans://v1.0.13.agent.webmesh.ai",
      "trustCard": "https://agent.webmesh.ai/.well-known/ans/trust-card.json",
      "transparencyLog": "https://transparency.ans.godaddy.com/v1/agents/de02d013-138e-4e50-9cae-daa20bc3dc37"
    },
    "wimse": {
      "spiffeId": "spiffe://webmesh.ai/agents/agent",
      "jwksUri": "https://agent.webmesh.ai/.well-known/jwks.json",
      "supportedProfiles": [
        "urn:ietf:params:wimse:agent-delegation-chain"
      ],
      "signingAlgs": [
        "EdDSA"
      ]
    }
  },
  "x-discovery": {
    "ans_registered": "prod",
    "ans_name": "ans://v1.0.13.agent.webmesh.ai",
    "tl_badge": "https://transparency.ans.godaddy.com/v1/agents/de02d013-138e-4e50-9cae-daa20bc3dc37",
    "trust_index": {
      "score_url": "https://api.godaddy.com/v1/ans/registered-agents?query=agent.webmesh.ai",
      "score_field": "scores.trustScore",
      "auth": "sso-key"
    },
    "dns_aid_svcb": "agent.webmesh.ai IN SVCB 1 . alpn=a2a,h2"
  },
  "x-security-note": "This agent is publicly accessible with no authentication required (noAuth). The ansIdentityCert scheme (mutual TLS, ANS private CA) is declared for future ANS-to-ANS production calls but is not currently enforced. The card accurately describes what is enforced.",
  "signatures": [
    {
      "protected": "eyJhbGciOiJFZERTQSIsImprdSI6Imh0dHBzOi8vYWdlbnQud2VibWVzaC5haS8ud2VsbC1rbm93bi9hbnMvdHJ1c3QtY2FyZC5qc29uIiwia2lkIjoib2NtSldqeVZEdU1VaXlaTWE2cE9Hcmd4X2RaaFNuU0RzejM1aG1OLWs5ayIsInR5cCI6ImFnZW50LWNhcmQrandzIn0",
      "signature": "RLXWOC6V2CQnwMd45OrEffbcJwXHJHuBc3ix9jvevre2-ThsxON18m25CVXn2WqjSbblIMkhS2SL_3cwYqE4DA",
      "header": {
        "kid": "ocmJWjyVDuMUiyZMa6pOGrgx_dZhSnSDsz35hmN-k9k"
      }
    }
  ]
}
```

## 5. Card signatures: shape and verification

Shape (`VERIFIED`, identical on all six cards): `signatures` is an array with one object `{protected, signature, header}`.

- `protected` base64url-decodes to `{"alg":"EdDSA","jku":"https://<host>/.well-known/ans/trust-card.json","kid":"<kid>","typ":"agent-card+jws"}`.
- `header` (unprotected) is `{"kid":"<same kid>"}`.
- `signature` is 64 bytes (Ed25519), base64url without padding.
- There is no `payload` member: it is a detached JWS over the canonicalized card.

| Host | `kid` |
|---|---|
| agent | `ocmJWjyVDuMUiyZMa6pOGrgx_dZhSnSDsz35hmN-k9k` |
| dnsdoc | `NIdpC3kzdLNrmpNKOKgsxzOvbR94x1tBU6UPFmW9_Gk` |
| seo | `b4kj5_G1pMGof3YxOm2wD7Pc4-oAuKBSkwOuIIOl6n0` |
| auditor | `MyGFNlbIqbsQHrlCBL_CxVVZ3GYY1xap-YyimJ6GSfY` |
| rogue-supplier | `oUEmcpMGlVaY8fwjcFZMuWwD5JgB-b0f4UhC_Ein7qg` |
| fraud | `4_RgdO4PzJZTHVMey-ZbaXTVP7LOC4fLksbn8d8anDg` |

Key source (`VERIFIED`, #17): `jku` is not a bare JWKS but the ANS trust card; it does have a top-level `keys[]` array, so JWKS-style lookup by `kid` works. Trust card for `agent.webmesh.ai` (long base64 values truncated here):

```json
{
  "ansName": "ans://v1.0.13.agent.webmesh.ai",
  "agentDisplayName": "agent.webmesh.ai",
  "version": "1.0.13",
  "agentHost": "agent.webmesh.ai",
  "endpoints": [
    {
      "protocol": "A2A",
      "agentUrl": "https://agent.webmesh.ai",
      "metaDataUrl": "https://agent.webmesh.ai/.well-known/agent-card.json"
    }
  ],
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "ihnMrBbo3WFd7wCOKBkcOr73CrAgkGIEaAQryO0OtS8",
      "use": "sig",
      "kid": "ocmJWjyVDuMUiyZMa6pOGrgx_dZhSnSDsz35hmN-k9k",
      "x5c": [
        "MIIFejCCA2KgAwIBAgISAaCWY17GAH4b/KEbekNaAAEEMA0GCSqGSIb3DQEB...<truncated, 1876 chars total>"
      ]
    }
  ],
  "agentId": "de02d013-138e-4e50-9cae-daa20bc3dc37",
  "transparencyReceipt": "0oRYNKQBJgREyeL1hBkBiwEPogF4HHRyYW5zcGFyZW5jeS5hbnMuZ29kYWRk...<truncated, 3620 chars total>",
  "botProfile": {
    "client_name": "agent.webmesh.ai",
    "client_uri": "https://agent.webmesh.ai",
    "expected-user-agent": "webmesh-agent/1.0 (+https://agent.webmesh.ai)",
    "trigger": "fetcher",
    "purpose": "Interrogates other agents by hostname. Verifies whether an a...<truncated, 482 chars total>"
  }
}
```

Verification recipe that **worked** for `agent.webmesh.ai` (`VERIFIED-LOCAL`, Python `cryptography`, offline, on the bytes from #2 and #17):

1. Parse the card; remove only the `signatures` member.
2. Canonicalize with RFC 8785 JCS (sorted keys, no whitespace). **Keep** `false`-valued fields and all `x-*` fields.
3. Signing input = `protected` + `"."` + base64url(canonical bytes).
4. Verify Ed25519 with `keys[kid].x` from the trust card. Result: **VALID**.

Variants that **failed** (`VERIFIED-LOCAL`): stripping default/false values before canonicalizing (what A2A 1.0 section 8.4 literally prescribes); dropping `x-*` members; original key order; unencoded (`b64=false`) payload. So a verifier that follows the spec's "remove properties with default values" step will reject these cards.

Cross-check (`VERIFIED-LOCAL`): sha256 of the raw card bytes equals `entries[0].trustManifest.subject.digest` in `ai-catalog.json` (`sha256:2b6450...b1fb`). That manifest is itself a compact detached JWS (`typ: trust-manifest+jws`, same `kid`); its signature was not checked (`UNVERIFIED`).

Not checked (`UNVERIFIED`): signatures of the other five cards (their trust cards were not fetched); the `x5c` chain to the GoDaddy ANS Registration Authority; the stapled SCITT `transparencyReceipt`; the `tlBadge` URLs; every DNS claim (SVCB, `_ans` / `_ans-badge` / `_dnsid` TXT, TLSA, DNSSEC).

## 6. How agent.webmesh.ai is meant to be asked to verify an agent by FQDN

Sources: card (#2), mcp.json (#8), landing page (#9), llms.txt (#10). All `VERIFIED` as published text.

- Interface is **natural language over A2A** (`text/plain`; `application/json` is also listed as an input mode but no JSON input shape is published - `UNVERIFIED`) or **MCP tools** with the same three names.
- Published example prompts for `verify`: `Verify agent.webmesh.ai` / `Is travel.agenthaven.dev compatible with our traveler?` / `Check the evidence trail for ans://v1.0.2.agent.webmesh.ai` / `What protocol does bookings.example.com speak?`. Both a bare FQDN and an `ans://v<semver>.<fqdn>` name appear.
- Published example prompts for `discover`: `Find agents that handle DNS diagnostics` / `List ANS-registered A2A agents tagged with compliance` / `Which agents in prod cover IP address management?` / `Show me MCP agents for infrastructure operations`.
- Published example prompts for `interact`: `Ask ddi-agent.ai.infoblox.com what DNS skills it has` / `Talk to agent.example.com: what can you do?` / `Send 'list your skills' to the agent at bookings.example.com`.
- Documented `verify` output: a four-dimension compatibility verdict (identity / protocol / auth / attestations, each pass / warning / unable-to-check), a `can_traveler_transact` summary, A2A protocol version vs "our v1.0 baseline", all A2A and MCP endpoints with versions, bearer auth forms and mandate authority, SPIFFE ID if present, and the identity evidence chain (ANS TL proof, DNSSEC, DNS-AID, DNSid). "Works for any agent, ANS-registered or not."
- `discover` searches the ANS registry only and returns "Trust Index-scored candidates".
- mcp.json note: "No HTTP authentication required. Tools exposed: verify, discover, interact. Outbound A2A calls are not exposed over this MCP endpoint." (The last sentence sits oddly next to an `interact` tool whose job is an outbound A2A call; behaviour `UNVERIFIED`.)

`https://agent.webmesh.ai/.well-known/mcp.json` verbatim (re-indented):

```json
{
  "mcpVersion": "2025-03-26",
  "version": "1.0.13",
  "endpoint": "https://agent.webmesh.ai/mcp",
  "transport": "streamable-http",
  "authentication": {
    "schemes": [
      "none"
    ],
    "notes": "No HTTP authentication required. Tools exposed: verify, discover, interact. Outbound A2A calls are not exposed over this MCP endpoint."
  },
  "tools": [
    {
      "name": "verify",
      "description": "Checks identity and compatibility for an agent at a given FQDN. Returns a four-dimension compatibility verdict (identity / protocol / auth / attestations, each pass/warning/unable-to-check) and a can_traveler_transact summary, plus: A2A protocol version vs our v1.0 baseline, all endpoints (A2A and MCP) with versions, bearer auth forms and mandate authority, SPIFFE ID if present, and the full identity evidence chain (ANS TL proof, DNSSEC, DNS-AID, DNSid). Works for any agent, ANS-registered or not."
    },
    {
      "name": "discover",
      "description": "Searches the ANS registry for agents matching a free-text query, a capability description, or a protocol filter. Returns Trust Index-scored candidates. Use this to find agents before verifying or interacting with them."
    },
    {
      "name": "interact",
      "description": "Sends a message to another A2A agent and returns its reply. Reads the target agent card to determine the correct endpoint and authentication requirements. For agents that require OAuth2, reports exactly what credential is needed and where to get it. For open agents, sends the message and returns the response directly."
    }
  ],
  "agentCardUrl": "https://agent.webmesh.ai/.well-known/agent-card.json",
  "trustCardUrl": "https://agent.webmesh.ai/.well-known/ans/trust-card.json"
}
```

There is **no `inputSchema`** for `verify` / `discover` / `interact` anywhere reachable by GET. The argument names are therefore `UNVERIFIED`; the test must read them from `tools/list`. For reference, the only schema the fleet publishes (seo `analyze_seo`, #21) is a flat object: `{"type":"object","properties":{"url":{"type":"string"},"goal":{"type":"string"}},"required":["url"]}`.

Safety guidance for a read-only test: `verify` and `discover` are lookups. `interact` makes Webmesh send a live A2A message to whatever host you name, so only ever point it at an agent you own. For `verify`, use `agent.webmesh.ai` itself (their first published example) or your own FQDN.

## 7. Safe read-only request examples (NOT executed in this research)

### 7.1 A2A 1.0 `SendMessage` (matches the card's `protocolVersion: "1.0"`)

Request shape confirmed against the live A2A 1.0.0 spec (#26): JSON-RPC 2.0 over HTTPS, `Content-Type: application/json`, PascalCase method `SendMessage`, clients MUST send `A2A-Version` (an absent header is treated as 0.3), role enum `ROLE_USER`, parts discriminated by member name (`{"text": ...}`), blocking by default. Whether Webmesh's server accepts it is `UNVERIFIED`.

```http
POST / HTTP/1.1
Host: agent.webmesh.ai
Content-Type: application/json
Accept: application/json
A2A-Version: 1.0
```

```json
{
  "jsonrpc": "2.0",
  "id": "agentdesk-interop-1",
  "method": "SendMessage",
  "params": {
    "message": {
      "messageId": "6f1c2a0e-3b7d-4e55-9a41-0c8d2e9b7f10",
      "role": "ROLE_USER",
      "parts": [
        { "text": "Verify agent.webmesh.ai" }
      ]
    }
  }
}
```

Use a fresh UUID for `messageId` on every call. Expected success envelope per spec: `{"jsonrpc":"2.0","id":"agentdesk-interop-1","result":{"task":{...}}}` or `{"result":{"message":{...}}}` (exactly one of `task` / `message`); task states look like `TASK_STATE_COMPLETED`. Allow a generous timeout (the skill does live DNS / HTTPS / transparency-log lookups). Do not send `SendStreamingMessage` (`streaming: false`).

### 7.2 A2A 0.3 fallback `message/send`

Use only if 7.1 returns JSON-RPC `-32601` (method not found) or `-32009` (`VersionNotSupportedError`). Send `A2A-Version: 0.3` or omit the header. The 0.3 body shape below is from spec knowledge, not fetched this session: `UNVERIFIED`.

```json
{
  "jsonrpc": "2.0",
  "id": "agentdesk-interop-1",
  "method": "message/send",
  "params": {
    "message": {
      "kind": "message",
      "messageId": "6f1c2a0e-3b7d-4e55-9a41-0c8d2e9b7f10",
      "role": "user",
      "parts": [
        { "kind": "text", "text": "Verify agent.webmesh.ai" }
      ]
    }
  }
}
```

### 7.3 MCP (streamable HTTP, protocol `2025-03-26`)

Endpoint: **`https://agent.webmesh.ai/mcp/`**. The advertised `https://agent.webmesh.ai/mcp` answers GET with `307 Location: /mcp/` (#23); a POST is expected to be redirected the same way (`UNVERIFIED`), and HTTP clients that do not follow redirects on POST (for example `httpx` defaults) will fail, so either use the trailing slash or enable redirect following. GET on `/mcp/` with `Accept: text/event-stream` opens a `200 text/event-stream` stream (#24).

The MCP message framing below follows the MCP 2025-03-26 spec from knowledge (not fetched this session: `UNVERIFIED`). Headers on every POST: `Content-Type: application/json` and `Accept: application/json, text/event-stream`. If the `initialize` response carries an `Mcp-Session-Id` header, echo it on every later request.

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"agentdesk-interop-test","version":"0.1.0"}}}
```

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

```json
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
```

Assert that `tools/list` returns exactly `verify`, `discover`, `interact` (matches mcp.json), read `inputSchema` of `verify`, then:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify","arguments":{"fqdn":"agent.webmesh.ai"}}}
```

The tool name `verify` is `VERIFIED` (mcp.json). The argument key **`fqdn` is a placeholder guess and is `UNVERIFIED`**: build `arguments` from the `inputSchema` returned by `tools/list` (put `agent.webmesh.ai` in its single required string property) rather than hard-coding it. Responses may arrive as plain JSON or as an SSE stream; handle both.

### 7.4 Suggested discover -> verify -> communicate flow

1. **Discover**: GET the index (section 2); select the entry whose `ownerName` is `agent.webmesh.ai`; GET its `agentCard`. Accept `Content-Type: application/a2a-agent-card+json` (not `application/json`).
2. **Verify**: parse leniently (section 9), verify `signatures[0]` per section 5 using the key fetched from `jku`; assert `kid` in `protected` equals `header.kid`; assert the `jku` host equals the card host; optionally compare sha256(raw card) with the digest in `/.well-known/ai-catalog.json`. Cross-check index vs card: `a2aEndpoint` equals `supportedInterfaces[0].url` modulo a trailing slash; `mcpEndpoint` equals the MCP extension's `params.endpoint`.
3. **Communicate**: 7.1 (with 7.2 as fallback) and/or 7.3. Assert a well-formed JSON-RPC result, not specific verdict text.

Second-choice target if a non-LLM-style tool is preferred: `dnsdoc.webmesh.ai` `diagnose` (declared free). It runs live DNS / TLS / HTTP / email probes against whatever domain you name, so only name a domain you own (or `webmesh.ai`). Its MCP tool name is ambiguous (`diagnose` vs `diagnose_domain`), so again trust `tools/list`.

## 8. Adversarial agents and the attack battery (documentation only - DO NOT RUN)

### 8.1 fraud.webmesh.ai ("Fraud Test Agent", index name "Fraud Agent (Attack Battery)")

Sources: card (#7), landing page (#11), mcp.json (#13). Tool descriptions are identical across the three; the threat-row names below come from the card's skill `name` fields. `VERIFIED` as published. (The table paraphrases lightly and uses ASCII; the card text is authoritative.)

Published summary: "Adversarial attack-battery agent (v2): runs 10 targeted authorization attacks and 3 structural probes against the real Supplier, or all 13 in one shot via run_battery. [...] Every attack must be BLOCKED; VULNERABLE or INCONCLUSIVE signals a supplier defect."

Verdict vocabulary: per attack `BLOCKED` / `VULNERABLE` / `INCONCLUSIVE`; `run_battery` returns `battery_verdict` (`CLEAN` | `FINDINGS` | `INCOMPLETE`), summary counts, a coverage matrix by threat row, and per-attack results.

| Tool / skill id | Published name (threat row) | What it does | Expected result |
|---|---|---|---|
| `run_battery` | Full Attack Battery | Runs all 10 attack-verdict tools concurrently plus the 3 structural probes | every attack BLOCKED |
| `replay_booking` | DPoP Replay (H6) | Replays a spent DPoP proof; tests the supplier's DPoP nonce tracker | `DPOP_REJECTED` |
| `underpay_booking` | Mandate Forgery - Underpay (M1) | Forges `max_amount=1.0` without re-signing; tests signature verification, not amount enforcement | `MANDATE_REJECTED` |
| `tamper_mandate` | Mandate Tampering (M1) | Inflates `max_amount` x10 after signing | `MANDATE_REJECTED` |
| `underpay_valid_sig` | Authority-Signed Underpayment (Authorization/M1) | Authority-signed mandate for $0.01 against a higher-priced ticket; tests amount enforcement independent of signature validity | `MANDATE_REJECTED` |
| `quote_swap_attack` | Quote-ID Binding Attack (Authorization/M1) | Uses mandate(quote A) to book under quote B | `MANDATE_REJECTED` |
| `wrong_audience_attack` | Audience Mismatch (Authorization/M1) | Submits to supplier a mandate addressed to rogue-supplier | `MANDATE_REJECTED` |
| `wrong_scope_attack` | Scope Mismatch (Authorization/M1) | Mandate scoped to MAD-NYC submitted against a MAD-SIN booking | `MANDATE_REJECTED` |
| `wrong_dpop_key_attack` | DPoP Key Binding (H3) | Valid mandate + DPoP proof from a key other than `mandate.jkt` | `DPOP_REJECTED` |
| `corrupt_jws_attack` | Corrupt JWS Signature (M1) | Last 2 bytes of the JWS signature flipped; verifier must reject cleanly, not throw | `MANDATE_REJECTED` |
| `superseded_format_attack` | Superseded Format (C1) | Mandate stripped to legacy fields (no scope, no jkt, no signature) | `MANDATE_REJECTED` or `MANDATE_PARSE_ERROR` |
| `unknown_key_mandate` | Unknown Signing Key (M3/E5) | Mandate signed by a fresh Ed25519 key absent from the authority's trust card; tests fail-closed | `MANDATE_REJECTED` |
| `replay_settled` | On-Chain Replay (H6/post-127) | Resubmits an already-used mandate with a fresh DPoP proof each time; probes EIP-3009 nonce state on Base Sepolia | `MANDATE_REJECTED`, `PAYMENT_REQUIRED`, or `EVM_SETTLEMENT_FAILED` |
| `canonicalization_probe` | JCS Canonicalization Probe (M2) | Requests two authority-signed mandates whose `max_amount` serializes differently (float vs int) | consistent handling; divergence is an M2 signal |
| `payto_binding_check` | payTo Attestation Probe (M4/H7) | Fetches the supplier's x402 `payTo` and checks whether it is attested in the signed agent card. "Structural probe, not an exploit." | attested |
| `card_drift_watch` | Supplier Card Drift (B1) | Hashes the supplier's signed agent card and compares with the previous run | no drift without re-registration |

Count inconsistency (`VERIFIED` as published): the prose says "10 targeted attacks + 3 probes = 13", but 12 attack ids are listed (16 tools in total with `run_battery`). Which 10 are inside `run_battery` is not stated (`UNVERIFIED`).

**How a target opts in: not published.** Across the landing page, agent card, and mcp.json there is no target parameter, allow-list, consent file, DNS record, registration step, or contact address. `fraud.webmesh.ai/llms.txt` is a 404. No tool `inputSchema` is published. Every description is written against one fixed target, "the real Supplier" - the examples name `supplier.webmesh.ai` ("Run the full fraud battery against supplier.webmesh.ai", "Check whether supplier.webmesh.ai's payTo is in its signed card"). Whether any tool accepts another target is `UNVERIFIED`.

Applicability to AgentDesk, as far as the published material goes: the battery is Webmesh's **self-test of its own Supplier**, not a service you aim at your own agent, and it exercises an AP2-mandate / DPoP / x402 / EIP-3009 booking flow that an agent must implement to be a meaningful target. Treat it as **not applicable** unless Webmesh documents an opt-in. Because the agent declares `noAuth`, any caller could apparently start live attack traffic against `supplier.webmesh.ai` plus Base Sepolia on-chain activity; a read-only interop test must never call any fraud tool or skill. Allowed interaction: GET the card and verify its signature.

### 8.2 rogue-supplier.webmesh.ai (card name "Travel Supplier")

Sources: card (#6), landing page (#12), mcp.json (#15). `VERIFIED` as published.

- Published description: "Adversarial test agent: issues flight quotes without enforcing mandate authorization, DPoP proof, or on-chain settlement. ANS-registered (the key IS anchored and the card IS signed), so the auditor's identity_chain check correctly passes; both are legitimate agents. Detection comes from the mandate and receipt layer: a rogue-supplier evidence bundle carries no authority-signed mandate and no SCITT receipt, so audit_transaction returns verdict=invalid on mandate_signature and receipt_anchored."
- One skill / tool: `get_quote` - "Plausible quotes - broken identity. Expected to fail verification." Tags `adversarial`, `test`. Input `application/json` only; schema unpublished.
- Internal contradiction: the description says identity is valid and passes, while the skill text and MCP extension text say "broken identity" / "no valid identity".
- There is no opt-in concept here: it is a passive fixture that answers quote requests. Nothing on the page describes pointing it at another party.
- Use in an AgentDesk test: a **discover + verify fixture only** (GET the card, check the signature). It demonstrates that a valid signature plus ANS registration says nothing about behaviour, and that the display name collides with the legitimate supplier's index name, so identity must be keyed on host / ANS name. Do not call `get_quote`.

## 9. Interop gotchas and surprises

All `VERIFIED` unless marked. Spec comparisons use the live A2A 1.0.0 spec text (#26).

1. **`protocolBinding` is lowercase `"jsonrpc"`**. The spec calls it an open-form string whose core values are `JSONRPC`, `GRPC`, `HTTP+JSON`. Match case-insensitively or no interface will be selected.
2. **Hybrid 0.3 / 1.0 card.** 1.0 fields are present (`supportedInterfaces`, `securityRequirements`, `capabilities.extendedAgentCard`), but so are top-level `url` and `protocolVersion`, which the 1.0 `AgentCard` no longer defines, plus non-spec `provider.did`, `x-identity`, `x-discovery`, `x-security-note`. A strict protobuf-JSON parser that rejects unknown fields will fail.
3. **`securitySchemes` is not 1.0-shaped.** 1.0 requires a wrapper with exactly one of `apiKeySecurityScheme` / `httpAuthSecurityScheme` / `oauth2SecurityScheme` / `openIdConnectSecurityScheme` / `mtlsSecurityScheme`. Webmesh uses flat OpenAPI-style objects (`{"type":"mutualTLS"}`, `{"type":"http","scheme":"signature"}`) and a non-standard `{"type":"noAuth"}`.
4. **Signature deviations** (section 5): `typ` is `agent-card+jws` (spec: SHOULD be `JOSE`); default-valued fields are **not** stripped before JCS (spec says strip); `jku` points at a trust card rather than a bare JWKS.
5. **ai-catalog.json describes the card as "A2A v0.3 AgentCard"** while the card says 1.0, and llms.txt says "1.0 backward-compatible with 0.3". Expect a dual-stack server (`UNVERIFIED`).
6. **`/mcp` -> 307 -> `/mcp/`**. Observed on `agent.webmesh.ai` (GET). The other hosts advertise the same slash-less `https://<host>/mcp` form and were not probed (`UNVERIFIED`).
7. **Card media type** is `application/a2a-agent-card+json`; clients that insist on `application/json` will reject it.
8. **"Costs nothing to call" conflicts with the seo card**: `webmesh.ai/` says every agent "costs nothing to call" and "no authentication", and its JSON-LD lists all 10 agents (seo included) with `price: 0`, yet `seo.webmesh.ai` declares an active x402 paywall and `dnsdoc` / `seo` declare USD 0.50 gated-commerce operations. `eip155:84532` is the Base Sepolia testnet by general knowledge (`UNVERIFIED`; the seo card itself only says "on Base", while the auditor and fraud cards do name Base Sepolia).
9. **dnsdoc tool-name mismatch**: `diagnose` (mcp.json, skill id) vs `diagnose_domain` (card extension text).
10. **rogue-supplier's card `name` is "Travel Supplier"**, identical to the legitimate supplier's index name.
11. **fraud count mismatch** (10 vs 12 attacks) and a dead `/llms.txt` link.
12. `ard.json` and `ai-catalog.json` are the same document, regenerated and re-signed on every request, so their bytes are never stable; do not hash them.
13. Only `seo` publishes an MCP `inputSchema` in `mcp.json`; every other host publishes names and descriptions only.
14. The wire JSON is ASCII with `\u` escapes; JCS output for cards containing non-ASCII text (fraud's descriptions) will differ from the wire bytes beyond key order. Canonicalize the parsed value, never the raw text.

## 10. UNVERIFIED list

Nothing below was confirmed by a live fetch. Most items would need a POST, which was out of scope.

1. That `POST https://agent.webmesh.ai/` accepts `SendMessage` (1.0), `message/send` (0.3), or both; whether `A2A-Version` is enforced; the error codes it returns.
2. The response shape from any Webmesh agent (Task vs Message, artifact layout, the JSON structure of the `verify` verdict, latency).
3. Input schemas / argument names for MCP `verify`, `discover`, `interact`, `diagnose`, `audit_transaction`, `get_quote`, and all fraud tools. The `fqdn` key in section 7.3 is a guess.
4. The JSON input shape accepted over A2A when `application/json` parts are used.
5. That POST to `/mcp` is redirected like GET; whether the MCP server is stateful (`Mcp-Session-Id`); which MCP protocol versions it negotiates beyond the advertised `2025-03-26`; whether `tools/list` matches `mcp.json`.
6. The MCP framing details in 7.3 and the A2A 0.3 body in 7.2 (from spec knowledge, not fetched).
7. Signature validity of the dnsdoc, seo, auditor, rogue-supplier, and fraud cards (shape confirmed, cryptography not checked).
8. The `x5c` chain, SCITT receipt, transparency-log badge, `did.json`, `jwks.json`, `agentfacts.json`, `http-message-signatures-directory`, `signature-agent-card`: linked from the pages, not fetched.
9. All DNS claims: SVCB `alpn=a2a,h2`, `_ans` / `_ans-badge` / `_dnsid` TXT, DANE TLSA, DNSSEC.
10. Actual enforcement of auth: `noAuth` is declared; mTLS is declared "not currently enforced"; RFC 9421 response signatures are declared. None observed.
11. The seo paywall behaviour (HTTP 402 on A2A, `isError` challenge on MCP) and both gated-commerce operations.
12. Any opt-in mechanism, target parameter, or rate limit for the fraud battery; which 10 attacks `run_battery` actually runs; whether it can be aimed at anything other than `supplier.webmesh.ai`.
13. Everything about `impact`, `traveler`, `supplier`, `authority` beyond their index entries.
14. Whether legacy `/.well-known/agent.json` exists on any host (never requested).
15. CORS behaviour, rate limits, and terms of use: none published on any fetched page.
16. The Trust Index score API (`https://api.godaddy.com/v1/ans/registered-agents?query=<host>`, declared `auth: sso-key`): not fetched.
