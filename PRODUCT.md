# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Hackathon judges (primary; they win ties).** They watch a 3-minute live demo for the GoDaddy "Best Use of ANS" track, mostly on a
  laptop screen shared with a room and once on a phone. Their job: decide quickly whether the five track gates are really met and
  whether the verification is real.
- **Small-business owners.** Non-specialists who want their existing website to become an agent that other agents can find. Their
  job: import the site, check that the extracted facts are right, publish, and register.
- **Other agents and developers.** They consume the A2A/MCP endpoints and `/api/proof`; the HTML pages are secondary for them.

## Product Purpose

Agent Desk turns a business's website into a verified, discoverable AI agent (CREATE), and lets people and other agents discover,
verify, and talk to such agents through the GoDaddy Agent Name Service (FIND). Success is a visitor who understands, at a glance
and without trusting our word for it, whether an agent is verified: PASS, FAIL or INCOMPLETE, and why.

## Positioning

Verification is the product. Every status on screen is the result of a live check (ANS lifecycle, host and endpoint binding, TLS,
transparency log, identity certificate, A2A card, MCP handshake), and "could not be proven" is shown as INCOMPLETE rather than
rounded up. A neighbouring product could show a badge; it could not truthfully show this checklist.

## Operating Context

- Three main tasks: (1) import a website and confirm the extracted facts; (2) search for an agent and read the verification
  results; (3) read a proof page and immediately understand PASS / FAIL / INCOMPLETE.
- Judged live in three minutes: laptop screen viewed from a distance, plus one phone view.
- The desk host (`desk.BASE_DOMAIN`) serves the product UI. Tenant hosts (e.g. `demo.BASE_DOMAIN`) serve a public landing page for
  one business agent that must stand alone.
- Owners copy DNS record names and values off the tenant page into their DNS provider.

## Capabilities and Constraints

- Server-rendered Jinja2 templates in `app/web/templates/`; styles in `app/web/static/`. No build step, no dependencies.
- Strict CSP (`app/security/headers.py`): `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:`. No inline
  styles, style attributes, inline scripts, external stylesheets, web fonts or CDNs. System font stack. Icons are inline SVG or CSS.
- JavaScript is not required. Any script must be a separate file under `/static/` and pages must work without it.
- Every form keeps its action, method, input names, hidden `csrf_token` / `idempotency_key` / `row_version` fields and validation
  attributes. Template variables and the `badge()` macro contract (`badge-pass`, `badge-fail`, `badge-incomplete`,
  `badge-not_checked`) are fixed.
- Light and dark themes via `prefers-color-scheme`; semantic status tokens `--pass`, `--fail`, `--inc`.
- Status is never invented: every badge, gate and check is real backend data.
- Agents are read-only. Payments, bookings and orders are unsupported.
- Content from websites, models, ANS and remote agents is untrusted and is always shown as escaped text; remote replies are
  explicitly labelled untrusted.
- `tests/integration/test_web_app.py` must keep passing.

## Brand Commitments

- Name: **Agent Desk**.
- Motto: **discover → verify → communicate**.
- No GoDaddy logos or brand colours.
- Voice: plain, precise, unhyped. No claim of being "unhackable"; limits are stated.

## Evidence on Hand

- Live five-gate proof and 15-check verification data at `/proof` and `/api/proof`.
- A seeded demo business agent ("Hokie Bean Cafe (demo)", explicitly fictional).
- A real read-only verification of the third-party agent `agent.webmesh.ai` recorded in `GATES.md`.
- No testimonials, customers, logos, screenshots, photography or illustration exist. None may be fabricated.
- Live gates for our own hosts are not yet observed (`GATES.md`); the UI must not imply otherwise.

## Product Principles

1. Show the evidence, not a claim about the evidence.
2. Uncertainty is a first-class state: INCOMPLETE is displayed as plainly as PASS and FAIL.
3. Status must be legible without colour and from across a room.
4. One obvious action per step; nothing becomes public without the owner's explicit confirmation.
5. Untrusted content is always visibly marked as such.

## Accessibility & Inclusion

WCAG 2.2 AA. Status conveyed by text label, never colour alone. Fully keyboard operable with visible focus indicators. Usable at
375px width. Respects `prefers-color-scheme` and `prefers-reduced-motion`.
