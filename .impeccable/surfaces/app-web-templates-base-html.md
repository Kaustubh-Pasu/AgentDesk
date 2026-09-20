---
version: 1
slug: "app-web-templates-base-html"
primary_target: "app/web/templates/base.html"
related_targets: ["app/web/templates","app/web/static/app.css"]
---

# Surface brief: Agent Desk web UI (all server-rendered pages)

Scope: every template under app/web/templates/. Visitor mode: home is Persuade; every other page is Operate.
Audience and job: judges deciding in three minutes whether verification is real (they win ties); owners importing, confirming, publishing, registering.
Proof/content: live five-gate proof, the 15-check list, honest copy. No imagery exists and none is invented.
Constraints: strict CSP, no inline style/script, system font stack, forms and template variables frozen, light/dark via prefers-color-scheme, --pass/--fail/--inc kept.
User decisions (2026-09-19): verdict banner with "n of 5 gates proven" computed in the template; shared nav left as is (restyle only); four ANS buttons stay equal; progressive-enhancement copy buttons via /static/copy.js on the tenant page only.
Unresolved: the tenant landing page still carries Desk nav links that 404 on tenant hosts (user chose to leave the nav alone).

## Direction contract

THESIS: The interface is a public register. Every fact is an entry on a ruled line with its mark in the margin, so the verification checklist is the composition itself. It refuses the category default of a dashboard of equal grey cards with small coloured pills.

OWN-WORLD: Cool paper-white ground, blue-black registrar's ink as the single accent, hairline rules instead of boxes, a fixed left margin column that holds marks (status glyph, step number). Three entry states with their own shapes: PASS is a solid sealed mark, FAIL is a solid struck mark, INCOMPLETE is a hollow dashed mark on an open line. Status words are set large in caps with tabular numerals; monospace only for hostnames, URLs, DNS values and fingerprints. Restrained colour: tint fills appear only behind status.

STORY: The visitor sees the verdict before anything else, understands that each line was witnessed by a live check, and either trusts the agent or knows exactly which line failed.

FIRST VIEWPORT: Home: the promise as one large sentence, one supporting line, then two equal entries (Create agent, Find agent) side by side, each a ruled panel with its own margin mark; primary action is the panel itself. Proof: a full-width verdict banner, status word at about 3rem beside its glyph, "n of 5 gates proven", host and timestamp; the five gates follow as a vertical register in fixed order.

FORM: a notary's / land-registry ledger of witnessed entries, position 5 on the grounded list (inspection certificate, passport stamps, pre-flight checklist, lab report, registry ledger, inspection tag, departure board); seed key e549b8bf. Materials translated to the brief's pinned look: no paper texture, no seals artwork, system fonts. Raised by the hands it beat: ticket wallet, "nothing disappears, it cancels" (a failed entry stays on its line, struck, never hidden); night six-pack, "a fixed constellation, each owning one truth" (the five gates never reorder, so the eye learns one sweep). Signature interaction: the register's margin stepper, the same motif for Create's four stages, Find's discover, verify, communicate, and the tenant page's stages. Motion: none beyond 150 ms state transitions; reduced motion respected.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
