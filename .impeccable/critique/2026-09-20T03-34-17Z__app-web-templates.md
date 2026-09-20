---
target: the current Agent Desk web UI
total_score: 20
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 5
target_identity: "file:/Users/prateekmalekar/AgentDesk/app/web/templates"
timestamp: 2026-09-20T03-34-17Z
slug: app-web-templates
---
Method: dual-agent (A: design review with live browser inspection; B: detector + measured browser evidence)

## Design health: 20/40 (Acceptable, bottom of band)
1 Status 2 · 2 Real-world 2 · 3 Control 2 · 4 Consistency 2 · 5 Error prevention 2 · 6 Recognition 2 · 7 Efficiency 1 · 8 Minimalist 3 · 9 Recovery 2 · 10 Help 2

## Design specificity: category-interchangeable
Copy is product-specific; visuals are a 45-line default admin skin. The verification checklist never becomes the composition.
Detector: 0 findings over app/web/templates (markup only; stylesheet not covered). Overlay injection blocked by site CSP.

## Priority issues
- [P1] Verdict unreadable from across a room: 11.5px outlined badges, no fill, FAIL and INCOMPLETE alike in dark mode, no "n of 5" roll-up. Fix: verdict banner at 2.5-3rem with tinted fill, distinct glyph per state, gate badges >= 1rem, INCOMPLETE gets its own dashed/hollow shape.
- [P1] Tenant landing page does not stand alone: Desk nav 404s on tenant hosts, brand links to the business page, Desk footer, no verification status shown. Fix: host-aware header, verification summary at top.
- [P1] DRAFT state recessive and owner page has no single next step: grey pill identical to state chip; 11 fields + 7 equal-weight buttons; ANS steps enabled out of order; re-import overwrites silently; published facts shown as an editable form with no submit. Fix: full-width --inc draft bar repeated at publish, one primary next step per stage, published facts read-only.
- [P1] Dark-mode buttons fail contrast: #fff on --accent 2.2:1, #fff on --fail 2.3:1 (measured).
- [P1] No :focus / :focus-visible rules at all; nav links 25px tall; no skip link.
- [P2] No width media queries: DNS and checks tables collapse to letter-stacked monospace at 375px; nav wraps to 88px.
- [P2] Copy: Find submit labelled with the motto; query required even with exact host; pipe syntax; error page has no next action; raw ISO timestamps.

## What's working
Honest copy; status always has a text label and separate light/dark tokens (text contrast passes AA); checks details auto-open only when unverified.

## Persona red flags
Judge at the back: six identical grey cards, no count, no verdict on the tenant page. First-time owner: pipe textareas, four ANS buttons, Disable gives no consequences. Keyboard/low-vision: 2.2:1 primary button, default focus ring, badges nested in headings.

## Coverage gaps
Reviewer did not sign in (/create, tenant page, Find results judged from templates); 375px checked by constraining page width; /security not opened.
