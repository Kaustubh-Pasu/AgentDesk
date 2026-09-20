---
name: Agent Desk
description: A public register of witnessed entries. Every fact sits on a ruled line with its mark in the margin.
colors:
  ink: "#1f3f8f"
  ink-hover: "#17306f"
  on-ink: "#ffffff"
  ground: "#f6f7f9"
  surface: "#ffffff"
  sunken: "#eef0f4"
  text: "#12161f"
  muted: "#535d6e"
  rule: "#d9dee7"
  rule-strong: "#858fa1"
  pass: "#166638"
  pass-bg: "#e4f3e9"
  fail: "#a1241d"
  fail-bg: "#fbe8e6"
  on-fail: "#ffffff"
  inc: "#775300"
  inc-bg: "#fbf0d6"
  ink-dark: "#9dbdff"
  ink-hover-dark: "#bcd2ff"
  on-ink-dark: "#0b1220"
  ground-dark: "#0e1117"
  surface-dark: "#161a23"
  sunken-dark: "#0a0d12"
  text-dark: "#e9ecf2"
  muted-dark: "#a3acbb"
  rule-dark: "#2a3140"
  rule-strong-dark: "#707a8d"
  pass-dark: "#72d998"
  pass-bg-dark: "#11281b"
  fail-dark: "#ff9d93"
  fail-bg-dark: "#32171a"
  on-fail-dark: "#1d0706"
  inc-dark: "#f1c45f"
  inc-bg-dark: "#2d2410"
typography:
  display:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "clamp(2.25rem, 1.2rem + 4.2vw, 3.5rem)"
    fontWeight: 700
    lineHeight: 1.06
    letterSpacing: "-0.035em"
  verdict:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "clamp(2.25rem, 1.4rem + 3.6vw, 3.5rem)"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "0.02em"
  headline:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "2.25rem"
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "-0.025em"
  title:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.375rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  entry-title:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.015em"
  body:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "1rem"
    fontWeight: 400
    lineHeight: 1.6
    fontFeature: "tabular-nums"
  body-small:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.9375rem"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "0.04em"
  status:
    fontFamily: "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
    fontSize: "0.8125rem"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "0.05em"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
    fontSize: "0.9em"
    fontWeight: 400
rounded:
  radius: "0.375rem"
  pill: "999px"
  mark: "50%"
spacing:
  s-1: "0.25rem"
  s-2: "0.5rem"
  s-3: "0.75rem"
  s-4: "1rem"
  s-5: "1.5rem"
  s-6: "2rem"
  s-7: "3rem"
  s-8: "4.5rem"
  margin-column: "12.5rem"
  container: "68rem"
  measure: "65ch"
  tap: "2.75rem"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.on-ink}"
    rounded: "{rounded.radius}"
    padding: "0 1.5rem"
    height: "{spacing.tap}"
  button-primary-hover:
    backgroundColor: "{colors.ink-hover}"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.ink}"
    rounded: "{rounded.radius}"
    padding: "0 1.5rem"
    height: "{spacing.tap}"
  button-secondary-hover:
    backgroundColor: "{colors.sunken}"
    textColor: "{colors.ink-hover}"
  button-danger:
    backgroundColor: "{colors.fail}"
    textColor: "{colors.on-fail}"
    rounded: "{rounded.radius}"
    height: "{spacing.tap}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "0.5rem 0.75rem"
    height: "{spacing.tap}"
  badge-pass:
    backgroundColor: "{colors.pass-bg}"
    textColor: "{colors.pass}"
    typography: "{typography.status}"
    rounded: "{rounded.pill}"
    padding: "0.2em 0.65em 0.2em 0.5em"
  badge-fail:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.fail}"
    typography: "{typography.status}"
    rounded: "{rounded.pill}"
    padding: "0.2em 0.65em 0.2em 0.5em"
  badge-incomplete:
    backgroundColor: "{colors.inc-bg}"
    textColor: "{colors.inc}"
    typography: "{typography.status}"
    rounded: "{rounded.pill}"
    padding: "0.2em 0.65em 0.2em 0.5em"
  badge-not-checked:
    backgroundColor: "{colors.sunken}"
    textColor: "{colors.muted}"
    typography: "{typography.status}"
    rounded: "{rounded.pill}"
    padding: "0.2em 0.65em 0.2em 0.5em"
  verdict-pass:
    backgroundColor: "{colors.pass-bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "2rem"
  verdict-fail:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "2rem"
  verdict-incomplete:
    backgroundColor: "{colors.inc-bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "2rem"
  state-chip:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    typography: "{typography.mono}"
    rounded: "{rounded.radius}"
    padding: "0.15em 0.6em"
  notice:
    backgroundColor: "{colors.inc-bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "0.75rem 1rem"
  note:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    padding: "0.75rem 0"
  alert:
    backgroundColor: "{colors.fail-bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.radius}"
    padding: "0.75rem 1rem"
---

# Design System: Agent Desk

## Overview

**Creative North Star: "The Register"**

Agent Desk is a public register. Every fact is an entry on a ruled line, and each entry carries its mark in a fixed margin column to its left. The verification checklist is not decoration laid over a dashboard; it is the composition. A reader sweeps the margin to read the verdicts, then reads across a line to see what was witnessed.

The system is quiet so that status can be loud. The ground is cool paper-white, text is blue-black, and one accent (registrar's ink) marks everything the reader can act on. Structure comes from hairline rules, not from boxes or shadows. Colour fills are held back for one job: sitting behind a status. A PASS, a FAIL and an INCOMPLETE each have their own shape as well as their own colour, and the word is always written out, so nothing depends on colour alone. A failed entry is never removed or collapsed; it stays on its line and is struck through.

The whole system ships as one stylesheet under a strict Content-Security-Policy. There are no inline styles, no inline scripts, no external stylesheets and no web fonts. Type is the platform's own system stack. Light and dark themes are the same register in two inks, switched by `prefers-color-scheme` alone.

**Key Characteristics:**
- Entries on ruled lines, marks in a fixed 12.5rem margin column that folds above the entry below 48rem.
- One accent, registrar's ink. No second accent hue anywhere.
- Hairline rules instead of boxes; flat, no shadows.
- Tint fills only behind status: green PASS, red FAIL, amber unproven.
- Three status shapes: solid sealed mark, solid "no entry" mark, hollow dashed mark. The text label is always present.
- Monospace only for machine values: hostnames, URLs, DNS values, fingerprints, tool ids, reported states.
- Status is real backend data. It is never invented, rounded up, or implied.

## Colors

Cool paper and blue-black ink, with three semantic status hues that appear nowhere else. Every colour is a custom property with a light value and a dark value; the frontmatter lists both (the `-dark` keys).

### Primary
- **Registrar's Ink** (`ink`, `--accent`): links, the primary button, the current step's filled mark, completed step outlines, the brand mark stroke, the two home path marks, text selection, the caret, and the focus ring (`--focus` carries the same value). In dark mode it lifts to a pale ink-blue with near-black text on it (`on-ink-dark`).
- **Ink Pressed** (`ink-hover`, `--accent-hover`): hover state for links and buttons only.

### Neutral
- **Cool Paper** (`ground`, `--bg`): the page. Also the sticky stage header's backing so ruled content scrolls under it cleanly.
- **Sheet White** (`surface`, `--surface`): header and footer bands, inputs, step marks, the state chip, the untrusted-content frame.
- **Sunken Paper** (`sunken`, `--sunken`): the recessed tone for machine-value blocks (endpoint list, copyable values, the subdomain affix), table row hover, nav hover, and the not-checked badge.
- **Blue-Black Text** (`text`, `--fg`) and **Slate Note** (`muted`, `--muted`): body copy, and secondary copy, hints, table headers and margin labels.
- **Hairline** (`rule`, `--line`): the ruled line under every entry, table row and section band.
- **Strong Rule** (`rule-strong`, `--line-strong`): the rule that opens a register, a table head or a stage; also input and chip borders and the stepper's connector.

### Status (semantic; token names are frozen)
- **Sealed Green** (`pass` / `pass-bg`, `--pass` / `--pass-bg`): PASS only, plus the transient "copied" confirmation.
- **Struck Red** (`fail` / `fail-bg`, `--fail` / `--fail-bg`, with `on-fail` for text on solid red): FAIL.
- **Open Amber** (`inc` / `inc-bg`, `--inc` / `--inc-bg`): INCOMPLETE and other genuinely unproven states.

The custom-property names `--pass`, `--fail` and `--inc` must keep those names; tests and templates depend on them.

### Named Rules
**The One Ink Rule.** Registrar's ink is the only accent. Anything the reader can act on is ink; nothing else is. Do not introduce a second accent hue, a gradient, or a brand colour borrowed from a partner.

**The Status-Only Tint Rule.** A tinted fill means a status is being reported. Green, red and amber fills never appear as decoration, section backgrounds or emphasis. Everything that is not a status sits on ground, surface or sunken.

**The Red Means Failed Rule.** The red fill sits behind a FAIL (verdict banner, FAIL badge) and behind an error alert that reports something that actually failed. Destructive chrome does not get it: the Danger zone is a red border and a red heading on the plain ground, and its button is the only solid red control.

**The Dashed Means Unproven Rule.** A dashed amber frame is reserved for genuinely unproven states: INCOMPLETE, a draft not yet confirmed, an import that produced nothing. A neutral aside is never amber; it is the ruled note (hairline above and below, no fill).

## Typography

**Display Font:** the system UI stack (`ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`)
**Body Font:** the same stack
**Label/Mono Font:** the system mono stack (`ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace`)

**Character:** One sans family doing every job, separated by weight, size and tracking rather than by a second face. This is a binding constraint, not a preference: the CSP forbids web fonts, so hierarchy is carried by a seven-step size scale (0.8125rem to 2.25rem, plus two fluid clamps), tight negative tracking on headings, and tabular numerals everywhere so counts and timestamps align.

### Hierarchy
- **Display** (700, `clamp(2.25rem, 1.2rem + 4.2vw, 3.5rem)`, 1.06, -0.035em): the home promise and a tenant agent's name; held to about 18ch.
- **Verdict** (800, `clamp(2.25rem, 1.4rem + 3.6vw, 3.5rem)`, 1, +0.02em, uppercase): the status word in the verdict banner, beside its glyph. Readable from across a room.
- **Headline** (700, 2.25rem, 1.2, -0.025em): page titles. Drops to 1.75rem below 48rem. The same 1.75rem step titles the two home paths.
- **Title** (650, 1.375rem, 1.2, -0.015em): section headings, stage headings, candidate names, the verdict count.
- **Entry Title** (650, 1.125rem, 1.2): the heading of an entry inside a register; also the lede size (in muted, weight 400).
- **Body** (400, 1rem, 1.6): running copy, capped at 65ch. Secondary copy, tables and fact lists use 0.9375rem.
- **Label** (600, 0.8125rem, +0.04em, uppercase): table column heads, the margin entry number ("Gate 3"), and the data labels of stacked tables. Hints and the footer use the same size untracked.
- **Status** (700, 0.8125rem, +0.05em, uppercase): the word inside a badge. The large badge in a register margin sets it at 1.125rem, +0.06em.

### Named Rules
**The Mono Is Evidence Rule.** Monospace is only for values a machine produced or will consume: hostnames, URLs, DNS names and values, fingerprints and hashes, tool ids, certificate fields, the reported lifecycle state. Prose, labels, headings, buttons and numbers in sentences are never mono.

**The Written Status Rule.** A status is always a word (PASS, FAIL, INCOMPLETE, NOT CHECKED) in bold tracked caps next to its glyph. The glyph is hidden from assistive technology; the word is the status. Never render a mark without its word, and never colour a word without its mark.

## Layout

A single centred column, 68rem wide, with 1.5rem side padding (1rem below 48rem) and generous vertical air: 3rem above content, 4.5rem below, 3rem before each section heading. Prose is capped at 65ch; registers, tables and fact lists run the full width.

The defining structure is the register: a list opened by a strong rule, each entry a two-column grid of a fixed 12.5rem margin column and a fluid body, closed by a hairline, with 1.5rem of padding above and below. The margin column holds the entry's number or tool id and its status badge; the body holds the title, the sentence and any evidence as a label/value fact list. Entries render in the order the backend supplies and are never reordered or filtered by status.

The same left-margin logic repeats at other scales: the stepper is a run of numbered circular marks joined by short strong rules; each tenant stage opens with a strong rule and a sticky header carrying its step mark; the home page's two paths are one ruled band split by a single vertical hairline, each led by a circular mark.

Spacing is a fixed eight-step scale (0.25, 0.5, 0.75, 1, 1.5, 2, 3, 4.5rem). Interactive targets are at least 2.75rem (44px) tall.

**One breakpoint, 48rem.** Below it: the margin column collapses to zero and the mark row sits above the entry body; the stepper becomes a vertical list with its connectors removed; the two home paths stack with a hairline between them; the verdict banner stacks word over count; fact lists become label-over-value; stage headers stop being sticky; and any table marked stackable becomes a series of labelled blocks, each cell preceded by its column name taken from `data-label` (the header row stays available to assistive technology). Tables that are not stackable scroll horizontally inside their wrapper. Print hides the nav and footer and drops status fills.

### Named Rules
**The Margin Column Rule.** Marks live in the margin, content lives on the line. A status badge, step number or tool id goes in the left column of an entry, not inline at the end of a heading and not in a card corner.

**The Stack, Don't Squeeze Rule.** A table with more than two columns must be marked stackable and carry a `data-label` on every cell. Below 48rem it becomes labelled blocks; it never becomes letter-stacked columns.

## Elevation & Depth

Flat. There are no shadows anywhere in the system. Depth is tonal and minimal: surface bands (header, footer, inputs) sit one step lighter than the ground, and machine-value blocks sit one step darker (sunken). Separation is done with hairlines. The only layered element is the sticky stage header, which uses the ground colour and a hairline beneath it, not a shadow.

Motion is equally restrained: 150ms colour transitions on buttons, a 150ms disclosure chevron turn, a 0.25rem arrow nudge on a home path on hover, a 1px press on buttons. All of it collapses under `prefers-reduced-motion`.

### Named Rules
**The No Shadow Rule.** Nothing lifts. If something needs separating, rule it; if it needs recessing, sink it.

## Shapes

Three radii and nothing else. Controls, frames and banners take a small soft corner (0.375rem). Status badges are full pills (999px). Marks (step numbers, path marks, status glyphs) are circles. Borders are always 1px; a solid border states a fact, a dashed border states that something is unproven or untrusted.

The status glyphs are the system's signature geometry, drawn as inline SVG on a 16-unit grid and coloured by `currentColor`:
- **PASS:** a solid disc with a tick cut out of it. A sealed mark.
- **FAIL:** a solid disc with a horizontal bar cut out of it. A "no entry" mark.
- **INCOMPLETE:** a hollow dashed ring with a small solid centre. An open line.
- **NOT CHECKED:** a thin hollow ring.

The cut-out is stroked in the colour of whatever sits behind the glyph (badge tint, verdict tint, ground, or row hover), so the mark reads as punched through rather than overprinted.

All icons are inline SVG in the templates, styled from the stylesheet: stroke-only, round caps and joins, 1.6 to 2 units of stroke on a 16 or 24 grid. There are no icon fonts, no image icons and no emoji.

### Named Rules
**The Three Shapes Rule.** Solid means decided, dashed means unproven. A PASS and a FAIL are both solid and differ by their cut; an INCOMPLETE is hollow and dashed, and so is its badge border, its verdict border and the notice that explains it. Never give an unproven state a solid frame.

## Components

### Buttons
Plain, rectangular and sure of themselves; the label does the work.
- **Shape:** small soft corner (0.375rem), 1px ink border, at least 2.75rem tall, 1.5rem side padding, weight 650 at 1rem. Left-aligned in forms, never full-width.
- **Primary:** solid ink with white (dark: near-black) text. Hover darkens to ink-pressed over 150ms; active presses down 1px.
- **Secondary:** transparent with ink text and ink border; hover fills with sunken paper. Used for every repeatable or non-committal action, including the four equal ANS actions.
- **Danger:** solid struck red with `on-fail` text. It appears only inside the Danger zone.
- **Link button:** a form-submitting button that looks like a text link (Sign out).
- **Small:** 2rem tall, label size; used by the script-added Copy button.
- **Disabled:** 45% opacity, not-allowed cursor.
- **Focus (all interactive elements):** 2px ink outline offset 2px; on fields the outline sits flush and the border turns ink.

### Status Badge
The register's mark. Frozen macro contract: `badge(status, size)` emits classes `badge`, `badge-<status lowercased>` (`badge-pass`, `badge-fail`, `badge-incomplete`, `badge-not_checked`) and optionally `badge-lg`, wrapping the glyph and a text label.
- **Style:** pill with a 1px border in the status colour over the status tint; bold tracked caps at label size. INCOMPLETE and NOT CHECKED have dashed borders; NOT CHECKED is muted on sunken paper.
- **Large:** 1.125rem, used in register margins and beside candidate names.
- **In tables:** the badge sheds its pill and renders as a bare mark: glyph plus coloured word, no border, no fill, at table text size. A column of pills would be noise; a column of marks is a margin.

### Verdict Banner
The first thing on a proof page: a full-width frame in the status tint with a 1px status-colour border (dashed for INCOMPLETE). Left, the glyph and status word at verdict size; right, "n of 5 gates proven" at title size over one plain sentence capped at 48ch. It stacks below 48rem. The count is computed from the real gate data.

### Register and Entry
See Layout. Body headings inside an entry are entry-title size with no top margin. **A failed entry stays on its line and is struck:** the entry's title takes a thin red line-through while its explanation and evidence remain fully readable. The same applies in tables, where a failed row's check label is struck. Nothing fails silently and nothing failed is hidden.

### Stepper
An ordered list of circular 1.75rem marks with labels, joined by 2rem strong rules. Upcoming steps are muted with a numbered outline mark; the current step is bold with a solid ink mark and `aria-current="step"`; done steps show an ink-outlined tick and a hidden "(done)". It is the shared motif for Create's four stages, Find's three, and the tenant page, whose stage headers reuse the same mark. Below 48rem it is a vertical list.

### Inputs / Fields
- **Style:** 1px strong-rule border, small soft corner, sheet-white fill, at least 2.75rem tall. The label sits above in bold small text; hints are muted, regular weight, label size.
- **Hover / Focus:** border goes to text colour on hover, to ink with the focus outline on focus.
- **Textareas** are mono by default because they hold structured pipe-delimited lines; the prose variant switches back to the body face.
- **Affix:** a field with a joined sunken mono suffix (the base domain).
- **Fieldset:** a hairline frame holding an auto-filling grid of checkboxes.
- Form field names, actions and hidden fields are frozen; styling may change, markup contracts may not.

### Tables and Fact Lists
Tables are ruled, not boxed: uppercase muted column heads over a strong rule, hairline under every row, no vertical lines, no zebra, sunken row hover on wide screens. Fact lists are a two-column label/value grid (muted label, value often mono) that becomes label-over-value on small screens.

### Notices
Three, each with one job:
- **Note:** the neutral ruled aside. Hairline above and below, no fill, no side borders.
- **Notice:** amber dashed frame on amber tint, for genuinely unproven states only. The **draft bar** is its larger sibling, leading with the word DRAFT in amber tracked caps.
- **Alert:** red 1px frame on red tint with `role="alert"` where appropriate, for an action that actually failed.

### State Chip
A small mono chip with a strong-rule border on sheet white, for a lifecycle state reported verbatim by a backend or by GoDaddy (for example PENDING_VALIDATION). It is deliberately colourless: a reported state is a value, not a verdict.

### Copyable Value
A mono value on sunken paper that selects whole on one click with no script. When `copy.js` runs (tenant page only, secure context with clipboard access) it appends a small secondary Copy button and a polite status message. Without the script nothing is missing.

### Untrusted Content Frame
A dashed strong-rule frame with a sunken dashed header stating that the content is untrusted and shown as text only, over a pre-wrapped text block capped at 80ch. Dashed and neutral, never red: it is framed, not an error.

### Navigation
A sheet-white band with a hairline beneath: brand mark and name at left, five quiet muted links at right (0.9375rem, weight 500, 2.75rem tall), each taking a sunken rounded hover. There is no active-page state. It wraps rather than collapsing into a menu; below 48rem the links tighten to label size. A skip link leads the page. The footer carries the motto and the request's correlation id in label size. By the owner's decision the same nav appears unchanged on tenant hosts.

## Do's and Don'ts

### Do:
- **Do** put every new list of facts on a register: strong rule to open, hairline per entry, mark in the 12.5rem margin, body on the line.
- **Do** write every status as glyph plus word, using the badge macro, and keep the solid/solid/dashed shape language.
- **Do** keep a failed entry on its line and strike its title; leave its explanation readable.
- **Do** use ink for everything actionable and nothing else.
- **Do** reserve amber dashed for the genuinely unproven and use the ruled note for neutral asides.
- **Do** set machine values in mono on sunken paper, and mark DNS-style values copyable.
- **Do** mark multi-column tables stackable and give every cell a `data-label`.
- **Do** draw icons as inline SVG in the template (stroke, round caps, `aria-hidden`, `focusable="false"`) and style them from `app.css`.
- **Do** keep scripts as separate files under `/static/`, loaded only where needed (today: `copy.js` on the tenant page), and make the page complete without them.
- **Do** define every new colour twice, in `:root` and in the `prefers-color-scheme: dark` block, and keep targets at least 2.75rem.

### Don't:
- **Don't** write an inline `<style>`, a `style=""` attribute, an inline `<script>`, an external stylesheet or a web font. The CSP blocks them and the tests fail.
- **Don't** rename `--pass`, `--fail` or `--inc`, change the badge macro's class contract (`badge-pass`, `badge-fail`, `badge-incomplete`, `badge-not_checked`), or change any form field name.
- **Don't** convey status by colour alone, and don't invent, round up or imply a status the backend did not report.
- **Don't** use the red fill for warnings, destructive chrome or emphasis. The Danger zone is a border only.
- **Don't** use amber dashed for ordinary information.
- **Don't** box content in cards or add shadows. Rule it or sink it.
- **Don't** render pill badges inside tables; there the badge is a bare mark.
- **Don't** hide, collapse, reorder or filter out failed entries.
- **Don't** set prose, labels or buttons in mono, and don't introduce a second typeface.
- **Don't** add a second accent colour, a gradient, or GoDaddy logos and brand colours.
- **Don't** add imagery, testimonials, logos or illustration; none exists and none may be fabricated.
- **Don't** add motion beyond 150ms state transitions, and always honour reduced motion.
