# Privacy Checker — Design System (MASTER)

> **Source of truth for visual language.** Read this before editing the UI.
> Per-page overrides live under `pages/` and extend (never replace) the
> tokens and rules defined here. If a page needs something not in MASTER,
> add it to MASTER first, then reference it from the page.

**Version:** 1.0.0 · **Stack:** vanilla CSS custom properties + WordPress
plugin + theme · **Targets:** WordPress 6.2+, PHP 8.1+, evergreen
browsers (last 2 versions of Chrome / Edge / Firefox / Safari).

---

## 1. Design Principles

1. **Privacy is a serious product, not a marketing surface.** Information
   density over decoration. Read like a diagnostic console, not a
   landing page.
2. **Never claim more than we can measure.** If a value is estimated, label
   it. If a hop is private, say "Private" — never invent coordinates.
3. **Color + label + icon for every status.** Color alone is never the
   sole indicator (WCAG 1.4.1).
4. **One canonical data model per feature.** 2D and 3D views must read
   from the same `route` object. No parallel route generators.
5. **Build on the working baseline.** v1 stays intact. v2 lives in
   separate files and never edits `scanner.js` / `scanner.css` /
   `class-public-assets.php` core handlers.
6. **No third-party trackers. No analytics scripts. No remote fonts.**

---

## 2. Three-Layer Token Architecture

```
PRIMITIVE  →  SEMANTIC  →  COMPONENT
(colors, sizes)    (role names)    (specific parts)
```

Components consume semantic tokens; semantic tokens resolve to primitives.
Never reference a primitive from a component directly.

---

### 2.1 Primitives

```text
NEUTRAL (cool, slight blue tint — not pure grey)
  --pc-ink-0    #ffffff          // pure white (light text on dark)
  --pc-ink-50   #f6f7f9          // page bg, light
  --pc-ink-100  #eceef2          // surface, light
  --pc-ink-200  #d9dde4          // border, light
  --pc-ink-300  #b6bcc7          // muted text, light
  --pc-ink-400  #8a93a3          // secondary text
  --pc-ink-500  #5b6373          // body text, light
  --pc-ink-600  #3a4250          // heading text, light
  --pc-ink-700  #232a36          // emphasis
  --pc-ink-800  #141a24          // surface, dark
  --pc-ink-900  #0b0f17          // page bg, dark
  --pc-ink-1000 #050810          // deep contrast bg

PRIMARY (cool cyan — privacy/security feel, not "AI blue")
  --pc-cyan-50   #e6f7fb
  --pc-cyan-100  #bfebf4
  --pc-cyan-300  #5fc8e0
  --pc-cyan-500  #1ea2c4   // primary accent
  --pc-cyan-600  #1683a0   // hover
  --pc-cyan-700  #0f6580   // active

SEVERITY (4-band; each has its own label and icon — never color-only)
  --pc-safe      #2ea043   // SAFE  — green
  --pc-low       #d4a72c   // LOW   — amber
  --pc-medium    #e07b16   // MED   — orange
  --pc-high      #cf222e   // HIGH  — red
  --pc-unknown   #6b7785   // UNKNOWN — neutral grey

CONFIDENCE (for IP geolocation)
  --pc-conf-high   #2ea043
  --pc-conf-med    #d4a72c
  --pc-conf-low    #e07b16
  --pc-conf-none   #6b7785

FOCUS
  --pc-focus-ring #1ea2c4
```

### 2.2 Semantic tokens

```text
SURFACE
  --pc-bg                page background
  --pc-bg-elevated       card background
  --pc-bg-sunken         inset / code / table-row-alt
  --pc-border            hairlines (alpha-aware)
  --pc-border-strong     dividers

TEXT
  --pc-text              body
  --pc-text-muted        secondary
  --pc-text-faint        tertiary / placeholder
  --pc-text-inverse      text on primary fill
  --pc-text-link         links
  --pc-text-link-hover

ACTION
  --pc-action            primary button bg
  --pc-action-hover
  --pc-action-active
  --pc-action-fg         text on action
  --pc-action-ghost-bg   ghost button bg (transparent)
  --pc-action-ghost-fg

STATUS (always paired with a label + icon)
  --pc-status-safe
  --pc-status-low
  --pc-status-medium
  --pc-status-high
  --pc-status-unknown

SHADOW
  --pc-shadow-1          card
  --pc-shadow-2          hover
  --pc-shadow-focus      focus ring (also 3px outline color)
```

### 2.3 Light / Dark / System

Every page must:

1. Default to `prefers-color-scheme` (system) on first visit.
2. Override to user choice (light / dark) when a `data-pc-theme="…"`
   attribute is set on `<html>` or when `localStorage.pc-theme` exists.
3. Persist user choice via `localStorage.pc-theme` (values: `light`,
   `dark`, `system`).
4. Re-evaluate on `prefers-color-scheme` change **only** when value is
   `system`.
5. **Contrast targets:** body text ≥ 4.5:1 against its surface; large
   text ≥ 3:1; status colors paired with label/icon.

Theme tokens map primitive → semantic:

```css
:root,
[data-pc-theme="light"] {
  --pc-bg:             var(--pc-ink-50);
  --pc-bg-elevated:    var(--pc-ink-0);
  --pc-bg-sunken:      var(--pc-ink-100);
  --pc-border:         rgba(20, 26, 36, 0.08);
  --pc-border-strong:  rgba(20, 26, 36, 0.16);
  --pc-text:           var(--pc-ink-600);
  --pc-text-muted:     var(--pc-ink-500);
  --pc-text-faint:     var(--pc-ink-400);
  --pc-text-inverse:   var(--pc-ink-0);
  --pc-text-link:      var(--pc-cyan-600);
  --pc-text-link-hover:var(--pc-cyan-700);
  --pc-action:         var(--pc-cyan-500);
  --pc-action-hover:   var(--pc-cyan-600);
  --pc-action-active:  var(--pc-cyan-700);
  --pc-action-fg:      var(--pc-ink-0);
  --pc-shadow-1:       0 1px 2px rgba(15, 23, 42, 0.06), 0 1px 1px rgba(15, 23, 42, 0.04);
  --pc-shadow-2:       0 4px 12px rgba(15, 23, 42, 0.10), 0 2px 4px rgba(15, 23, 42, 0.06);
}

[data-pc-theme="dark"],
:root[data-pc-theme="system"]:where([data-pc-resolved-theme="dark"]) {
  --pc-bg:             var(--pc-ink-900);
  --pc-bg-elevated:    var(--pc-ink-800);
  --pc-bg-sunken:      var(--pc-ink-1000);
  --pc-border:         rgba(255, 255, 255, 0.08);
  --pc-border-strong:  rgba(255, 255, 255, 0.14);
  --pc-text:           var(--pc-ink-100);
  --pc-text-muted:     var(--pc-ink-300);
  --pc-text-faint:     var(--pc-ink-400);
  --pc-text-inverse:   var(--pc-ink-900);
  --pc-text-link:      var(--pc-cyan-300);
  --pc-text-link-hover:var(--pc-cyan-100);
  --pc-action:         var(--pc-cyan-300);
  --pc-action-hover:   var(--pc-cyan-100);
  --pc-action-active:  var(--pc-cyan-50);
  --pc-action-fg:      var(--pc-ink-900);
  --pc-shadow-1:       0 1px 2px rgba(0, 0, 0, 0.4), 0 1px 1px rgba(0, 0, 0, 0.3);
  --pc-shadow-2:       0 6px 16px rgba(0, 0, 0, 0.45), 0 2px 6px rgba(0, 0, 0, 0.3);
}
```

---

## 3. Type Scale

Font stack (system fonts only — no remote font fetch):

```css
--pc-font-sans: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
                "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
--pc-font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas,
                "Liberation Mono", monospace;
```

Type ramp (modular scale 1.2, body 16 px):

```text
--pc-fs-12   0.75rem  // micro / chip / timestamp
--pc-fs-14   0.875rem // caption / secondary
--pc-fs-16   1rem     // body
--pc-fs-18   1.125rem // lede
--pc-fs-20   1.25rem  // small heading
--pc-fs-24   1.5rem   // section title
--pc-fs-30   1.875rem // page title
--pc-fs-36   2.25rem  // hero

--pc-fw-400  regular
--pc-fw-500  medium
--pc-fw-600  semibold
--pc-fw-700  bold
--pc-fw-800  heavy (numeric only)
```

Rules:
- IP addresses, ASN strings, hostnames: `--pc-font-mono`.
- Numbers (latency, scores, hop counts): tabular-nums (`font-variant-numeric: tabular-nums`).
- Max line length: 65ch on body text.
- Headings never wrap mid-word; allow `overflow-wrap: anywhere` for long
  technical strings (ASN names, FQDN).

---

## 4. Spacing & Layout

4 px base unit.

```text
--pc-s-1   4px
--pc-s-2   8px
--pc-s-3   12px
--pc-s-4   16px   // base
--pc-s-5   20px
--pc-s-6   24px
--pc-s-8   32px
--pc-s-10  40px
--pc-s-12  48px
--pc-s-16  64px
--pc-s-20  80px
```

Container max widths:

```text
--pc-container-sm  640px   // lede / single column
--pc-container-md  900px   // form
--pc-container-lg  1200px  // dashboard
--pc-container-xl  1440px  // wide map / globe
```

Breakpoints:

```text
--pc-bp-sm   375px   // mobile S
--pc-bp-md   768px   // tablet
--pc-bp-lg   1024px  // desktop
--pc-bp-xl   1440px  // wide
```

Radii:

```text
--pc-r-1   2px    // chip
--pc-r-2   4px    // input
--pc-r-3   8px    // card
--pc-r-4   12px   // modal
--pc-r-5   16px   // hero panel
--pc-r-pill 999px
```

---

## 5. Components

### 5.1 Button

```text
.primary     filled, --pc-action bg, --pc-action-fg text
.secondary   filled, --pc-bg-sunken bg, --pc-text text
.ghost       transparent, border --pc-border-strong, --pc-text text
.danger      filled, --pc-status-high bg, --pc-text-inverse text
.icon        square, 36px, --pc-bg-sunken bg, --pc-text text
```

Sizes: `sm` 28 px / `md` 36 px / `lg` 44 px. Min tap target 44×44 on
mobile (touch target wraps the visible button).

States: hover, focus-visible (3 px outline `--pc-focus-ring` + 2 px
offset), active (slight depress), disabled (0.5 opacity, `cursor:
not-allowed`).

### 5.2 Card

```text
.pc-card
  bg          var(--pc-bg-elevated)
  border      1px solid var(--pc-border)
  radius      var(--pc-r-3)
  shadow      var(--pc-shadow-1)
  padding     var(--pc-s-5)
  transition  box-shadow 160ms ease, transform 160ms ease

.pc-card[data-pc-elevated="hover"]:hover
  shadow      var(--pc-shadow-2)
  transform   translateY(-1px)
```

Card sections: `.pc-card__header` (title + status chip), `.pc-card__body`
(content), `.pc-card__footer` (meta / actions).

### 5.3 Status chip

Every status uses a chip with **label + icon + color** — never color alone:

```text
.pc-chip[data-pc-severity="safe"]    icon ✓  SAFE
.pc-chip[data-pc-severity="low"]     icon !  LOW
.pc-chip[data-pc-severity="medium"]  icon !! MED
.pc-chip[data-pc-severity="high"]    icon ✕  HIGH
.pc-chip[data-pc-severity="unknown"] icon ?  UNKNOWN
```

Confidence (for IP geo):

```text
.pc-chip[data-pc-confidence="high"]   HIGH
.pc-chip[data-pc-confidence="medium"] MED
.pc-chip[data-pc-confidence="low"]    LOW
.pc-chip[data-pc-confidence="none"]   UNKNOWN
```

Icon set: inline SVG (Lucide-style). Always `aria-hidden="true"`; the
visible label carries the accessible name.

### 5.4 Score gauge

Circular SVG, 0–100. Color band derived from `--pc-status-*` based on the
numeric value. Numeric value shown both in the center and as the
`aria-valuenow` on a hidden progressbar (`role="progressbar"`).

### 5.5 Map / Globe

Single canvas / Leaflet instance per page. Color of route segments
reflects per-hop RTT (safe / low / medium / high). Origin marker uses
the neutral `--pc-text` color; destination uses `--pc-action`. Each hop
marker numbered and clickable.

When hops are unanswered/private, draw a dashed gap segment, not a
straight line to a fake point.

### 5.6 Progress timeline

Vertical timeline for GeoTrace. Each hop row: index, label, IP/hostname,
city/country, ASN/ISP, RTT. Latency delta > 1.5× the previous hop is
flagged with `data-pc-latency-jump="true"` (color + label, never color
alone). Clicking a row highlights the matching map marker.

### 5.7 Toast

Auto-dismiss after 6 s. `role="status"`, `aria-live="polite"`.

### 5.8 Modal

`role="dialog"`, `aria-modal="true"`, focus-trap, ESC closes, backdrop
click closes. First focusable element gets focus on open; focus returns
to trigger on close.

---

## 6. Motion

- Default duration: 160 ms (hover), 240 ms (enter/exit), 480 ms (page
  transition).
- Easing: `cubic-bezier(0.2, 0.8, 0.2, 1)` (out-quint feel) for
  enter, `cubic-bezier(0.4, 0, 0.6, 1)` for exit.
- **`prefers-reduced-motion: reduce` overrides everything** to
  `duration: 0.001ms`. The hop-by-hop packet animation must step (no
  continuous interpolation) when reduced motion is requested.
- Score gauge count-up: disabled under reduced motion (snap to final).

---

## 7. Accessibility

- All interactive elements reachable by keyboard (Tab order matches
  visual order).
- Visible focus on **every** focusable element (`:focus-visible`).
- Skip-link at top of every page.
- Status conveyed by **label + icon + color** (never color alone).
- ARIA live regions for scan progress (`role="status"` +
  `aria-live="polite"`).
- Tap targets ≥ 44×44 px on mobile.
- Long technical strings: `overflow-wrap: anywhere` + a "copy" button.
- Color contrast ≥ 4.5:1 body / ≥ 3:1 large.
- No emoji as the sole icon for status (text label always present).

---

## 8. Privacy & Performance

- No remote fonts, no analytics, no third-party trackers.
- All assets served same-origin from `PRIVACY_CHECKER_URL`.
- CSS budget: < 80 KB uncompressed per page (excluding vendored libs).
- JS budget: < 250 KB uncompressed on first load (excluding Leaflet /
  three.js, which are lazy-loaded only when the map/globe page is in
  view).
- LCP target: < 2.0 s on 4G.

---

## 9. Anti-Patterns

Banned across every page:

- Glassmorphism (blurred translucent panels), neon glow, AI-purple
  gradients.
- Decorative illustrations above the fold.
- Emoji as the only indicator for status / severity.
- Filled cards with no border that disappear in dark mode.
- Hover effects that change layout (causes reflow).
- Auto-playing audio / video.
- Carousels (especially for the hero).
- Any remote font (`@import url(...)`, Google Fonts, Adobe Fonts).
- Any third-party analytics or tag manager.

---

## 10. File Layout

```text
plugin/public/assets/
  css/
    scanner.css            // v1 — DO NOT EDIT FROM v2 WORK
    scanner-v2.css         // v2 — new file
    leaflet.css            // vendored
  js/
    scanner.js             // v1 — DO NOT EDIT FROM v2 WORK
    scanner-v2.js          // v2 — new file
    leaflet.js             // vendored
    three.min.js           // vendored
    three-globe.min.js     // vendored

design-system/
  privacy-checker/
    MASTER.md              // this file
    pages/
      home.md              // homepage + dashboard composition
      geotrace.md          // geo traceroute page composition
```

---

## 11. v1 / v2 Separation Rules

- `[privacy_checker]` and all `privacy_checker_*` shortcodes → v1.
- `[privacy_checker_v2]` → v2 only.
- v2 lives in `scanner-v2.js` / `scanner-v2.css` / `class-public-assets-v2.php`.
- v2 registers its own DOM hooks (`data-pcv2-*`) so it never collides
  with v1's `data-pc-*` selectors.
- Deleting the v2 files removes v2 entirely; v1 is unaffected.
