# Home Page — Page Override (v2 · Phase 18)

> Extends `../MASTER.md`. Document only what's **specific to this page**
> — tokens live in MASTER.

## Composition

1. **Header** (sticky, glass): brand mark + minimal nav (Home, IP Check,
   DNS Leak, Browser, About) + theme toggle + Run-Check button.
2. **Hero** — single primary CTA, gradient-filled heading, soft purple
   page background with three decorative orbs.
3. **Score hero** — large central ring (Privacy Score) + 4 sub-score
   mini rings (IP exposure, Fingerprint, Connection, DNS) in a 2-col
   grid that becomes 4-col on ≥ md.
4. **Detail grid** — 6 glass cards: Overview, Connection (wide),
   Anonymity, DNS, Browser Privacy, Security Findings. The Connection
   card spans 2 columns on ≥ 1100px.
5. **Privacy Findings** — list of category rows with tone-tinted left
   border + icon + body + score.
6. **Post-scan toolbar** — Copy JSON / Copy summary / Download JSON /
   Copy share link + inline feedback chip.
7. **Footer** — methodology + credits + "no analytics" promise.

## Hero

```text
eyebrow:     "Privacy & anonymity diagnostic"  (pill, glass bg)
title (h1):  "How Private Are You Online?"     (gradient-filled text)
subtitle:    "See what your browser and network reveal about you..."
primary CTA: "Run Privacy Check"                (gradient + glow)
ghost CTA:   "Learn how it works"               (glass)
```

**Layout rule:** The hero must not exceed one viewport on a 1440px display.
The CTA must be reachable without scrolling on 375 / 768 / 1024.

## Decorative orbs

Three large blurred radial-gradient orbs sit behind the content via
`position: fixed; pointer-events: none; filter: blur(60px);`:

- `.pcv2::before` — top-left, purple
- `.pcv2::after` — top-right, pink
- `.pcv2__orb--bottom` — bottom-center, cyan (real DOM element)

The orbs are decorative only and must remain
`pointer-events: none` and `aria-hidden="true"`.

## Scan progress (before result)

Vertical list of 6 steps inside a glass card; the current step pulses
with a `--pcv2-action` border + glow:

```text
1. Detecting IP
2. Resolving geolocation
3. Checking IP reputation
4. Estimating browser fingerprint       (Browser-only)
5. Testing WebRTC exposure              (Browser-only)
6. Calculating privacy score
```

Each step is gated on a real network call. Browser-only steps are
labeled with the "Browser-only" pill so users understand why they're
instant. No fake progress timers.

## Score hero

```text
.pcv2__score-hero
├── .pcv2__score-hero-main           (left, on ≥ 900px)
│   ├── .pcv2__score-ring             (200px conic-gradient ring)
│   └── .pcv2__score-grade            ("Strong / Moderate / At Risk")
└── .pcv2__score-hero-grid            (right, 4 mini cards)
    ├── .pcv2__mini-card × 4
    │   ├── .pcv2__mini-ring           (72px ring)
    │   ├── .pcv2__mini-card-label
    │   └── .pcv2__mini-card-tone      (small dot, color = tone)
```

If `report.privacy_report.subscores` is missing, the mini cards fall
back to `report.privacy_report.categories` (the same data the
findings list uses). If both are empty, the score hero still renders
with just the main ring showing "—" for the value.

## Detail cards

| Section | Card title | Primary value | Severity rules |
|---|---|---|---|
| Overview | Overview | score + grade + confidence | informational only |
| Connection | Connection | IPv4/IPv6 + city/country + ISP + ASN + timezone | n/a (data) |
| Anonymity | Anonymity | VPN/Proxy/Tor detection + type + confidence | SAFE if "No signal", DANGER if Tor, WARNING if VPN/Proxy, NEUTRAL otherwise |
| DNS | DNS Resolver | provider + status + latency | n/a (data) |
| Browser Privacy | Browser Privacy | UA + languages + timezone + screen + entropy | n/a (data) |
| Security Findings | Security Findings | TLS version + status + browser + outdated | n/a (data) |

Each card is a glass surface with translucent bg, 1px border,
backdrop-blur, and a hover lift. Missing data renders as
`.pcv2__row-missing` ("Not available", faint italic) — never a bare
em-dash.

## Privacy Findings

```text
.pcv2__findings
└── .pcv2__finding [data-pcv2-severity="safe|warning|danger|info|neutral"]
    ├── .pcv2__finding-icon          (icon per tone)
    ├── .pcv2__finding-title         (category name + score)
    ├── .pcv2__finding-body          (one-line explanation)
    └── .pcv2__finding-score         (e.g. "85%")
```

The left border of each finding row is tinted to its severity tone
with a soft glow. Icons are tone-aware (✓ / ! / ✕ / ⓘ / ·).

## Theme toggle

Position: header, right side. Cycles System → Light → Dark. The active
mode is announced via `aria-label="Theme: Dark"` on the button. The
theme is persisted in `localStorage.pcv2_theme`.

## v2 toggle

Floating bottom-right "Try the new UI" pill, **only** when `?v=2` is
not present and no `pc_ui_v2` cookie exists. Click sets the cookie
(30-day) and reloads with `?v=2`. On the v2 page, the pill becomes
"Switch back to classic UI" which clears the cookie.

## Responsive behaviour

```text
< 768 px      single-column stack
              score hero: main ring on top, mini rings in 2x2 below
              cards full-width
              hero CTA fills width; nav collapses
768–1099 px   score hero: main ring on top, mini rings 4-across
              cards 2-up
≥ 1100 px     score hero: side-by-side
              cards 3-up; Connection card spans 2 columns
```

Long technical strings (`AS13335 Cloudflare, Inc.`) wrap inside the
row `<dd>` via `overflow-wrap: anywhere` — never break the card grid.

## What this page does NOT do

- Does not animate the score ring (conic-gradient renders the final
  state directly; no count-up; honors `prefers-reduced-motion`).
- Does not show testimonials, social proof, or "trusted by N users".
- Does not auto-start the scan.
- Does not request notification permission.
- Does not load third-party scripts.
