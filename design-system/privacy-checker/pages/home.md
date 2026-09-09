# Home Page — Page Override

> Extends `../MASTER.md`. Document only what's **specific to this page**
> — tokens live in MASTER.

## Composition

1. **Header** (sticky, translucent): brand mark + minimal nav (Home, IP
   Check, DNS Leak, Browser, About) + theme toggle + Run-Check button.
2. **Hero** — single primary CTA, no decorative media above.
3. **Privacy Score** — top-level summary (0–100 gauge + 5 chips: Connection,
   Anonymity, Browser, DNS, Reputation).
4. **Cards** — Overview / Connection / Anonymity / DNS / Browser Privacy /
   Security Findings.
5. **Anonymity Tips** strip (3 highest-priority tips).
6. **Footer** — methodology + credits + "no analytics" promise.

## Hero

```text
eyebrow:     "Privacy & anonymity diagnostic"
title (h1):  "How Private Are You Online?"
subtitle:    "See what your browser and network reveal about you. We analyze your IP,
              connection, VPN/proxy status, DNS exposure, browser signals, and privacy
              risks — entirely from your browser and our server. No analytics, no profiles."
primary CTA: "Run Privacy Check"           # fills 100% on mobile, auto-width on ≥ md
ghost CTA:   "Learn how it works"          # href=/anonymity-tips/
```

**Layout rule:** The hero must not exceed one viewport on a 1440px display.
The CTA must be reachable without scrolling on 375 / 768 / 1024.

## Scan progress (before result)

Vertical timeline of 6 steps; the current step pulses. Labels:

```text
1. Detecting IP
2. Resolving geolocation
3. Checking reputation
4. Estimating fingerprint
5. Testing WebRTC
6. Calculating score
```

Each step is gated on a real network call (POST /scan, /scan/connection,
/scan/reputation, etc.). No fake progress. On a step that has no
backend endpoint (e.g. browser-only signals), the JS labels it
"Browser-only · no network call" so users understand why it's instant.

## Dashboard cards

| Section | Card title | Primary value | Severity rules |
|---|---|---|---|
| Overview | Privacy Score | 0–100 + grade A–F | 90+ SAFE, 70–89 LOW, 50–69 MED, <50 HIGH |
| Connection | Connection Details | IP + city/country | LOW if VPN, MED if proxy, HIGH if datacenter/tor + service denies (combined rule) |
| Anonymity | VPN / Proxy / Tor | clean / vpn / proxy / tor | HIGH if tor; LOW if vpn |
| DNS | DNS Resolver | provider + leak verdict | MED if mismatch with browser IP family; LOW if mismatch within same family |
| Browser Privacy | Browser Exposure | entropy bit + capability list | band by entropy |
| Security Findings | Security Posture | TLS + browser status | HIGH if very outdated; LOW if current |

Every card includes a `Privacy Findings` list at the bottom where each
finding has: `severity chip` + `headline` + `one-line explanation` + `?`
icon linking to the relevant `Learn how it works` page.

## Theme toggle

Position: header, right side. Cycles Light → Dark → System. The active
mode is announced via `aria-label="Theme: Dark"` on the button.

## v2 toggle

Floating bottom-right "Try the new UI" pill, **only** when `?v=2` is
not present and no `pc_ui_v2` cookie exists. Click sets the cookie
(30-day) and reloads with `?v=2`. On the v2 page, the pill becomes
"Switch back to classic UI" which clears the cookie.

## Responsive behaviour

```text
< 768 px      single-column stack; cards become full-width
              hero CTA fills width; nav collapses to a sheet menu
768–1023 px   two-column dashboard grid (cards 2-up)
≥ 1024 px     three-column dashboard grid
≥ 1440 px     three-column with wider gutter (var(--pc-s-8))
```

Long technical strings (`AS13335 Cloudflare, Inc.`) must wrap safely —
never break the card grid.

## What this page does NOT do

- Does not animate the hero background.
- Does not show testimonials, social proof, or "trusted by 10k users".
- Does not auto-start the scan.
- Does not request notification permission.
- Does not load third-party scripts.
