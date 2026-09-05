# Privacy Checker — Architecture & Scope

> Authoritative architecture document for the Privacy Checker plugin + theme.
> Read alongside `claude.md` (operating rules) and `progress.md` (status).

## Mission

Production-ready, self-hosted WordPress platform that diagnoses a visitor's
online privacy posture — IP, geolocation, ISP, ASN, hostname, WebRTC, browser
fingerprint, DNS, IP reputation. Inspired by Whoer.net but with **original
code, branding, and architecture**. Hosted on a stock WordPress install.

## Goals (in priority order)

1. **Privacy-by-default.** No raw IPs ever stored. Hashed rate-limit identifiers.
   Opt-in event log.
2. **Honest results.** When DNS-leak or reputation infrastructure is unavailable,
   the UI reports "unable to determine" — never invents data.
3. **Easy to host.** Everything ships in the WordPress plugin + theme; no
   external services required for the core flow (MaxMind local DB is optional;
   ip-api.com is the free fallback that works out of the box).
4. **Self-contained.** No CDN scripts, no third-party fonts, no analytics.
5. **Accessible.** WCAG 2.2 AA targets, semantic HTML, ARIA where needed.

## Non-goals (intentional)

- VPN affiliate recommendations (we never recommend or score VPNs).
- Replacing the WordPress admin shell.
- Multi-tenant SaaS features.
- Supporting PHP < 8.1 or WP < 6.2.
- Raw ICMP ping, BGP/ASN inference, full Nmap-style service/version
  detection. (See Data flow note 5 for what we *do* ship.)
- Auto-launching the user-guide onboarding tour — manual-only by design.

## Architecture diagram

```
┌─────────────────────────────────────────────────────────────┐
│                       WordPress 7.1                          │
│ ┌──────────────┐    ┌──────────────────────────────────────┐ │
│ │ Custom theme │    │         Privacy Checker plugin      │ │
│ │ (dark UI,    │    │  ┌────────────┐  ┌────────────────┐  │ │
│ │ front-page,  │    │  │ Scanner    │  │ REST API       │  │ │
│ │ shortcode    │◄──►│  │ Orchestra- │◄►│ privacy-       │  │ │
│ │ pages)       │    │  │ tor        │  │ checker/v1/*   │  │ │
│ └──────────────┘    │  └─────┬──────┘  └────────────────┘  │ │
│                      │        │                             │ │
│                      │  ┌─────▼────────────────────────┐    │ │
│                      │  │   IP fallback chain           │    │ │
│                      │  │   MaxMind → ip-api.com →      │    │ │
│                      │  │   ipinfo → ipapi → mock       │    │ │
│                      │  └───────────────────────────────┘    │ │
│                      │  ┌────────────────────────────────┐   │ │
│                      │  │  Admin Dashboard               │   │ │
│                      │  │  • status tiles                │   │ │
│                      │  │  • chain order                 │   │ │
│                      │  │  • MaxMind cache manager       │   │ │
│                      │  │  • charts (line/bar/pie)       │   │ │
│                      │  │  • recent events               │   │ │
│                      │  │  • tools + docs                │   │ │
│                      │  └────────────────────────────────┘   │ │
│                      └──────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                ┌──────────────────────────────────┐
                │   Providers (external)           │
                │  • MaxMind .mmdb (local)         │
                │  • ip-api.com (HTTP, 45 r/m)     │
                │  • ipinfo.io / ipapi (free tier) │
                │  • Mock (always available)       │
                └──────────────────────────────────┘
```

## Data flow (visitor scan)

1. **Visitor loads** `/` (front page).
2. `scanner.js` runs the WCAG-compliant UI; progressively reveals the cards.
3. Step 1: `GET /wp-json/privacy-checker/v1/scan/ip` → returns the visitor's
   IP + immediately-rendered IP-only card (no provider call).
4. Step 2: `GET /wp-json/privacy-checker/v1/scan/connection` → triggers the
   `IpFallback::lookup()` chain. First provider that returns useful data wins.
5. Step 3: `GET /wp-json/privacy-checker/v1/scan/reputation` → Spamhaus DNSBL
   blocklist lookup (cached briefly).
6. Step 4: `POST /wp-json/privacy-checker/v1/scan` with the browser's WebRTC
   candidates + fingerprint signals → `ScannerOrchestrator::scan()` produces
   the final score + recommendations.
7. The UI reveals DNS, security-headers, fingerprint, and WebRTC cards, then
   the overall score ring.
8. **Additional card-row sub-flows** (run in parallel after step 6):
   - **DNS Leak Test** — server-side DoH fan-out (`/scan/dns-test/run`) +
     optional client-side token probe (`/scan/dns-test/verify`).
   - **Ping / Latency** — `stream_socket_client` TCP-connect to admin
     allowlisted targets (`/scan/ping`). No ICMP, no shell.
   - **Port Scan** — `stream_socket_client` TCP-probe to admin allowlisted
     ports on visitor's own host (`/scan/port`). SSH (22), SMTP (25),
     RDP (3389) hard-blocked.
9. **Network Path card** — `NetworkProbe::path_hops()` builds an honest hop
   list from PTR + IP-intel + `ProxyDetector` + request hostname; exposed
   as `connection.path_hops` on every `/scan` response.
10. **Geo Traceroute page** (`/geotraceroute/`) — own dedicated shortcode +
    REST route + 3D globe toggle (self-hosted `three.min.js` +
    `three-globe.min.js` + earth textures under `plugin/public/assets/img/`).
11. **Share endpoint** (`POST /share`, `GET /share/{sid}`) — accepts a
    visitor-supplied redacted report, stores as a transient keyed on a
    short URL-safe ID with `share_ttl_seconds` (default 7 d).
12. **Manual-only user-guide tour** — `[privacy_checker_user_guide]`
    shortcode renders a floating "?" FAB. The tour opens **only** when
    the user clicks the FAB or an in-page trigger carrying
    `data-pc-action="open-guide"`. No first-visit auto-launch, no
    `localStorage` flag, no scheduled timer.

## File layout (high-level)

See `claude.md`. Tests live in `plugin/tests/` (PHPUnit) and `tests-playwright/`
(Playwright).

## Settings

Stored in `wp_options.pc_settings` as a single serialized array. Sanitized
through `Settings::sanitize()`. Secrets (license key, API keys, salt) are
**never** returned by the REST `GET /settings` endpoint.

Key entries:
- `provider_chain_ip` — array of provider keys (default: maxmind, ip-api-com, ipinfo, ipapi, mock)
- `maxmind_license_key` — password, not echoed back
- `maxmind_custom_urls` — array of HTTPS URLs (admin mirrors/MaxMind alternatives)
- `ip_api_com_enabled` — bool, toggleable
- `rate_limit_scan`, `rate_limit_lookup`, `rate_limit_security` — per-minute caps
- `cache_ttl` — transient TTL, clamped to 60–86400 seconds
- `logging_enabled`, `log_retention_days` — opt-in event log
- `dev_mode` — relaxed thresholds for local testing

## Security model

- **SSRF guard.** `Security::validate_remote_url()` blocks any URL whose host
  is a private/loopback/link-local IP, or whose hostname resolves to one. Applies
  to `/scan/security-headers` and any URL users submit.
- **Rate limiting.** SHA-256(salt + IP + bucket + minute) identifier stored in a
  per-minute transient. No raw IP storage.
- **Input sanitization.** `Settings::sanitize()` enforces bounds, normalizes
  chain keys, strips non-HTTPS custom URLs, and preserves secret values when
  blank-submitted.
- **Secret handling.** License keys + API keys are stored in `wp_options`, never
  in source, never returned by `GET /settings`.
- **Path-traversal defense.** `MaxmindManager::extract_mmdb()` rejects any
  archive entry whose basename escapes the destination directory.
- **HTTPS-only custom URLs.** Admin-entered URLs must start with `https://`.

## Acceptance criteria

- [x] Custom theme with dark palette, hero, sticky nav, mobile menu, footer grid.
- [x] Plugin boots on WordPress 7.1 with no fatal errors.
- [x] MaxMind GeoLite2 reads from `wp-content/uploads/maxmind/*.mmdb`.
- [x] ip-api.com integration as automatic fallback (default 2nd hop).
- [x] Configurable fallback chain (admin reorder via Dashboard).
- [x] Reorderable chain persists across requests.
- [x] `wp-content/uploads/maxmind/.htaccess` denies direct HTTP access.
- [x] `/scan` REST route accepts POST.
- [x] Admin dashboard with status tiles, chain UI, MaxMind cache, charts,
      recent events, tools, docs.
- [x] Event log writes only when opt-in; deletes rows older than
      `log_retention_days`.
- [x] Real DNS leak test (server-side DoH fan-out, Cloudflare + Google +
      Quad9 + tier-chain extension to Mullvad / ControlD / NextDNS).
- [x] Real TCP-connect ping / latency (no ICMP, no shell exec).
- [x] Real TCP port probe (self-only by default, admin allowlist, hard
      denylist for SSH / SMTP / RDP).
- [x] Detailed privacy report — Whoer-style breakdown with grade (A-F),
      confidence, weighted overall percentage, per-category rows, tiered
      recommendations.
- [x] Anonymity Tips card (15 tips across 5 tiers).
- [x] Network Path card with real backend-derived hops (PTR + IP-intel +
      `ProxyDetector` category), real-vs-estimated source tagging,
      vertical layout fallback for narrow viewports / >8 hops.
- [x] Geo Traceroute page with 2D map + 3D globe toggle (locally-bundled
      Three.js + three-globe + textures), paste-and-visualize, recent
      traceroutes, probe-network registration.
- [x] Server-side share endpoint with redaction (IP, rDNS, fingerprint
      hashes, DNS token; coordinates rounded to ~11 km).
- [x] Country flag emoji (regional-indicator) on IP / DNS / ASN /
      reputation rows + Geo Traceroute hops.
- [x] Multi-format export (JSON / CSV / TXT / HTML).
- [x] Manual-only user-guide onboarding tour — FAB + 12-step overlay.
- [x] PHPUnit suite green (**170 tests / 600 assertions**, 0 failures).
- [x] All secrets stripped from `/settings` GET response.
- [x] No raw IPs ever persisted anywhere.
- [x] Self-hosted Three.js, three-globe, and globe textures — no
      external CDN dependency on the visitor's browser for these assets.
- [x] `.gitignore` excludes `wp/`, `vendor/`, `wp-config.php`,
      `GeoIP Database/`, `vendor-src/`, `tools/`, `Screenshots/`, etc.
- [x] `DEPLOYMENT.md` for DevOps (server reqs, env vars, nginx/Apache
      configs, cron, monitoring, rollback, compliance).
- [x] GitHub repo: https://github.com/sabbirimon/imon-privacy-checker.

## Open questions / deferred

- **Tor / Cloudflare fingerprint heuristics** — partially deferred; the UI
  honestly reports "unable to determine" for those rows when their inputs
  aren't available.
- **Geolocation accuracy tuning** — relies on the provider chain. Admins can
  rearrange based on their regional accuracy needs.
- **Population-stats seam for fingerprint entropy** — `Fingerprint::entropy_estimate()`
  currently uses cardinality assumptions rather than a real histogram. A
  rolling histogram per signal (via `Cache`) is left as a TODO for whenever
  real traffic stats exist.
- **Phase 1 of `IMON-BUILD-GUIDE.md` (connection quality)** — pending. Smallest
  of the seven roadmap phases; will be executed in its own session with
  diff review between JS and PHP sides.

## Conventions (paste from `IMON-BUILD-GUIDE.md` Phase 0)

- All PHP classes are `final class X` under namespace `PrivacyChecker`, one
  class per file, filename `class-x.php`, with `declare(strict_types=1);`.
- REST handlers live in `class-rest-api.php` and register via
  `register_rest_route($ns, '/path', [...])`.
- Provider-pattern classes (swappable data sources) live under
  `plugin/includes/providers/` and implement an interface from
  `plugin/includes/interfaces/`. Follow this pattern for any new external
  data source — no ad-hoc fetchers sprinkled through `ScannerOrchestrator`.
- The frontend is a single vanilla-JS file (`plugin/public/assets/js/scanner.js`).
  No bundler, no framework, no new dependency without saying so first.
- Every new feature must work with JS disabled degrading gracefully or at
  minimum fail closed ("unable to determine" instead of a broken UI).
- This is a user-facing self-test tool. Nothing should silently collect
  data across sessions to build a persistent cross-visit identity — the
  whole point is transparency. Every new signal collected must be displayed
  back to the user in the report, not just logged server-side.
- Every new external CDN dependency must be checked for a locally-bundled
  fallback first (the rule established by self-hosting `three.min.js`,
  `three-globe.min.js`, and the globe textures under
  `plugin/public/assets/img/`).

## Related

- `claude.md` — Agent operating rules
- `build.md` — Build / install / run
- `progress.md` — Status tracker
- `DEPLOYMENT.md` — DevOps deployment guide
- `IMON-BUILD-GUIDE.md` — Seven-phase roadmap (one phase per session)
- `puku.md` — Puku CLI usage

## Related

- `claude.md` — Agent operating rules
- `build.md` — Build / install / run
- `progress.md` — Status tracker
- `puku.md` — Puku CLI usage
