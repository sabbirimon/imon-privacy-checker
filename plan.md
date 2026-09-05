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
- Real DNS-leak testing (requires authoritative DNS servers we don't ship).
- Replacing the WordPress admin shell.
- Multi-tenant SaaS features.
- Supporting PHP < 8.1 or WP < 6.2.

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
2. `scanner.js` runs the WCAG-compliant UI; progressively reveals 7 cards.
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
- [x] PHPUnit suite green (61 tests).
- [x] All secrets stripped from `/settings` GET response.
- [x] No raw IPs ever persisted anywhere.

## Open questions / deferred

- **DNS leak test** — currently reports "not configured". Plumbing is in place
  via the `privacy_checker_dns_hostname` filter; integrating a real DNS provider
  is left to whoever ships a resolver.
- **Tor / Cloudflare fingerprint heuristics** — similarly deferred; the UI
  honestly reports "unable to determine" for those rows.
- **Geolocation accuracy tuning** — relies on the provider chain. Admins can
  rearrange based on their regional accuracy needs.

## Related

- `claude.md` — Agent operating rules
- `build.md` — Build / install / run
- `progress.md` — Status tracker
- `puku.md` — Puku CLI usage
