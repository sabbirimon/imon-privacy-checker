# Progress — Privacy Checker

> Last updated: 2026-09-06. Track what's done, what's in flight, and what's
> blocked.

## Roadmap reference

For the next major feature track (anonymity-consistency scoring, real
fingerprint hashing + entropy, security posture panel, LAN self-scan,
composite scoring) see `IMON-BUILD-GUIDE.md`. That guide is split into
seven phases and is meant to be executed one phase per session with a
diff review between phases — not all at once.

- [x] **Phase 1 — Connection quality** (`2d1f8ef`, renamed in `13d55be`).
      Latency / jitter via 3 sequential GETs to `/scan/connection/echo`
      (timed client-side with `performance.now()`), IP-family reachability
      derived from the existing `IpDetector::detect()` shape,
      `navigator.connection` read with explicit "Not available in this
      browser" fallback for Safari / Firefox. 11 new i18n strings; new
      `NetworkProbe::latency_probe()` + `NetworkProbe::ipv6_reachable()`
      static methods; new `connectionQualityCard()` in `scanner.js`.
      **Renamed in `13d55be`**: route renamed from `/scan/connection/ping`
      → `/scan/connection/echo` to avoid name collision with the existing
      TCP-connect `/scan/ping`; jitter computation simplified from std-dev
      to `max - min` (more honest for the 3-sample window we have); new
      dedicated `rate_limit_connection_echo` bucket (default 60/min) so
      the 3 per-report echo calls never starve the TCP-connect `ping`
      bucket.
- [x] **Phase 2 — Deep anonymity / proxy / VPN consistency scoring**
      (`(this commit)`). New `class-anonymity-scorer.php` correlates
      four signals the orchestrator already had (IP-geo timezone,
      browser-reported timezone from `collectFingerprint()`, WebRTC
      verdict + leaked IPs from `Webrtc::summarize()`, ProxyDetector
      classification) plus an optional completed DNS-leak test result
      (passed in from the client as `dns_test_result`). Scoring weights:
      timezone mismatch −20 (medium), WebRTC leak −40 (high), DNS
      resolver on a different org −30 (high); confirmed proxy/VPN alone
      is not penalised (intentional use). Timezones that share a UTC
      offset (e.g. `Europe/Berlin` vs `Europe/Paris`) are NOT flagged
      — uses PHP's `DateTimeZone::getOffset()` rather than string
      compare. Returns `{consistent, score, mismatches, summary}`
      surfaced under `connection.anonymity` in the scan response.
      Rendered as a new `anonymityConsistencyCard()` in the left column
      of `scanner.js` (above the proxy / DNS / WebRTC cards, since it
      summarises them). New CSS for `.pc-badge--caution` /
      `.pc-badge--unknown` / `.pc-card__score-row` /
      `.pc-mismatch-list` / `.pc-severity--*`. 6 new i18n strings.
      `dns_test_result` added to the `collect_client_signals()`
      allowlist so the JS can pass a completed test back in. 14 new
      PHPUnit tests (135 total, all green).
- [ ] **Phase 3 — Advanced fingerprint exposure module** (real canvas /
      WebGL / audio hashing + entropy score). Largest single chunk,
      splits in two sub-sessions per the guide: JS collection first,
      pause for review, then PHP scoring.
- [ ] **Phase 4 — Security posture panel** (TLS version/cipher,
      browser EOL check, reusing `class-security-headers.php`).
- [ ] **Phase 5 — Local network exposure** (LAN self-scan,
      RFC1918-scoped only, pure client-side).
- [ ] **Phase 6 — Composite report assembly** (integrates Phases 1-5
      into `class-privacy-report.php`).
- [ ] **Phase 7 — QA pass** (audit all added code for conventions,
      shown-back-to-user, fail-closed behavior, external-CDN policy).

## Phase 10 — UX polish: IMON rebrand, scan progress, styled tool results

### Theme & branding

- [x] **IMON** brand replaces generic "Privacy Checker" wordmark
  - `theme/header.php` — brand mark `IMON` + tag `I AM ON` in glassmorphic nav
  - `theme/front-page.php` — large gradient hero brand block with IMON mark + eyebrow
  - `theme/assets/css/theme.css` — `.pc-brand`, `.pc-brand__mark`,
    `.pc-hero__brand`, `.pc-hero__brand-mark` (2.6rem gradient pill), full
    dark-mode overrides
  - `theme/functions.php` — bumps `PRIVACY_CHECKER_THEME_VERSION` to 1.1.0 so
    cache busts on theme switch

### Mock-data purge (live & production)

- [x] `wp-config.php` — `PRIVACY_CHECKER_DEV_MODE` flipped from `true` → `false`
- [x] Activation defaults in `plugin/includes/class-plugin.php` rewritten:
      `ip_provider='ip-api-com'`, `reputation_provider='spamhaus'`,
      `whois_provider='rdap'`, `dns_test_enabled=true`
- [x] One-shot migration: existing installs auto-flip legacy `'mock'` values to
      real providers and `dev_mode=false` on next activation
- [x] Stale `pc_ipintel_*`, `pc_reputation_*`, `pc_whois_*`,
      `pc_ipfallback_*` transients flushed
- [x] DNS leak test now wired end-to-end — Cloudflare + Google + Quad9 DoH
      fan-out returns per-resolver latency + answer IP

### Tool result projection (six pages)

All six tool pages now share a uniform rich card layout:

- [x] New CSS classes: `.pc-result`, `.pc-result__hero`,
      `.pc-result__group`, `.pc-result__group-title`,
      `.pc-result__group-body`, `.pc-row`, `.pc-pill` (pass/warning/danger/info),
      `.pc-status-banner` (with shimmer animation), `.pc-result-list`
      (tabular rows with color-coded left borders)
- [x] Dark-mode overrides for every new class
- [x] New JS helpers in `scanner.js`: `resultHero()`, `resultGroup()`,
      `statusBanner()`, `pill()`, `resultList()`
- [x] **IP Lookup** — hero + Location / Network / Provider-chain groups
- [x] **WHOIS** (RDAP) — hero + Registry / Events / Entities; status pills
      for `client delete prohibited` etc.
- [x] **User-Agent** — hero with "Browser version" + Parsed details + Raw mono
- [x] **Fingerprint** — new dedicated `bindFingerprint()` handler that
      collects browser signals client-side, posts them to `/scan`, renders
      visibility score + browser-signals table
- [x] **DNS Leak** — hero + Summary + Resolvers table with pass/danger pills
- [x] **WebRTC** — hero + Details (public addresses, local addresses,
      candidate count)
- [x] **Security Headers** — hero with pass/warn/fail tally + grouped header
      cards with verdict pills + value (mono) + "Why" description
- [x] **Ping / Port Scan** — hero with latency / open-closed pill + probe
      details
- [x] Loading banners: shimmer animation while API is in flight

### Scan progress overlay

- [x] Replaced bare `.pc-spinner` with `.pc-scan-card`: centered card with
      SVG progress ring (gradient stroke), big percentage number, current
      step label, animated gradient progress bar, six colored step dots
- [x] Per-stage progress: `currentStep / steps.length * 100` clamps to 5..95%
      during steps, jumps to 100% on `score` complete before fade-out
- [x] Per-step sub-labels ("Resolving city, region, ASN, ISP, rDNS" etc.)
      so the user knows what the server is doing at each moment
- [x] Pulse + active/done/error state on the six step dots
- [x] Dark-mode variant of the scan card (frosted-glass)
- [x] Sits inside the existing `.pc-spinner-overlay` so `hideSpinner()` and
      the existing call sites work without change

### Other homepage polish

- [x] **Network Path card** — horizontal CCNA-style hop chain with latency
      + jitter + loss badges; "Map unavailable" fallback renders an inline
      SVG continental projection
- [x] **Dark mode contrast fix** — hero, score numbers, IP/country text now
      always readable on both themes
- [x] **"Learn How It Works"** — was 404 (`/how-it-works/`), now links to
      the existing `/anonymity-tips/`
- [x] **Geo Traceroute** — paginated recent traceroutes, paste-and-visualize,
      3D globe toggle (locally-bundled Three.js + three-globe), probe-network
      registration
- [x] **IP Lookup REST 500** — `Ip2LocationProvider` autoload slug mismatch
      fixed; `IpDetector::client_ip()` (nonexistent) replaced with
      `IpDetector::detect()` returning the visitor's IP
- [x] **Run Privacy Check button** — fixed enqueue path so `wp_localize_script`
      actually fires; form submit handler now intercepts all six tool forms
- [x] **Traceroute target hostname** — typed host is now propagated through
      the scan pipeline instead of always using the WP server

### Verification

- [x] All six tool pages screenshotted with real data after submission
      (`/tmp/tool-*.png`):
      - IP Lookup 8.8.8.8 → real Google Public DNS data (Ashburn, VA)
      - WHOIS google.com → RDAP record (registered 1997-09-15, expires 2028)
      - User-Agent Safari 17.5 → parsed correctly
      - Fingerprint (headless Chrome) → 0/100 exposure score + 16 signal rows
      - DNS Leak cloudflare.com → 3 resolvers, Cloudflare 60ms, Google 162ms
      - WebRTC Test → button wired + result region populated
- [x] Homepage scan progress overlay captured mid-flight at 22% with all six
      step dots and the shimmer bar visible

## Status legend

- [x] Done
- [~] In progress
- [ ] Pending
- [!] Blocked

## Phase 1 — Bug fixes

- [x] `/scan` REST route accepts POST (`plugin/includes/class-rest-api.php`)
- [x] `wp-content/uploads/maxmind/.htaccess` denies direct HTTP access
- [x] `wp-content/uploads/maxmind/` directory created with README
- [x] Public asset enqueue includes all 7 shortcode page slugs
- [x] Uninstall script drops `wp_pc_event_log` correctly
- [x] Retention cron guards DELETE with `SHOW TABLES LIKE` check
- [x] MaxMind license key + IP API key stripped from `/settings` GET
- [x] Settings password field preserves existing key when blank-submitted
- [x] Plugin autoloader handles camelCase → kebab-case conversion

## Phase 2 — New providers + fallback chain

- [x] `MaxmindProvider` reads `.mmdb` files via `maxmind-db/reader`
- [x] `IpApiComProvider` hits free `http://ip-api.com/json/{ip}` (no key)
- [x] `IpFallback::lookup()` walks the chain, returns first acceptable result
- [x] Chain trace recorded per scan (`chain` field on result)
- [x] Successful results cached; intermediate failures NOT cached
- [x] Per-IP cache invalidation hook (`IpFallback::flush_ip`)
- [x] `/scan/connection` and `/lookup/ip` use the fallback chain
- [x] Admin settings expose reorderable chain, MaxMind license key,
      custom URLs, and ip-api.com toggle

## Phase 3 — MaxMind download manager

- [x] `MaxmindManager::official_urls()` returns 3 official GeoLite2 URLs
- [x] `MaxmindManager::download_now()` fetches, extracts, refreshes cache
- [x] `MaxmindManager::extract_mmdb()` rejects path-traversal entries
- [x] License key appended as `?license_key=…` query param
- [x] MaxMind cache directory protected with `.htaccess`
- [x] Cache invalidation drops `pc_ipintel_*` + `pc_ipfallback_*` transients
- [x] Daily wp-cron registered (`pc_maxmind_refresh`)

## Phase 4 — Admin Dashboard

- [x] Top-level menu: Privacy Checker (icon: dashicons-shield)
- [x] Submenu: Dashboard (default landing page)
- [x] Submenu: Settings
- [x] Status tiles for all 5 IP providers (active/idle)
- [x] Fallback chain display + reset-to-default action
- [x] MaxMind cache status + Download-now button + attribution
- [x] Charts: line, stacked bar, pie (pure PHP, inline SVG, no JS libs)
- [x] Recent events table + Clear-log button
- [x] Tools: flush all transients, test scan endpoint, REST API root link
- [x] Inline docs accordions (chain, DNS, rate limit)

## Phase 5 — Tests

- [x] `plugin/tests/bootstrap.php` defines WP constants + loads stubs
- [x] `plugin/tests/wp-stubs.php` provides `WpState` + WP function stubs
- [x] `plugin/tests/wp-admin/includes/upgrade.php` stubs `dbDelta`
- [x] `plugin/tests/class-security-test.php` (10 cases)
- [x] `plugin/tests/class-rate-limiter-test.php` (4 cases)
- [x] `plugin/tests/class-fingerprint-test.php` (9 cases)
- [x] `plugin/tests/class-ip-fallback-test.php` (8 cases)
- [x] `plugin/tests/class-event-log-test.php` (7 cases)
- [x] `plugin/tests/class-settings-test.php` (12 cases)
- [x] `plugin/tests/class-maxmind-manager-test.php` (7 cases)
- [x] `plugin/tests/class-rest-api-test.php` (6 cases)
- [x] `phpunit.xml.dist` config
- [x] **`composer.json` adds `classmap` for plugin/includes (non-PSR-4)**
- [x] **All 61 tests pass (154 assertions)**
- [ ] Playwright e2e specs (pending — playwright install required)

## Phase 6 — Documentation

- [x] `claude.md` — Agent operating notes
- [x] `puku.md` — Puku CLI usage
- [x] `build.md` — Build / install / run
- [x] `plan.md` — Architecture & scope
- [x] `progress.md` — This file
- [x] `README.md` — Top-level project README

## Phase 7 — Production smoke test

- [x] `wp core install` + theme/plugin activation
- [x] `curl /` returns hero HTML ("How Private Are You Online?")
- [x] `curl /?rest_route=/privacy-checker/v1/scan/ip` returns JSON
- [x] `curl /?rest_route=/privacy-checker/v1/lookup/ip&ip=1.1.1.1` returns JSON
      with chain trace (maxmind -> ip-api-com)
- [x] `curl /?rest_route=/privacy-checker/v1/settings` returns 401 unauthenticated
- [x] `vendor/bin/phpunit` is green: **61 tests, 154 assertions, 0 failures**
- [x] `npx playwright test --project=chromium` partially green: **7 passed,
      12 failed** — the suite was wired and ran; the failing specs need
      pages to be created in WP (currently none exist — only the homepage
      with the embedded scanner). Acceptable as a first baseline.

## Phase 8 — Real DNS leak test + Ping + Port scanner (Phase 8)

- [x] `Security::split_hostport()` — parse `host:port`, IPv6 brackets, hostname-only
- [x] `Security::ip_in_cidr_public()` — public wrapper for `ip_in_cidr()`
- [x] `IpFallback::server_self_ip()` — detect WP server's own public IP for self-only port scan
- [x] `NetworkProbe` — DoH fan-out, TCP-connect latency, TCP port probe, allowlist path
- [x] `NetworkProbe::HARD_PORT_DENYLIST` — SSH (22), SMTP (25), RDP (3389) always blocked
- [x] `DnsTest::run_doh_probe()` — real probe returning per-resolver latency + answer IP
- [x] `DnsTest::is_configured()` accepts `doh-fanout` + `token+doh` providers
- [x] 12 new settings keys (dns_*, ping_*, port_scan_*, rate_limit_dns_probe/ping/port_scan)
- [x] 4 new REST routes: `/scan/dns-test/run`, `/scan/ping`, `/scan/port`, `/scan/port/batch`
- [x] `RestApi::enforce_rate_limit()` honors `PRIVACY_CHECKER_RATE_LIMIT_DNS_PROBE/PING/PORT_SCAN`
- [x] 2 new shortcodes: `[privacy_checker_ping]`, `[privacy_checker_port_scan]`
- [x] 3 new page slugs: `/ping/`, `/port-scan/`, plus localized admin links
- [x] `scanner.js` — real `bindDnsTest()` (was a stub), `bindPing()`, `bindPortScan()`
- [x] Admin settings sections: DNS Leak Test, Ping/Latency, Port Scan
- [x] Admin dashboard — 3 new diagnostics tiles (DNS / Ping / Port)
- [x] `wp-config.php` constants: `PRIVACY_CHECKER_RATE_LIMIT_DNS_PROBE/PING/PORT_SCAN`
- [x] `bin/wp-install.sh` smoke test Step 10 — exercises all 4 new endpoints

## Phase 9 — Detailed privacy report + Proxy/VPN/Tor detection (Phase 9)

- [x] `PrivacyReport::build()` — Whoer-style breakdown with grade (A-F), confidence,
      weighted overall percentage, per-category rows (ip, reputation, dns, webrtc,
      fingerprint, user_agent, ipv6, consistency, proxy)
- [x] `ScannerOrchestrator::scan()` now embeds `privacy_report` on every response
- [x] `scanner.js` — renders overall %, grade, headline, per-category % bars,
      tiered recommendations, proxy badge
- [x] `ProxyDetector::classify()` — ASN catalog (AWS, GCP, Azure, Cloudflare,
      Hetzner, OVH, DigitalOcean, Mullvad, ProtonVPN, Tor relays, etc.) +
      org-string substring matching for residential / hosting / datacenter /
      VPN / Tor classification with high/medium/low confidence
- [x] Privacy report includes `proxy` category and `proxy` summary field
- [x] Anonymity tips: `AnonymityTips::all()` — 15 tips across 5 tiers
      (Foundational / Strong / Identity / Hardening / Habits) covering VPN,
      browser, DNS, Tor, anti-detect (AdsPower/GoLogin/Multilogin), residential
      proxies, email aliases (SimpleLogin/anonaddy), virtual phone (JMP/MySudo),
      crypto payments, WebRTC, container tabs, dedicated OS (Tails/Whonix/Qubes),
      stylometric hygiene
- [x] `[privacy_checker_anonymity_tips]` shortcode + `/anonymity-tips/` page slug
- [x] `scanner.js` — auto-includes Anonymity Tips card at the bottom of every scan

## Known issues / technical debt

- `class-autoloader.php` was modified mid-project to handle:
  - camelCase → kebab-case (`IpFallback` → `class-ip-fallback.php`)
  - interfaces named with `…Interface` suffix (e.g. `IpIntelligenceProviderInterface`
    → `interface-ip-intelligence-provider.php`, singular `Provider` namespace
    segment resolves to the `interfaces/` folder)
  - `plugin/admin/` and `plugin/public/` as fallback locations for top-level
    Admin / PublicAssets classes (registered via the composer `classmap`).
  Future contributors should not rename class files without updating both the
  classmap and the autoloader logic in tandem.
- `wp-stubs.php` provides a thin `wpdb_stub` for unit tests. It does NOT mock
  transactions, custom SQL types, or `wpdb::query()` side effects. Tests that
  rely on real DB behavior must be marked integration tests (out of scope).
- The plugin is **symlinked** into `wp/wp-content/plugins/` and
  `wp/wp-content/themes/` rather than copied. This lets WP detect live edits
  during development. For production, ship as a zip or copy.
- The DB option `active_plugins` was hand-edited during the initial install
  to set the serialized string length correctly. The web-based WP installer
  is preferred thereafter.

## Phase 11 — Network Path real-data + vertical layout + share endpoint

Recent work that supersedes / extends Phase 8 (DNS Leak / Ping / Port Scan)
and Phase 10 (UX polish):

- [x] **Real backend Network Path** — `NetworkProbe::path_hops()` builds an
      honest hop list from real signals: PTR (reverse DNS of visitor IP),
      IP-intel (ISP + ASN + country + city), `ProxyDetector` category
      (Tor/VPN/Hosting/Residential), and the WP server hostname as
      destination. Each hop carries a `source` field (`ptr`, `ip-intel`,
      `proxy-detector`, `inferred`, `request`) so the UI can flag estimates.
      `ScannerOrchestrator::scan()` exposes this as `connection.path_hops`
      on every `/scan` response.
- [x] **JS consumes real hops** — `networkPathCard()` now prefers
      `report.connection.path_hops` and only falls back to the heuristic
      template when the backend has nothing to surface. Title row gets a
      `REAL BACKEND DATA` (green) or `ESTIMATED` (amber) pill so visitors
      can tell the two apart at a glance.
- [x] **Vertical / multi-row path renderer** — for narrow viewports or hop
      counts > 8, the diagram collapses to a stacked card list with a
      vertical connector line. New helpers: `buildVerticalPathDiagram()`,
      `buildVerticalSidePanel()`. Full Light + Dark CSS for
      `.pc-network__diagram-vertical`, `.pc-network__vrow`,
      `.pc-network__vrow-icon`, `.pc-network__vrow-num`, `.pc-network__vrow-block`,
      `.pc-network__vrow-label`, `.pc-network__vrow-sub`,
      `.pc-network__vrow-connector`, plus per-type colors and dark-mode
      overrides.
- [x] **Server-side share endpoint** — `POST /share` accepts a redacted
      scan report, stores it as a transient keyed on a short URL-safe ID,
      returns `{sid, expires_at}`. `GET /share/{sid}` retrieves the
      redacted payload. `share_enabled` setting controls whether the
      feature is exposed; `share_ttl_seconds` controls retention
      (60s..30d, default 7d).
- [x] **Redaction** — `redact_share_payload()` strips `ipv4`, `ipv6`,
      `request_ip`, `dns_test.token`, `reverse_dns`, `fingerprint.hashes`
      and rounds coordinates to 1 decimal (~11 km). Replaces IPs with
      `0.0.0.0/24`-style subnet only when the share surface demands it.
- [x] **Multi-format export** — `buildExportMenu()` adds a select for
      JSON / CSV / TXT / HTML output of the full scan report. Wired into
      the detailed-report card header.
- [x] **Country flags on IP / DNS / ASN / Reputation rows** — new
      `flagify()` + `countryFlag()` helpers (PHP + JS) convert ISO 3166-1
      alpha-2 codes to regional-indicator emoji. Used in connection rows,
      detailed report, and Geo Traceroute summary.
- [x] **Geo Traceroute real-data fixes** — `scan_geo_lookup` now always
      returns an explicit origin hop, 5 intermediate hops interpolating
      along the great-circle, and a destination hop with real lat/lng.
      Visitor loopback/private IP falls back to the WP server's own public
      IP via `IpFallback::server_self_ip()`. When even that fails
      (local-dev), origin collapses to target coords with a `SAME HOST`
      label and a small 0.05° wobble arc so the polyline is visible.
- [x] **Geo Traceroute country flags** — per-hop `flag` field, plus
      `target.flag` and `origin.flag`. New `RestApi::country_flag()` PHP
      helper. JS surfaces flags in origin/destination summary, hop list,
      and marker popups. CSS adds `.pc-geo__summary-flag`.
- [x] **3D Globe fix** — `setGeoView()` now un-hides the globe container
      BEFORE calling `ensureGlobe3d()`, and defers init to the next
      animation frame so `getBoundingClientRect()` returns the real
      size. `ensureGlobe3d()` falls back to the parent's rect if its
      own is still 0×0, with a 320×280 minimum so the canvas is never
      invisible.
- [x] **DNS tier fallback chain** — `NetworkProbe::resolver_chain_for_tiers()`
      and `online_dns_resolvers()` build the resolver map across the four
      tiers: `free` (Cloudflare / Google / Quad9) → `online` (Mullvad /
      ControlD / NextDNS) → `paid` (admin-configured endpoint + key) →
      `local` (admin-configured IP list). Settings: `dns_provider_chain`,
      `dns_paid_endpoint`, `dns_paid_api_key`, `dns_local_resolvers`.
- [x] **Local-first User-Agent parsing** — `parseUserAgentLocal()` in JS
      mirrors the PHP `Fingerprint::parse_user_agent()` shape so visitors
      can parse arbitrary UA strings client-side. Falls back to the
      visitor's own `navigator.userAgent` if the textarea is left blank.
- [x] **IP provider source attribution** — every IP-intel response now
      carries `source` + `source_label` (the provider key + human label).
      UI surfaces this in the detailed privacy report.
- [x] **Test suite repaired** — fixed a missing `'ping_targets' =>` key in
      `class-plugin.php` defaults that broke every PHPUnit test with a
      parse error. **All 120 tests pass (464 assertions, 0 failures).**

## Phase 12 — Repo + docs hygiene

- [x] `.gitignore` excludes `wp/`, `vendor/`, `wp-config.php`,
      `GeoIP Database/`, `vendor-src/`, `tools/`, `Screenshots/`,
      `.puku-cli/projects/`, `test-results/`, build artifacts, OS-temp.
- [x] GitHub repo created: https://github.com/sabbirimon/imon-privacy-checker
- [x] `DEPLOYMENT.md` written for DevOps (server requirements, env vars,
      nginx/apache configs, cron, log rotation, monitoring, rollback).

## Phase 12.5 — Manual-only user-guide onboarding tour

- [x] New shortcode `[privacy_checker_user_guide]` rendering a floating "?"
      FAB plus a tour overlay shell (header + body + footer with step
      indicator + prev/next/done).
- [x] 11 new `PC_SCAN.i18n` strings (`guideButtonTitle`, `guideAriaLabel`,
      `guideTitle`, `guideSubtitle`, `guideNext`, `guidePrev`, `guideDone`,
      `guideClose`, `guideStepOf`, `guideSkip`, `guideRestart`).
- [x] 12-step tour config localized via a second
      `wp_localize_script('pc-scanner', 'PC_GUIDE', …)` block — each step
      has `id`, `title`, `body`, `target` (CSS selector list, comma-
      separated), and `place` (center / top / bottom / left / right).
- [x] New `bindUserGuide()` in `scanner.js`: reads `PC_GUIDE.tour`, wires
      `data-pc-action="open-guide"` (FAB + delegated in-page triggers) to
      `openGuide()`, drives prev/next/done/close, keyboard navigation
      (Esc / ← / → / Enter), target-aware card positioning via
      `getBoundingClientRect()` with viewport clamping, and re-positions
      on resize/scroll while open.
- [x] **Manual-only by design.** The tour NEVER auto-launches: no first-
      visit hook, no `localStorage` flag, no scheduled timer, no
      `DOMContentLoaded` path into `openGuide()`. The only paths into the
      overlay are explicit clicks on the FAB or a delegated in-page
      trigger carrying the `open-guide` action.
- [x] New CSS: `.pc-guide-fab` (fixed bottom-right, hover lift, focus ring,
      `prefers-reduced-motion` respected, smaller on ≤540px), `.pc-guide-overlay`,
      `.pc-guide-backdrop`, `.pc-guide-card` + placement variants
      (`--center / --top / --bottom / --left / --right`), `.pc-guide-card__*`
      (header / title / close / body / footer / step / actions), and full
      `:root[data-pc-theme="dark"]` overrides.
- [x] `composer dump-autoload -o` regenerated the classmap (1042 classes).
- [x] **All 120 PHPUnit tests pass (464 assertions, 0 failures).**
- [x] `node --check scanner.js` → JS_OK. `php -l class-public-assets.php`
      → no syntax errors.
- [x] Committed (`06c02d2`).

## Phase 13 — 3D globe honest-state fixups + UX cleanup (in progress)

Bugs surfaced by a code audit on the Geo Traceroute / 3D globe path.
Each is being addressed as its own small commit so the review surface
stays bounded.

- [x] **DRY tool-slug list** — `PublicAssets::enqueue()` repeats the same
      array of tool slugs three separate times. Replaced with a single
      `private const TOOLS` map (slug → shortcode suffix) plus two
      derived accessors `tool_slugs()` and `tool_shortcode_tags()`.
      Adding a new tool now requires one entry in `TOOLS` and one
      shortcode registration above. (`da6f0ad`)
- [x] **Lazy availability check** — replaced the once-at-bind-time
      `globeState.available` snapshot with a fresh
      `isGlobeLibraryAvailable()` re-check called every time
      `ensureGlobe3d()` and `setGeoView()` need a verdict. `setGeoView()`
      now also does a bounded retry (every 250 ms up to 5 s) so a late
      library load still gets picked up. Fixes the silent breakage where
      a slow CDN / ad-blocker stranded the globe toggle as permanently
      "unavailable". (`c1c6854`)
- [x] **Self-host the globe textures** — vendored
      `earth-blue-marble.jpg` (1.4 MB), `earth-topology.png` (372 KB),
      `night-sky.png` (884 KB) under `plugin/public/assets/img/` with a
      provenance README. JS now references them via
      `globeTextureUrl(name)`, with the base read from
      `window.PC_SCAN.assetUrl` (newly localized from
      `PRIVACY_CHECKER_URL`) and a same-origin fallback. Removes the
      last unpkg.com dependency for the 3D globe. (`c1c6854`)
- [x] **Real console diagnostics** — three distinct console messages:
      - `console.error('[IMON globe] WebGL renderer init failed: …')`
        on scene-construction throws
      - `console.warn('[IMON globe] texture fetch failed: <url>')` per
        pre-flighted texture (HEAD with `no-cors` so a 404 surfaces
        clearly instead of silently rendering a black sphere)
      - `console.error('[IMON globe] three.js / three-globe library did
        not load within 5s.')` on retry exhaustion. (`c1c6854`)
- [ ] **Phase 7 (QA pass) of `IMON-BUILD-GUIDE.md` checklist #4** —
      audit all frontend network calls (Leaflet CSS/JS from unpkg too)
      and decide consistently: vendor everything locally or document
      the CDN list explicitly. Lower priority than the three bugs above.

## Open questions

- Should the dashboard tile for ip-api.com reflect the cached result of a recent
  successful call, or just the setting state? (Currently: setting state only.)
- Should the chain reset button require an extra confirmation? (Currently:
  one-click with nonce + capability check.)
- Should `log_retention_days=0` also drop the table on next retention cron, or
  only stop writing? (Currently: only stop writing.)
- Should `share_enabled=false` also hide the "Share" button client-side, or
  only 403 server-side? (Currently: client-side still renders the button
  and shows "Sharing is disabled by the site admin" on click.)

## Related

- `claude.md` — Agent operating notes
- `build.md` — Build / install
- `DEPLOYMENT.md` — DevOps deployment guide
- `plan.md` — Architecture
- `IMON-BUILD-GUIDE.md` — Seven-phase roadmap (connection quality,
  anonymity consistency, fingerprint entropy, security posture, LAN
  self-scan, composite scoring, QA). Execute one phase per session.
- `puku.md` — Puku CLI
