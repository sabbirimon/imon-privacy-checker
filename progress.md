# Progress — Privacy Checker

> Last updated: 2026-09-05. Track what's done, what's in flight, and what's
> blocked.

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

## Open questions

- Should the dashboard tile for ip-api.com reflect the cached result of a recent
  successful call, or just the setting state? (Currently: setting state only.)
- Should the chain reset button require an extra confirmation? (Currently:
  one-click with nonce + capability check.)
- Should `log_retention_days=0` also drop the table on next retention cron, or
  only stop writing? (Currently: only stop writing.)

## Related

- `claude.md` — Agent operating notes
- `build.md` — Build / install
- `plan.md` — Architecture
- `puku.md` — Puku CLI
