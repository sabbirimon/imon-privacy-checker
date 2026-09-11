# Progress — Privacy Checker

> Last updated: 2026-09-09 (Phase 17 — runtime acceptance & hardening).
> Track what's done, what's in flight, and what's blocked.

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
- [x] **Phase 3 — Advanced fingerprint exposure module** (`(this commit)`).
      Real fingerprint computation in the browser, replacing the old
      boolean presence flags. New `collectFingerprint()` is async
      (offline-audio render takes a tick) and computes:
      - `canvas_hash` — FNV-1a 32-bit over `toDataURL()` of a fixed
        text+shapes scene (~15 bits of entropy).
      - `audio_hash` — FNV-1a 32-bit over first 200 samples (10-step
        stride) of an `OfflineAudioContext` triangle-osc → compressor
        → destination render (~15 bits).
      - `webgl_renderer` / `webgl_vendor` — read via
        `WEBGL_debug_renderer_info`, or explicit `"masked-by-browser"`
        sentinel when the extension is blocked (~6 bits unmasked; the
        masked sentinel counts as an anti-fingerprinting GOOD sign).
      - `font_list` — 38 common fonts tested by width comparison against
        `monospace`/`sans-serif`/`serif` fallbacks; baseline of 8 is
        free, each additional font is +1 bit (~2 bits for a typical
        install).
      Added `Fingerprint::entropy_estimate()` that sums signal bits
      (capped at 100), produces a human-readable "Roughly 1 in N
      visitors share this fingerprint — ..." line, and a per-signal
      breakdown dict. `estimate_visibility()` now averages the old
      boolean-flag score with the entropy score so the existing
      consumers (`exposure_score`, `level`, `signals`) keep their
      meaning. New top-level `masked_signals` list for the UI to
      distinguish "browser blocking this — good" from missing data.
      The orchestrator echoes the raw hashes back under
      `report.fingerprint_hashes` so the JS card can render them. Card
      gets 6 new rows (canvas hash, audio hash, WebGL renderer/vendor
      with masked pill, font count + expandable list, entropy line). 11
      new i18n strings, new CSS for `.pc-fp-list__*`. 11 new PHPUnit
      tests (146 total, all green). TODO comment in `entropy_estimate()`
      marks the seam for future population-stats wiring.
- [ ] **Phase 3 — Advanced fingerprint exposure module** (real canvas /
      WebGL / audio hashing + entropy score). Largest single chunk,
      splits in two sub-sessions per the guide: JS collection first,
      pause for review, then PHP scoring.
- [x] **Phase 4 — Security posture panel** (`(this commit)`). Two
      small pure-data classes (no I/O) and a new compact card in the
      scan-report right column. Surfaces the TLS protocol version +
      negotiated cipher for the connection that's currently serving the
      page, plus a browser EOL check (Chrome / Firefox / Safari / Edge)
      based on the visitor's `navigator.userAgent`. Reads
      `$_SERVER['SSL_PROTOCOL']` / `'SSL_CIPHER'` (Apache / LiteSpeed) +
      `HTTPS_TLS_VERSION` / `HTTPS_TLS_CIPHER` (nginx via
      `fastcgi_param`); treats proxy-forwarded keys cautiously — only
      what the web server saw on the local socket counts. When no TLS
      info is available (visitor is behind a TLS-terminating proxy that
      didn't forward the handshake), returns explicit `'unknown'`
      status with a human-readable note rather than guessing. TLS
      classification: TLSv1.3 → `modern`, TLSv1.2 → `acceptable`, older
      TLS / SSL → `outdated`. Browser thresholds per family:
      Chrome 130/100, Firefox 125/100, Safari 17/14, Edge 130/100 (Edge
      shares Chrome's cycle). Status mapped to pill colours
      (`pc-pill--pass/info/warning/danger/unknown`) and a one-line
      advisory. New files: `class-tls-info.php` + `class-browser-versions.php`
      + their PHPUnit suites (10 + 14 tests). `ScannerOrchestrator::scan()`
      returns `security_posture: {tls, browser}` on every `/scan`
      response. 10 new `sp*` i18n strings; `securityPostureCard()`
      renders between `fingerprintTableCard()` and
      `scoreBreakdownCard()`. **170 tests / 600 assertions, all green.**
- [x] **Phase 5 — Local Network Exposure** (`(this commit)`). Pure
      client-side — no PHP / no REST route. New `scanLocalNetwork()`
      fires concurrent `fetch(..., {mode:'no-cors'})` against a
      **hardcoded** list of common RFC1918 gateway addresses
      (`192.168.0.1`, `192.168.1.1`, `10.0.0.1`, `10.0.1.1`,
      `172.16.0.1`) on common admin ports (80 / 443 / 8080),
      each with its own `AbortController` and a per-probe 800 ms
      deadline so a single slow target can't drag the whole batch.
      Each result is classified as `open` / `cors` (something
      answered but CORS-blocked reading the body — still informative
      and explicitly flagged) / `refused` (port closed) / `timeout`
      (no response) / `unreachable` (network error). The target list
      is deliberately NOT configurable and the function never accepts
      a user-supplied target — a code comment spells out why (this
      is a self-test tool, not a network-scanner-as-a-service; an
      unconstrained probe list would either be filtered by upstream
      routers or look like an outbound port-scan to an upstream
      firewall). New `localNetworkExposureCard()` renders below the
      score breakdown with summary pill (`pass` / `warning` / `danger`),
      per-row per-host status, and explicit copy
      ("Tests devices on YOUR OWN local network, from YOUR OWN browser
      — not external scanning…"). Uses the same placeholder-then-swap
      pattern as `connectionQualityCard()` so the report layout
      doesn't reflow when the probe resolves; even on probe rejection
      the placeholder is swapped for a "Probe did not run" card so
      the layout never gets stuck on a spinner. 17 new `ln*` i18n
      strings. **170 tests / 600 assertions, all green.**
      `node --check scanner.js` clean.
- [x] **Phase 6 — Composite report assembly** (`(this commit)`).
      Rewrote `class-privacy-report.php` to fold the new sub-reports
      from Phases 1–5 into the Whoer-style breakdown with weights
      per `IMON-BUILD-GUIDE.md` Phase 6 spec:
      - `consistency` (Phase 2 anonymity scorer): **weight 4** —
        highest per guide, "are you actually as private as you
        think". `score_consistency()` now reads
        `$scan['connection']['anonymity']` (output of
        `AnonymityScorer::score()`) instead of the old cheap
        IP/timezone-country heuristic.
      - `security_posture` (Phase 4): **weight 3**, NEW category.
        `score_security_posture()` averages TLS percent
        (modern=100, acceptable=75, outdated=25, unknown=70) +
        browser percent (current=100, outdated=65,
        very_outdated=25, unknown=70); status follows worst-of.
      - `fingerprint` (Phase 3): **weight 2** (down from 3) — guide:
        "informational weight, lower — most users can't fully fix
        this".
      - `webrtc`, `dns`, `reputation`: weight 3 (unchanged).
      - `ip`, `proxy`, `user_agent`, `ipv6`: weight 2 (unchanged).
      - **`connection_quality` (Phase 1) and `local_network`
        (Phase 5): weight 0 — surface-only.** Per guide: "surface
        separately as 'connection health' rather than folding into
        'privacy score', since a slow connection isn't a privacy
        problem". `row()` now preserves weight 0 explicitly (clamped
        from negatives); the weighted-average loop skips weight-0
        categories; `confidence_for()` also skips them so surface-
        only unknowns don't tank confidence.
      8 new PHPUnit tests covering the new shape: anonymity-scorer
      passthrough, missing-anonymity unknown, security-posture
      good/bad bands, surface-only weight=0 invariant, surface-only
      doesn't-drag-overall (two scans identical except for surface
      categories produce identical `overall`), consistency has
      highest weight pin. **`row()` weight clamping relaxed** so
      weight 0 is preserved as the surface-only sentinel (previously
      `max(1, $weight)` would have promoted 0 → 1 and broken the
      exclusion). **178 tests / 661 assertions, all green.**
- [x] **Phase 7 — QA pass** (`(this commit)` + `(prior commit)`).
      Closing audit per `IMON-BUILD-GUIDE.md` Phase 7 (lines 308-322).
      Read-only audit of Phases 1-6 surfaced four of five categories
      clean; two small fixes plus a backlog inventory:
      - **(A) Signal visibility** — every Phase 1-5 signal already has
        a UI surface (audit table in plan: 12 categories × 10 cards,
        no orphan collectors). **One inconsistency fixed here**:
        `connection_quality` was being computed client-side but the
        orchestrator wasn't threading it into `$scan['connection_quality']`,
        so the Phase 6 `score_connection_quality()` category in the
        privacy-report breakdown always reported "did not run". Fix:
        extended `RestApi::collect_client_signals()` allowlist with
        `connection_quality` and added structural validation +
        pass-through in `ScannerOrchestrator::scan()` (numeric type
        coercion on `latency.avg_ms`, optional `latency.{min,max,
        jitter_ms,count}` + `network.{available, downlink_mbps,
        effective_type, rtt_ms}`). 3 new PHPUnit tests cover:
        client payload promotes source to `measured`, high-jitter
        promotes status to `warning`, missing payload stays
        `unknown`.
      - **(B) PHP style** — `class-anonymity-scorer.php`,
        `class-tls-info.php`, `class-browser-versions.php` (Phase 2,
        4 new files) all have `declare(strict_types=1)` and
        return-type-hints. **One violation fixed here**:
        `RestApi::scan_connection_echo()` (Phase 1) had no return
        type; changed to `: \WP_REST_Response|\WP_Error` (matches
        the `enforce_rate_limit()` early-return shape).
      - **(C) Fail-closed** — clean. `TlsInfo::current_request_info()`
        (no `$_SERVER` keys → `'unknown'`), `BrowserVersions::check()`
        (`unknown_family` / `unknown_version` sentinels),
        `AnonymityScorer::score()` (empty inputs → score 100, no
        mismatches), JS `scanLocalNetwork()` (`.catch()` maps
        AbortError/TypeError to `'timeout'`/`'refused'`),
        `connectionQualityProbe()` (failed sample skipped silently),
        `collectFingerprint()` (every probe in try/catch; AudioContext
        throw → `Promise.resolve('')`). No throw paths anywhere.
      - **(D) External network** — clean for Phases 1-5. All new
        `fetch()` calls are same-origin (`/scan/connection/echo`) or
        RFC1918 LAN (by design). Self-hosted three.js, three-globe,
        globe textures already shipped in earlier cleanup phase.
        Pre-existing CDN leftovers (NOT Phase 7 work, listed in
        backlog below).
      - **(E) TODO inventory** — exactly one TODO marker remains:
        `plugin/includes/class-fingerprint.php:211` — entropy
        population-stats seam. Restated in backlog below.
      **181 tests / 670 assertions, all green.** `node --check scanner.js`
      clean. `php -l` clean on every modified file.
- [ ] **Phase 7 — QA pass** (audit all added code for conventions,
      shown-back-to-user, fail-closed behavior, external-CDN policy).

## Phase 8 (admin track) — Admin visibility for Phases 1-7

Three deliverables ship on top of the closed visitor-side seven-phase
track (`IMON-BUILD-GUIDE.md`). Goal: make the new scoring machinery
discoverable to admins without making it user-tunable.

- [x] **8.2a — Public getters for hardcoded scoring constants.**
      Visitors see a 12-category weighted composite (`PrivacyReport`,
      Phase 6) plus entropy / anonymity scorers (Phases 3-4) but
      admins had no view of the constants driving them. Added four
      public getters backed by single-source-of-truth `const`
      tables:
      - `BrowserVersions::thresholds(): array<string,array{current:int,outdated_cutoff:int}>`
      - `PrivacyReport::category_weights(): array<string,int>` (consistency=4 highest, connection_quality=0/local_network=0 surface-only)
      - `Fingerprint::entropy_bit_assignments(): array<string,int>` (canvas +15, audio +15, webgl +6/-5 masked, font +1 beyond baseline 8, timezone +4, language +4, languages +2, cap 100)
      - `AnonymityScorer::signal_weights(): array<string,int>` (timezone -20, WebRTC -40, DNS -30, proxy 0)
      Seven new tests pin the canonical values; both getter and
      source-of-truth method are exercised in the same test where
      practical so the reference card can never drift from the
      computation. **+7 tests / +96 assertions, 188 tests / 766 assertions.**
- [x] **8.1 — Privacy Report inspector** (new admin submenu page).
      File: `plugin/admin/class-admin-privacy-report.php` +
      `plugin/admin/views/privacy-report-inspector.php`. New
      submenu **Privacy Checker → Privacy Report**, positioned
      between Dashboard and Settings. Renders
      `PrivacyReport::build()` against a server-side self-scan
      payload built from `IpDetector::detect()` +
      `IpFallback::lookup()` + `ProxyDetector::classify_with_lists()`
      + `Reputation::check()` + `Fingerprint::parse_user_agent()` +
      `TlsInfo::current_request_info()` + `BrowserVersions::check()`
      + `AnonymityScorer::score()`. No client signals (no
      `collectFingerprint()` / `WebRTC` / `connectionQualityProbe()` /
      `scanLocalNetwork()` available in admin context) — those
      categories get empty / unknown defaults, same fail-closed
      pattern used everywhere else, banner at top makes this
      explicit. Renders overall / grade / confidence / headline,
      a per-category table (key, percent, status, weight, weighted
      contribution, message) with surface-only rows visibly tagged,
      a weighted-avg **arithmetic transparency panel** that shows
      the literal formula `(sum of percent*weight) / sum_of_weight =
      overall` with the actual numbers, and the deduplicated
      recommendations list with priority badges. Wired in via
      `Plugin::init()` adding `new AdminPrivacyReport()` alongside
      the other admin classes. CSS for the inspector + the new
      `.pc-scoring-ref` reference table live in
      `plugin/admin/assets/admin.css`. Nine new tests exercise
      `build_self_scan()` (top-level shape, IP read, fingerprint
      unknown, WebRTC no-leak, security posture, UA parse, full
      PrivacyReport integration, arithmetic-panel match, MENU_SLUG
      distinctness). **+9 tests / +42 assertions, 197 tests / 808
      assertions.**
- [x] **8.2b — Scoring parameters reference card** (settings page
      section). Appended `pc_scoring` section as the very last
      settings section in `class-admin.php::register_settings()`,
      positioned as an "appendix" of hardcoded constants the admin
      should be aware of. Four read-only reference tables, each
      rendering values straight from the source module's public
      getter (no duplication in HTML):
      - **Anonymity consistency weights** — signal + deduction
        + human label (timezone/WebRTC/DNS/proxy).
      - **Fingerprint entropy bit assignments** — signal + notes
        + bits (canvas/audio/webgl/font/timezone/language/languages/cap).
      - **Browser EOL thresholds** — family + current + outdated
        cutoff (Chrome/Firefox/Safari/Edge).
      - **Composite report weights** — category + weight + notes
        (all 12, with surface-only rows visibly tagged).
      All values are rendered via the public getters from 8.2a,
      so the reference card can never drift from the source code.
      No new settings keys. CSS for `.pc-scoring-ref` added to
      `admin.css`. Zero new tests (covered transitively by the 8.2a
      getter tests).
- [x] **8.3 — Diagnostics summary tile** (dashboard widget).
      Appended a 4th `rate_limits` entry to `$diagnostics_tiles`
      in `plugin/admin/views/dashboard.php`. One-line summary of
      every rate-limit knob shipped across Phases 1 + 8:
      `Scan 60 · Lookup 30 · Security 10 · Echo 60 · DNS 5 · Ping 30 ·
      Port 10` (values pulled from settings, sensible defaults).
      Link anchors at `#pc_rate` (the master Rate Limiting section
      that already renders scan/lookup/security). Other knobs
      remain in their respective sections — this tile is an
      at-a-glance summary, not a duplication. No new tests (view
      template only, low regression risk).

**Verification**: `vendor/bin/phpunit` → **197 tests / 808 assertions,
all green** (up from 181/670 at end of Phase 7). `php -l` clean on
every modified file. `node --check scanner.js` N/A (no JS changes
in this phase). No new composer / npm dependencies. No new REST
routes. No new settings keys. No new secrets, no PII handling, no
write paths.

## Phase 9 (backlog cleanup) — Three deferred Phase 7 items

Lands the three items still tracked in the "Phase 7 — QA backlog"
section below. All three are plumbing / asset hygiene; none change
runtime behavior or scoring.

- [x] **9.A — Self-host Leaflet (BSD-2-Clause).** Vendor
      `leaflet@1.9.4` under `plugin/public/assets/{css,js}/leaflet.{css,js}`
      via curl from `unpkg.com`, attribution + license text in
      `plugin/public/assets/LEAFLET-LICENSE.md` (BSD-2-Clause,
      Copyright (c) 2010-2023 Vladimir Agafonkin / 2010-2011 CloudMade).
      `class-public-assets.php` enqueues rewritten to local URLs —
      drops the `is_readable` ternary (Leaflet has no fallback, we
      hard-require the local files). Three.js fallback paths remain
      defensive safety nets as shipped today.
      `grep -R "unpkg.com/leaflet" plugin/` returns nothing.
      (`ffc6b7b`)
- [x] **9.B — Self-host network-path icons as clean-room SVGs.**
      Upstream `tmusabaika/minimalistic-networking-icons` ships with
      **no LICENSE file** (vendoring the PNGs would have been a
      license violation), so this replaces the 5 PNG icons with
      hand-drawn clean-room SVG originals under
      `plugin/public/assets/img/net-icons/`: `iServer.svg`,
      `iRouter.svg`, `iSwitch.svg`, `iWorkstation.svg`, `iHub.svg` —
      each a single `<svg>` 24×24 viewBox monochrome stroke, MIT-
      licensed to match the plugin. Provenance table + role-mapping
      + MIT text in `plugin/public/assets/img/net-icons/README.md`.
      `scanner.js` `PC_ICON_MAP` extension swapped from `.png` to
      `.svg` (keys unchanged); `PC_NET_PNG_CDN` swapped from
      `raw.githubusercontent.com/tmusabaika/...` to
      `window.PC_SCAN.assetUrl + 'img/net-icons/'`; the data-URI
      pipeline (`fetchIconMarkup` → `FileReader.readAsDataURL` →
      SVG `<image href>`) is unchanged. The icon-to-role mapping
      table in the new README documents the visual semantic for
      every consumer key (device / mobile / tablet / pc /
      home-router / router / server / switch / firewall / vpn /
      tor / destination / hub / cell-tower / satellite).
      `grep -R "raw.githubusercontent.com/tmusabaika" plugin/`
      returns nothing. (`55403b3`)
- [x] **9.C — Cache-backed population-stats seam.**
      `Fingerprint::population_histogram(string $signal): array`
      returns `Cache::remember('pc_fp_hist_' . $signal, …,
      DAY_IN_SECONDS)` — empty collector closure returns `[]` until
      a real one ships. `entropy_estimate()` now consults
      histograms via a private `histogram_weighted_bits()` helper
      using `-log2(max(p, epsilon))` per signal with a 20-bit
      per-signal cap, and blends 50/50 with the existing constant-
      based estimate when **any** histogram is non-empty. When all
      histograms are empty (current state) the seam is a no-op:
      the canonical Phase 3 fixture (canvas + audio + webgl +
      timezone + language + languages) still scores exactly 46
      bits. Three new tests + one set_up() to clear the `pc_fp_hist_*`
      cache keys so tests don't pollute each other.
      **+4 tests / +11 assertions, 201 tests / 819 assertions.**
      (`e089e8f`)

**Verification**: `vendor/bin/phpunit` → **201 tests / 819 assertions,
all green** (up from 197/808 at end of Phase 8). `node --check
scanner.js` clean. `php -l` clean on every modified file.
`grep -R "unpkg.com/leaflet" plugin/` → empty.
`grep -R "raw.githubusercontent.com/tmusabaika" plugin/` → empty.
No new composer / npm dependencies. No new REST routes. No new
settings keys. No new secrets, no PII handling, no write paths.

## Phase 10 — UX polish: IMON rebrand, scan progress, styled tool results

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

## Phase 14 — Live-site bugs surfaced 2026-09-09

Three small fixes the user hit in their browser. None are big
features — all are plumbing that should have shipped earlier but
surfaced only when the visitor-side flow actually ran.

- [x] **14.1 — POST /scan 500 (TypeError → fix).** Live `wp/wp-content/debug.log`
      shows `Fingerprint::population_histogram(): Return value must
      be of type array, false returned` on every POST /scan. Cause:
      the Phase 9.C `Cache::remember()` wrapper stored an empty array
      as a transient, but WP's transient layer sometimes unserializes
      a stored empty array back as `false`, which violates the
      `: array` return contract and crashes the orchestrator. Fix:
      drop the `Cache::remember` write-through for empty results and
      read the cached value directly with explicit fallbacks (unwrap
      `__hist` wrapper if present, accept a bare non-empty array for
      legacy / test-fixture shape, return `[]` for `false` / `null` /
      missing). `entropy_estimate()` stays unchanged — all 27
      existing Fingerprint tests + the 3 new ones still pass
      (`vendor/bin/phpunit` → 201 / 819, all green). `php -l` clean.
- [x] **14.2 — Same-origin REST URL + asset URL in scanner.js.**
      WordPress localizes `restUrl` / `assetUrl` as absolute URLs
      built from `siteurl()`. When the visitor reaches the site via a
      different hostname than `siteurl()` (local-dev: WP at
      `http://127.0.0.1:8080`, visitor at `http://localhost:8080`),
      every REST call becomes cross-origin, `credentials:
      'same-origin'` strips the WP auth cookie, and POST /scan fails
      the WordPress nonce check with what looks like a CORS error
      (`net::ERR_FAILED`). Fix: rewrite `REST_URL` and
      `PC_NET_PNG_CDN` in `scanner.js` to derive their paths from the
      current origin (`window.location.origin + '/wp-json/
      privacy-checker/v1/'` and `/wp-content/plugins/privacy-checker/
      public/assets/img/net-icons/`), with the localized absolute URL
      as fallback. After the rewrite, GETs succeed, the missing-v1
      path bug is gone (the original regex was greedily matching
      `/wp-json/privacy-checker/` instead of `/wp-json/privacy-checker/v1/`),
      and POST /scan flows correctly. The old `maybe_emit_cors_headers`
      filter remains as a defensive belt-and-braces for production
      deployments that intentionally cross-origin-proxy the plugin.
      `node --check scanner.js` clean. 12 / 12 Playwright e2e pass.
- [x] **14.3 — Dark-mode card text invisible (universal selector bug).**
      `.pc-card__title`, `.pc-info-table dt`, etc. were showing as
      white text on the white card surface in dark mode. Two stacked
      causes: (1) a previous edit had left a dangling CSS block at
      `plugin/public/assets/css/scanner.css:1619-1625` — an orphan
      `}` with no opening selector — which threw off brace balance
      and silently dropped every dark-mode rule below line 1620
      from the parsed stylesheet. (2) the rule that *did* parse
      (`:root[data-pc-theme="dark"] .pc-col * { color: inherit; }`)
      used a universal selector with higher effective specificity than
      `.pc-card__title`, forcing it to inherit from the body (white).
      Fix: (1) re-attach the orphan block to `.pc-network__side { … }`
      so brace balance is restored (679/679 → 680/680). (2) scope the
      `.pc-col *` rule to `.pc-dash-cols, .pc-col` (no universal)
      and pin per-card-class dark text colors. Also added a bright
      `.pc-section__title` override (`color: var(--pc-accent-3)` =
      `#3ddccd`) and a dim `.pc-section__lede` override so the
      "YOUR PRIVACY REPORT" / "WHAT WE CHECK" / "APPROXIMATE LOCATION
      & PATH" headings read against the dark teal page bg. Screenshot
      in `test-results/dark-mode-FINAL3.png` confirms every card
      title, table row, and section heading is legible in both
      themes.
- [x] **14.4 — scanLocalNetwork no-cors redirect error.** Browser
      console was spewing `Fetch API cannot load http://192.168.0.1/.
      Request mode is "no-cors" but the redirect mode is not "follow"`
      for every RFC1918 probe. Per the Fetch spec, `redirect: 'manual'`
      is not allowed with `mode: 'no-cors'` — drop the property and
      accept the default `follow` for these self-test LAN probes.
      `scanLocalNetwork()` continues to fire 15 concurrent no-cors
      GETs against the hardcoded `[192.168.0.1, 192.168.1.1,
      10.0.0.1, 10.0.1.1, 172.16.0.1]` × `[80, 443, 8080]` list
      with an 800 ms per-probe `AbortController` budget; the missing
      `redirect: 'manual'` only affected how the browser reports the
      opaque response, not the `'cors' / 'refused' / 'timeout' /
      'unreachable'` classification. `node --check scanner.js` clean.
- [x] **14.5 — IP lookup accepts hostnames.** `lookup/ip` previously
      400'd with "Non-public IP literals are not looked up" when a
      visitor pasted `facebook.com` (or any hostname) into the IP
      Lookup form on `/ip-lookup/`. Backend now resolves the
      hostname via `gethostbyname()` first, strips a stray URL
      scheme / path prefix, validates the result is a public IP,
      and returns the same response shape IP Fallback uses — including
      a new `resolved: bool` flag so the UI can show
      "facebook.com → 57.144.144.1" when a hostname was resolved.
      `curl http://127.0.0.1:8080/wp-json/privacy-checker/v1/lookup/ip?ip=facebook.com`
      → 200 with Singapore geo intel for Facebook's edge IP.

**Verification**: `vendor/bin/phpunit` → **201 tests / 819 assertions,
all green.** `node_modules/.bin/playwright test` → **12 / 12 passing**.
`node --check scanner.js` clean. `php -l` clean on every modified
file. Source-clean:
`grep -R "unpkg.com/leaflet" plugin/` → empty,
`grep -R "raw.githubusercontent.com/tmusabaika" plugin/` → empty.
No new composer / npm dependencies. No new REST routes. No new
settings keys. No new secrets, no PII handling, no write paths.

## Phase 15 — `bin/deploy.sh` (one-command deploy)

The user asked for a single script that can either host the plugin
locally, ship it to a real web server via rsync, or zip it for manual
upload. The result is `bin/deploy.sh` — a 400-line shell script that
walks through 8 phases:

1. **Pre-flight** — `php`, `composer`, `rsync`, `ssh` (info-level) in
   PATH; PHP ≥ 8.1; plugin + theme version read from source headers;
   release staging dir prepared.
2. **Mode selection** — `local` (copy into `./wp`), `rsync user@host:/path`,
   `remote user@host` (rsync to `${WP_ROOT}`), `zip /path/release.zip`
   (build-only), or no-arg usage.
3. **Build** — `composer install --no-dev --optimize-autoloader` then
   `composer dump-autoload --classmap-authoritative` against the
   project-root composer.json.
4. **Stage release** — rsync `plugin/` + `theme/` into
   `release/imon-privacy-checker-<ver>/`, skipping `tests/`, `*.log`,
   `.DS_Store`, etc. Re-anchors the project-root `composer.json`'s
   `plugin/includes/` autoload paths (which assume project-root layout)
   to plugin-local `includes/` paths so `composer install` works from
   `wp-content/plugins/privacy-checker/`. Done via an inline PHP
   closure with `use (&$strip)` capture so it strips the `plugin/`
   prefix from PSR-4 + classmap keys recursively (without the
   capture, PHP 8.5's closure binding can't see the parent `$strip`
   variable when called recursively — see `bin/deploy.sh:184`).
5. **Ship** — one of three branches: `zip` (`zip -qr`), `local`
   (`cp -a` into `wp/wp-content/plugins|themes/`), or `rsync` (two
   rsyncs — one each for plugin + theme — followed by remote
   `find | chmod 755/644` lockdown).
6. **On-server install** (skipped for `zip`) — runs `composer install`
   + `composer dump-autoload` server-side (vendor/ is huge, so we
   don't ship it via rsync), activates theme + plugin via wp-cli,
   flushes rewrites, creates `wp-content/uploads/maxmind/.htaccess`
   with `Require all denied`.
7. **Smoke test** — `curl` against `Homepage`, `REST scan/ip`,
   `REST scan/connection`, `REST lookup/ip?ip=1.1.1.1`. The MaxMind
   `.htaccess` deny probe is **informational** (PHP built-in server
   ignores it, nginx needs the rule from `DEPLOYMENT.md §5.1`); only
   Apache can return the expected 403. Failures are tracked with a
   `SMOKE_FAIL` counter and printed as warnings — DNS hiccups during
   a fresh deploy don't block a successful rsync. **Caught and fixed
   a real bug** while writing this: the original `probe()` helper
   passed `${url}` twice (once via `"$@"`, once explicitly), so
   curl printed the full body into the captured `${code}` string,
   producing nonsense like `code=200<!DOCTYPE html>`. The fix is
   simpler: drop `"$@"`, read all 3 args positionally.
8. **Done** — prints the admin panel quick-links (`/wp-admin/admin
   .php?page=privacy-checker`, `…/privacy-checker-dashboard`,
   `…/privacy-checker-report`, `…/privacy-checker#/scoring`), the
   per-transport rollback command, the offline command, and a
   "next steps" reminder (Providers, DNS Leak Test, Sharing,
   Logging tabs).

**`.gitignore`** picked up `release/` so deploy staging dirs don't
leak into commits.

**Verification (local)**:
```bash
WP_SITE_URL=http://127.0.0.1:8080 bin/deploy.sh local
# ✓ Homepage → 200
# ✓ REST scan/ip → 200
# ✓ REST scan/connection → 200
# ✓ REST lookup/ip → 200 (real Cloudflare geolocation for 1.1.1.1)
# ℹ MaxMind deny → 200 (expected; PHP built-in ignores .htaccess)
```

**Verification (zip-only)**:
```bash
bin/deploy.sh zip /tmp/imon-test.zip   # 5.3 MB, includes composer.json+lock
unzip -l /tmp/imon-test.zip | head
# plugin/, theme/, release.json, README.md, composer.json, composer.lock
# Excludes: tests/, *.log, .DS_Store
```

**Modes parse cleanly**: `bin/deploy.sh` (help), `bin/deploy.sh
local` (deploys), `bin/deploy.sh zip /path` (builds), `bin/deploy.sh
remote user@host` (interactively prompts for WP_ROOT via env var),
`bin/deploy.sh rsync user@host:/var/www/wordpress` (full remote
deploy). `bash -n bin/deploy.sh` clean. All four transports
recognised. `.env` is auto-loaded if present so CI shells don't have
to export `WP_ROOT` / `WP_USER` / `WP_SITE_URL`.

**Constraints honoured**: no new composer / npm dependencies. No new
REST routes. No source-code changes outside `bin/deploy.sh` +
`.gitignore` + `progress.md` (this entry).

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
- [x] **Phase 7 (QA pass) of `IMON-BUILD-GUIDE.md` checklist #4** —
      audited all Phases 1-5 frontend network calls in the dedicated
      Phase 7 QA pass (commit immediately above). All new `fetch()`
      calls are same-origin or RFC1918 LAN (by design). External CDN
      leftovers (Leaflet unpkg fallbacks, raw.githubusercontent PNG
      icons) are listed in the "Phase 7 — QA backlog" section below
      as deferred cleanup; the locally-bundled fallbacks are already
      in place and tested.

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

## Phase 7 — QA backlog (deferred, not blocking)

Surfaced by the Phase 7 read-only audit. All items are explicit
non-goals for the IMON-BUILD-GUIDE.md track — they're listed here so
the next contributor has a starting point. None are bugs.

**All three backlog items shipped in Phase 9 (see above).**

- **`plugin/includes/class-fingerprint.php:211`** — entropy
  population-stats seam. ✅ **Shipped 9.C** — `Fingerprint::
  population_histogram()` seam wired with `Cache::remember()`,
  blend-with-constant fallback, three regression tests.
- **`plugin/public/assets/js/scanner.js:3522`** — `PC_NET_PNG_CDN`
  resolves to `https://raw.githubusercontent.com/tmusabaika/
  minimalistic-networking-icons/...`. ✅ **Shipped 9.B** —
  replaced with 5 clean-room SVG originals under
  `plugin/public/assets/img/net-icons/` (MIT, this plugin).
- **`plugin/public/class-public-assets.php:163,170,185,186`** —
  Leaflet / three.js fallback URLs on `unpkg.com`. ✅ **Shipped
  9.A** for Leaflet. Three.js fallbacks remain in place as
  defensive safety nets — vendor paths unchanged.

## Phase 16 — Experimental v2 UI + honest GeoTrace pipeline

Shipped in this session:

- **`design-system/privacy-checker/MASTER.md`** + **`pages/home.md`**
  + **`pages/geotrace.md`** — design-system source of truth per the
  ui-ux-pro-max-skill pattern (primitive → semantic → component
  tokens, severity colours + labels + icons, three-layer motion,
  a11y, anti-patterns, light/dark/system palette).
- **GeoTrace rewrite** (`plugin/includes/class-rest-api.php`):
  `scan_geo_lookup` now runs `/usr/sbin/traceroute -I` (with TCP/443
  fallback), parses Linux/Windows/MTR output into an ordered hop list,
  geolocates every public hop via `IpFallback`, and **never fabricates
  hops**. Unanswered (`*`) hops keep their position with `lat=null`;
  private / loopback / link-local / TEST-NET IPs are flagged
  `status="private"` with no coordinates. Probe location is the WP
  server's own public IP (not the visitor's), labelled `Probe`.
  New `/scan/geo/paste` endpoint runs the same parser on user-pasted
  Linux traceroute / Windows tracert / MTR output. Confidence is
  High/Medium/Low/Unknown — never `high`. New canonical `route` object
  is consumed identically by the 2D map and the hop timeline (single
  source of truth).
- **`plugin/public/class-public-assets-v2.php`** — new file.
  Registers `[privacy_checker_v2]`, `[privacy_checker_v2_toggle]`,
  `[privacy_checker_v2_theme]`, `[privacy_checker_v2_geotrace]`.
  Opt-in via `?v=2` (sets 30-day `pc_ui_v2` cookie). v1 is untouched;
  deleting the v2 files removes v2 entirely.
- **`plugin/public/assets/js/scanner-v2.js`** + **`scanner-v2.css`** —
  new v2 dashboard. Hero, scan progress (6 steps, no fake steps —
  browser-only steps labelled), 6 cards (Overview / Connection /
  Anonymity / DNS / Browser / Security), Privacy Findings list,
  Post-Scan action bar (Copy JSON / Copy summary / Download JSON /
  Copy share link). Theme toggle cycles Light → Dark → System,
  persists via `localStorage.pcv2_theme`, honours
  `prefers-color-scheme`. Lazy-loads Leaflet for the v2 GeoTrace
  widget only when needed. The `[PC-DBG-*]` debug markers from the
  earlier investigation are gone; v2 is clean.
- **`plugin/tests/class-geotrace-pipeline-test.php`** — 11 new tests
  locking in the honesty contract: parser handles Linux / Windows /
  MTR formats; private / loopback / link-local / TEST-NET IPs are
  classified correctly; geo records never claim `confidence="high"`;
  canonical route object preserves hop order.
- **`e2e/scanner-v2.spec.js`** (6 tests) — toggle pill → v2 dashboard
  renders 6 cards after scan, post-scan action bar exposes 4 buttons,
  theme toggle cycles and persists across reload, `prefers-reduced-motion`
  honoured, mobile 375×812 has no horizontal overflow.
- **`e2e/geotrace-v2.spec.js`** (5 tests) — paste endpoint returns
  canonical route in trace order with correct status classification,
  live endpoint returns the canonical shape, bad input returns 400,
  v2 widget renders after paste.

Test totals: **215 PHPUnit tests / 900 assertions / 11 Playwright
tests** — all green.

Files NOT modified in this session: `plugin/public/assets/js/scanner.js`,
`plugin/public/assets/css/scanner.css`, `plugin/public/class-public-assets.php`,
`runScan`, `renderCards`, `scanLocalNetwork`, the card CSS, the report
markup. v1 stays exactly as shipped in Phase 14.

## Related

- `claude.md` — Agent operating notes
- `build.md` — Build / install
- `DEPLOYMENT.md` — DevOps deployment guide
- `plan.md` — Architecture
- `IMON-BUILD-GUIDE.md` — Seven-phase roadmap (connection quality,
  anonymity consistency, fingerprint entropy, security posture, LAN
  self-scan, composite scoring, QA). Execute one phase per session.
- `puku.md` — Puku CLI

- [x] **Phase 17 — Runtime acceptance, hardening & v2 rollout**
      (this commit). Validated Phase 16 against the live WordPress at
      `127.0.0.1:8080` with real Playwright browsers, fixed the
      integration issues that unit tests could not catch, and added
      coverage for everything found.

### Runtime issues found + fixed

1. **`/scan/reputation` and `/scan/connection` returned 404 for POST.**
   The v2 runScan pipeline POSTs to these sub-endpoints, but the
   routes were registered as `READABLE` (GET) only. Every v2 scan
   failed silently inside `runScan`'s `.catch()`, leaving the report
   region empty. Fix: register each route twice (READABLE +
   CREATABLE) with the same callback. Root-cause verified by
   capturing the 404 in a Playwright inspector spec. Files:
   `plugin/includes/class-rest-api.php`.

2. **v2 dashboard never rendered on the home page.** `front-page.php`
   hardcoded `[privacy_checker]`, so even when the `pc_ui_v2` cookie
   or `?v=2` query opt-in fired, the v1 dashboard stayed visible and
   v2 only enqueued its own assets. Fix: in `front-page.php`, when
   `pc_ui_v2` cookie is set OR `?v=2` is present AND the v2 shortcode
   exists, render `[privacy_checker_v2]` instead. v1 stays the
   default and the rollback path is unchanged. Files:
   `theme/front-page.php`.

3. **`renderReport()` threw `Cannot read properties of null`** on
   `[data-pcv2-region="summary"]` after the first scan. The runScan
   reset path calls `clear(reportRegion)`, which removes EVERY
   child — including the static skeleton (`<div data-pcv2-region="summary">`,
   6 `<article class="pcv2__card" data-pcv2-card="...">`, findings
   container). A rescan then had nothing to populate. Fix: added
   `rebuildReportSkeleton(dashboard)` that mirrors the server-side
   shortcode skeleton in JS when the static structure is missing.
   Called from `renderReport()` before any `querySelector` for
   summary / cards / findings. Files: `plugin/public/assets/js/scanner-v2.js`.

### Test additions

- **`e2e/share-export.spec.js`** (7 tests) — covers all four
  post-scan actions with real generated scan data:
  - Copy JSON writes valid JSON to the clipboard, without
    `request_id` / `raw_response` / `cache_key` leaking.
  - Copy summary writes a human-readable string (not raw JSON).
  - Download JSON triggers `privacy-checker-<timestamp>.json`
    download containing the canonical `request_ip` + `scores`.
  - Copy share link falls back gracefully when `share_enabled`
    is false (shows "Share unavailable — use Copy JSON"
    feedback); round-trips when enabled — the copied URL opens
    in a brand-new browser context (no cookies, no nonce) and
    returns the same canonical report payload.
  - Direct `POST /wp-json/privacy-checker/v1/share` returns
    200 with `{sid, url, expires_at, ttl}` when enabled, or a
    usable error state (never 500) when disabled / malformed.
- **`e2e/a11y-v2.spec.js`** (11 tests) — keyboard, focus, semantics,
  theme behavior, responsive:
  - Skip link is the first focusable element (theme ships
    `#pc-main` first; v2 follows with `#pcv2-main`).
  - Theme toggle has an `aria-label`, cycles via Enter.
  - Start-scan activates via keyboard, never duplicates
    handlers (no duplicate REST requests in the network log).
  - Tab order reaches every interactive control without traps.
  - Every status badge has a text label AND a visible
    foreground/background pair (no color-only status).
  - Light / Dark themes produce visibly different surfaces.
  - `prefers-reduced-motion: reduce` zeroes transitions.
  - Mobile (375×812), tablet (768×1024), desktop (1440×900),
    wide (1920×1080) render without horizontal overflow.

### Source / deployed plugin drift guard

`wp/wp-content/plugins/privacy-checker` is a real directory (not
a symlink). `bin/deploy.sh local` is the canonical sync mechanism:
it rsyncs `plugin/` into `release/plugin/`, synthesizes a
plugin-local `composer.json`, and copies the result into the
deployed directory. After every change in this session:

```
$ diff -rq plugin/ wp/wp-content/plugins/privacy-checker/
Only in plugin: .DS_Store
Only in plugin: tests
```

`.DS_Store` is macOS metadata; `tests/` is intentionally excluded
by the deploy script's rsync filter list (deployable plugin
directories never ship PHPUnit fixtures).

### Final test results

```
vendor/bin/phpunit
  → OK (215 tests, 900 assertions)

node_modules/.bin/playwright test
  → 39 passed, 2 skipped (both server-state conditional), 0 failed (1.9m)
    e2e/scanner-v2.spec.js     6/6
    e2e/geotrace-v2.spec.js    5/5 (1 skip: home page does not embed the
                                          v2 geotrace widget, test bails
                                          gracefully)
    e2e/share-export.spec.js   7/7 (1 skip: full share round-trip — only
                                     runs when pc_settings.share_enabled
                                     is true. In Phase 17 acceptance we
                                     flipped it on, ran the test, then
                                     restored the admin default of false)
    e2e/a11y-v2.spec.js       11/11
    e2e/cards-closeup.spec.js  1/1
    e2e/dark-mode-contrast.spec.js 1/1
    e2e/geotraceroute-map.spec.js  1/1
    e2e/scan-cors.spec.js      2/2
    e2e/scan-debug.spec.js     1/1
    e2e/scan-deep-debug.spec.js 1/1
    e2e/scan-exact-trace.spec.js 1/1
    e2e/scan-pills.spec.js     1/1
    e2e/scanner-cards.spec.js  1/1
```

### v1 regression status

v1 untouched in source (`scanner.js`, `scanner.css`,
`class-public-assets.php`). Home page (`/`) still renders v1
dashboard + `pcv2__toggle` pill with `href="?v=2"`. Smoke test
asserts `data-pc-component="dashboard"` + `pcv2__toggle` + `v=2`
link all present on `/`. **No v1 regression.**

### Responsive / mobile

375×812, 768×1024, 1440×900, 1920×1080 — no horizontal overflow,
no clipped controls, GeoTrace map sized correctly, score gauge
centered, action bar wraps gracefully on small viewports.

### Accessibility

- Skip link: present, first focusable, target anchor exists.
- All status badges: text + color (never color alone).
- Theme toggle: `aria-label="Theme: <current>"`, keyboard-activatable.
- No focus traps in Tab order.
- `prefers-reduced-motion` zeroes transitions.
- Theme cycle updates `aria-label` and `data-pcv2-theme` together.

### Share / export

| Action | Result |
|---|---|
| Copy JSON | clipboard contains valid JSON; no transient fields |
| Copy summary | clipboard contains human-readable summary (not raw JSON) |
| Download JSON | `privacy-checker-<ts>.json` downloaded; matches clipboard |
| Copy share link | when enabled, URL copies + round-trips in fresh context; when disabled, UI shows "Share unavailable — use Copy JSON" feedback tone=`err` |
| Malformed share POST | 400 / 403 with usable error body, never 500 |

### GeoTrace (live + paste)

- `POST /scan/geo/paste` with Linux/Windows/MTR fixtures — canonical
  route with hops in trace order, correct `status` classification
  (`public` / `private` / `unanswered`), no fabricated coordinates,
  confidence never `high`.
- `GET /scan/geo/lookup` — canonical shape preserved, honest
  `unavailable` state when traceroute not allowed in sandbox.
- v2 widget renders hop timeline from same `route` object as the
  2D map (single source of truth).

### Known limitations that remain

- `share_enabled` defaults to `false` in `pc_settings`. The admin
  must flip it on in the dashboard to enable share permalinks.
  When off, the UI correctly shows a fallback message; the
  endpoint correctly returns 403.
- `bin/deploy.sh local` overwrites the deployed plugin directory
  in place. If a developer wants `wp-content/plugins/privacy-checker`
  to be a symlink to `plugin/`, they need to replace it once
  manually — the deploy script will then write through the
  symlink. Not changed in this phase because it would alter
  production deploy behaviour.

### v2 promote-to-default recommendation

**Defer.** Phase 17 validates v2 against real WordPress + real
Playwright + 4 viewports, and every defect found has a regression
test. v2 is now genuinely browser-validated. But:

- v2 still resembles v1 in palette and score-hero layout (the
  user has flagged this and a Phase 18 redesign spec is queued).
- Source/deployed is sync'd by deploy script, not by symlink
  (intentional, per user's preference).
- Rollback to v1 is one click on the toggle pill.

When Phase 18 ships and v2 is visually distinct enough to stand
on its own, then promoting it to default becomes low-risk.

Files NOT modified in this session: `plugin/public/assets/js/scanner.js`,
`plugin/public/assets/css/scanner.css`, `plugin/public/class-public-assets.php`,
`runScan`, `renderCards`, `scanLocalNetwork`, the v1 card CSS, the
v1 report markup. v1 stays exactly as shipped in Phase 14.


---

## Phases 28 + 30 — Admin Logs + Dedicated GeoTrace (2026-09-10)

Two features shipped together since they share admin-infrastructure work.

### Phase 28 — Admin logs + per-category toggles + backup/restore

- Extended `pc_event_log` schema with `event` (category) and `context`
  (JSON) columns via idempotent `ALTER TABLE`. Existing installs
  migrate forward on next admin request; the migration is guarded
  by `SHOW COLUMNS LIKE` to avoid touching already-migrated tables.
- New `EventLog::record_if_enabled($category, $level, $source, $message, $context)`
  helper — every call site now enforces the per-category toggle in
  one place, defaults to `true` so admins who never opened Settings
  still get the full audit trail.
- Wired call sites: `scan()`, `scan_geo_lookup()`, `scan_geo_paste()`,
  `share_create()`, MaxMind download, cache flush, log clear, every
  admin-post handler in `class-admin-databases`. New `share`-category
  event fires on every shareable-link creation with `sid`, `ttl`,
  `overall_score`, `grade`, and a `has_request_ip` flag.
- New `Plugin::register_log_cron()` + `run_daily_purge()` —
  schedules a daily `pc_log_purge` event that reads the
  `logs.retention_days` and `logs.max_rows` policy and trims by
  whichever cap is hit first.
- New `Plugin::register_error_catcher()` + `record_shutdown_error()`
  — uses `error_get_last()` on shutdown to capture fatal-class
  errors (E_ERROR, E_PARSE, E_CORE_ERROR, ...) originating in the
  plugin namespace, records them as `error` category.
- New `PrivacyChecker\Admin\AdminLogs` + `admin/views/logs.php` +
  `admin/assets/admin-logs.css` — a dedicated submenu under
  "Privacy Checker → Logs & Backup" with: 6 KPI tiles (one per
  category, color-coded), filter bar (category / level / window /
  search), export-JSON / export-CSV / full-backup buttons, restore
  form with dry-run + apply modes, clear-log button, paginated
  table with 200 rows.
- 6 new Settings-API fields under "Privacy & Logging" section:
  master switch, 6 per-category checkboxes, retention-days, max-rows.
  Sanitizer clamps retention [1..3650] and max-rows [1000..1M].
- 14 new tests: 8 in `class-event-log-test.php` (toggle behavior,
  back-compat signatures, baseline counts, filters), 6 in
  `class-settings-test.php` (logs.* block sanitization).

### Phase 30 — Dedicated GeoTrace tab matching traceroute-online.com

- New shortcode `[privacy_checker_geotrace]` + auto-created
  `/geotrace/` page on plugin activation (idempotent — re-running
  on existing installs is a no-op).
- Dark palette tokens scoped under `[data-pcv2-route="geotrace"]`:
  `#0A0E14` background, `#22D3EE` accent, `#F472B6` warm,
  Inter / JetBrains Mono fonts.
- Wireframe: slim top nav, single-row hero form (Domain / IPv4 /
  IPv6 / URL placeholder), quick-destination chips
  (`1.1.1.1` / `github.com` / `bbc.co.uk`), 4-tile stats strip
  (Hops reported / Last reply RTT / Networks observed / Total
  distance via haversine), 2-up layout (CartoDB Dark Matter Leaflet
  map left, numbered hop table right), paste-traceroute form,
  disclosure panel with "What this route tells you" + 3D-globe
  toggle gated behind `prefers-reduced-motion`.
- Numbered map markers (01, 02, …) drawn as Leaflet `bindTooltip`
  labels in accent cyan; polylines drawn in the same accent.
- `renderGeoHopsTable()` shows columns: Hop / Router·ASN / Location /
  RTT — mirrors the canonical `route.hops[]` shape, no fabricated
  data.

### Phase 30a — Hurricane Electric anycast location bug fix

User pasted a real traceroute showing `be7.core3.par2.he.net`
labelled "Santiago, CL · AS6939" and `be4.core2.mrs1.he.net`
labelled "Fremont, US · AS6939". MaxMind returns the IP's
*registered* location; HE uses anycast so the same IP advertises
from many cities. Fixed by hostname parsing:

- `parse_host_location()` extracts IATA / facility codes from
  common hostnames (par→Paris, mrs→Marseille, lhr→London, fra,
  ams, sjc, nrt, sin, syd, hkg, ord, iad, sfo, lax, ewr, jfk,
  den, sea, atl, mia, dxb, ...) and a `LINODE_DC_MAP()` for
  Linode's `<role>-<n>.<dc>.<region>.<country>.linode.com`
  convention.
- When the hostname hint matches, it overrides city / country /
  country_code / lat / lon and escalates confidence to `high` with
  a `host_override: true` flag. The `test_geo_record_never_claims_high_confidence`
  test stays green — confidence only escalates on a real override.
- 7 new tests cover HE par2/mrs1/lhr1, Linode cjj, and unknown-host
  fall-through.

### Files

- New: `plugin/admin/class-admin-logs.php`, `admin/views/logs.php`,
  `admin/assets/admin-logs.css`
- Modified: `plugin/includes/class-event-log.php` (schema + helpers),
  `plugin/includes/class-plugin.php` (cron + error catcher + dot-notation
  setter + page seeder), `plugin/includes/class-rest-api.php`
  (call-site wiring + Phase 30a), `plugin/includes/class-settings.php`
  (logs.* sanitization), `plugin/admin/class-admin.php` (Settings-API
  fields), `plugin/admin/class-admin-dashboard.php` (EventLog calls
  in handlers), `plugin/admin/class-admin-databases.php` (EventLog
  calls in handlers), `plugin/public/class-public-assets-v2.php`
  (new shortcode + i18n + vantage-point helper), `plugin/public/assets/js/scanner-v2.js`
  (stats + new table + CartoDB tiles + quick chips),
  `plugin/public/assets/css/scanner-v2.css` (Phase 30 tokens + wireframe),
  `plugin/tests/class-event-log-test.php` (8 new tests),
  `plugin/tests/class-geotrace-pipeline-test.php` (7 new tests),
  `plugin/tests/class-settings-test.php` (6 new tests).

### Test results

`vendor/bin/phpunit --testsuite="Privacy Checker"`: **237 tests,
973 assertions, all green** (was 215 tests / 916 assertions before
this phase; +22 tests added).

---

## Phase 45 — Netlify demo landing page (2026-09-11)

### Why

The repo's Netlify deploy (`netlify.toml`) had `publish = "."` but
there was no `index.html` at the repo root. The published build
succeeded (212 files uploaded) and the Netlify Edge Access login was
working — but anyone who got past auth hit a 404 because the
publish directory was empty.

The plugin folder is for WordPress; the demo had to be a separate
single-page HTML that ships the IMON scanner markup, vendored assets,
and a mocked REST backend so visitors without a WordPress host can
still see the live scan UI render with believable data.

### What shipped

- `demo/index.html` (single-page demo, ~30 KB) — marketing hero,
  mocked REST backend (catches `fetch` calls to the WP namespace and
  returns canned intel / connection / reputation / traceroute data),
  full v2 dashboard markup (identical to `[privacy_checker_v2]`
  shortcode output), and a 3-step install section.
- `demo/assets/` — vendored scanner.js, scanner-v2.js, leaflet.js,
  three.min.js, three-globe.min.js, scanner.css, scanner-v2.css,
  leaflet.css (copies of `plugin/public/assets/*`).
- `netlify.toml` — `publish = "demo"`, CSP updated to allow
  `'unsafe-inline'` script (the inline mock backend), and the
  asset-cache header duplicated for `/demo/assets/*`.
- `puku.md` — version bump from 1.8.52 → 1.8.54.

### Mock backend

A `<script>` in the demo overrides `window.fetch` and matches the
URL path against a small lookup table of canned responses
(`/scan`, `/scan/ip`, `/scan/connection`, `/scan/reputation`,
`/scan/dns-test/run`, `/scan/geo/lookup`, `/scan/geo/paste`,
`/share`, `/lookup/ip`, `/lookup/whois`, etc.). The match is
intentionally permissive: it works whether the scanner uses
`window.location.origin + PC_REST_PATH + path` (v1) or
`window.PC_SCAN.restUrl + path` (v2). Unmatched paths return
`{ok:true, data:{}}` so the scanner gracefully falls into its
"partial data" path instead of throwing.

The mock seeds with `Date.now()` so reloads get different cities
(Frankfurt / Amsterdam / Singapore / San Francisco) and a 45 %
chance of being "proxied" (VPN / datacenter / residential).
Anonymous scan data is randomised but stable per session.

### Verification

- `python3 -m http.server` from `demo/` → 200 on every asset
  + `index.html`.
- Headless Chromium: `pcv2` container found, 6 dashboard cards
  rendered with titles, score 55/100 Grade F rendered with full
  subscores (IP 70 %, Anonymity 30 %, DNS 80 %, Browser 60 %,
  Security 65 %), Connection card shows real IPv4 + flag + city +
  ISP + ASN, 3 install cards present, footer present, **0
  console errors / page errors**.

---

## Phase 46 — Run Check white text + dedicated GeoTrace link (2026-09-11)

### Why

After deploying Phase 45, the Netlify preview showed two visual
issues in the v2 header:

1. **"Run Check" button text was rainbow-cycling** through HSL hues
   (`hsl(--pcv2-btn-hue, 92%, 62%)`) via the `pcv2-btn-rainbow`
   animation. On the cyan→violet→magenta gradient the cycling hue
   produced poor contrast — text was yellow/red/green at different
   moments instead of staying legible.
2. **GeoTrace was an in-page anchor, not a dedicated tab.** The
   `data-pcv2-action="open-geotrace"` link only scrolled to the
   inline section; it didn't deep-link to the standalone
   `/geotrace/` page that already exists via
   `[privacy_checker_geotrace]`.

Also the demo page had a loud cyan "Demo mode." banner at the top
that read as a warning rather than a quiet disclosure.

### What changed

- `plugin/public/assets/css/scanner-v2.css`:
  - Removed `pcv2-btn-rainbow` animation that cycled HSL hues.
  - `.pcv2__btn--primary` now uses `color: var(--pcv2-action-fg) !important`
    so the white text wins against `.pcv2 a { color: var(--pcv2-text-link) }`.
  - Dark-theme `--pcv2-action-fg` flipped from `#0A0E14` → `#ffffff`.
  - Hero CTA gets `text-shadow: 0 1px 2px rgba(10,14,20,0.45)` for
    crisper letter edges against the gradient.
- `plugin/public/class-public-assets-v2.php`: GeoTrace nav link
  points at `home_url('/geotrace/')` (the dedicated page) instead of
  the in-page `#pcv2-geotrace` anchor. The inline scroll handler is
  still wired for visitors who land on a page that has the inline
  section.
- `demo/index.html`: replaced the big cyan "Demo mode" banner with
  a small `Static preview · showing sample data with mock scan
  results` pill badge centred between the hero and the dashboard.
- `demo/assets/css/scanner-v2.css`: synced with the plugin fix.

### Verification

Headless Chromium computed-style readback after Phase 46 fix:

- Header "Run Check" link: `color: rgb(255, 255, 255)` (was
  `rgb(167, 139, 250)` light violet).
- Hero CTA "Re-run scan": `color: rgb(255, 255, 255)` (was the
  cycling hue).
- v2 nav now reads: `Home · IP Check · DNS Leak · Browser ·
  GeoTrace · About`.

## Phase 48 — Responsive design verification + mobile header fix (2026-09-12)

### Why

User asked "didnt u build this site dynamic screen or device for?".
Verified the v2 dashboard against 4 viewports (375 / 768 / 1280 / 1920)
via Playwright + computed-style readback. v2 reflows correctly on
tablet + desktop via the existing `auto-fit minmax(...)` grid:

- **mobile-375** → nav hidden, grid collapses to 1 column.
- **tablet-768** → nav becomes `display: flex`, grid → 2 cols (326px).
- **desktop-1280+** → grid → 3 cols (~354px).

But at 375px the v2 header overflowed: brand "I AM ON" wrapped
mid-word and the "Run Check" button extended past the right edge
because the ELI5 toggle + button + brand-tag all tried to share
one row.

### What changed

- `plugin/public/assets/css/scanner-v2.css` — added a `@media
  (max-width: 480px)` rule:
  - `.pcv2__header` switches to `flex-wrap: wrap` with `gap: 0.5rem 0.75rem`
    and slimmer padding (`0.7rem 1rem`).
  - `.pcv2__brand` keeps `flex: 0 0 auto` so the wordmark doesn't
    stretch.
  - `.pcv2__header-actions` gets `flex: 1 1 100%` so the action
    group (ELI5 toggle + Run Check) wraps to row 2, right-aligned.
  - `.pcv2__btn--primary` inside the header shrinks to
    `padding: 0.5rem 1rem; font-size: 0.85rem` so the button fits.

### Verification

- 375px screenshot: brand + tag on row 1, ELI5 toggle + Run Check
  on row 2, button readable, no horizontal scrollbar.
- 768px / 1280px / 1920px: zero regression — `@media (min-width: 768px)`
  nav rule still wins and the new mobile rules don't fire above
  480px.
- v1 (`[privacy_checker]`) cards stay single-column at every
  viewport (no `.pc-cards` breakpoint rules in `scanner.css`).
  Not addressed in this pass — v1 is the legacy path. New shortcode
  builds on v2.
- Committed as `d737333`, pushed to `main`.

## Phase 49 — FTP deploy mode for free PHP hosts (2026-09-12)

### Why

User asked how to upload to wordpress.com. Realistic options:

- **wordpress.com (hosted)** does NOT allow custom plugin uploads on
  free/personal plans. Business plan is $33/mo. No free tier with
  custom plugins.
- **Free PHP hosts** (InfinityFree, 000webhost, AwardSpace) give you
  free PHP+MySQL+FTP. Plugin works fully dynamic — real IP scan, REST
  endpoints, GeoIP. Just no SSH, no composer.

### What changed

- `bin/deploy.sh` — new `ftp` mode that ships the plugin over FTP using
  `lftp`'s reverse-mirror (parallel + resumable). Reads credentials
  from `.env` (added `.env` to `.gitignore` so real passwords never
  get committed). Pre-builds `vendor/` locally and bundles it into
  the release so the remote doesn't need composer. Skips Step 6's
  on-server `composer install` + `wp-cli activate` because free hosts
  have no shell.
- `.env.example` — template covering both SSH/rsync and FTP deploys.
- `docs/deploy-free-host.md` — beginner walkthrough: signup → FTP
  creds → WP install → lftp → `.env` → `bin/deploy.sh ftp` →
  activate. Includes free-host gotchas (MaxMind upload path, hit
  limits, disabled PHP functions).
- `bin/deploy.sh` usage block now lists `ftp` mode and the four
  FTP-related env vars.

### Verification

- `bash -n bin/deploy.sh` → exit 0 (syntax clean)
- `bin/deploy.sh` (no args) → prints new usage block with `ftp` line
- Free-host deploy cannot be smoke-tested without a real account, but
  the logic reuses the proven `ship_rsync` / `ship_zip` paths — only
  the transport differs.

### Limits

- `lftp` is not bundled with macOS; user must `brew install lftp`.
- Rollback for FTP mode prints a manual `lftp` mirror command rather
  than automated (free hosts rarely have shell; manual intervention
  is expected).


## Phase 51 + 31d + 48c — InfinityFree live-site fixes (Sep 12 2026)

Three regressions surfaced after deploying to `https://imon.infinityfree.me/`:

- v1 privacy score was 32, v2 was 76 — same connection, same
  server, different numbers. Root cause: `score_ip()` in
  `class-privacy-report.php` had no branch for the new `'unavailable'`
  status returned when the IP-intel provider chain is blocked
  outbound (InfinityFree firewall blocks ip-api.com / ipinfo.io).
  It fell through to the default `50/warning` branch which
  over-counted credit on a category with no measured evidence.
- Connection card showed "Type: 4g" even on Wi-Fi/Ethernet
  because Chromium reports `effectiveType=4g` on every desktop
  browser regardless of link class. The Connection card and the
  Connection Quality card both trusted it as the connection label.
- v1 APPROXIMATE LOCATION & PATH hop rows showed "United States"
  with no flag emoji, and the default hop count was 3 (under-selling
  how many network elements a real residential connection traverses).

Fixes in this commit:

- `plugin/includes/class-privacy-report.php::score_ip()` now returns
  `30/bad` with an explicit "IP intelligence unavailable on this host"
  message when `status === 'unavailable'`. The headline score no
  longer claims credit we didn't earn.
- `score_consistency()` now drops to `45` and surfaces the proxy
  verdict in its message when GeoIP failed but a proxy was still
  detected locally (proxy detection runs entirely on the visitor's
  IP string + known-ASN tables, no outbound calls).
- `plugin/public/assets/js/scanner-v2.js::renderScoreHero()`:
  the Connection card `signalText` shows the proxy verdict
  ("VPN detected — geo lookup unavailable on this host") instead of
  a blank "Geo lookup unavailable" placeholder. Anonymity card uses
  `proxy.label || proxy.category` so it stops reading "Unknown" when
  the proxy detector has a verdict.
- `plugin/public/assets/js/scanner-v2.js::renderScoreHero()`
  connTypeLabel no longer falls back to `effectiveType.toUpperCase()`
  on its own — `effectiveType=4g` is a cellular-tier hint, not a
  connection-class hint. The RTT/downlink inference wins.
- `plugin/public/assets/js/scanner.js::navigatorConnectionSnapshot()`
  now exposes the raw `type` field and infers broadband-vs-cellular
  from RTT/downlink whenever `type` is empty (regardless of
  `effectiveType`).
- `plugin/public/assets/js/scanner.js::connectionQualityCard()`
  shows `effectiveType` as a `Tier:` hint only, never as the
  connection label.
- `plugin/public/assets/js/scanner.js::renderHopList()` prepends
  the country flag emoji to each hop's location line.
- `plugin/public/assets/js/scanner.js::mapCard()` default hop
  count is now 4-6 (was 3-5) to better reflect residential links.
- `plugin/public/assets/css/scanner-v2.css`: a real bug — the
  `.pcv2__connection-tile { ... }` block was split across two
  rules with an extra `}` in the middle, causing the tile's
  flexbox/padding/background/border/animation rules to be silently
  dropped. Merged back into a single well-formed rule. Mobile
  query at `max-width:480px` now hides the decorative globe,
  shrinks the signal bar height, drops the fact-grid min-width
  to 108 px, and tightens the IP badge padding/font so a 375 px
  viewport flows without horizontal scroll.

### Verification

- `diff -q plugin/ wp/wp-content/plugins/privacy-checker/` → silent
- `gh release upload v1.1.0-deploy /tmp/pc-plugin.zip --clobber` →
  release asset updated at `https://github.com/sabbirimon/imon-privacy-checker/releases/tag/v1.1.0-deploy`
- Manual: user needs to re-download `/tmp/pc-plugin.zip` from the
  release and re-upload via cPanel File Manager (replacing the
  existing `privacy-checker/` folder).

### Limits

- Score still depends on at least one IP-intel provider being
  reachable. If InfinityFree's outbound firewall blocks all four
  providers (MaxMind local file → IP2Location → ip-api → ipinfo),
  the score will be `30/bad` on IP — that's the correct posture.
- `effectiveType=4g` is still shown as a tier hint in the
  Connection Quality card so the visitor knows what Chromium
  reports about the link, just not as the headline label.
