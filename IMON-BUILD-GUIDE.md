# IMON — Full Build Guide: Connection & Anonymity Self-Test Report

**How to use this document:** each phase below is self-contained. Paste the "Prompt to give the assistant" block into your AI coding assistant (Claude in your IDE, Claude Code, whatever you're using — there's no model literally called "Claude 4.8 Opus"; the current lineup is Sonnet 5 / Opus 5 / Haiku 4.5, so just use whichever Claude model you have configured) as its own turn, let it finish, review the diff, then move to the next phase. Don't paste all phases at once — each one assumes the previous phase's files already exist.

Every prompt below is grounded in your actual repo (`sabbirimon/imon-privacy-checker`) — real class names, real file paths, real existing methods — so the assistant extends what's there instead of reinventing it.

---

## Phase 0 — Orientation (paste this first, every session)

Paste this at the start of any session before phase-specific prompts, so the assistant doesn't guess at conventions:

```
You're working in the IMON privacy-checker WordPress plugin
(namespace PrivacyChecker, PHP 8+, declare(strict_types=1) in every
file). Read these files first before writing anything:

- plugin/includes/class-scanner-orchestrator.php   (ties all modules into one report)
- plugin/includes/class-rest-api.php                (all REST routes, namespace pc/v1 or similar — check the $ns var)
- plugin/includes/class-fingerprint.php             (current fingerprint module — UA parsing + a coarse visibility estimate only)
- plugin/includes/class-proxy-detector.php          (VPN/proxy/Tor classification from IP intel)
- plugin/includes/class-network-probe.php           (DoH probes, TCP latency, port probes, inferred path hops)
- plugin/public/assets/js/scanner.js                (single frontend file, ~4800 lines, modules commented as
  "state, api, fingerprint-collector, webrtc, ui/*, scanner" — collectFingerprint() is around line 181)
- plugin/public/class-public-assets.php             (script/style enqueueing, wp_localize_script('pc-scanner', 'PC_SCAN', ...))

Conventions to follow:
- All PHP classes are `final class X` under namespace PrivacyChecker, one class per file, filename class-x.php.
- REST handlers live in class-rest-api.php and register via register_rest_route($ns, '/path', [...]).
- Provider-pattern classes (swappable data sources) live under plugin/includes/providers/ and implement an
  interface from plugin/includes/interfaces/ — follow this pattern for any new external data source.
- Frontend has no build step / no framework — it's one big vanilla-JS file. Don't introduce a bundler or a
  new dependency without saying so first.
- Every new feature must work with JS disabled degrading gracefully or at minimum fail closed (show "unable
  to determine" rather than a broken UI).
- This is a *user-facing self-test tool*: the visitor runs it on their own device with their own knowledge.
  Nothing here should silently collect data across sessions to build a persistent cross-visit identity — the
  whole point is transparency. Every new signal collected must be displayed back to the user in the report,
  not just logged server-side.
```

---

## Phase 1 — Connection quality module

**Goal:** latency/jitter, IPv4-vs-IPv6 reachability, downlink estimate, DNS resolution timing — surfaced as one panel.

**Files touched:** `plugin/includes/class-network-probe.php` (extend), new REST route in `class-rest-api.php`, new UI card in `scanner.js`.

**Prompt to give the assistant:**
```
Add a "connection quality" check to NetworkProbe (plugin/includes/class-network-probe.php).

1. Add a static method `latency_probe(): array` that:
   - Times 3 sequential requests from the browser to a new REST endpoint (see step 3) and returns
     min/max/avg/jitter in ms. Do this measurement CLIENT-SIDE in scanner.js using performance.now()
     around fetch() calls to the endpoint — the server just needs to respond fast with a trivial payload
     (a timestamp + nothing else). Don't try to measure latency server-side; that only measures the
     server's view of itself.
2. Add a static method `ipv6_reachable(): array` that reports whether the CURRENT detected connection
   (from IpDetector::detect(), already used in ScannerOrchestrator::scan()) is IPv4, IPv6, or dual-stack,
   reusing $detected['ipv4'] / $detected['ipv6'] — don't re-implement IP detection, this data already exists
   in the scan() flow.
3. Add a lightweight REST route `/scan/connection/echo` (see the existing `/scan/ping` route around line
   202 of class-rest-api.php for the pattern) that just returns `{ "t": <server microtime> }` with
   aggressive no-cache headers — used by the client-side latency probe above. Use a dedicated
   `connection_echo` rate-limit bucket (`rate_limit_connection_echo`, default 60/min) so the 3 trips per
   report don't starve the TCP-connect `ping` bucket.
4. In scanner.js, add a new module section (follow the existing module-comment convention at the top of the
   file) that:
   - Fires 3 requests to /scan/connection/echo, computes min/max/avg/jitter client-side (jitter =
     `max - min`, the simplest honest spread for n=3).
   - Reads navigator.connection?.downlink and navigator.connection?.effectiveType if present (Network
     Information API — Chrome/Android only), and explicitly shows "Not available in this browser" rather
     than a blank/zero value in Safari/Firefox.
   - Renders a new report card following the same card-building pattern as fingerprintTableCard()
     (~line 813) — same DOM-building helpers (el(), formatRow()), same card CSS classes.
5. Wire the new card into the existing report layout in scanner.js's report-rendering function, and add the
   new i18n strings to the PC_SCAN localize block in class-public-assets.php following the existing
   i18n array style (see 'detectIp', 'detectScore', etc.).

Do not add any new npm/composer dependency for this. Show me the diff before assuming it's done.
```

---

## Phase 2 — Deep anonymity / proxy / VPN consistency scoring

**Goal:** go beyond ProxyDetector's IP-based classification and cross-check IP-geo vs. timezone vs. WebRTC vs. DNS-resolver origin, producing one coherent "anonymity consistency" score instead of four disconnected pages.

**Files touched:** `plugin/includes/class-proxy-detector.php` (extend), `plugin/includes/class-webrtc.php` (extend), `plugin/includes/class-dns-test.php` (extend), `plugin/includes/class-scanner-orchestrator.php` (wire together), `scanner.js`.

**Prompt to give the assistant:**
```
I want a new "anonymity consistency" score that cross-references signals that already exist separately in
this codebase, rather than adding a new fingerprinting technique. Read class-proxy-detector.php,
class-webrtc.php, and class-dns-test.php fully before writing anything — all three already do part of what
I need; I just need them correlated.

1. Add a new final class `plugin/includes/class-anonymity-scorer.php` (namespace PrivacyChecker) with a
   single static method:

   public static function score( array $ip_intel, array $webrtc_result, array $dns_test_result,
                                  string $browser_timezone ): array

   It should return:
   {
     "consistent": bool,
     "score": int (0-100, 100 = fully consistent / no leak signals),
     "mismatches": [ { "signal": string, "detail": string, "severity": "low"|"medium"|"high" } ],
     "summary": string  // one human-readable sentence
   }

   Checks to implement inside it (pure functions, no I/O — this class only correlates data already passed
   in, following the existing pattern where ProxyDetector::classify() also takes pre-fetched intel rather
   than making its own network calls):

   a) IP-geo country/timezone mismatch: compare $ip_intel['timezone'] (already present in the IP intel
      shape used elsewhere — check IpFallback::lookup()'s return shape) against $browser_timezone (passed
      from the client via Intl.DateTimeFormat().resolvedOptions().timeZone). Flag "medium" severity
      mismatch if they don't match AND aren't at least plausible for the same UTC offset.

   b) WebRTC leak: if $webrtc_result contains a local/public IP that does NOT match the server-detected
      connection IP used for $ip_intel, flag "high" severity — this is the strongest signal, weight it
      heaviest in the score.

   c) DNS resolver mismatch: if $dns_test_result's resolving-server IP's ASN/org doesn't match $ip_intel's
      ASN/org (i.e. DNS queries are exiting through a different network than the visible IP), flag "high"
      severity — this indicates DNS leaking outside a VPN tunnel.

   d) Existing ProxyDetector confidence: fold in ProxyDetector::classify_with_lists()'s existing
      'confidence'/'score' output as one input to the composite, don't replace it.

2. In ScannerOrchestrator::scan() (around where $connection['proxy'] is already set, look for the
   ProxyDetector::classify_with_lists() call), add a call to AnonymityScorer::score() once webrtc_result,
   dns_test_result, and browser_timezone are available in the request, and attach the result as
   $connection['anonymity'].

3. Client-side: scanner.js already collects fingerprint signals in collectFingerprint() (~line 181) — add
   Intl.DateTimeFormat().resolvedOptions().timeZone to that same payload object, don't create a second
   collection function.

4. Render one new report card (reuse fingerprintTableCard()'s structure as a template) titled "Anonymity
   Consistency" showing the score, a colored severity badge per mismatch, and the plain-language summary —
   this replaces having VPN detection, WebRTC results, and DNS leak results as three unrelated sections; it
   should sit ABOVE those three existing sections as the "headline," with the existing sections kept as the
   detail underneath.

Show me the AnonymityScorer class in full before touching the orchestrator or the JS.
```

---

## Phase 3 — Advanced fingerprint exposure module

**Goal:** replace the current boolean-only `collectFingerprint()` (webgl/canvas/audio presence flags only, no actual fingerprinting) with real canvas/WebGL/audio hash computation, font enumeration, and a per-signal rarity/entropy score — the EFF Cover-Your-Tracks style report.

**Files touched:** `scanner.js` (`collectFingerprint()`, new hashing helpers), `plugin/includes/class-fingerprint.php` (extend `estimate_visibility()`), possibly a new small table in `plugin/includes/class-cache.php`-backed storage for population rarity stats.

**Prompt to give the assistant:**
```
Read plugin/includes/class-fingerprint.php in full — estimate_visibility() currently scores based on coarse
capability flags (webgl: true/false, canvas: true/false, audio: true/false) supplied by
scanner.js's collectFingerprint() (~line 181). I want to replace the coarse flags with real fingerprint
hashes and a rarity-based score, while keeping the function signature/report shape backward compatible
where reasonably possible (report.fingerprint.exposure_score is read elsewhere in scanner.js, e.g. around
line 834 — don't break that).

1. In scanner.js, extend collectFingerprint() to compute (add each as a new key, keep the existing keys):
   - canvasHash: render fixed text + shapes to an offscreen canvas, toDataURL(), hash it (use a simple
     non-cryptographic hash like a 32-bit FNV-1a over the string — no external crypto library needed).
   - webglRenderer: read UNMASKED_RENDERER_WEBGL / UNMASKED_VENDOR_WEBGL via the WEBGL_debug_renderer_info
     extension if available; explicitly set this to the string "masked-by-browser" (not null/undefined) if
     the extension is blocked, and say so distinctly in the UI later — a masked value is itself informative
     (means the browser is doing anti-fingerprinting) and should count as a GOOD sign in the score, not a
     missing-data error.
   - audioHash: run a short OfflineAudioContext render (oscillator -> dynamicsCompressor -> destination),
     hash the resulting Float32Array output the same way as canvasHash.
   - fontList: test a fixed list of ~40 common font names (system + Adobe + Google Fonts) by measuring
     rendered text width against a fallback font at a few font sizes; return the array of fonts that appear
     to be installed.
   - Keep the existing webgl/canvas/audio booleans as-is for backward compatibility with the existing report
     card, just add the new keys alongside them.

2. In class-fingerprint.php, add a new static method:
     public static function entropy_estimate( array $signals ): array
   For now (no real population database yet — flag this as a known limitation in a code comment), compute a
   *rough* entropy proxy from cardinality assumptions per signal type (canvas/audio hash: assume high
   entropy ~15-20 bits if present; webglRenderer: ~5-7 bits; fontList: ~1 bit per font present beyond a
   common baseline set; timezone/language: ~3-5 bits) and sum them into a 0-100 "uniqueness score" plus a
   human sentence like "Your browser's fingerprint is likely unique among roughly 1 in N visitors based on
   the signals available." Be explicit in a code comment that this is an ESTIMATE, not measured against real
   traffic, and leave a TODO for wiring in actual population stats later (e.g. via Cache class storing a
   rolling histogram per signal — don't build that persistence layer yet, just leave the seam).

3. Update estimate_visibility() to fold in entropy_estimate()'s score rather than the old boolean-only
   scoring, but keep returning the same top-level keys the JS already reads (exposure_score, visibility
   label) so renderFingerprintResult() (~line 1639) doesn't need a rewrite, only new rows added.

4. Add new rows to the fingerprint report card for: WebGL renderer (with "browser is blocking this — good
   sign" messaging when masked), canvas/audio hash (show the hash itself, short, so the user can literally
   see "this is your ID"), and installed-font count with a "show full list" expandable section.

This is the biggest phase — do it in this order and pause for my review after step 1 (the JS collection
code) before touching the PHP scoring.
```

---

## Phase 4 — Security posture panel

**Goal:** TLS version/cipher actually negotiated, browser EOL/known-CVE-range warning, HSTS check — using what already exists (`class-security-headers.php`) plus new pieces.

**Files touched:** `plugin/includes/class-security-headers.php` (extend), new `plugin/includes/class-browser-versions.php` (small static lookup table), `class-rest-api.php`, `scanner.js`.

**Prompt to give the assistant:**
```
Read plugin/includes/class-security-headers.php fully first — it already checks response headers
(presumably HSTS, CSP, X-Frame-Options etc. — confirm what it currently covers before assuming gaps).

1. Add a static method to SecurityHeaders (or a new small class if SecurityHeaders is scoped to outbound
   response headers only and this is a different concern — your call after reading it) that reports the
   TLS protocol version and cipher suite negotiated for the CURRENT request, using
   $_SERVER['SSL_PROTOCOL'] / $_SERVER['SSL_CIPHER'] (Apache/mod_ssl) with a documented fallback path for
   nginx (typically proxied via a custom header your server config would need to set — add a code comment
   explaining the site admin may need to add `fastcgi_param HTTPS_TLS_VERSION $ssl_protocol;` or similar,
   don't assume it's always available). If neither is present, return "unknown" explicitly, don't guess.

2. Add plugin/includes/class-browser-versions.php: a small final class with a hardcoded array constant
   mapping browser-family + major-version ranges to an "outdated"/"current"/"very outdated" status
   (Chrome, Firefox, Safari, Edge — top 4 only for now). Add a comment noting this table needs periodic
   manual updates and isn't meant to be exhaustive. Static method:
     public static function check( string $browser_name, int $major_version ): array
   returning { status, message }. Reuse Fingerprint::parse_user_agent()'s existing output for browser
   name/version — don't re-parse the UA string a second way.

3. Wire both into ScannerOrchestrator::scan() as $connection['security_posture'] = [ 'tls' => ..., 'browser'
   => ... ], following the existing pattern of nesting sub-reports under $connection.

4. New report card in scanner.js: TLS version/cipher, browser status, plus the EXISTING security-headers
   data (don't duplicate what SecurityHeaders already surfaces — check the current UI first, this phase
   should ADD the two new items to whatever card already displays header results, not create a redundant
   second security card).
```

---

## Phase 5 — Local network exposure (LAN self-scan)

**Goal:** ShieldsUp-style check of whether the user's own router/LAN devices are reachable from their browser — scoped strictly to their own private-IP ranges.

**Files touched:** pure client-side, `scanner.js` only, plus one new REST-adjacent i18n block.

**Prompt to give the assistant:**
```
Add a "local network exposure" check to scanner.js, pure client-side, no new PHP needed.

1. New function `scanLocalNetwork()` that attempts fetch() with a short timeout (~800ms, AbortController)
   against a small fixed list of common LAN gateway addresses (192.168.0.1, 192.168.1.1, 10.0.0.1, 10.0.1.1)
   on common admin ports (80, 443, 8080) — report which ones responded (even a CORS-blocked response still
   proves something is listening; catch the error type and distinguish "connection refused/timeout" from
   "something answered but blocked by CORS", since both are informative differently).
2. IMPORTANT scope limit: hardcode the probe list to RFC1918 private ranges only (192.168.x.x, 10.x.x.x,
   172.16-31.x.x common gateway addresses). Do NOT make this configurable or accept a user-supplied target —
   this must only ever probe the visitor's own likely local network, never an arbitrary host. Add a code
   comment explaining why this scope limit exists (this is a self-test tool, not a network scanner-as-a-
   service).
3. Render a report card titled "Local Network Exposure" with copy that explicitly says "This tests devices
   on YOUR OWN local network, from YOUR OWN browser — not external scanning" so users don't misread it as
   testing something remote.
4. Add the i18n strings to PC_SCAN's localize block for this card's labels.

Keep this phase small and self-contained — no PHP changes needed.
```

---

## Phase 6 — Composite report assembly

**Goal:** tie every module above into one overall score with sensible weighting, replacing/extending whatever `class-privacy-report.php` currently assembles.

**Files touched:** `plugin/includes/class-privacy-report.php`.

**Prompt to give the assistant:**
```
Read plugin/includes/class-privacy-report.php in full (642 lines — it's the biggest report-assembly class,
so there's likely already a scoring/weighting scheme in here; find it before adding a parallel one).

Integrate the new sub-reports from phases 1-5 (connection quality, anonymity consistency, fingerprint
entropy, security posture, local network exposure) into whatever composite scoring function already exists
here. Weight them roughly:
  - Anonymity consistency (phase 2): highest weight — this is the "are you actually as private as you think"
    signal.
  - Security posture (phase 4): second-highest — outdated TLS/browser is a real risk.
  - Fingerprint exposure (phase 3): informational weight, lower — most users can't fully fix this, so don't
    let a high fingerprint entropy score tank an otherwise-good report as much as an actual leak does.
  - Connection quality (phase 1) and local network exposure (phase 5): informational, not weighted into the
    anonymity/privacy score at all — surface separately as "connection health" rather than folding into
    "privacy score", since a slow connection isn't a privacy problem.

Show me the current scoring function's weights before changing anything, and propose the new weight split
as a comment for my approval before implementing.
```

---

## Phase 7 — QA pass

**Prompt to give the assistant:**
```
Do a review pass across everything added in phases 1-6:
1. Confirm every new client-collected signal is actually rendered back to the user somewhere in the report
   — nothing should be collected and only logged/scored without being shown.
2. Confirm every new PHP method has the same strict_types + return-type-hint style as the rest of the
   codebase.
3. Confirm nothing new silently fails into a broken UI state — every new check should degrade to an
   "unable to determine" message rather than throwing to the console.
4. Check that no new external network call was introduced without checking for a locally-bundled fallback
   first, consistent with how three.min.js/three-globe.min.js and the globe textures were handled.
5. List any TODOs left in code comments (e.g. the entropy_estimate population-stats seam from phase 3) as a
   final summary so I have a backlog.
```

---

## Notes for you, not for the assistant

- Do these roughly in order 1 → 2 → 3 → 4 → 5 → 6 → 7. Phase 2 depends on phase 1's client timezone
  collection point existing in `collectFingerprint()`, and phase 6 depends on everything before it.
- Phase 3 is the largest single chunk of work — consider splitting it into two separate assistant sessions
  (JS collection, then PHP scoring) exactly as the prompt suggests pausing for.
- None of this needs the traceroute/globe work from earlier — that's a separate feature track and can be
  done in parallel or after, in any order relative to this guide.
