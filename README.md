# IMON (I AM ON)

Production-ready WordPress privacy/anonymity diagnostic platform, branded as
**IMON — I AM ON**. Originally
authored scaffold inspired by Whoer.net — but every byte of code, design, and
branding is original. Inspects the visitor's IP, geolocation, ISP, ASN, browser
fingerprint surface, WebRTC leaks, and IP reputation, then renders an honest
visibility score plus per-card "what we saw" + "what we couldn't tell" rows.

## Highlights

- **IP intelligence** with a transparent fallback chain. The first provider
  that returns useful data wins; later providers are only consulted on miss
  or error.
  - **MaxMind GeoLite2 (local `.mmdb`)** — fastest, fully offline, ships with
    City / ASN / Country / Anonymous-IP databases if you drop them under
    `wp-content/uploads/maxmind/`. CC BY-SA 4.0 attribution shown in the admin
    footer.
  - **ip-api.com (free, no key)** — public HTTP API, 45 req/min per source IP,
    used as the default second hop so visitors get a real lookup even when
    the admin hasn't set up MaxMind. Toggle in Settings.
  - **ipinfo.io / ipapi.com / Spamhaus / Cloudflare heuristics / Tor exit
    list** — wired in but disabled by default; enable per provider.
  - **Mock** — last-resort dev provider, always returns realistic shape.
- **Browser fingerprinting** — UA parsing, language/timezone canvas-font probe
  via the public scan page (no Canvas / WebGL pixel reads, no audio context
  sampling — only what the website already sees).
- **WebRTC summary** — categorizes the public IP / candidate pair as
  "consistent with your advertised IP" / "leaks a different IP" /
  "no candidate".
- **IP reputation** — Spamhaus DROP/EDROP lookup, Iphub scoring, and a Cloudflare
  heuristics provider. Cached for 6 hours per IP.
- **WHOIS / RDAP** — server-side RDAP query for domains and ASNs, with a mock
  fallback when RDAP is unreachable.
- **Security headers probe** — POSTs a URL to the server which performs the
  fetch (so the user's browser is never used for the request, and SSRF guards
  reject private/local IPs).
- **Honest "Not configured" states** — kept for probes that genuinely can't
  be done from a server-only context. Where real probes ARE possible, the
  plugin ships them:
  - **Real DNS leak test** — DNS-over-HTTPS fan-out across Cloudflare,
    Google, Quad9 with per-resolver latency + answer IP, leak score,
    consistency check.
  - **TCP-connect ping / latency** — no ICMP, no shell exec; `stream_socket_client`
    with an explicit finite timeout. Default targets: cloudflare.com:443,
    google.com:443, example.com:443.
  - **TCP port scanner** — opens / closed / filtered detection. **Self-only by
    default** (visitor's own WP server). Admin allowlist of IP / CIDR /
    hostname to extend. SSH (22), SMTP (25), RDP (3389) always blocked.
  - **Proxy / VPN / Tor / Hosting detection** — ASN catalog + organization
    substring matching across major VPN providers (Mullvad, ProtonVPN,
    NordVPN, Surfshark, ExpressVPN, …), hyperscalers (AWS, GCP, Azure,
    Cloudflare), hosting providers (Hetzner, OVH, DigitalOcean, Vultr,
    Linode, ColoCrossing, Psychz, …), and Tor exit relays. Confidence levels:
    high (exact ASN), medium (org token), low (generic).
- **Anonymity Tips** — 15 prioritized tips across 5 tiers covering VPN
  selection, browser hardening, Tor, anti-detect browsers (AdsPower,
  GoLogin, Multilogin), residential proxies, email aliases (SimpleLogin,
  anonaddy), virtual phone numbers (JMP.chat, MySudo), privacy payments,
  WebRTC, container tabs, dedicated OS (Tails / Whonix / Qubes), and
  stylometric hygiene.
- **Detailed Privacy Report** — Whoer-style breakdown: overall percentage,
  letter grade (A-F), confidence (high/medium/low), per-category scores
  with weight, status badges, and prioritized recommendations.

## Architecture

```
theme/             — custom dark WordPress theme (no plugin code here).
plugin/            — the entire product lives here.
  privacy-checker.php     — PSR-4-ish autoload bootstrap.
  includes/
    class-plugin.php      — singleton orchestrator. boot() wires hooks.
    class-rest-api.php    — REST routes (/scan, /scan/ip, /scan/connection,
                            /scan/reputation, /scan/dns-test/{run,token,verify},
                            /scan/ping, /scan/port, /scan/port/batch,
                            /scan/security-headers, /lookup/ip, /lookup/whois,
                            /user-agent, /settings).
    class-scanner-orchestrator.php — aggregates provider responses,
                            embeds `privacy_report` on every response.
    class-privacy-report.php — Whoer-style breakdown builder: overall %,
                            letter grade, confidence, per-category scores,
                            recommendations.
    class-proxy-detector.php — VPN/proxy/Tor/hosting classification by
                            ASN catalog + org-string matching.
    class-anonymity-tips.php — 15 prioritized tips across 5 tiers covering
                            VPN, Tor, anti-detect browsers, residential
                            proxies, identity hygiene.
    class-network-probe.php — DNS-over-HTTPS fan-out, TCP-connect latency,
                            TCP port probe, allowlist path. Hardcoded port
                            denylist (SSH/SMTP/RDP).
    class-ip-fallback.php — provider chain runner. Honors preconditions and
                            records per-step status.
    class-maxmind-manager.php — downloads .mmdb files from MaxMind, extracts
                            archives with PharData, refreshes via wp-cron.
    class-fingerprint.php — UA / language / timezone visibility estimator.
    class-security.php    — IP literal validation, SSRF guards, redirect-target
                            sanitization, SHA-256 hashed rate-limit identifiers.
    class-rate-limiter.php — sliding-window per IP + route.
    class-cache.php       — wp_cache wrapper used by every provider.
    class-settings.php    — settings registry, sanitization, defaults seeding.
    class-privacy.php     — log retention + opt-in cookie cleanup.
    class-event-log.php   — optional wp_pc_event_log table (created lazily).
    class-admin-charts.php — pure-PHP inline-SVG chart helpers.
    providers/            — IpapiProvider, IpinfoProvider, MaxmindProvider,
                            IpApiComProvider, SpamhausProvider, IphubProvider,
                            MockIpProvider, MockReputationProvider, MockWhoisProvider,
                            RdapWhoisProvider.
    interfaces/           — IpIntelligenceProviderInterface,
                            ReputationProviderInterface, WhoisProviderInterface.
  admin/                  — settings page + dashboard view + admin-post handlers.
  public/                 — enqueues scanner.js / scanner.css; shortcodes.
  tests/                  — PHPUnit + WP function stubs.
tests-playwright/         — end-to-end Playwright suite (3 viewports).
GeoIP Database/           — 6 official MaxMind .tar.gz / .zip archives.
wp/                       — WordPress 7.1 core (untouched).
wp-content/plugins/privacy-checker → symlink to ../plugin
wp-content/themes/privacy-checker-theme → symlink to ../theme
wp-config.php             — local development config (DB + keys).
```

## Installation (local development)

```bash
# 1. DB + WP core (one-time)
mysql -uroot -e "CREATE DATABASE IF NOT EXISTS wp_privacy_checker;
                 GRANT ALL ON wp_privacy_checker.* TO 'wp_user'@'localhost' IDENTIFIED BY 'wp_pass';
                 FLUSH PRIVILEGES;"

# 2. wp-config.php is already at project root. Edit DB_* constants if you
#    diverge from the defaults above.

# 3. Symlinks so WP can find the plugin / theme (since WP_CONTENT_DIR is wp/wp-content/).
ln -sf "$(pwd)/plugin"   wp/wp-content/plugins/privacy-checker
ln -sf "$(pwd)/theme"    wp/wp-content/themes/privacy-checker-theme

# 4. WP install + activate via the install script.
./bin/wp-install.sh

# 5. Start the dev PHP server.
cd wp && php -S 127.0.0.1:8080 -t .
```

Default admin credentials: **admin / admin** (dev only — change immediately
for any non-local deployment).

### Optional — MaxMind databases

Drop the `.mmdb` files from `GeoIP Database/` (after extracting the
`.tar.gz` archives) into `wp/wp-content/uploads/maxmind/`:

```
wp-content/uploads/maxmind/GeoLite2-City.mmdb
wp-content/uploads/maxmind/GeoLite2-Country.mmdb
wp-content/uploads/maxmind/GeoLite2-ASN.mmdb
wp-content/uploads/maxmind/GeoLite2-Anonymous-IP.mmdb   # optional
```

Or enter your MaxMind license key in **Privacy Checker → Settings → MaxMind**
and use the "Download now" button to fetch them automatically.

## Installation (production)

1. Bundle the plugin (`plugin/`) and theme (`theme/`) into a release zip.
2. Upload to a fresh WordPress 6.2+ install.
3. Activate the theme + plugin.
4. Visit `wp-admin → Privacy Checker → Settings`:
   - Reorder the provider chain.
   - Paste your MaxMind license key (optional but recommended).
   - Set rate limits appropriate for your traffic.
5. (Optional) Add pages and use these shortcodes to embed the scanner anywhere:
   - `[pc_scanner]` — full IP / connection / fingerprint dashboard.
   - `[pc_ip_lookup]` — single-IP lookup form.
   - `[pc_whois]` — domain WHOIS form.
   - `[pc_user_agent]` — UA parser form.
   - `[pc_security_headers]` — security headers probe form.

## API providers + fallback chain

The IP chain defaults to:

```
maxmind → ip-api-com → ipinfo → ipapi → mock
```

For each provider the orchestrator checks preconditions before calling:

| Provider | Precondition |
| --- | --- |
| `maxmind` | At least one `.mmdb` file under `wp-content/uploads/maxmind/`. |
| `ip-api-com` | Setting `ip_api_com_enabled` is true. |
| `ipinfo` | Setting `ipinfo_enabled` is true. |
| `ipapi` | Setting `ipapi_enabled` is true. |
| `mock` | Always available (returns a static shape). |

If a provider returns `status => "error"` or `"unavailable"`, the next one is
tried. The final response includes a `chain` array listing every provider
that was consulted plus its per-step status — useful for diagnostics.

## Development mode

`wp-config.php` sets:

```php
define( 'PRIVACY_CHECKER_DEV_MODE', true );          // mock providers where helpful.
define( 'PRIVACY_CHECKER_RATE_LIMIT_SCAN', 60 );     // generous rate limits.
define( 'PRIVACY_CHECKER_RATE_LIMIT_LOOKUP', 30 );
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
define( 'SCRIPT_DEBUG', true );
define( 'DISABLE_WP_CRON', true );                   // cron driven manually in dev.
```

When `PRIVACY_CHECKER_DEV_MODE` is true, the WHOIS provider falls back to a
mock shape so the UI doesn't hard-fail without RDAP access.

## Testing

### PHPUnit (unit)

```bash
composer install        # one-time
vendor/bin/phpunit      # runs 120 tests, 464 assertions
```

Coverage is configured for `plugin/includes/` (excluding `plugin/includes/providers/`
which are mostly thin adapters). The bootstrap loads `plugin/tests/bootstrap.php`,
which defines `ABSPATH`, requires composer autoload + a small set of WP
function stubs (`plugin/tests/wp-stubs.php`).

### Playwright (end-to-end)

```bash
cd tests-playwright
npm install
npx playwright install chromium
BASE_URL=http://127.0.0.1:8080 npx playwright test
```

The suite covers three viewports (1440x900, 768x1024, 390x844), exercises the
homepage, fingerprint, IP lookup, WHOIS, user-agent, security headers, the
admin dashboard, and a security smoke (auth + rate limit + SSRF).

## Security

- **No raw IP storage.** Rate-limit identifiers are SHA-256 hashed before
  they hit the database (`Security::hash_identifier`).
- **SSRF guard.** `Security::validate_remote_url()` rejects any URL whose
  hostname resolves to a private / loopback / link-local range before the
  server-side fetch runs.
- **WordPress nonces.** Every admin form uses `_wpnonce`; every
  `admin-post.php` handler re-verifies the nonce + capability.
- **Capability checks.** All REST routes that expose settings require
  `manage_options`; all read-only public routes use `__return_true` because
  they only return data the visitor could already derive.
- **Sandboxed log retention.** The optional `wp_pc_event_log` table is only
  created when logging is enabled, and rows older than the configured
  retention are deleted via a daily cron.

## Privacy

- The plugin is privacy-by-default: no scan logs are written unless the
  admin explicitly enables `event_log_enabled`.
- No analytics, no third-party trackers, no telemetry pings.
- The MaxMind attribution is shown in the admin footer when the local DB
  is in use, per CC BY-SA 4.0.

## Deployment checklist

- [ ] Replace `wp-config.php` constants with real values for your DB + domain.
- [ ] Generate fresh `AUTH_KEY` / `SALT` constants (don't ship the dev ones).
- [ ] Set `WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`, `SCRIPT_DEBUG`,
      `DISABLE_WP_CRON`, `PRIVACY_CHECKER_DEV_MODE` to `false` /
      production-appropriate values.
- [ ] If using MaxMind, rotate the license key from chat to one stored only
      in `wp-config.php` or the settings page.
- [ ] Ensure `wp-content/uploads/maxmind/` is `.htaccess`-denied from public
      HTTP access (the install script creates this rule).
- [ ] Run `vendor/bin/phpunit` and `npx playwright test` against the
      production-equivalent environment before promoting.

## Troubleshooting

**REST routes return 404**
Verify the plugin is symlinked at `wp-content/plugins/privacy-checker` and
that `wp-config.php`'s serialized `active_plugins` row is the right length
(use the dashboard to deactivate + reactivate rather than direct DB edits).

**No MaxMind data**
Confirm the `.mmdb` files are under `wp-content/uploads/maxmind/` and are
world-readable. The chain will skip MaxMind silently if no DB is present and
fall back to ip-api.com.

**Rate-limited locally**
The dev defaults are 60/min for scans and 30/min for lookups. Either wait, or
bump the constants in `wp-config.php`. To flush per-IP buckets from the
admin dashboard, use the "Flush IP cache" tool (which also clears
transients).

**PHP autoload fails for an interface**
After adding a new interface in `plugin/includes/interfaces/`, re-run
`composer dump-autoload -o` so the classmap picks it up.

## License

GPL-2.0-or-later.
