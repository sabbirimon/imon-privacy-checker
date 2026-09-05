# Deployment Guide — IMON Privacy Checker

> Production deployment runbook for DevOps / SRE.
> Audience: anyone putting the plugin + theme on a public WordPress install
> behind nginx or Apache, with TLS, real credentials, and operational
> observability.

## 1. Requirements

| Resource | Minimum | Recommended | Notes |
|---|---|---|---|
| PHP | 8.1 | 8.3 (8.4 works) | `php -v` |
| PHP extensions | `curl`, `mbstring`, `intl`, `json`, `xml`, `zip`, `phar`, `bcmath` | + `opcache` | `php -m` |
| MySQL / MariaDB | MySQL 8.0 / MariaDB 10.6 | MySQL 8.4 LTS | UTF8MB4 required |
| Web server | nginx 1.22 / Apache 2.4 | nginx 1.26 | Both supported |
| Composer | 2.x | 2.7+ | Plugin uses classmap autoload |
| TLS | TLS 1.2 | TLS 1.3 (Mozilla "intermediate" config) | Required for security-headers + share endpoints |
| Outbound HTTPS | open to `*.ip-api.com`, `ipinfo.io`, `ipapi.com`, `*.maxmind.com`, `unpkg.com` (optional, for 3D globe) | allowlist through egress proxy | Some providers require a paid tier |
| Disk | 500 MB | 2 GB | Mostly uploads/maxmind/*.mmdb |
| RAM | 256 MB | 1 GB | MaxMind loads `.mmdb` in PHP heap |

## 2. Pre-deploy checklist

- [ ] WordPress 6.2+ already installed at the deploy target.
- [ ] `wp-config.php` generated with **fresh** salts
      (https://api.wordpress.org/secret-key/1.1/salt/), production DB creds,
      `WP_DEBUG=false`, `WP_DEBUG_LOG=false`, `DISABLE_WP_CRON=false`.
- [ ] `PRIVACY_CHECKER_DEV_MODE` is **NOT** defined (or set to `false`).
- [ ] Egress firewall allows outbound HTTPS to providers in use.
- [ ] TLS cert installed and tested
      (https://www.ssllabs.com/ssltest/analyze.html — target A or A+).
- [ ] Backup of existing `wp-content/plugins/` and `wp-content/themes/`.

## 3. One-time install (cold start)

```bash
# On the deploy host, in the WP root (e.g. /var/www/wordpress):

# 1. Copy plugin + theme into place
sudo rsync -a --delete \
  /path/to/release/imon-privacy-checker/plugin/ \
  wp-content/plugins/privacy-checker/
sudo rsync -a --delete \
  /path/to/release/imon-privacy-checker/theme/ \
  wp-content/themes/privacy-checker-theme/

# 2. Build the autoloader (the plugin uses non-PSR-4 filenames)
cd wp-content/plugins/privacy-checker
composer install --no-dev --optimize-autoloader
cd -

# 3. Lock down file permissions
sudo chown -R www-data:www-data wp-content/plugins/privacy-checker
sudo chown -R www-data:www-data wp-content/themes/privacy-checker-theme
sudo find wp-content/plugins/privacy-checker -type f -exec chmod 644 {} \;
sudo find wp-content/plugins/privacy-checker -type d -exec chmod 755 {} \;
sudo find wp-content/themes/privacy-checker-theme -type f -exec chmod 644 {} \;
sudo find wp-content/themes/privacy-checker-theme -type d -exec chmod 755 {} \;

# 4. Activate theme + plugin (idempotent — safe to re-run)
sudo -u www-data wp theme activate privacy-checker-theme
sudo -u www-data wp plugin activate privacy-checker

# 5. Create uploads subdirectory with a deny rule
sudo mkdir -p wp-content/uploads/maxmind
sudo tee wp-content/uploads/maxmind/.htaccess > /dev/null <<'EOF'
Require all denied
EOF
# (nginx users: see §5)

# 6. Flush rewrite rules
sudo -u www-data wp rewrite flush
```

## 4. Environment variables / wp-config.php constants

These belong in `wp-config.php` and **never** in version control. The
deploy pipeline should template them.

### Standard WP

```php
define( 'WP_DEBUG',         false );
define( 'WP_DEBUG_LOG',     false );
define( 'WP_DEBUG_DISPLAY', false );
define( 'SCRIPT_DEBUG',     false );
define( 'DISABLE_WP_CRON',  false ); // let wp-cron fire; we hook into it
define( 'WP_AUTO_UPDATE_CORE',       'minor' ); // security patches only
define( 'WP_AUTO_UPDATE_PLUGINS',    true );
define( 'WP_AUTO_UPDATE_THEMES',     true );
define( 'FS_METHOD',        'direct' ); // or 'ssh2' if remote storage
define( 'DISALLOW_FILE_EDIT', true ); // block code editor in /wp-admin
```

### IMON-specific

```php
// DEV MODE — must be false in production. The plugin auto-flips to false on
// activation but never back to true — confirm it is off.
define( 'PRIVACY_CHECKER_DEV_MODE', false );

// Rate limits (per minute, per route bucket).
// Defaults if undefined: scan=60, lookup=30, security=10, dns=5, ping=30,
// port_scan=10. Lower if you're seeing abuse; raise if real users hit 429.
define( 'PRIVACY_CHECKER_RATE_LIMIT_SCAN',       60 );
define( 'PRIVACY_CHECKER_RATE_LIMIT_LOOKUP',     30 );
define( 'PRIVACY_CHECKER_RATE_LIMIT_SECURITY',   10 );
define( 'PRIVACY_CHECKER_RATE_LIMIT_DNS_PROBE',   5 );
define( 'PRIVACY_CHECKER_RATE_LIMIT_PING',       30 );
define( 'PRIVACY_CHECKER_RATE_LIMIT_PORT_SCAN',  10 );

// (Optional) Set a fallback MaxMind license key via env-injected constant.
// The plugin prefers this constant over the DB setting, so CI/CD can rotate
// it without touching the database. NEVER ship the key in chat / git.
define( 'PRIVACY_CHECKER_MAXMIND_LICENSE_KEY', getenv('IMON_MAXMIND_KEY') ?: '' );

// (Optional) Same trick for paid DNS resolver credentials.
define( 'PRIVACY_CHECKER_DNS_PAID_API_KEY', getenv('IMON_DNS_KEY') ?: '' );
```

### Secrets in the DB

Everything not declared above lives in `wp_options.pc_settings` and is
editable from `/wp-admin/admin.php?page=privacy-checker`. Treat the
`wp_options` row as a secret — back it up encrypted.

## 5. Web server configs

### 5.1 nginx (recommended)

Use the official `wp-config.php → nginx` guide as a base, then add:

```nginx
# /etc/nginx/conf.d/wordpress.conf (snippet — full config in nginx.conf)

# Block direct access to plugin / theme PHP internals.
location ~* /wp-content/(plugins|themes)/.*\.php$ {
    deny all;
    return 403;
}

# MaxMind databases must never be served.
location ^~ /wp-content/uploads/maxmind/ {
    deny all;
    return 403;
}

# Cache the static scanner asset bundle aggressively (they have a `?ver=`
# query string that busts on every release).
location ~* /wp-content/(plugins|themes)/.*\.(?:js|css|woff2?|svg|png|jpg|webp)$ {
    expires 7d;
    access_log off;
    add_header Cache-Control "public";
    add_header X-Content-Type-Options "nosniff";
    try_files $uri =404;
}

# REST API rate-limit hint (enforced in PHP, but the upstream nginx limit_req
# gives cheap protection against floods).
limit_req_zone $binary_remote_addr zone=pc_rest:10m rate=30r/m;
location ~ ^/wp-json/privacy-checker/v1/ {
    limit_req zone=pc_rest burst=60 nodelay;
    try_files $uri $uri/ /index.php?$args;
}

# Security headers — applied to every response.
add_header X-Frame-Options          "SAMEORIGIN" always;
add_header X-Content-Type-Options   "nosniff"    always;
add_header Referrer-Policy          "strict-origin-when-cross-origin" always;
add_header Permissions-Policy       "geolocation=(), camera=(), microphone=()" always;
# HSTS only when you are 100% sure HTTPS works everywhere
# add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Reload: `sudo nginx -t && sudo systemctl reload nginx`.

### 5.2 Apache

```apache
# .htaccess in /wp-content/uploads/maxmind/
Require all denied

# In wp-content/plugins/privacy-checker/.htaccess (create if missing):
<FilesMatch "\.(mmdb|sql|sqlite)$">
    Require all denied
</FilesMatch>

# Optional: rate-limit at the Apache layer (mod_evasion or mod_qos).
```

Enable the required modules: `sudo a2enmod headers expires rewrite ssl`.

### 5.3 TLS

Use Mozilla's "intermediate" profile (https://ssl-config.mozilla.org/). The
plugin's own `Security::validate_remote_url()` will reject any downstream
fetch whose cert fails validation, but you should still pass a public test
(SSL Labs A grade).

## 6. Cron

`wp-cron` is the dispatcher. Hooked jobs in this plugin:

| Hook | Purpose | Default schedule |
|---|---|---|
| `pc_maxmind_refresh` | Re-download `GeoLite2-*.mmdb` if the local copy is >7d old | daily |
| `pc_log_retention` | Delete event-log rows older than `log_retention_days` | daily |

If you run **system cron** instead of WP-Cron (recommended for production
reliability), disable WP-Cron and add:

```cron
# /etc/cron.d/wordpress-imon
*/15 * * * * www-data cd /var/www/wordpress && wp cron event run --due-now >/dev/null 2>&1
```

The plugin does NOT spawn its own daemons or long-running workers.

## 7. File-system layout

```
/var/www/wordpress/                       # WP root
├── wp-config.php                         # generated from template
├── wp-content/
│   ├── plugins/
│   │   └── privacy-checker/              # from this release
│   │       ├── vendor/                   # composer install --no-dev
│   │       └── ...
│   ├── themes/
│   │   └── privacy-checker-theme/        # from this release
│   └── uploads/
│       └── maxmind/                      # .htaccess deny, owned by www-data
│           ├── GeoLite2-City.mmdb
│           ├── GeoLite2-Country.mmdb
│           ├── GeoLite2-ASN.mmdb
│           └── GeoLite2-Anonymous-IP.mmdb   # optional
```

Disk usage: each `.mmdb` is ~50-80 MB. Plan for ~300 MB uploads.

## 8. Database

The plugin only writes to `wp_options` (settings) and, if
`event_log_enabled=true`, an optional `wp_pc_event_log` table (created
lazily on first write via `dbDelta`). No other schema changes.

```sql
-- Sanity check after deploy:
SELECT option_name, LENGTH(option_value) AS bytes
FROM wp_options WHERE option_name = 'pc_settings';
-- Expected: bytes between 2k and 6k depending on saved settings.

SHOW TABLES LIKE 'wp_pc_event_log';
-- Empty set OR a CREATE TABLE statement consistent with the plugin.
```

Backup both with `wp db export` as part of the standard WP backup routine.

## 9. Post-deploy verification

Run these **before** pointing traffic at the new release.

```bash
# 1. The plugin activates cleanly:
wp plugin list | grep privacy-checker
# Expect: privacy-checker  active

# 2. REST routes resolve:
curl -sS -o /dev/null -w '%{http_code}\n' \
  https://example.test/wp-json/privacy-checker/v1/scan/ip
# Expect: 200

# 3. The IP-intel chain returns real data:
curl -sS https://example.test/wp-json/privacy-checker/v1/scan/connection \
  | jq '.connection.intel.status,.connection.intel.country,.connection.intel.isp'
# Expect: "ok", "<country>", "<isp>"

# 4. The 3D-globe assets load (HEAD only, no body):
curl -sIo /dev/null -w '%{http_code} %{size_download}\n' \
  https://example.test/wp-content/plugins/privacy-checker/public/assets/js/three.min.js
# Expect: 200, ~660KB

# 5. The MaxMind upload dir is locked down:
curl -sIo /dev/null -w '%{http_code}\n' \
  https://example.test/wp-content/uploads/maxmind/.htaccess
# Expect: 403

# 6. The share endpoint respects the setting (404 if disabled):
curl -sS -X POST -H 'Content-Type: application/json' \
  -d '{"report":{"generated_at":"2026-01-01T00:00:00Z"}}' \
  -o /dev/null -w '%{http_code}\n' \
  https://example.test/wp-json/privacy-checker/v1/share
# Expect: 200 if share_enabled=true, 403 if disabled

# 7. Rate-limit headers / 429 behavior (lower the threshold via
# PRIVACY_CHECKER_RATE_LIMIT_SCAN=2 in a temporary deploy):
for i in $(seq 1 4); do
  curl -sS -o /dev/null -w "scan $i: %{http_code}\n" \
    https://example.test/wp-json/privacy-checker/v1/scan
done
# Expect: 200, 200, 429, 429
```

If any check fails, roll back (see §14) before exposing the URL to visitors.

## 10. Post-install settings

After the first deploy, visit `/wp-admin/admin.php?page=privacy-checker`
and set, at minimum:

1. **Privacy Checker → Settings → Providers**: pick the order that matches
   your egress budget.
   - **Local-only**: MaxMind + Spamhaus (both local/DB).
   - **Cheapest live**: ip-api.com (free, 45 req/min) + Spamhaus.
   - **Best coverage**: MaxMind + ipinfo.io (paid) + Cloudflare heuristics.
2. **Privacy Checker → Settings → DNS Leak Test**: enable, leave the
   resolver chain at the default (`free → online → paid → local`).
3. **Privacy Checker → Settings → Ping / Latency**: keep the default
   targets; raise the per-IP rate limit if you expect heavy reuse.
4. **Privacy Checker → Settings → Port Scan**: leave allowlist empty
   (self-only) unless you have a deliberate reason.
5. **Privacy Checker → Settings → Sharing**: keep `share_enabled=false`
   unless you've read the privacy implications — shared reports survive
   7 days by default.
6. **Privacy Checker → Settings → Logging**: enable only if you have a
   reason. Logs grow fast and contain the visitor's IP hashed with a
   daily-rotated salt.

## 11. Monitoring

Expose these signals to your monitoring system (Prometheus / Datadog /
CloudWatch — the plugin doesn't ship an exporter; scrape via standard
hosts and the WP options row).

### Liveness / readiness

```text
GET /wp-json/privacy-checker/v1/scan/ip -> 200 in <500ms p95
```

The route has no DB writes and no upstream calls in this codebase, so it's
a good canary. A 200 means: plugin loaded, REST registered, autoload
works, constants sane.

### Synthetic check (every 5 min)

```bash
# Replace with your real domain.
SITE=https://example.test
curl -fsS -o /dev/null -w '%{http_code} %{time_total}\n' \
  $SITE/wp-json/privacy-checker/v1/scan/connection
# Alert on: status != 200 OR time_total > 1.5s
```

### Key metrics to chart

- **p95 latency** of `/scan`, `/scan/connection`, `/scan/geo/lookup`.
- **4xx / 5xx rate** per route (privacy-checker namespace).
- **Provider chain hit-rate**: parse `connection.intel.chain` from the
  synthetic scan and increment a counter per `provider_key`. If
  `maxmind` shows up <80% of the time, your `.mmdb` files are stale or
  the daily `pc_maxmind_refresh` cron is failing.
- **Rate-limit 429s** per bucket (parse from nginx access log or the WP
  exception hook). Sustained 429s indicate a crawler, not real abuse.

### Log noise to suppress

- The plugin never logs visitor IPs in plaintext. Event-log rows contain
  a SHA-256 of (IP + daily-rotated salt) — safe to forward.
- `wp-content/debug.log` should stay empty when `WP_DEBUG_LOG=false`.
  If you see recurring entries, fix the bug, don't silence the logger.

### Audit cadence

- **Weekly**: confirm `pc_maxmind_last_update` is < 8 days old
  (`wp option get pc_settings --format=json | jq '.pc_maxmind_last_update'`).
- **Monthly**: confirm disk usage in `wp-content/uploads/maxmind/`
  stays bounded; rotate out archived `.tar.gz` files.
- **Quarterly**: review `provider_chain_ip` order against current egress
  costs and provider SLAs.

## 12. Backup / restore

The plugin's footprint is small:

- **Must back up**: `wp_options.pc_settings` (contains all provider
  configuration and rate limits).
- **Should back up** if logging is enabled: `wp_pc_event_log` table.
- **Optional**: `wp-content/uploads/maxmind/*.mmdb` — these are
  re-downloadable from MaxMind so they're convenience, not authoritative.

```bash
# Snapshot
wp db export /backups/wordpress-imon-$(date +%F).sql

# Restore
wp db import /backups/wordpress-imon-2026-01-15.sql
wp cache flush
```

## 13. Hardening

In addition to the wp-config flags in §4:

- **Two-factor authentication** for every admin account.
- **`DISALLOW_FILE_EDIT=true`** so the theme/plugin editor in wp-admin
  is hidden. Code changes should go through deploys.
- **Application password** for any external automation (e.g. the
  share-creation webhook). Don't share real user passwords.
- **Fail2ban** rule for `/wp-login.php` (4xx bursts in <60s).
- **Separate DB user** for WordPress with no `GRANT OPTION` and no
  access to other schemas. Rotate on personnel change.
- **Offsite backups** encrypted at rest (e.g. S3 SSE-KMS).
- **Plugin allowlist** in policy: don't enable arbitrary new plugins on
  this site. This plugin's composer autoloader assumes a controlled
  plugin environment.

## 14. Rollback

The plugin is fully self-contained and version-aware (the
`PRIVACY_CHECKER_VERSION` constant and `plugin_version` option). Rollback
is a single rsync:

```bash
# 1. Pin to the previous release
sudo rsync -a --delete \
  /var/releases/imon-privacy-checker/v1.4.0/plugin/ \
  wp-content/plugins/privacy-checker/

# 2. Re-run composer for the rolled-back version
cd wp-content/plugins/privacy-checker
composer install --no-dev --optimize-autoloader

# 3. Re-activate (idempotent)
sudo -u www-data wp plugin activate privacy-checker

# 4. Flush
sudo -u www-data wp cache flush
sudo -u www-data wp rewrite flush
```

DB rollback: the plugin never runs destructive migrations on upgrade.
Settings additions are pure `array_key_exists` backfill, so a downgrade
keeps working with the wider settings row intact (extra keys are ignored).

## 15. Capacity planning

Each `/scan` request:

- 1 DB read for `pc_settings`.
- 0-2 outbound HTTPS calls (MaxMind local path: 0; ip-api.com path: 1).
- ~50-200 ms server-side work (cache hit: 5 ms; cache miss: 100-200 ms).
- Response body ~6-12 KB.

A single 1-vCPU / 1-GB-RAM VM handles **~30 scans/sec** with all caches
warm. With cold caches, expect **~5 scans/sec**. Above that, scale out
behind a load balancer and switch the cache to Redis (drop-in: the
plugin's `class-cache.php` already calls `wp_cache_*`, so swap the
object cache plugin to redis-cache).

## 16. Compliance notes

- **GDPR**: the plugin stores no PII beyond the visitor's IP for the
  duration of the request. The optional event log stores a **hashed**
  identifier that rotates daily. If you enable logging, disclose it in
  your privacy policy and provide a way to opt out.
- **MaxMind CC BY-SA 4.0**: when local `.mmdb` files are used, the
  admin footer must show attribution. The plugin renders this
  automatically when `ip2location_attribution=1` (default) or when
  MaxMind files are detected.
- **Provider ToS**: ipinfo.io, ipapi.com, and Spamhaus all have terms
  around free-tier rate limits. The plugin's rate limiter is your
  enforcement mechanism — do not raise it without provider consent.
- **TLS** is required for the security-headers probe (it fetches URLs
  the visitor pastes; without TLS the upstream fetch fails).

## 17. Quick reference

```text
Repo         https://github.com/sabbirimon/imon-privacy-checker
License      GPL-2.0-or-later
PHP          8.1+ (tested 8.5)
WP           6.2+
Composer     2.x
Tests        vendor/bin/phpunit  -> 120 tests, 464 assertions
E2E          tests-playwright/    -> npx playwright test
Settings UI  /wp-admin/admin.php?page=privacy-checker
REST root    /wp-json/privacy-checker/v1/
Logs         wp-content/debug.log (only if WP_DEBUG_LOG=true)
Help         progress.md, build.md, plan.md, claude.md, puku.md
```

## 18. Related

- `README.md` — End-user overview + feature list
- `build.md` — Local install + smoke test
- `progress.md` — Phase-by-phase status tracker
- `plan.md` — Architecture + scope decisions
- `claude.md` / `puku.md` — Agent + Puku CLI conventions
