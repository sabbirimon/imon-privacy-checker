# Build & Install — Privacy Checker

> How to set up, build, run, and test the Privacy Checker plugin + theme.

## Prerequisites

| Tool | Min version | Check |
|---|---|---|
| PHP | 8.1 (8.5 tested) | `php -v` |
| Composer | 2.x | `composer --version` |
| Node | 18+ (for Playwright) | `node -v` |
| MySQL | 8.0+ | `mysql --version` |
| WP-CLI | 2.x | `tools/wp --version` (bundled) |

## First-time install

```bash
# 1. Install PHP deps
composer install

# 2. Build the classmap (required — the plugin uses non-PSR-4 filenames)
composer dump-autoload

# 3. Create the local DB
mysql -uroot -p -e "CREATE DATABASE IF NOT EXISTS wp_privacy_checker DEFAULT CHARACTER SET utf8mb4;"
mysql -uroot -p -e "CREATE USER IF NOT EXISTS 'wp_user'@'localhost' IDENTIFIED BY 'wp_pass';"
mysql -uroot -p -e "GRANT ALL ON wp_privacy_checker.* TO 'wp_user'@'localhost';"

# 4. Configure WordPress (wp-config.php already exists; check DB creds)

# 5. Install WordPress via WP-CLI
tools/wp core install \
  --url=http://localhost:8080 \
  --title="Privacy Checker" \
  --admin_user=admin \
  --admin_password=admin \
  --admin_email=admin@example.test \
  --skip-email

# 6. Activate theme + plugin
tools/wp theme activate privacy-checker-theme
tools/wp plugin activate privacy-checker

# 7. Seed uploads directory
mkdir -p wp-content/uploads/maxmind
```

## Run locally

```bash
# Start the PHP built-in server with a router that mimics WP rewrites
cd wp && php -S 127.0.0.1:8080 router.php
# OR
tools/wp server --host=127.0.0.1 --port=8080
```

Then open http://localhost:8080.

## Tests

### PHPUnit (unit)

```bash
vendor/bin/phpunit --no-coverage
# 61 tests, 154 assertions
```

The bootstrap (`plugin/tests/bootstrap.php`) defines WP constants and stubs
all WP function calls so the plugin classes can be exercised in isolation.

### Playwright (e2e)

```bash
cd tests-playwright
npm install
npx playwright install --with-deps chromium
npx playwright test --project=chromium
```

Playwright specs cover: homepage, scanner run, fingerprint, IP lookup, WHOIS,
user-agent, security-headers, responsive layout, and admin dashboard.

## Smoke test (after a fresh install)

```bash
# HTML smoke
curl -s http://localhost:8080/ | grep -q "How Private Are You Online?"

# JSON smoke (visitor IP via REST)
curl -s http://localhost:8080/wp-json/privacy-checker/v1/scan/ip | jq '.ipv4'

# Admin login + settings page
curl -c /tmp/cookies -b /tmp/cookies -d 'log=admin&pwd=admin' \
  http://localhost:8080/wp-login.php > /dev/null
curl -b /tmp/cookies -s 'http://localhost:8080/wp-admin/admin.php?page=privacy-checker' \
  | grep -q "Privacy Checker"
```

## Production deploy

1. Build assets:
   ```bash
   composer install --no-dev --optimize-autoloader
   ```
2. Sync `wp-content/plugins/privacy-checker/` to the production host.
3. Copy `wp-content/themes/privacy-checker-theme/` to the production host.
4. Activate via WP-CLI or admin UI.
5. In Settings → Privacy Checker, paste the MaxMind license key (if available)
   and click "Download MaxMind databases now".
6. Smoke test: `curl /wp-json/privacy-checker/v1/scan/ip` should return JSON
   with real geolocation (via MaxMind or ip-api.com depending on chain order).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Class PrivacyChecker\X not found" | Classmap stale | `composer dump-autoload` |
| MaxMind download returns 401 | No license key set | Add key in Settings, retry |
| All scans show mock data | MaxMind DB files missing | Click "Download MaxMind databases now" |
| Rate-limit returns 429 | Per-minute cap hit | Tune in Settings → Rate Limiting |
| Settings form wipes MaxMind key | Old plugin version (pre-1.1) | Update `class-settings.php` |

## Related

- `claude.md` — Agent operating notes
- `puku.md` — Puku CLI usage
- `plan.md` — Architecture & scope
- `progress.md` — Status tracker
