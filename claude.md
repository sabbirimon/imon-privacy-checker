# Claude — Agent Operating Notes

> Operating instructions for AI agents working on the **Privacy Checker** project.
> Read this file **first** before touching the codebase.

## Project overview

A self-hosted WordPress privacy/anonymity diagnostic platform inspired by Whoer.net.
Detects visitor IP, geolocation, ISP, ASN, hostname, WebRTC leaks, browser fingerprint,
and IP reputation. Ships with a custom theme, custom plugin, REST API, dedicated admin
dashboard, and full PHPUnit + Playwright test suites. **All code, branding, and design
are original** — no Whoer assets are reused.

## Stack

| Layer | Tech | Notes |
|---|---|---|
| CMS | WordPress 7.1 (core at `./wp/`) | PHP 8.5, MySQL |
| Plugin | Custom, PSR-4-ish, under `plugin/` | Namespace: `PrivacyChecker\` |
| Theme | Custom dark theme under `theme/` | No scanner code in theme |
| IP data | MaxMind GeoLite2 (local .mmdb) + ip-api.com (free HTTP, no key) | Both via fallback chain |
| Tests | PHPUnit 9.6 + Playwright (Chromium) | See `plan.md` for full spec |
| Deps | Composer (`maxmind-db/reader`, phpunit, phpcompat, phpcs) | `composer.json` |
| CLI | Puku CLI v1.8.52 (npm) | `/Users/code/.npm-global/bin/puku-cli` |

## Non-negotiables

1. **Privacy-by-default.** Never store raw IPs. Rate-limit identifiers are SHA-256
   hashes of `(salt + ip + bucket + minute)`. Logs are opt-in.
2. **SSRF-safe.** Every URL the user submits goes through `Security::validate_remote_url()`.
3. **No fake data.** If DNS leak testing infrastructure isn't configured, the UI
   says "Not configured" — it does not invent results.
4. **No third-party VPN affiliate recommendations.** Ever.
5. **Honest fallback chain.** MaxMind → ip-api.com → ipinfo → ipapi → mock.
   Each step is wrapped in try/catch and logged.
6. **Original code & branding.** No Whoer copy, no Whoer color palette, no Whoer logos.

## Working rules

- **Composer autoload** uses both `psr-4` *and* `classmap` for `plugin/includes/`,
  `plugin/includes/providers/`, and `plugin/includes/interfaces/`. The plugin's
  custom `class-{kebab}.php` filename convention is not strict PSR-4, so the
  classmap is mandatory. Regenerate with `composer dump-autoload` after adding
  new files.
- **PHPUnit** is run with `vendor/bin/phpunit --no-coverage` from the project root.
  The bootstrap (`plugin/tests/bootstrap.php`) defines all WP constants before
  composer autoload fires so the plugin's `ABSPATH` guards don't trip.
- **Playwright** specs live under `tests-playwright/`. The browser config targets
  Chromium only at three viewports (1440x900, 768x1024, 390x844).
- **No production secrets in source.** License keys, API tokens, salts are entered
  via the admin UI. Any value pasted into chat is treated as compromised.
- **PHPCS** runs with `vendor/bin/phpcs --standard=WordPress plugin/ theme/`. New
  code should pass without warnings.

## File layout (key paths)

```
plugin/                       — Plugin source (PHP, namespaced under PrivacyChecker\)
  privacy-checker.php         — Plugin entry point
  includes/                   — Main classes (admin/, REST, providers/, etc.)
  admin/                      — Admin pages + dashboard view + CSS
  public/                     — Front-end scanner.js, scanner.css
  tests/                      — PHPUnit tests + WP stubs
theme/                        — Custom dark theme
tests-playwright/             — Playwright e2e tests
wp/                           — WordPress core (don't edit directly)
wp-content/uploads/maxmind/   — MaxMind .mmdb cache (private, .htaccess-deny)
GeoIP Database/               — Shipped MaxMind archives
phpunit.xml.dist              — PHPUnit config
composer.json                 — Deps + autoload
```

## Hand-off checklist

When you're done in a session, make sure:

- [ ] All modified PHP files pass `php -l` syntax check
- [ ] `vendor/bin/phpunit --no-coverage` is green
- [ ] `progress.md` reflects the latest state
- [ ] No secrets committed to source
- [ ] `README.md` updated if architecture changed

## Related files

- `plan.md` — Architecture, decisions, scope
- `build.md` — Build / install / run steps
- `progress.md` — What's done, what's pending, what's blocked
- `puku.md` — Puku CLI usage notes for this project
