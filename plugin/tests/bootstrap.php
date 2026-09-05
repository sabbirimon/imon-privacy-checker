<?php
/**
 * PHPUnit bootstrap.
 *
 * Stubs out WordPress function calls so we can exercise pure-PHP plugin
 * classes in isolation. Avoids the full WP test framework install for fast,
 * hermetic unit tests.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

// Plugin classes `exit` outside ABSPATH and reference plugin constants, so
// declare them BEFORE composer autoload registers the loader.
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
    define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
    define( 'MINUTE_IN_SECONDS', 60 );
}
if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
    define( 'HOUR_IN_SECONDS', 3600 );
}
if ( ! defined( 'PRIVACY_CHECKER_DIR' ) ) {
    define( 'PRIVACY_CHECKER_DIR', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'PRIVACY_CHECKER_URL' ) ) {
    define( 'PRIVACY_CHECKER_URL', 'https://example.test/wp-content/plugins/privacy-checker/' );
}
if ( ! defined( 'PRIVACY_CHECKER_VERSION' ) ) {
    define( 'PRIVACY_CHECKER_VERSION', '1.0.0' );
}
if ( ! defined( 'PRIVACY_CHECKER_REST_NS' ) ) {
    define( 'PRIVACY_CHECKER_REST_NS', 'privacy-checker/v1' );
}

// PHPUnit Polyfills (yoast/phpunit-polyfills) — provides compat shims.
require_once __DIR__ . '/../../vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php';

// Composer autoload — classmap resolves every PrivacyChecker\* class to its
// file (the plugin uses a custom `class-{kebab}.php` naming scheme that
// doesn't strictly follow PSR-4). For test classes, the PSR-4 mapping
// PrivacyChecker\Tests\ -> plugin/tests/ applies.
require_once __DIR__ . '/../../vendor/autoload.php';

// Test-only stubs that mirror the WP API surface used by our plugin classes.
// Loaded AFTER composer autoload so the WpState class declaration doesn't
// interfere with composer's classmap.
require_once __DIR__ . '/wp-stubs.php';
