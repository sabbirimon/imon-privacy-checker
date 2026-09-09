<?php
/**
 * Plugin Name: IMON
 * Plugin URI: https://example.com/imon
 * Description: IMON (I AM ON) — privacy & anonymity diagnostic platform. Detects IP, geolocation, fingerprint signals, WebRTC exposure, and IP reputation. REST API + admin settings + shortcode-based dashboard.
 * Version: 1.1.0
 * Requires at least: 6.2
 * Requires PHP: 8.1
 * Author: IMON Team
 * License: GPL-2.0-or-later
 * Text Domain: privacy-checker
 *
 * @package IMON
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'PRIVACY_CHECKER_VERSION' ) ) {
    define( 'PRIVACY_CHECKER_VERSION', '1.1.0' );
}
if ( ! defined( 'PRIVACY_CHECKER_FILE' ) ) {
    define( 'PRIVACY_CHECKER_FILE', __FILE__ );
}
if ( ! defined( 'PRIVACY_CHECKER_DIR' ) ) {
    define( 'PRIVACY_CHECKER_DIR', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'PRIVACY_CHECKER_URL' ) ) {
    // The local dev WP install symlinks wp-content/plugins/privacy-checker
    // -> ../../../plugin. PHP's __FILE__ resolves through the symlink to
    // the real filesystem path, so `plugin_dir_url(__FILE__)` bakes the
    // absolute filesystem path into every asset URL the plugin emits —
    // which 404s the JS/CSS in the browser and silently breaks the
    // dashboard. Anchor the URL to the known plugin slug via
    // `content_url()` (symlink-safe; computed from WP_CONTENT_URL /
    // siteurl()), so it resolves to /wp-content/plugins/privacy-checker/
    // whether the plugin is a real dir or a symlink.
    define( 'PRIVACY_CHECKER_URL', content_url( 'plugins/privacy-checker/' ) );
}
if ( ! defined( 'PRIVACY_CHECKER_REST_NS' ) ) {
    define( 'PRIVACY_CHECKER_REST_NS', 'privacy-checker/v1' );
}

require_once PRIVACY_CHECKER_DIR . 'includes/class-autoloader.php';

PrivacyChecker\Autoloader::register();

register_activation_hook( __FILE__, array( 'PrivacyChecker\\Plugin', 'on_activate' ) );
register_deactivation_hook( __FILE__, array( 'PrivacyChecker\\Plugin', 'on_deactivate' ) );

add_action(
    'plugins_loaded',
    static function (): void {
        PrivacyChecker\Plugin::instance()->boot();
    }
);