<?php
/**
 * Uninstall handler. Removes plugin options and transients.
 *
 * @package PrivacyChecker
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

// Remove plugin options. All keys are consolidated into the single pc_settings
// option (see Settings::OPTION_KEY), but we also clean up any historical
// standalone options an older install might have left behind.
$options = array(
    'pc_settings',
    'pc_ip_provider',
    'pc_reputation_provider',
    'pc_whois_provider',
    'pc_dns_provider',
    'pc_dns_test_enabled',
    'pc_logging_enabled',
    'pc_log_retention_days',
    'pc_rate_limit_scan',
    'pc_rate_limit_lookup',
    'pc_rate_limit_security',
    'pc_rate_limit_security_headers',
    'pc_cache_ttl',
    'pc_ip_api_key',
    'pc_reputation_api_key',
    'pc_whois_api_key',
    'pc_dev_mode',
    'pc_secret_salt',
    'pc_pages_seeded',
);
foreach ( $options as $option ) {
    delete_option( $option );
}

// Clean transient cache (scoped).
$wpdb->query(
    "DELETE FROM {$wpdb->options}
     WHERE option_name LIKE '_transient_pc_%'
        OR option_name LIKE '_transient_timeout_pc_%'"
);

// Drop the optional event log table if it exists. We don't depend on it; the
// uninstall must be idempotent.
$table = $wpdb->prefix . 'pc_event_log';
$wpdb->query( "DROP TABLE IF EXISTS {$table}" );