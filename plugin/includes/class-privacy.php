<?php
/**
 * Privacy controls — logging, retention, anonymization.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Centralised privacy-by-default behaviors.
 */
final class Privacy {

    /**
     * Register WordPress lifecycle hooks for retention enforcement.
     */
    public static function register_hooks(): void {
        // Daily cleanup if logging is enabled.
        add_action( 'wp_scheduled_delete', array( self::class, 'enforce_retention' ) );
        add_action( 'admin_init', array( self::class, 'maybe_schedule_retention' ) );
    }

    /**
     * Decide whether raw IPs may be logged.
     *
     * Admin must explicitly enable logging AND set a positive retention period.
     */
    public static function raw_ip_logging_allowed(): bool {
        $enabled  = (bool) Plugin::instance()->setting( 'logging_enabled', false );
        $retention = (int) Plugin::instance()->setting( 'log_retention_days', 0 );
        return $enabled && $retention > 0;
    }

    /**
     * Hash an IP for low-trust retention use (e.g. short-lived rate limiting).
     */
    public static function hash_ip( string $ip ): string {
        $salt = (string) Plugin::instance()->setting( 'secret_salt', 'pc-default-salt' );
        return substr( hash( 'sha256', $salt . '|' . $ip ), 0, 32 );
    }

    /**
     * Enforce configured retention on the privacy_checker_log table.
     */
    public static function enforce_retention(): void {
        $retention = (int) Plugin::instance()->setting( 'log_retention_days', 0 );
        if ( $retention <= 0 ) {
            return;
        }
        global $wpdb;
        $table = self::log_table();
        // Guard: the table is created lazily only when logging is enabled. Bail
        // out if it doesn't exist (e.g. fresh install where admin never turned
        // logging on). This keeps the cron safe to schedule on every request.
        $exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
        if ( $exists !== $table ) {
            return;
        }
        $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", gmdate( 'Y-m-d H:i:s', time() - ( $retention * DAY_IN_SECONDS ) ) ) );
    }

    /**
     * Schedule a daily cleanup event when logging is enabled.
     */
    public static function maybe_schedule_retention(): void {
        if ( ! self::raw_ip_logging_allowed() ) {
            return;
        }
        if ( ! wp_next_scheduled( 'pc_retention_cron' ) ) {
            wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'pc_retention_cron' );
        }
        add_action( 'pc_retention_cron', array( self::class, 'enforce_retention' ) );
    }

    /**
     * Name of the optional log table.
     */
    public static function log_table(): string {
        global $wpdb;
        return $wpdb->prefix . 'pc_scan_log';
    }
}