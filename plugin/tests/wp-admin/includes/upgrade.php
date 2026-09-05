<?php
/**
 * Stub of WP's wp-admin/includes/upgrade.php for the unit test suite.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! function_exists( 'dbDelta' ) ) {
    function dbDelta( string $sql, bool $execute = true ): array {
        return array();
    }
}
if ( ! function_exists( 'wp_should_upgrade_global_tables' ) ) {
    function wp_should_upgrade_global_tables(): bool {
        return false;
    }
}
