<?php
/**
 * Rate limiter (hashed identifier, transient-backed).
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Lightweight rate limiting that does not store raw IP addresses.
 *
 * Identifiers are SHA-256 hashes of (salt + raw_ip + bucket_minute). They expire
 * automatically with their transient.
 */
final class RateLimiter {

    /**
     * Check whether the current request is allowed to proceed.
     *
     * @param string $bucket Bucket name (e.g. 'scan', 'lookup', 'security-headers').
     * @param int    $limit  Maximum requests in the window.
     * @return array{allowed:bool, remaining:int, retry_after:int}
     */
    public static function check( string $bucket, int $limit ): array {
        $identifier = self::identifier( $bucket );
        $key        = 'pc_rl_' . $bucket . '_' . $identifier;
        $count      = (int) get_transient( $key );

        $remaining = max( 0, $limit - $count - 1 );
        $retry     = (int) get_transient( $key . '_retry' );

        if ( $count >= $limit ) {
            return array(
                'allowed'     => false,
                'remaining'   => 0,
                'retry_after' => max( 1, $retry - time() ),
            );
        }

        set_transient( $key, $count + 1, MINUTE_IN_SECONDS );
        // Persist retry-after until the window expires.
        if ( ! get_transient( $key . '_retry' ) ) {
            set_transient( $key . '_retry', time() + MINUTE_IN_SECONDS, MINUTE_IN_SECONDS );
        }

        return array(
            'allowed'     => true,
            'remaining'   => $remaining,
            'retry_after' => 0,
        );
    }

    /**
     * Check a caller-specific bucket without storing the raw identifier.
     *
     * @param string $bucket Logical bucket name.
     * @param string $identifier Stable opaque identifier (hashed before storage).
     */
    public static function check_identifier( string $bucket, string $identifier, int $limit ): array {
        $salt = (string) Plugin::instance()->setting( 'secret_salt', 'pc-default-salt' );
        $safe = substr( hash( 'sha256', $salt . '|' . $identifier . '|' . $bucket ), 0, 32 );
        $key  = 'pc_rl_' . sanitize_key( $bucket ) . '_' . $safe;
        $count = (int) get_transient( $key );
        $limit = max( 1, $limit );
        $remaining = max( 0, $limit - $count - 1 );
        $retry = (int) get_transient( $key . '_retry' );

        if ( $count >= $limit ) {
            return array(
                'allowed'     => false,
                'remaining'   => 0,
                'retry_after' => max( 1, $retry - time() ),
            );
        }

        set_transient( $key, $count + 1, MINUTE_IN_SECONDS );
        if ( ! get_transient( $key . '_retry' ) ) {
            set_transient( $key . '_retry', time() + MINUTE_IN_SECONDS, MINUTE_IN_SECONDS );
        }

        return array(
            'allowed'     => true,
            'remaining'   => $remaining,
            'retry_after' => 0,
        );
    }

    /**
     * Generate a per-bucket, per-window identifier that does not reveal the IP.
     */
    private static function identifier( string $bucket ): string {
        $salt    = (string) Plugin::instance()->setting( 'secret_salt', 'pc-default-salt' );
        $ip      = self::client_ip();
        $minute  = (int) floor( time() / MINUTE_IN_SECONDS );

        return substr( hash( 'sha256', $salt . '|' . $ip . '|' . $bucket . '|' . $minute ), 0, 24 );
    }

    /**
     * Best-effort client IP without storing it.
     */
    private static function client_ip(): string {
        // Prefer REMOTE_ADDR; trusted proxies should be configured at the WP level.
        return isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }
}