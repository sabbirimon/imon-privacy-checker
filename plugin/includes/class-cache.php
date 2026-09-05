<?php
/**
 * Cache helpers — transient wrapper with sensible defaults.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Transient-backed cache with namespacing.
 */
final class Cache {

    /**
     * Get a cached value.
     *
     * @param string $key Cache key.
     * @return mixed|null Null on miss.
     */
    public static function get( string $key ) {
        return get_transient( self::prefix() . $key );
    }

    /**
     * Set a cached value with a TTL.
     *
     * @param string $key   Cache key.
     * @param mixed  $value Value to store.
     * @param int|null $ttl Time-to-live in seconds. Defaults to plugin setting.
     */
    public static function set( string $key, $value, ?int $ttl = null ): void {
        $ttl = $ttl ?? (int) Plugin::instance()->setting( 'cache_ttl', 3600 );
        set_transient( self::prefix() . $key, $value, max( 60, $ttl ) );
    }

    /**
     * Delete a cached value.
     */
    public static function delete( string $key ): void {
        delete_transient( self::prefix() . $key );
    }

    /**
     * Remember pattern: get if cached, otherwise compute and store.
     *
     * @template T
     * @param string   $key
     * @param callable $callback
     * @param int|null $ttl
     * @return T
     */
    public static function remember( string $key, callable $callback, ?int $ttl = null ) {
        $cached = self::get( $key );
        if ( null !== $cached ) {
            return $cached;
        }
        $value = $callback();
        self::set( $key, $value, $ttl );
        return $value;
    }

    /**
     * Standard key prefix.
     */
    private static function prefix(): string {
        return 'pc_';
    }
}