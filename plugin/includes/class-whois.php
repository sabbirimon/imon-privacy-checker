<?php
/**
 * WHOIS / RDAP — orchestrator with caching.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use PrivacyChecker\Provider\WhoisProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class Whois {

    /**
     * Query the configured WHOIS / RDAP provider with caching.
     *
     * @param string $query
     * @return array<string,mixed>
     */
    public static function query( string $query ): array {
        $query = trim( $query );
        if ( '' === $query ) {
            return array(
                'status' => 'error',
                'query'  => $query,
                'error'  => 'Query is required.',
            );
        }

        $cache_key = 'whois_' . md5( strtolower( $query ) );
        $cached    = Cache::get( $cache_key );
        if ( is_array( $cached ) ) {
            return $cached;
        }

        $provider_key = (string) Plugin::instance()->setting( 'whois_provider', 'mock' );
        $provider     = Plugin::instance()->provider( WhoisProviderInterface::class, $provider_key );

        $result = $provider->query( $query );
        $result['provider_key']   = $provider_key;
        $result['provider_label'] = $provider->label();

        Cache::set( $cache_key, $result );
        return $result;
    }
}