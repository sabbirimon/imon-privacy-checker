<?php
/**
 * Reputation — orchestrator with caching.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use PrivacyChecker\Provider\ReputationProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class Reputation {

    /**
     * Check an IP's reputation with caching.
     *
     * @param string $ip
     * @return array<string,mixed>
     */
    public static function check( string $ip ): array {
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return array(
                'status'   => 'error',
                'ip'       => $ip,
                'provider' => 'none',
                'error'    => 'Non-public IP literals are not checked.',
            );
        }

        $cache_key = 'reputation_' . strtolower( $ip );
        $cached    = Cache::get( $cache_key );
        if ( is_array( $cached ) ) {
            return $cached;
        }

        $provider_key = (string) Plugin::instance()->setting( 'reputation_provider', 'mock' );
        $provider     = Plugin::instance()->provider( ReputationProviderInterface::class, $provider_key );

        $result = $provider->check( $ip );
        $result['provider_key']  = $provider_key;
        $result['provider_label'] = $provider->label();

        Cache::set( $cache_key, $result );
        return $result;
    }
}