<?php
/**
 * IP intelligence — orchestrates provider lookup with caching.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use PrivacyChecker\Provider\IpIntelligenceProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Convenience wrapper that adds caching and provider selection around
 * IpIntelligenceProviderInterface implementations.
 */
final class IpIntelligence {

    /**
     * Look up an IP via the configured provider.
     *
     * @param string $ip
     * @return array<string,mixed>
     */
    public static function lookup( string $ip ): array {
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => 'Non-public IP literals are not looked up.',
            );
        }

        $cache_key = 'ipintel_' . strtolower( $ip );
        $cached    = Cache::get( $cache_key );
        if ( is_array( $cached ) ) {
            return $cached;
        }

        $provider_key = (string) Plugin::instance()->setting( 'ip_provider', 'mock' );
        $provider     = Plugin::instance()->provider( IpIntelligenceProviderInterface::class, $provider_key );

        $result = $provider->lookup( $ip );
        $result['provider_key']  = $provider_key;
        $result['provider_label'] = $provider->label();

        Cache::set( $cache_key, $result );
        return $result;
    }
}