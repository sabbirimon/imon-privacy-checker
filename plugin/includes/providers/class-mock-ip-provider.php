<?php
/**
 * Mock IP intelligence provider (for development & CI).
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Returns clearly marked "DEVELOPMENT DATA" so it cannot be confused with real intelligence.
 */
final class MockIpProvider implements IpIntelligenceProviderInterface {

    public function key(): string {
        return 'mock';
    }

    public function label(): string {
        return 'Mock (Development)';
    }

    public function lookup( string $ip ): array {
        $family = Security::is_public_ip_literal( $ip ) ? 'IPv4' : 'IPv6';
        return array(
            'status'    => 'ok',
            'is_mock'   => true,
            'ip'        => $ip,
            'version'   => $family,
            'city'      => 'Mock City',
            'region'    => 'Mock Region',
            'country'   => 'XX',
            'country_name' => 'Mock Country',
            'postal'    => '00000',
            'latitude'  => 0.0,
            'longitude' => 0.0,
            'timezone'  => 'UTC',
            'org'       => 'AS0 Mock Network',
            'asn'       => 'AS0',
            'asn_org'   => 'Mock Network Operator',
            'hostname'  => 'mock.example.test',
            'note'      => 'DEVELOPMENT DATA — configure a real provider for production.',
        );
    }
}