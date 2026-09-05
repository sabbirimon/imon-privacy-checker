<?php
/**
 * Mock WHOIS provider.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Provider\WhoisProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

final class MockWhoisProvider implements WhoisProviderInterface {

    public function key(): string {
        return 'mock';
    }

    public function label(): string {
        return 'Mock (Development)';
    }

    public function query( string $query ): array {
        $type = 'domain';
        if ( filter_var( $query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            $type = 'ipv4';
        } elseif ( filter_var( $query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $type = 'ipv6';
        } elseif ( preg_match( '/^AS\d+$/i', $query ) ) {
            $type = 'asn';
        }

        return array(
            'status'   => 'ok',
            'query'    => $query,
            'type'     => $type,
            'is_mock'  => true,
            'handle'   => 'MOCK-' . strtoupper( substr( md5( $query ), 0, 8 ) ),
            'name'     => 'Mock Registry Object',
            'country'  => 'XX',
            'events'   => array(
                'registration' => '1970-01-01T00:00:00Z',
                'last changed' => '1970-01-01T00:00:00Z',
            ),
            'entities'  => array(
                array(
                    'roles'  => array( 'registrar' ),
                    'name'   => 'Mock Registrar Inc.',
                    'handle' => 'MOCKREG',
                ),
            ),
            'note' => 'DEVELOPMENT DATA — configure RDAP for production.',
        );
    }
}