<?php
/**
 * ipinfo.io provider.
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
 * ipinfo.io IP intelligence provider.
 *
 * API reference: https://ipinfo.io/developers
 */
final class IpinfoProvider implements IpIntelligenceProviderInterface {

    public function key(): string {
        return 'ipinfo';
    }

    public function label(): string {
        return 'ipinfo.io';
    }

    public function lookup( string $ip ): array {
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => 'Invalid IP address.',
            );
        }

        $api_key = (string) Plugin::instance()->setting( 'ip_api_key', '' );
        $url     = 'https://ipinfo.io/' . rawurlencode( $ip ) . '/json';
        if ( '' !== $api_key ) {
            $url .= '?token=' . rawurlencode( $api_key );
        }

        $response = wp_remote_get(
            $url,
            array(
                'timeout'     => 5,
                'redirection' => 0,
                'user-agent'  => 'PrivacyChecker/' . PRIVACY_CHECKER_VERSION . ' (WordPress)',
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => $response->get_error_message(),
            );
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code === 429 ) {
            return array(
                'status' => 'unavailable',
                'ip'     => $ip,
                'error'  => 'Rate limit reached.',
            );
        }
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'status' => 'unavailable',
                'ip'     => $ip,
                'error'  => 'ipinfo responded with HTTP ' . (int) $code . '.',
            );
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => 'Malformed response from ipinfo.',
            );
        }

        // ipinfo nests org in "org" string; split into ASN.
        if ( isset( $data['org'] ) && is_string( $data['org'] ) && strpos( $data['org'], 'AS' ) === 0 ) {
            $parts = explode( ' ', $data['org'], 2 );
            $data['asn']    = $parts[0];
            $data['asn_org'] = $parts[1] ?? '';
        }

        return array_merge(
            array( 'status' => 'ok', 'ip' => $ip ),
            array_change_key_case( $data, CASE_LOWER )
        );
    }
}