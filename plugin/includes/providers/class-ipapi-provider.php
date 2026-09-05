<?php
/**
 * ipapi.com provider.
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
 * Uses ipapi.com free tier (no key required for limited use).
 *
 * API reference: https://ipapi.com/api
 */
final class IpapiProvider implements IpIntelligenceProviderInterface {

    public function key(): string {
        return 'ipapi';
    }

    public function label(): string {
        return 'ipapi.com';
    }

    public function lookup( string $ip ): array {
        $base = 'https://ipapi.com';
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => 'Invalid IP address.',
            );
        }

        $url = $base . '/' . rawurlencode( $ip ) . '?format=json';

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
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'status' => 'unavailable',
                'ip'     => $ip,
                'error'  => 'ipapi responded with HTTP ' . (int) $code . '.',
            );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );
        if ( ! is_array( $data ) ) {
            return array(
                'status' => 'error',
                'ip'     => $ip,
                'error'  => 'Malformed response from ipapi.',
            );
        }

        return array_merge(
            array(
                'status' => 'ok',
                'ip'     => $ip,
            ),
            array_change_key_case( $data, CASE_LOWER )
        );
    }
}