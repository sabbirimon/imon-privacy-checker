<?php
/**
 * iphub.info reputation provider.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Provider\ReputationProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Uses iphub.info (free tier requires API key).
 *
 * API reference: https://iphub.info/
 */
final class IphubProvider implements ReputationProviderInterface {

    public function key(): string {
        return 'iphub';
    }

    public function label(): string {
        return 'iphub.info';
    }

    public function check( string $ip ): array {
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return array(
                'status'  => 'error',
                'ip'      => $ip,
                'provider'=> $this->key(),
                'error'   => 'Invalid IP address.',
            );
        }

        $api_key = (string) Plugin::instance()->setting( 'reputation_api_key', '' );
        if ( '' === $api_key ) {
            return array(
                'status'  => 'unknown',
                'ip'      => $ip,
                'provider'=> $this->key(),
                'error'   => 'API key not configured.',
            );
        }

        $response = wp_remote_get(
            'https://iphub.info/api/' . rawurlencode( $ip ),
            array(
                'timeout' => 5,
                'headers' => array( 'X-Key' => $api_key ),
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status'   => 'error',
                'ip'       => $ip,
                'provider' => $this->key(),
                'error'    => $response->get_error_message(),
            );
        }

        $code = wp_remote_retrieve_response_code( $response );
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'status'   => 'unavailable',
                'ip'       => $ip,
                'provider' => $this->key(),
                'error'    => 'iphub responded with HTTP ' . (int) $code . '.',
            );
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return array(
                'status'   => 'error',
                'ip'       => $ip,
                'provider' => $this->key(),
                'error'    => 'Malformed response from iphub.',
            );
        }

        $status = 'unknown';
        if ( isset( $data['block'] ) ) {
            $block = (int) $data['block'];
            $status = ( 1 === $block ) ? 'listed' : 'clean';
        } elseif ( isset( $data['countryCode'] ) && isset( $data['asn'] ) ) {
            // free tier sometimes returns country/ASN without block verdict
            $status = 'unknown';
        }

        return array(
            'status'   => $status,
            'ip'       => $ip,
            'provider' => $this->key(),
            'raw'      => $data,
        );
    }
}