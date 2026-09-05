<?php
/**
 * Server-side IP detection and reverse DNS.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Detect the visitor IP from server variables without trusting proxies blindly.
 */
final class IpDetector {

    /**
     * Determine the visitor's public IP address.
     *
     * @return array{ipv4:?string, ipv6:?string, source:string}
     */
    public static function detect(): array {
        $candidates = array();

        // REMOTE_ADDR is the only value a vanilla PHP server populates reliably.
        $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';

        if ( '' !== $remote ) {
            $candidates[] = $remote;
        }

        $ipv4 = null;
        $ipv6 = null;
        foreach ( $candidates as $candidate ) {
            // Split if both addresses are present (RFC 7239 forwarded).
            foreach ( explode( ',', $candidate ) as $ip ) {
                $ip = trim( $ip );
                if ( '' === $ip ) {
                    continue;
                }
                if ( null === $ipv4 && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                    $ipv4 = $ip;
                } elseif ( null === $ipv6 && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
                    $ipv6 = $ip;
                }
            }
        }

        return array(
            'ipv4'   => $ipv4,
            'ipv6'   => $ipv6,
            'source' => 'REMOTE_ADDR',
        );
    }

    /**
     * Reverse DNS lookup for an IP (best-effort, never throws).
     *
     * @param string $ip IPv4 or IPv6 literal.
     * @return array{hostname:?string, error:?string}
     */
    public static function reverse_dns( string $ip ): array {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return array(
                'hostname' => null,
                'error'    => 'Invalid IP.',
            );
        }
        if ( ! function_exists( 'gethostbyaddr' ) ) {
            return array(
                'hostname' => null,
                'error'    => 'gethostbyaddr unavailable.',
            );
        }

        // gethostbyaddr can hang on broken DNS; bound the time.
        $previous = ini_get( 'default_socket_timeout' );
        @ini_set( 'default_socket_timeout', '2' );

        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        $host = @gethostbyaddr( $ip );

        if ( '' !== $previous ) {
            ini_set( 'default_socket_timeout', $previous );
        }

        if ( false === $host || $host === $ip ) {
            return array(
                'hostname' => null,
                'error'    => 'No reverse DNS record detected.',
            );
        }

        return array(
            'hostname' => $host,
            'error'    => null,
        );
    }
}