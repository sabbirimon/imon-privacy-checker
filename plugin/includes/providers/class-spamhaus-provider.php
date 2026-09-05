<?php
/**
 * Spamhaus reputation provider (DNSBL-based; no API key needed).
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
 * Queries Spamhaus DNSBL lists using PHP's built-in DNS resolver.
 *
 * Note: server-side DNS queries may be subject to environment restrictions
 * and may not exactly mirror Spamhaus' policy. Use this as an indicator only.
 */
final class SpamhausProvider implements ReputationProviderInterface {

    /**
     * Spamhaus zones consulted.
     *
     * @var string[]
     */
    private const ZONES = array(
        'zen.spamhaus.org',          // combined
        'bl.spamcop.net',
    );

    public function key(): string {
        return 'spamhaus';
    }

    public function label(): string {
        return 'Spamhaus DNSBL';
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

        $reverse   = $this->reverse_ip( $ip );
        $sources   = array();
        $any_list  = false;

        foreach ( self::ZONES as $zone ) {
            $host  = $reverse . '.' . $zone;
            $entry = $this->resolve( $host );
            $listed = ! empty( $entry['records'] );
            $sources[] = array(
                'source' => $zone,
                'listed' => $listed,
                'detail' => $listed ? $entry['records'] : null,
            );
            if ( $listed ) {
                $any_list = true;
            }
        }

        return array(
            'status'   => $any_list ? 'listed' : 'clean',
            'ip'       => $ip,
            'provider' => $this->key(),
            'sources'  => $sources,
        );
    }

    /**
     * Reverse an IPv4 address for DNSBL queries (1.2.3.4 → 4.3.2.1).
     */
    private function reverse_ip( string $ip ): string {
        $parts = explode( '.', $ip );
        if ( count( $parts ) === 4 ) {
            return implode( '.', array_reverse( $parts ) );
        }
        // IPv6 reversal would be more involved; we focus on IPv4 here.
        return $ip;
    }

    /**
     * Resolve a hostname and return records.
     *
     * @return array{records: string[]|null, error: ?string}
     */
    private function resolve( string $host ): array {
        if ( ! function_exists( 'dns_get_record' ) ) {
            return array( 'records' => null, 'error' => 'DNS functions unavailable.' );
        }

        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        $records = @dns_get_record( $host, DNS_A );
        if ( false === $records ) {
            return array( 'records' => null, 'error' => 'DNS lookup failed.' );
        }
        $values = array();
        foreach ( $records as $record ) {
            if ( isset( $record['ip'] ) ) {
                $values[] = $record['ip'];
            }
        }
        return array( 'records' => $values, 'error' => null );
    }
}