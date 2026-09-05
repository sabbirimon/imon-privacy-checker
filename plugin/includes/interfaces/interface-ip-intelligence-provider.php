<?php
/**
 * IP intelligence provider contract.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Provider;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Resolves an IP address to geographic and network metadata.
 */
interface IpIntelligenceProviderInterface {

    /**
     * Provider identifier (ipapi, ipinfo, mock, …).
     */
    public function key(): string;

    /**
     * Human-friendly label.
     */
    public function label(): string;

    /**
     * Look up information for a single IP.
     *
     * Implementations MUST return an array with at minimum:
     *   - status: 'ok' | 'error' | 'unavailable'
     *   - ip:     the queried IP (string)
     * Plus any additional fields supported by the provider.
     *
     * Implementations MUST NOT throw; instead return status => 'error' with a message.
     *
     * @param string $ip IPv4 or IPv6 literal.
     * @return array<string,mixed>
     */
    public function lookup( string $ip ): array;
}