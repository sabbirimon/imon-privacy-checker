<?php
/**
 * Reputation / blacklist provider contract.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Provider;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Reports whether an IP appears in any reputation database the provider has access to.
 */
interface ReputationProviderInterface {

    public function key(): string;
    public function label(): string;

    /**
     * Check an IP address.
     *
     * Returns an array with at least:
     *   - status:   'clean' | 'listed' | 'suspicious' | 'unknown' | 'error'
     *   - provider: provider key
     *   - ip:       queried IP
     *   - sources:  list of named sources and their verdict (when available)
     *
     * @param string $ip IPv4 or IPv6 literal.
     * @return array<string,mixed>
     */
    public function check( string $ip ): array;
}