<?php
/**
 * WHOIS / RDAP provider contract.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Provider;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Looks up registration / network ownership information.
 */
interface WhoisProviderInterface {

    public function key(): string;
    public function label(): string;

    /**
     * Query a domain, IP, or ASN.
     *
     * Returns an array with at minimum:
     *   - status:  'ok' | 'not_found' | 'error'
     *   - query:   the original query string
     *   - type:    'domain' | 'ipv4' | 'ipv6' | 'asn'
     *
     * Plus provider-specific fields (registrar, network, abuse contact, …).
     *
     * @param string $query Domain, IP, or ASN identifier.
     * @return array<string,mixed>
     */
    public function query( string $query ): array;
}