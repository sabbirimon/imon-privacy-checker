<?php
/**
 * DNS leak test orchestrator.
 *
 * IMPORTANT: A web page cannot reliably enumerate every DNS resolver used by
 * a visitor's operating system. A real DNS leak test requires dedicated DNS
 * infrastructure that the operator runs (or subscribes to). When such
 * infrastructure is unavailable, this module reports that honestly and the UI
 * renders the "Not available" state.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Token-based DNS leak test plumbing.
 *
 * The default provider is `none`. To enable a real test, deploy dedicated DNS
 * infrastructure and configure a provider. The plugin ships with hooks to
 * integrate providers without modifying core code.
 */
final class DnsTest {

    /**
     * Whether DNS leak testing is wired to a real provider.
     */
    public static function is_configured(): bool {
        $enabled  = (bool) Plugin::instance()->setting( 'dns_test_enabled', false );
        $provider = (string) Plugin::instance()->setting( 'dns_provider', 'none' );
        return $enabled && in_array( $provider, array( 'doh-fanout', 'token+doh' ), true );
    }

    /**
     * Issue a token for the client to use in DNS lookups.
     *
     * Returns an array with:
     *   - token:     random identifier
     *   - hostnames: list of hostnames the client should resolve
     *   - ttl:       how long the token is valid
     *
     * @return array<string,mixed>
     */
    public static function issue_token(): array {
        $token  = bin2hex( random_bytes( 16 ) );
        $host   = self::resolve_test_hostname();

        $payload = array(
            'token'     => $token,
            'hostnames' => $host ? array( sprintf( '%s.%s', $token, $host ) ) : array(),
            'ttl'       => 120,
            'timestamp' => time(),
        );

        // Persist the token server-side so the verifier can look it up later.
        set_transient( 'pc_dns_token_' . $token, array(
            'hostnames' => $payload['hostnames'],
            'issued'    => $payload['timestamp'],
        ), $payload['ttl'] );

        return $payload;
    }

    /**
     * Verify a token by consulting the configured DNS test provider.
     *
     * If no provider is configured, returns a `not_configured` status so the UI
     * can clearly say so.
     *
     * @param string $token Token returned by issue_token().
     * @return array<string,mixed>
     */
    public static function verify_token( string $token ): array {
        $token = preg_replace( '/[^a-f0-9]/', '', strtolower( (string) $token ) );
        if ( '' === $token || strlen( $token ) !== 32 ) {
            return array(
                'status'  => 'invalid',
                'message' => 'Token is malformed.',
            );
        }

        $stored = get_transient( 'pc_dns_token_' . $token );
        if ( ! is_array( $stored ) ) {
            return array(
                'status'  => 'expired',
                'message' => 'Token expired or unknown.',
            );
        }

        if ( ! self::is_configured() ) {
            return array(
                'status'  => 'not_configured',
                'message' => 'DNS leak testing requires an external DNS test service. Not configured on this server.',
                'token'   => $token,
            );
        }

        // The plugin ships with no real DNS provider; an installed provider
        // would call out to its own DNS infrastructure here.
        return apply_filters(
            'privacy_checker_dns_verify',
            array(
                'status'  => 'not_configured',
                'message' => 'DNS leak testing requires an external DNS test service.',
                'token'   => $token,
            ),
            $token,
            $stored
        );
    }

    /**
     * Determine the configured DNS test hostname.
     */
    private static function resolve_test_hostname(): ?string {
        $configured = (string) Plugin::instance()->setting( 'dns_provider', 'none' );
        if ( 'none' === $configured ) {
            return null;
        }
        $base = (string) Plugin::instance()->setting( 'dns_test_hostname_base', '' );
        $base = strtolower( trim( $base ) );
        $base = preg_replace( '/[^a-z0-9.-]/', '', $base );
        if ( '' !== $base && preg_match( '/^[a-z0-9.-]+\.[a-z]{2,}$/', $base ) ) {
            return $base;
        }
        $host = apply_filters( 'privacy_checker_dns_hostname', null, $configured );
        return is_string( $host ) && '' !== $host ? $host : null;
    }

    /**
     * Run a real DNS-over-HTTPS fan-out to detect resolver usage.
     *
     * Returns the same shape as `verify_token()` (status, message, resolvers)
     * but with concrete data when configured. The "token" field is the
     * unique probe id we surface to the browser so it can correlate its
     * own no-cors timings with our server results.
     *
     * @param string|null $hostname Optional override; otherwise uses the
     *                              configured `dns_test_hostname_base`.
     * @return array<string,mixed>
     */
    public static function run_doh_probe( ?string $hostname = null ): array {
        $token = bin2hex( random_bytes( 8 ) );

        if ( ! self::is_configured() ) {
            return array(
                'status'    => 'not_configured',
                'message'   => 'DNS leak testing is disabled.',
                'token'     => $token,
                'resolvers' => array(),
                'leak_score'=> 0.0,
                'consistent'=> true,
            );
        }

        $target = trim( (string) ( $hostname ?: Plugin::instance()->setting( 'dns_test_hostname_base', 'cloudflare.com' ) ) );
        if ( '' === $target ) {
            return array(
                'status'    => 'error',
                'message'   => 'No DNS test hostname configured.',
                'token'     => $token,
                'resolvers' => array(),
                'leak_score'=> 0.0,
                'consistent'=> true,
            );
        }

        $settings  = (array) get_option( Settings::OPTION_KEY, array() );
        $chain     = (array) ( $settings['dns_provider_chain'] ?? array( 'free', 'online', 'paid', 'local' ) );
        $configured_resolvers = (array) ( $settings['dns_resolvers'] ?? NetworkProbe::default_dns_resolvers() );
        $chain_resolvers      = NetworkProbe::resolver_chain_for_tiers( $chain, $settings );

        // Free tier wins by default; admin's custom resolvers override; tier
        // resolvers only fill in if the configured list is missing entries.
        $resolvers = array_merge( $chain_resolvers, $configured_resolvers );
        $timeout   = (int) ( $settings['dns_query_timeout_sec'] ?? 3 );

        $probe = NetworkProbe::doh_probe( $target, $resolvers, $timeout );

        // Annotate each row with its source tier so the UI can show provenance.
        $tier_map = self::build_tier_map( $resolvers, $chain, $settings );

        $annotated = array();
        foreach ( ( $probe['resolvers'] ?? array() ) as $row ) {
            $name = (string) ( $row['name'] ?? '' );
            $row['source_tier'] = $tier_map[ $name ] ?? 'custom';
            $annotated[]        = $row;
        }

        return array(
            'status'     => $probe['status'],
            'token'      => $token,
            'hostname'   => $target,
            'resolvers'  => $annotated,
            'chain'      => $chain,
            'leak_score' => $probe['leak_score'] ?? 0.0,
            'consistent' => $probe['consistent'] ?? true,
            'message'    => 'ok' === $probe['status']
                ? 'Probe complete.'
                : 'One or more resolvers failed.',
        );
    }

    /**
     * Map resolver name to its source tier for UI attribution.
     *
     * @param array<string,string> $resolvers
     * @param string[]             $chain
     * @param array<string,mixed>  $settings
     * @return array<string,string>
     */
    private static function build_tier_map( array $resolvers, array $chain, array $settings ): array {
        $map = array();
        $free_names = array_keys( NetworkProbe::default_dns_resolvers() );
        $online_names = array_keys( NetworkProbe::online_dns_resolvers() );
        $paid_endpoint = (string) ( $settings['dns_paid_endpoint'] ?? '' );
        $local = (array) ( $settings['dns_local_resolvers'] ?? array() );
        foreach ( $resolvers as $name => $_url ) {
            if ( in_array( $name, $free_names, true ) )         { $map[ $name ] = 'free'; }
            else if ( in_array( $name, $online_names, true ) )   { $map[ $name ] = 'online'; }
            else if ( 'paid' === $name )                         { $map[ $name ] = 'paid'; }
            else if ( str_starts_with( $name, 'local-' ) )       { $map[ $name ] = 'local'; }
            else                                                 { $map[ $name ] = 'custom'; }
        }
        return $map;
    }
}