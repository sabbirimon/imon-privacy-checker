<?php
/**
 * RDAP WHOIS provider with free IANA + port-43 fallback.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Provider\WhoisProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Primary path: RDAP (Registration Data Access Protocol) via the public
 * rdap.org bootstrap. RDAP coverage is excellent for gTLDs and growing for
 * ccTLDs, but a few TLDs (e.g. .io, .ai, some country-code zones) have no
 * RDAP service. For those, fall back to the IANA WHOIS referral + raw
 * port-43 query to the authoritative registry WHOIS server. Both are free
 * public services — no API key required.
 *
 * Reference: https://www.iana.org/domains/root/db
 */
final class RdapWhoisProvider implements WhoisProviderInterface {

    /** WHOIS port (RFC 3912). */
    private const WHOIS_PORT = 43;

    /** TCP read timeout for the port-43 connection. */
    private const WHOIS_TIMEOUT_SEC = 8.0;

    /** Default IANA referral server. */
    private const IANA_WHOIS_HOST = 'whois.iana.org';

    /** Cache TTL for the IANA referral lookup. */
    private const REFERRAL_CACHE_TTL = DAY_IN_SECONDS;

    /** Cache TTL for a successful port-43 record. */
    private const RECORD_CACHE_TTL = 6 * HOUR_IN_SECONDS;

    public function key(): string {
        return 'rdap';
    }

    public function label(): string {
        return 'RDAP (IANA bootstrap)';
    }

    public function query( string $query ): array {
        $type = $this->classify( $query );
        if ( 'unknown' === $type ) {
            return array(
                'status'  => 'error',
                'query'   => $query,
                'type'    => $type,
                'error'   => 'Cannot classify query. Provide a domain, IP, or ASN.',
            );
        }

        switch ( $type ) {
            case 'ipv4':
            case 'ipv6':
                return $this->query_ip( $query, $type );
            case 'domain':
                return $this->query_domain( $query );
            case 'asn':
                return $this->query_asn( $query );
            default:
                return array(
                    'status' => 'error',
                    'query'  => $query,
                    'type'   => $type,
                    'error'  => 'Unsupported query type.',
                );
        }
    }

    /**
     * Classify a query string.
     */
    private function classify( string $query ): string {
        $query = trim( $query );
        if ( '' === $query ) {
            return 'unknown';
        }
        if ( filter_var( $query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return 'ipv4';
        }
        if ( filter_var( $query, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            return 'ipv6';
        }
        if ( preg_match( '/^AS\d+$/i', $query ) ) {
            return 'asn';
        }
        if ( preg_match( '/^[a-z0-9.\-]+\.[a-z]{2,}$/i', $query ) ) {
            return 'domain';
        }
        return 'unknown';
    }

    /**
     * Query RDAP for an IP.
     */
    private function query_ip( string $ip, string $type ): array {
        $url = 'https://rdap.org/' . strtolower( $type ) . '/' . rawurlencode( $ip );

        $response = wp_remote_get(
            $url,
            array(
                'timeout'    => 5,
                'redirection'=> 3,
                'headers'    => array( 'Accept' => 'application/rdap+json' ),
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status' => 'error',
                'query'  => $ip,
                'type'   => $type,
                'error'  => $response->get_error_message(),
            );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( 404 === $code ) {
            return array(
                'status' => 'not_found',
                'query'  => $ip,
                'type'   => $type,
            );
        }
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'status' => 'error',
                'query'  => $ip,
                'type'   => $type,
                'error'  => 'RDAP responded with HTTP ' . $code . '.',
            );
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return array(
                'status' => 'error',
                'query'  => $ip,
                'type'   => $type,
                'error'  => 'Malformed RDAP response.',
            );
        }

        return array(
            'status'   => 'ok',
            'query'    => $ip,
            'type'     => $type,
            'handle'   => $data['handle'] ?? null,
            'name'     => $data['name'] ?? null,
            'country'  => $data['country'] ?? null,
            'start_ip' => $data['startAddress'] ?? null,
            'end_ip'   => $data['endAddress'] ?? null,
            'entities' => $this->summarize_entities( $data['entities'] ?? array() ),
        );
    }

    /**
     * Query RDAP for a domain.
     *
     * RDAP has gaps for some TLDs (e.g. .io, .ai). When rdap.org 404s,
     * fall back to the IANA WHOIS referral + port-43 query to the
     * authoritative registry. Both are free public services.
     */
    private function query_domain( string $domain ): array {
        $url = 'https://rdap.org/domain/' . rawurlencode( $domain );

        $response = wp_remote_get(
            $url,
            array(
                'timeout'    => 5,
                'redirection'=> 3,
                'headers'    => array( 'Accept' => 'application/rdap+json' ),
            )
        );

        if ( is_wp_error( $response ) ) {
            // Don't bail — try the IANA/port-43 fallback below.
            $rdap_error = $response->get_error_message();
        } else {
            $code = (int) wp_remote_retrieve_response_code( $response );
            if ( 404 === $code ) {
                // RDAP has no record for this TLD — fall through to IANA.
                return $this->query_domain_fallback( $domain );
            }
            if ( $code < 200 || $code >= 300 ) {
                return array(
                    'status' => 'error',
                    'query'  => $domain,
                    'type'   => 'domain',
                    'error'  => 'RDAP responded with HTTP ' . $code . '.',
                );
            }

            $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
            if ( ! is_array( $data ) ) {
                return array(
                    'status' => 'error',
                    'query'  => $domain,
                    'type'   => 'domain',
                    'error'  => 'Malformed RDAP response.',
                );
            }

            $events = array();
            foreach ( ( $data['events'] ?? array() ) as $event ) {
                if ( isset( $event['eventAction'] ) && isset( $event['eventDate'] ) ) {
                    $events[ $event['eventAction'] ] = $event['eventDate'];
                }
            }

            return array(
                'status'   => 'ok',
                'source'   => 'rdap',
                'query'    => $domain,
                'type'     => 'domain',
                'handle'   => $data['handle'] ?? null,
                'ldh_name' => $data['ldhName'] ?? $domain,
                'statuses' => $data['status'] ?? array(),
                'events'   => $events,
                'entities' => $this->summarize_entities( $data['entities'] ?? array() ),
            );
        }

        // WP error path — try the fallback once before giving up.
        $fallback = $this->query_domain_fallback( $domain );
        if ( 'ok' === ( $fallback['status'] ?? '' ) ) {
            return $fallback;
        }
        return array(
            'status' => 'error',
            'query'  => $domain,
            'type'   => 'domain',
            'error'  => $rdap_error ?? 'RDAP request failed and IANA fallback returned no data.',
        );
    }

    /**
     * IANA WHOIS referral + port-43 query fallback.
     *
     * Steps:
     *   1. Ask whois.iana.org for the TLD of $domain. IANA returns the
     *      authoritative WHOIS server in its `whois:` / `refer:` field.
     *   2. Open a TCP connection to that WHOIS server on port 43 and
     *      submit the domain. Parse the standard "Domain Name: …" etc.
     *      fields out of the response.
     *
     * The result is normalized to look like an RDAP record so the UI
     * doesn't need a separate rendering path.
     *
     * @return array<string,mixed>
     */
    private function query_domain_fallback( string $domain ): array {
        $cache_key = 'pc_whois_fallback_' . md5( strtolower( $domain ) );
        $cached    = get_transient( $cache_key );
        if ( is_array( $cached ) ) {
            return $cached;
        }

        $referral = $this->iana_referral( $domain );
        if ( '' === $referral ) {
            $result = array(
                'status' => 'not_found',
                'source' => 'iana-whois',
                'query'  => $domain,
                'type'   => 'domain',
                'error'  => 'IANA returned no WHOIS referral for this TLD.',
            );
            set_transient( $cache_key, $result, HOUR_IN_SECONDS );
            return $result;
        }

        $record = $this->whois_port_43_query( $referral, $domain );
        if ( '' === $record ) {
            $result = array(
                'status' => 'error',
                'source' => 'iana-whois',
                'query'  => $domain,
                'type'   => 'domain',
                'error'  => sprintf(
                    'WHOIS server %s did not respond.',
                    $referral
                ),
            );
            set_transient( $cache_key, $result, HOUR_IN_SECONDS );
            return $result;
        }

        $parsed = $this->parse_whois_text( $record, $domain, $referral );
        if ( 'ok' !== ( $parsed['status'] ?? '' ) ) {
            set_transient( $cache_key, $parsed, HOUR_IN_SECONDS );
            return $parsed;
        }

        set_transient( $cache_key, $parsed, self::RECORD_CACHE_TTL );
        return $parsed;
    }

    /**
     * Ask whois.iana.org for the authoritative WHOIS server of $domain's TLD.
     * Returns a hostname (without port) or '' on failure.
     */
    private function iana_referral( string $domain ): string {
        $cache_key = 'pc_whois_referral_' . md5( strtolower( $domain ) );
        $cached    = get_transient( $cache_key );
        if ( is_string( $cached ) ) {
            return $cached;
        }

        $raw = $this->whois_port_43_query( self::IANA_WHOIS_HOST, $domain );
        if ( '' === $raw ) {
            set_transient( $cache_key, '', HOUR_IN_SECONDS );
            return '';
        }

        $referral = '';
        foreach ( preg_split( '/\r?\n/', $raw ) as $line ) {
            // IANA prefixes its lines with 8 spaces (the contact-block
            // formatting); tolerate leading whitespace.
            if ( preg_match( '/^\s*(?:whois|refer):\s*([^\s]+)/i', $line, $m ) ) {
                $referral = strtolower( trim( $m[1] ) );
                break;
            }
        }

        // Validate the referral is a plausible hostname and not a URL.
        if ( '' !== $referral && ! preg_match( '/^[a-z0-9.\-]+$/i', $referral ) ) {
            $referral = '';
        }

        set_transient( $cache_key, $referral, self::REFERRAL_CACHE_TTL );
        return $referral;
    }

    /**
     * Open a TCP connection to $host:43, send $query, return the response.
     *
     * @return string Empty string on connection failure or empty reply.
     */
    private function whois_port_43_query( string $host, string $query ): string {
        // Some registries (Verisign) require a `=` prefix; others reject it.
        // Try the bare query first, then the prefixed form, then fall back
        // to whichever response has more content.
        $bare = $this->whois_tcp( $host, $query . "\r\n" );
        if ( '' !== $bare ) {
            return $bare;
        }
        return $this->whois_tcp( $host, "=" . $query . "\r\n" );
    }

    /**
     * One TCP round-trip to a WHOIS server.
     *
     * Strategy:
     *   - Send the query.
     *   - Try with a half-close (STREAM_SHUT_WR) first; many WHOIS servers
     *     (Verisign, Identity Digital) wait for the client to indicate it
     *     is done sending before responding.
     *   - If that yields zero bytes (some servers, e.g. IANA, use the
     *     connection-close itself as EOF), retry without the half-close
     *     and rely on stream timeouts.
     */
    private function whois_tcp( string $host, string $payload ): string {
        $with_shutdown = $this->whois_tcp_once( $host, $payload, true );
        if ( '' !== $with_shutdown ) {
            return $with_shutdown;
        }
        return $this->whois_tcp_once( $host, $payload, false );
    }

    /**
     * Single attempt at a WHOIS TCP round-trip.
     */
    private function whois_tcp_once( string $host, string $payload, bool $half_close ): string {
        $errno  = 0;
        $errstr = '';
        $fp     = @stream_socket_client(
            'tcp://' . $host . ':' . self::WHOIS_PORT,
            $errno,
            $errstr,
            self::WHOIS_TIMEOUT_SEC,
            STREAM_CLIENT_CONNECT
        );
        if ( ! $fp ) {
            return '';
        }

        // Many WHOIS servers want a UA-style greeting. Some reject bare
        // domain queries if no identifying banner is sent.
        @fwrite( $fp, $payload );
        if ( $half_close ) {
            @stream_socket_shutdown( $fp, STREAM_SHUT_WR );
        }

        stream_set_timeout( $fp, (int) self::WHOIS_TIMEOUT_SEC );

        $out = '';
        while ( ! feof( $fp ) ) {
            $chunk = @fread( $fp, 4096 );
            if ( false === $chunk || '' === $chunk ) {
                break;
            }
            $out .= $chunk;
        }
        @fclose( $fp );
        return trim( $out );
    }

    /**
     * Parse a flat-key WHOIS text response into a normalized record.
     *
     * Output mirrors the RDAP shape so the UI doesn't need a separate
     * rendering path: `events`, `entities`, `statuses`, `nameservers`.
     *
     * @return array<string,mixed>
     */
    private function parse_whois_text( string $text, string $domain, string $server ): array {
        $lines = preg_split( '/\r?\n/', $text );

        $fields = array();
        foreach ( $lines as $line ) {
            // Most WHOIS records use "Field: Value" — sometimes the value
            // continues on subsequent indented lines, which we ignore.
            if ( preg_match( '/^([^:\r\n]+):\s*(.*)$/', $line, $m ) ) {
                $key                          = strtolower( trim( $m[1] ) );
                $fields[ $key ][]             = trim( $m[2] );
            }
        }

        $first = function ( string $key ) use ( &$fields ): ?string {
            return $fields[ $key ][0] ?? null;
        };

        $events = array();
        $map    = array(
            'creation date'        => 'registration',
            'created'              => 'registration',
            'registered'           => 'registration',
            'updated date'         => 'last changed',
            'updated'              => 'last changed',
            'last updated'         => 'last changed',
            'registry expiry date' => 'expiration',
            'expiry date'          => 'expiration',
            'expires'              => 'expiration',
            'expiration'           => 'expiration',
        );
        foreach ( $map as $src => $event ) {
            $val = $first( $src );
            if ( null !== $val && '' !== $val ) {
                // Normalize ISO timestamps.
                $events[ $event ] = $this->normalize_date( $val );
            }
        }

        $statuses = $fields['domain status'] ?? $fields['status'] ?? array();
        $statuses = array_values( array_unique( array_filter( $statuses, 'strlen' ) ) );

        $nameservers = $fields['name server'] ?? $fields['nserver'] ?? array();
        $nameservers = array_values(
            array_filter(
                array_map(
                    static function ( string $ns ): string {
                        // Strip trailing dot; lower-case.
                        return strtolower( rtrim( $ns, '.' ) );
                    },
                    $nameservers
                ),
                'strlen'
            )
        );

        $registrar = $first( 'registrar' );
        $abuse     = $first( 'registrar abuse contact email' ) ?: $first( 'abuse contact email' );

        $entities = array();
        if ( null !== $registrar && '' !== $registrar ) {
            $entities[] = array(
                'roles' => array( 'registrar' ),
                'name'  => $registrar,
                'handle'=> null,
            );
        }
        $registrant_org = $first( 'registrant organization' );
        if ( null !== $registrant_org && '' !== $registrant_org ) {
            $entities[] = array(
                'roles' => array( 'registrant' ),
                'name'  => $registrant_org,
                'handle'=> null,
            );
        }

        $created = $events['registration'] ?? null;

        // Reject obviously-empty parses so we surface a clear "not found"
        // rather than a row with everything blank.
        if (
            empty( $events )
            && empty( $statuses )
            && null === $registrar
            && empty( $nameservers )
        ) {
            return array(
                'status' => 'not_found',
                'source' => 'iana-whois',
                'query'  => $domain,
                'type'   => 'domain',
                'whois_server' => $server,
                'error'  => 'WHOIS server returned no parseable fields.',
            );
        }

        return array(
            'status'        => 'ok',
            'source'        => 'iana-whois',
            'query'         => $domain,
            'type'          => 'domain',
            'handle'        => $first( 'registry domain id' ) ?: $first( 'domain id' ),
            'ldh_name'      => $domain,
            'whois_server'  => $server,
            'registrar'     => $registrar,
            'abuse_email'   => $abuse,
            'statuses'      => $statuses,
            'events'        => $events,
            'nameservers'   => $nameservers,
            'entities'      => $entities,
            'created_at'    => $created,
            'raw_excerpt'   => $this->raw_excerpt( $lines, 40 ),
        );
    }

    /**
     * Best-effort normalization of WHOIS date strings to ISO 8601.
     */
    private function normalize_date( string $value ): string {
        $value = trim( $value );
        // Already ISO-ish?
        if ( preg_match( '/^\d{4}-\d{2}-\d{2}/', $value ) ) {
            return $value;
        }
        $ts = strtotime( $value );
        if ( false !== $ts ) {
            return gmdate( 'Y-m-d\TH:i:s\Z', $ts );
        }
        return $value;
    }

    /**
     * Trim a WHOIS text dump to the most useful first N lines for the UI
     * "raw" view, dropping the long ICANN legal footer.
     */
    private function raw_excerpt( array $lines, int $limit ): array {
        $out = array();
        foreach ( $lines as $line ) {
            $trim = trim( $line );
            if ( '' === $trim ) {
                continue;
            }
            // Cut off the long ICANN terms-of-use paragraphs.
            if ( preg_match( '/^(For more information|Terms of Use|URL of the ICANN|>>> Last update|>>>)/i', $trim ) ) {
                break;
            }
            $out[] = $trim;
            if ( count( $out ) >= $limit ) {
                break;
            }
        }
        return $out;
    }

    /**
     * Query RDAP for an ASN.
     */
    private function query_asn( string $asn ): array {
        // RDAP.org routes ASN queries too.
        $url = 'https://rdap.org/autnum/' . rawurlencode( strtoupper( $asn ) );

        $response = wp_remote_get(
            $url,
            array(
                'timeout'    => 5,
                'redirection'=> 3,
                'headers'    => array( 'Accept' => 'application/rdap+json' ),
            )
        );

        if ( is_wp_error( $response ) ) {
            return array(
                'status' => 'error',
                'query'  => $asn,
                'type'   => 'asn',
                'error'  => $response->get_error_message(),
            );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( 404 === $code ) {
            return array(
                'status' => 'not_found',
                'query'  => $asn,
                'type'   => 'asn',
            );
        }
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'status' => 'error',
                'query'  => $asn,
                'type'   => 'asn',
                'error'  => 'RDAP responded with HTTP ' . $code . '.',
            );
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        if ( ! is_array( $data ) ) {
            return array(
                'status' => 'error',
                'query'  => $asn,
                'type'   => 'asn',
                'error'  => 'Malformed RDAP response.',
            );
        }

        return array(
            'status'   => 'ok',
            'query'    => $asn,
            'type'     => 'asn',
            'handle'   => $data['handle'] ?? null,
            'name'     => $data['name'] ?? null,
            'entities' => $this->summarize_entities( $data['entities'] ?? array() ),
        );
    }

    /**
     * Reduce an RDAP entities array to a small, UI-friendly list.
     */
    private function summarize_entities( array $entities ): array {
        $out = array();
        foreach ( $entities as $entity ) {
            $roles = $entity['roles'] ?? array();
            $name  = null;
            foreach ( ( $entity['vcardArray'][1] ?? array() ) as $field ) {
                if ( isset( $field[0] ) && 'fn' === $field[0] ) {
                    $name = $field[3] ?? null;
                    break;
                }
            }
            $out[] = array(
                'roles' => $roles,
                'name'  => $name,
                'handle'=> $entity['handle'] ?? null,
            );
        }
        return $out;
    }
}