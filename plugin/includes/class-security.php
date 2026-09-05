<?php
/**
 * Security helpers — URL/SSRF validation and IP helpers.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static security helpers.
 */
final class Security {

    /**
     * Reserved/private IPv4 CIDRs.
     *
     * @var string[]
     */
    private const IPV4_RESERVED = array(
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',          // CGNAT
        '127.0.0.0/8',
        '169.254.0.0/16',         // link-local incl. cloud metadata 169.254.169.254
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',            // multicast
        '240.0.0.0/4',            // reserved
        '255.255.255.255/32',
    );

    /**
     * Reserved/private IPv6 prefixes.
     *
     * @var string[]
     */
    private const IPV6_RESERVED = array(
        '::/128',
        '::1/128',                // loopback
        '::ffff:0:0/96',          // IPv4-mapped
        '64:ff9b::/96',
        '100::/64',
        '2001::/23',
        '2001:db8::/32',          // documentation
        'fc00::/7',               // unique local
        'fe80::/10',              // link-local
        'ff00::/8',               // multicast
        'fd00:ec2::254/128',      // AWS metadata v6
    );

    /**
     * Validate a URL the user submitted to the security-headers probe.
     *
     * Blocks:
     *   - non-http(s) schemes
     *   - hostnames that resolve to private/loopback/link-local addresses
     *   - redirects to disallowed destinations
     *
     * @param string $url User-supplied URL.
     * @return array{valid:bool, normalized:string|null, error:?string, host:?string}
     */
    public static function validate_remote_url( string $url ): array {
        $url = trim( $url );
        if ( '' === $url ) {
            return array(
                'valid'      => false,
                'normalized' => null,
                'error'      => 'URL is required.',
                'host'       => null,
            );
        }

        $parts = wp_parse_url( $url );
        if ( false === $parts || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
            return array(
                'valid'      => false,
                'normalized' => null,
                'error'      => 'Malformed URL.',
                'host'       => null,
            );
        }

        $scheme = strtolower( (string) $parts['scheme'] );
        if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
            return array(
                'valid'      => false,
                'normalized' => null,
                'error'      => 'Only http and https are allowed.',
                'host'       => $parts['host'],
            );
        }

        $host = (string) $parts['host'];
        // Strip IPv6 brackets.
        if ( substr( $host, 0, 1 ) === '[' && substr( $host, -1 ) === ']' ) {
            $host = substr( $host, 1, -1 );
        }

        // Block obvious hostnames.
        $lower = strtolower( $host );
        if ( in_array( $lower, array( 'localhost', 'localhost.localdomain' ), true ) ) {
            return array(
                'valid'      => false,
                'normalized' => null,
                'error'      => 'Localhost is not allowed.',
                'host'       => $host,
            );
        }

        // If host is an IP literal, check it directly.
        if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
            if ( ! self::is_public_ip_literal( $host ) ) {
                return array(
                    'valid'      => false,
                    'normalized' => null,
                    'error'      => 'Private or reserved IP literals are not allowed.',
                    'host'       => $host,
                );
            }
        } else {
            // Resolve and validate every address.
            $records = @dns_get_record( $host, DNS_A + DNS_AAAA );
            if ( false === $records ) {
                // Could be a name that simply doesn't resolve in this environment.
                // Be strict and reject to prevent abuse.
                return array(
                    'valid'      => false,
                    'normalized' => null,
                    'error'      => 'Hostname could not be resolved.',
                    'host'       => $host,
                );
            }
            foreach ( $records as $record ) {
                $ip = $record['ip'] ?? ( $record['ipv6'] ?? null );
                if ( $ip && ! self::is_public_ip_literal( (string) $ip ) ) {
                    return array(
                        'valid'      => false,
                        'normalized' => null,
                        'error'      => 'Hostname resolves to a non-public address.',
                        'host'       => $host,
                    );
                }
            }
        }

        $normalized = self::normalize_url( $parts );
        return array(
            'valid'      => true,
            'normalized' => $normalized,
            'error'      => null,
            'host'       => $host,
        );
    }

    /**
     * Check whether an IP literal is a public (non-private, non-loopback, non-reserved) address.
     */
    public static function is_public_ip_literal( string $ip ): bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return false;
        }

        $is_v4 = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
        $cidrs = $is_v4 ? self::IPV4_RESERVED : self::IPV6_RESERVED;

        foreach ( $cidrs as $cidr ) {
            if ( self::ip_in_cidr( $ip, $cidr ) ) {
                return false;
            }
        }
        return true;
    }

    /**
     * Public wrapper for the CIDR membership check. Used by
     * `NetworkProbe` for allowlist matching.
     */
    public static function ip_in_cidr_public( string $ip, string $cidr ): bool {
        return self::ip_in_cidr( $ip, $cidr );
    }

    /**
     * Test whether an IP falls inside a CIDR block.
     */
    private static function ip_in_cidr( string $ip, string $cidr ): bool {
        $parts = explode( '/', $cidr, 2 );
        $subnet = $parts[0];
        $bits   = isset( $parts[1] ) ? (int) $parts[1] : null;

        $ip_long     = ip2long( $ip );
        $subnet_long = ip2long( $subnet );

        if ( false === $ip_long || false === $subnet_long ) {
            // IPv6 path.
            return self::ipv6_in_cidr( $ip, $cidr );
        }
        if ( null === $bits ) {
            return $ip_long === $subnet_long;
        }
        if ( $bits === 0 ) {
            return true;
        }
        $mask = -1 << ( 32 - $bits );
        return ( $ip_long & $mask ) === ( $subnet_long & $mask );
    }

    /**
     * IPv6 CIDR membership check.
     */
    private static function ipv6_in_cidr( string $ip, string $cidr ): bool {
        $parts = explode( '/', $cidr, 2 );
        $subnet = $parts[0];
        $bits   = isset( $parts[1] ) ? (int) $parts[1] : 128;
        if ( ! function_exists( 'inet_pton' ) ) {
            return false;
        }
        $ip_bin     = inet_pton( $ip );
        $subnet_bin = inet_pton( $subnet );
        if ( false === $ip_bin || false === $subnet_bin ) {
            return false;
        }
        $bytes = (int) floor( $bits / 8 );
        $rem   = $bits % 8;
        if ( 0 !== strncmp( $ip_bin, $subnet_bin, $bytes ) ) {
            return false;
        }
        if ( 0 === $rem ) {
            return true;
        }
        $mask     = chr( 0xff << ( 8 - $rem ) & 0xff );
        return ( ( ord( $ip_bin[ $bytes ] ) & ord( $mask ) ) === ( ord( $subnet_bin[ $bytes ] ) & ord( $mask ) ) );
    }

    /**
     * Normalize a parsed URL array back to a string with scheme + host + path + query.
     */
    private static function normalize_url( array $parts ): string {
        $scheme   = strtolower( (string) $parts['scheme'] );
        $host     = (string) $parts['host'];
        $port     = isset( $parts['port'] ) ? ':' . (int) $parts['port'] : '';
        $path     = $parts['path'] ?? '';
        $query    = isset( $parts['query'] ) ? '?' . $parts['query'] : '';
        $fragment = isset( $parts['fragment'] ) ? '#' . $parts['fragment'] : '';

        // Re-quote IPv6.
        if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
            $host = '[' . $host . ']';
        }

        return $scheme . '://' . $host . $port . $path . $query . $fragment;
    }

    /**
     * Re-validate a redirect target to prevent SSRF via redirect.
     */
    public static function is_safe_redirect_target( string $url ): bool {
        $check = self::validate_remote_url( $url );
        return $check['valid'];
    }

    /**
     * Split a `host`, `host:port`, or `[ipv6]:port` string into its parts.
     *
     * Returns `null` for port if no port was supplied (so callers can default
     * to a sane value like 80 or 443). The port is clamped to `[1, 65535]`.
     * Returns `['', null]` for an empty input.
     *
     * @return array{0:string,1:?int}
     */
    public static function split_hostport( string $input ): array {
        $input = trim( $input );
        if ( '' === $input ) {
            return array( '', null );
        }

        // IPv6 literal in brackets: [::1] or [::1]:443
        if ( '[' === substr( $input, 0, 1 ) ) {
            $close = strpos( $input, ']' );
            if ( false === $close ) {
                return array( '', null );
            }
            $host = substr( $input, 1, $close - 1 );
            $rest = substr( $input, $close + 1 );
            if ( '' === $rest ) {
                return array( $host, null );
            }
            if ( ':' !== substr( $rest, 0, 1 ) ) {
                return array( $host, null );
            }
            $port = (int) substr( $rest, 1 );
            if ( $port < 1 || $port > 65535 ) {
                return array( $host, null );
            }
            return array( $host, $port );
        }

        // Find the LAST `:` so hostnames don't get confused with port. If
        // there is exactly one colon and the part before it contains no
        // dots, treat it as `host:port`. Otherwise it's likely an IPv6
        // literal (without brackets, which we'll reject elsewhere).
        $last_colon = strrpos( $input, ':' );
        if ( false === $last_colon ) {
            return array( $input, null );
        }

        $host_part = substr( $input, 0, $last_colon );
        $port_part = substr( $input, $last_colon + 1 );

        // If the entire string is an IPv6 literal (multiple colons, no
        // brackets), reject by returning no host.
        if ( false !== strpos( $host_part, ':' ) ) {
            return array( $input, null );
        }

        // Port must be all digits and in range.
        if ( '' === $port_part || ! ctype_digit( $port_part ) ) {
            return array( $input, null );
        }
        $port = (int) $port_part;
        if ( $port < 1 || $port > 65535 ) {
            return array( $input, null );
        }
        return array( $host_part, $port );
    }
}