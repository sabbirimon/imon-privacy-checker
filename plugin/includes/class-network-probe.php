<?php
/**
 * NetworkProbe — DNS-over-HTTPS fan-out, TCP-connect latency, TCP port probe.
 *
 * Three diagnostic primitives that the visitor-side `scanner.js` and the
 * admin dashboard compose into DNS-leak / ping / port-scan tools.
 *
 * SECURITY MODEL:
 *   - All hostnames are resolved and every resolved address is checked
 *     against `Security::is_public_ip_literal()`. Loopback, RFC1918,
 *     link-local (incl. AWS metadata 169.254.169.254), CGNAT, etc. are
 *     blocked before any TCP socket opens.
 *   - A hardcoded port denylist (SSH=22, SMTP=25, RDP=3389) is enforced
 *     in code, never user-overridable.
 *   - By default, only the WP server's own public IP is accepted as a
 *     probe target. Admin can extend via `pc_settings.port_scan_allowlist`.
 *   - TCP probes always pass an explicit finite timeout; no `0` ever.
 *   - No shell exec, no ICMP, no setuid.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static probe orchestrator.
 */
final class NetworkProbe {

    /**
     * Ports that are NEVER allowed to be probed, regardless of admin
     * configuration. These are services that commonly trigger IDS / abuse
     * reports when scanned by an unfamiliar IP.
     *
     * @var int[]
     */
    private const HARD_PORT_DENYLIST = array( 22, 25, 3389 );

    /**
     * Default DoH endpoints. The URL is the JSON `dns-query` endpoint;
     * the `name` is what we surface in the UI. Admin can override per-
     * resolver via `pc_settings.dns_resolvers`.
     *
     * @return array<string,string>
     */
    public static function default_dns_resolvers(): array {
        return array(
            'cloudflare' => 'https://cloudflare-dns.com/dns-query',
            'google'     => 'https://dns.google/resolve',
            'quad9'      => 'https://dns.quad9.net/dns-query',
        );
    }

    /**
     * "online" tier DoH endpoints (public, no API key, but with a different
     * privacy / reliability profile than the free default tier). Used when
     * the configured `dns_provider_chain` includes "online".
     *
     * @return array<string,string>
     */
    public static function online_dns_resolvers(): array {
        return array(
            'mullvad'      => 'https://adblock.doh.mullvad.net/dns-query',
            'controld'     => 'https://freedns.controld.com/p0',
            'nextdns'      => 'https://dns.nextdns.io',
        );
    }

    /**
     * Build the merged resolver map based on the configured tier chain.
     *
     * Tiers are processed in the order the admin configured. Empty tiers are
     * skipped. The "local" tier adds an entry per configured local server,
     * but uses Google DoH as the transport because local resolvers cannot
     * normally be queried via DoH; the entry is purely informational.
     *
     * @param string[]            $chain    Tiers in priority order.
     * @param array<string,mixed> $settings Plugin settings array.
     * @return array<string,string>
     */
    public static function resolver_chain_for_tiers( array $chain, array $settings ): array {
        $out = array();
        foreach ( $chain as $tier ) {
            $tier = (string) $tier;
            if ( 'free' === $tier ) {
                $out = array_merge( $out, self::default_dns_resolvers() );
            } elseif ( 'online' === $tier ) {
                $out = array_merge( $out, self::online_dns_resolvers() );
            } elseif ( 'paid' === $tier && ! empty( $settings['dns_paid_endpoint'] ) ) {
                $out['paid'] = (string) $settings['dns_paid_endpoint'];
            } elseif ( 'local' === $tier ) {
                foreach ( (array) ( $settings['dns_local_resolvers'] ?? array() ) as $ip ) {
                    $ip = (string) $ip;
                    if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                        $out[ 'local-' . $ip ] = 'https://dns.google/resolve';
                    }
                }
            }
        }
        return $out;
    }

    /**
     * Advertise the endpoint the browser should hit for latency probing.
     *
     * The actual measurement is done client-side (see scanner.js →
     * `connectionQualityProbe()`) because latency must be measured from the
     * visitor's perspective, not the server's. This method exists so the
     * orchestrator / REST handlers can advertise a single source of truth
     * for "where to ping" without hard-coding the URL in JS.
     *
     * @return array{endpoint:string,method:string,sample_count:int,note:string}
     */
    public static function latency_probe(): array {
        return array(
            'endpoint'     => '/wp-json/privacy-checker/v1/scan/connection/echo',
            'method'       => 'GET',
            'sample_count' => 3,
            'note'         => __( 'Latency is measured end-to-end in the visitor\'s browser using performance.now() around fetch(). Server response is a trivial {t: microtime} payload with no upstream work.', 'privacy-checker' ),
        );
    }

    /**
     * Classify whether the detected connection is IPv4-only, IPv6-only,
     * dual-stack, or neither (e.g. misconfigured proxy).
     *
     * Reuses the IP-detection shape returned by IpDetector::detect() —
     * `{ipv4: ?string, ipv6: ?string, source: string}` — rather than
     * re-implementing IP detection. Returns a normalised summary that the
     * scanner orchestrator and the Connection Quality card can consume.
     *
     * @param array{ipv4?:?string, ipv6?:?string, source?:string} $detected
     * @return array{reachable:bool,family:string,ipv4:?string,ipv6:?string,source:string}
     */
    public static function ipv6_reachable( array $detected ): array {
        $ipv4   = isset( $detected['ipv4'] ) ? (string) $detected['ipv4'] : '';
        $ipv6   = isset( $detected['ipv6'] ) ? (string) $detected['ipv6'] : '';
        $source = isset( $detected['source'] ) ? (string) $detected['source'] : '';

        $has_v4 = '' !== $ipv4;
        $has_v6 = '' !== $ipv6;

        $family = 'none';
        if ( $has_v4 && $has_v6 ) {
            $family = 'dual';
        } elseif ( $has_v6 ) {
            $family = 'ipv6';
        } elseif ( $has_v4 ) {
            $family = 'ipv4';
        }

        return array(
            'reachable' => ( $has_v4 || $has_v6 ),
            'family'    => $family,
            'ipv4'      => $has_v4 ? $ipv4 : null,
            'ipv6'      => $has_v6 ? $ipv6 : null,
            'source'    => $source,
        );
    }

    /**
     * Default ping targets. Format: `host:port`.
     *
     * @return string[]
     */
    public static function default_ping_targets(): array {
        return array(
            'cloudflare.com:443',
            'google.com:443',
            'example.com:443',
        );
    }

    /**
     * Default ports shown in the port-scan UI as quick-select chips.
     *
     * @return int[]
     */
    public static function default_port_scan_ports(): array {
        return array( 80, 443, 8080, 8443 );
    }

    /**
     * DNS-over-HTTPS fan-out.
     *
     * Resolves the given hostname via every configured DoH resolver and
     * returns per-resolver latency + answer IP. Successful lookups are
     * cached for 60s. Failures are NOT cached (transient outage self-heals).
     *
     * @param string               $hostname  Hostname to resolve (A record).
     * @param array<string,string> $resolvers Map of resolver name => URL.
     * @param int                  $timeout   Seconds, clamped to [1, 10].
     * @return array<string,mixed>
     */
    public static function doh_probe( string $hostname, array $resolvers, int $timeout = 3 ): array {
        $hostname = trim( $hostname );
        $timeout  = max( 1, min( 10, $timeout ) );

        if ( '' === $hostname ) {
            return array(
                'status'    => 'error',
                'error'     => 'Hostname is required.',
                'resolvers' => array(),
            );
        }
        if ( empty( $resolvers ) ) {
            return array(
                'status'    => 'error',
                'error'     => 'No DoH resolvers configured.',
                'resolvers' => array(),
            );
        }

        $results = array();
        $any_ok  = false;
        foreach ( $resolvers as $name => $url ) {
            $name  = (string) $name;
            $url   = (string) $url;
            $cache = 'doh_' . md5( $name . '|' . $hostname );

            // Only cache successes.
            $cached = Cache::get( $cache );
            if ( is_array( $cached ) ) {
                $results[] = $cached;
                if ( 'ok' === ( $cached['status'] ?? '' ) ) {
                    $any_ok = true;
                }
                continue;
            }

            $row = self::doh_query( $name, $url, $hostname, $timeout );
            if ( 'ok' === $row['status'] ) {
                Cache::set( $cache, $row, 60 );
                $any_ok = true;
            }
            $results[] = $row;
        }

        return array(
            'status'    => $any_ok ? 'ok' : 'error',
            'hostname'  => $hostname,
            'resolvers' => $results,
            'leak_score' => self::compute_leak_score( $results ),
            'consistent' => self::is_consistent( $results ),
        );
    }

    /**
     * Perform a single DoH lookup. Supports both Cloudflare wireformat
     * (`Answer[].data` = A record) and Google wireformat (same shape, JSON
     * response from `/resolve`). Both return an array of `Answer` objects.
     *
     * @return array<string,mixed>
     */
    private static function doh_query( string $name, string $url, string $hostname, int $timeout ): array {
        // Cloudflare wireformat: `?name=…&type=A`. Google uses the same
        // query string; both endpoints accept it. We additionally set the
        // `Accept: application/dns-json` header so Cloudflare responds with
        // JSON regardless of path.
        $endpoint = $url;
        $sep      = false === strpos( $url, '?' ) ? '?' : '&';
        $endpoint .= $sep . 'name=' . rawurlencode( $hostname ) . '&type=A';

        $start    = microtime( true );
        $response = wp_remote_get( $endpoint, array(
            'timeout'    => $timeout,
            'user-agent' => 'PrivacyChecker/' . PRIVACY_CHECKER_VERSION . ' (+dns-probe)',
            'headers'    => array(
                'Accept' => 'application/dns-json',
            ),
            'sslverify' => true,
        ) );
        $latency  = (int) round( ( microtime( true ) - $start ) * 1000 );

        if ( is_wp_error( $response ) ) {
            return array(
                'name'       => $name,
                'status'     => 'error',
                'error'      => $response->get_error_message(),
                'latency_ms' => $latency,
            );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( $code < 200 || $code >= 300 ) {
            return array(
                'name'       => $name,
                'status'     => 'error',
                'error'      => 'HTTP ' . $code,
                'latency_ms' => $latency,
            );
        }

        $body = (string) wp_remote_retrieve_body( $response );
        $json = json_decode( $body, true );
        if ( ! is_array( $json ) || empty( $json['Answer'] ) || ! is_array( $json['Answer'] ) ) {
            return array(
                'name'       => $name,
                'status'     => 'error',
                'error'      => 'No answer in response.',
                'latency_ms' => $latency,
            );
        }

        $answer_ip = null;
        foreach ( $json['Answer'] as $ans ) {
            $data = $ans['data'] ?? null;
            if ( is_string( $data ) && filter_var( $data, FILTER_VALIDATE_IP ) ) {
                $answer_ip = $data;
                break;
            }
        }

        if ( null === $answer_ip ) {
            return array(
                'name'       => $name,
                'status'     => 'error',
                'error'      => 'No A record in answer.',
                'latency_ms' => $latency,
            );
        }

        return array(
            'name'       => $name,
            'status'     => 'ok',
            'answer_ip'  => $answer_ip,
            'latency_ms' => $latency,
        );
    }

    /**
     * Heuristic 0..1 "leak" score based on agreement among resolver answers.
     * 0 = all resolvers agree on one IP. 1 = all resolvers disagree.
     * Mid values indicate partial disagreement. We never report a leak
     * definitively — the score is just a UI hint.
     *
     * @param array<int,array<string,mixed>> $results
     */
    private static function compute_leak_score( array $results ): float {
        $ips = array();
        foreach ( $results as $r ) {
            if ( 'ok' === ( $r['status'] ?? '' ) && ! empty( $r['answer_ip'] ) ) {
                $ips[] = (string) $r['answer_ip'];
            }
        }
        $ok = count( $ips );
        if ( 0 === $ok ) {
            return 0.0;
        }
        $unique = count( array_unique( $ips ) );
        if ( 1 === $unique ) {
            return 0.0;
        }
        // Majority / total — if 2 of 3 agree, score = 1/3.
        $counts = array_count_values( $ips );
        rsort( $counts );
        $top = (int) $counts[0];
        return round( 1.0 - ( $top / $ok ), 2 );
    }

    /**
     * Whether all successful resolver answers agree.
     *
     * @param array<int,array<string,mixed>> $results
     */
    private static function is_consistent( array $results ): bool {
        $ips = array();
        foreach ( $results as $r ) {
            if ( 'ok' === ( $r['status'] ?? '' ) && ! empty( $r['answer_ip'] ) ) {
                $ips[] = (string) $r['answer_ip'];
            }
        }
        return count( array_unique( $ips ) ) <= 1;
    }

    /**
     * TCP-connect latency probe.
     *
     * Opens a TCP socket to `host:port` and measures the time-to-connect
     * with `microtime(true)`. Returns `{status: "ok"|"error"|"unavailable",
     * latency_ms: int|null, error: ?string, host, port}`.
     *
     * IMPORTANT: callers MUST pass through `is_target_allowed()` first.
     *
     * @return array<string,mixed>
     */
    public static function tcp_latency( string $host, int $port, float $timeout_sec = 1.5 ): array {
        $base = self::tcp_probe( $host, $port, $timeout_sec, true );
        $base['status'] = $base['connected'] ? 'ok' : 'unavailable';
        unset( $base['connected'] );
        return $base;
    }

    /**
     * TCP port probe — open / closed / filtered.
     *
     * @return array<string,mixed>
     */
    public static function tcp_probe_port( string $host, int $port, float $timeout_sec = 1.0 ): array {
        $result  = self::tcp_probe( $host, $port, $timeout_sec, false );
        $connect = $result['connected'];
        unset( $result['connected'] );
        if ( $connect ) {
            $result['status'] = 'open';
        } elseif ( 'timed-out' === ( $result['error'] ?? '' ) ) {
            // Could be open + filtered (firewall dropped SYN) OR the host
            // dropped the packet. We surface "filtered" honestly.
            $result['status'] = 'filtered';
        } else {
            $result['status'] = 'closed';
        }
        return $result;
    }

    /**
     * Shared TCP socket logic. Pass `$measure_latency=true` for ping,
     * `false` for port probe.
     *
     * @return array<string,mixed>  {connected, host, port, latency_ms, error}
     */
    private static function tcp_probe( string $host, int $port, float $timeout_sec, bool $measure_latency ): array {
        $errno  = 0;
        $errstr = '';
        $remote = sprintf( 'tcp://%s:%d', $host, $port );

        $start = microtime( true );
        // @ to suppress the warning emitted when the connect fails (e.g.
        // connection refused); we capture the error code instead.
        $sock = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            (float) max( 0.1, $timeout_sec ),
            STREAM_CLIENT_CONNECT
        );
        $latency = (int) round( ( microtime( true ) - $start ) * 1000 );

        if ( false === $sock ) {
            $error = self::classify_socket_error( $errno, $errstr );
            return array(
                'connected'  => false,
                'host'       => $host,
                'port'       => $port,
                'latency_ms' => null,
                'error'      => $error,
            );
        }
        @fclose( $sock );
        return array(
            'connected'  => true,
            'host'       => $host,
            'port'       => $port,
            'latency_ms' => $measure_latency ? $latency : null,
            'error'      => null,
        );
    }

    /**
     * Map `stream_socket_client` errno to a friendly category.
     */
    private static function classify_socket_error( int $errno, string $errstr ): string {
        // Common cases:
        //  111 ECONNREFUSED — port closed, host up.
        //  110 ETIMEDOUT    — host unreachable / firewall dropped.
        //  113 EHOSTUNREACH — routing failure.
        if ( 110 === $errno ) {
            return 'timed-out';
        }
        if ( 111 === $errno ) {
            return 'refused';
        }
        if ( 113 === $errno ) {
            return 'unreachable';
        }
        if ( '' !== $errstr ) {
            return strtolower( substr( $errstr, 0, 80 ) );
        }
        return 'error-' . $errno;
    }

    /**
     * Decide whether a probe target is allowed.
     *
     * Rules (all must pass):
     *   1. Port is not in HARD_PORT_DENYLIST.
     *   2. Port is in `[1, 65535]`.
     *   3. Hostname/IP is not localhost / private / loopback / link-local /
     *      CGNAT / multicast / reserved.
     *   4. If `pc_settings.port_scan_allowlist` is empty: the resolved IP
     *      must equal the WP server's own public IP (cached via
     *      `IpFallback::server_self_ip()`).
     *   5. If allowlist is non-empty: the resolved IP must match an entry
     *      (exact match, IP, or CIDR). Empty allowlist + no self-IP
     *      detected = deny.
     *
     * @return array{0:bool, 1:?string}  [allowed, reason-if-denied]
     */
    public static function check_target_allowed( string $host_or_ip, int $port ): array {
        if ( in_array( $port, self::HARD_PORT_DENYLIST, true ) ) {
            return array( false, 'Port ' . $port . ' is on the hardcoded denylist.' );
        }
        if ( $port < 1 || $port > 65535 ) {
            return array( false, 'Port must be between 1 and 65535.' );
        }

        $host = trim( $host_or_ip );
        if ( '' === $host ) {
            return array( false, 'Host is required.' );
        }

        // Reject obvious hostnames before any DNS lookup.
        $lower = strtolower( $host );
        if ( in_array( $lower, array( 'localhost', 'localhost.localdomain' ), true ) ) {
            return array( false, 'Localhost is not allowed.' );
        }

        // If host is an IP literal, validate it directly.
        if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
            if ( ! Security::is_public_ip_literal( $host ) ) {
                return array( false, 'Private or reserved IP literals are not allowed.' );
            }
            return self::evaluate_allowlist( $host, $port );
        }

        // Hostname — resolve and validate every address.
        $records = @dns_get_record( $host, DNS_A + DNS_AAAA );
        if ( false === $records || empty( $records ) ) {
            return array( false, 'Hostname could not be resolved.' );
        }
        foreach ( $records as $record ) {
            $ip = $record['ip'] ?? ( $record['ipv6'] ?? null );
            if ( $ip && ! Security::is_public_ip_literal( (string) $ip ) ) {
                return array( false, 'Hostname resolves to a non-public address.' );
            }
        }
        // Use the first resolved IP for the self-IP / allowlist check.
        $first = null;
        foreach ( $records as $record ) {
            $ip = $record['ip'] ?? ( $record['ipv6'] ?? null );
            if ( $ip ) {
                $first = (string) $ip;
                break;
            }
        }
        if ( null === $first ) {
            return array( false, 'Hostname resolved but no IP address returned.' );
        }
        return self::evaluate_allowlist( $first, $port );
    }

    /**
     * Apply the allowlist / self-only rule.
     */
    private static function evaluate_allowlist( string $resolved_ip, int $port ): array {
        $allowlist = (array) Plugin::instance()->setting( 'port_scan_allowlist', array() );

        if ( ! empty( $allowlist ) ) {
            foreach ( $allowlist as $entry ) {
                $entry = trim( (string) $entry );
                if ( '' === $entry ) {
                    continue;
                }
                if ( self::ip_matches_entry( $resolved_ip, $entry ) ) {
                    return array( true, null );
                }
            }
            return array( false, 'Host is not on the admin allowlist.' );
        }

        // Empty allowlist = self-only.
        $self_ip = IpFallback::server_self_ip();
        if ( null === $self_ip ) {
            return array( false, 'Self-IP not detected and allowlist is empty.' );
        }
        if ( strcasecmp( $self_ip, $resolved_ip ) === 0 ) {
            return array( true, null );
        }
        return array( false, 'Self-only mode: target IP ' . $resolved_ip . ' does not match server IP ' . $self_ip . '.' );
    }

    /**
     * Test whether an IP matches an allowlist entry — exact IP, CIDR, or
     * bare hostname (which we resolve to a single IP).
     */
    private static function ip_matches_entry( string $ip, string $entry ): bool {
        // Exact IP match.
        if ( false !== strpos( $entry, '/' ) ) {
            // CIDR.
            return Security::ip_in_cidr_public( $ip, $entry );
        }
        if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
            return 0 === strcasecmp( $ip, $entry );
        }
        // Hostname — resolve once.
        $resolved = @gethostbyname( $entry );
        if ( $resolved === $entry ) {
            return false;
        }
        return 0 === strcasecmp( $ip, $resolved );
    }

    /**
     * Build a backend-derived network-path hop list.
     *
     * Real ICMP traceroute requires root + raw sockets, neither of which is
     * available from a WordPress PHP request. Instead we walk the public
     * signals we DO have and produce an honest hop sequence that:
     *
     *   1. Source: the visitor's own device + uplink (from network intel:
     *      ISP, ASN, country, connection class).
     *   2. Reverse DNS (PTR) of the visitor IP, when available.
     *   3. ISP / ASN edge inferred from `intel.asn` and `intel.org`.
     *   4. Country-level geo hop (when `intel.country` is known).
     *   5. Proxy / VPN / Tor / hosting hops derived from ProxyDetector's
     *      classification — not synthesized, not mocked.
     *   6. Destination: the WP server's own hostname.
     *
     * Every hop carries a `source` field so the UI can flag estimates.
     *
     * @param array<string,mixed> $intel        Output of IpFallback::lookup().
     * @param array<string,mixed> $proxy        Output of ProxyDetector::classify_with_lists().
     * @param array<string,mixed> $connection   Resolved connection signals.
     * @param string              $destination  Destination hostname (e.g. WP site host).
     * @return array<int,array<string,mixed>>
     */
    public static function path_hops( array $intel, array $proxy, array $connection, string $destination ): array {
        $hops   = array();
        $id     = 0;
        $add    = function ( array $hop ) use ( &$hops, &$id ) {
            $id++;
            $hop['id']     = $id;
            $hop['source'] = $hop['source'] ?? 'inferred';
            $hops[]        = $hop;
        };

        $category  = (string) ( $proxy['category'] ?? '' );
        $isTor     = 'tor'     === $category;
        $isVpn     = 'vpn'     === $category || 'proxy' === $category;
        $isHosting = 'hosting' === $category;
        $isp       = (string) ( $intel['isp']   ?? '' );
        $org       = (string) ( $intel['org']   ?? $intel['asn_org'] ?? '' );
        $asn       = (string) ( $intel['asn']   ?? '' );
        $country   = (string) ( $intel['country'] ?? '' );
        $city      = (string) ( $intel['city']    ?? '' );
        $region    = (string) ( $intel['region']  ?? '' );

        $ipv4 = (string) ( $connection['ipv4'] ?? '' );
        $ptr  = (string) ( $connection['reverse_dns'] ?? '' );

        // 1. Source device — never synthesized. Real signals: visitor UA class
        //    is determined client-side; we surface "your device" only.
        $add( array(
            'type'    => 'device',
            'label'   => 'YOUR DEVICE',
            'sub'     => 'Source endpoint',
            'detail'  => 'The visitor\'s workstation or phone',
        ) );

        // 2. PTR (reverse DNS) when present — this is REAL backend data.
        if ( '' !== $ptr && 'unknown' !== strtolower( $ptr ) ) {
            $add( array(
                'type'    => 'router',
                'label'   => 'EDGE ROUTER',
                'sub'     => $ptr,
                'detail'  => 'PTR record for ' . $ipv4,
                'source'  => 'ptr',
            ) );
        }

        // 3. ISP / ASN edge — derived from real IP-intelligence data.
        if ( '' !== $isp || '' !== $org ) {
            $sub = trim( $isp . ( $asn ? ' (AS' . preg_replace( '/[^0-9]/', '', $asn ) . ')' : '' ) );
            if ( '' === $sub ) {
                $sub = $org;
            }
            $add( array(
                'type'    => 'switch',
                'label'   => 'ISP EDGE',
                'sub'     => $sub,
                'detail'  => 'ISP first-hop aggregation',
                'source'  => 'ip-intel',
            ) );
        }

        // 4. Country / region hop when known.
        if ( '' !== $country ) {
            $locality = trim( $city . ( $region ? ( ', ' . $region ) : '' ) . ( $city || $region ? ', ' : '' ) . $country );
            $add( array(
                'type'    => 'router',
                'label'   => 'GEO BACKBONE',
                'sub'     => $locality,
                'detail'  => 'Public routing through ' . $country,
                'source'  => 'ip-intel',
            ) );
        }

        // 5. Proxy / VPN / Tor / hosting hops.
        if ( $isTor ) {
            $label_org = '' !== $org ? $org : 'Tor circuit';
            $add( array(
                'type'    => 'tor', 'label' => 'TOR GUARD',  'sub' => 'Entry relay',  'detail' => 'Tor guard relay',
                'source'  => 'proxy-detector',
            ) );
            $add( array(
                'type'    => 'tor', 'label' => 'TOR MIDDLE', 'sub' => 'Middle relay', 'detail' => 'Tor middle relay',
                'source'  => 'proxy-detector',
            ) );
            $add( array(
                'type'    => 'tor', 'label' => 'TOR EXIT',   'sub' => $label_org,    'detail' => 'Tor exit relay',
                'source'  => 'proxy-detector',
            ) );
        } elseif ( $isVpn ) {
            $provider_name = '' !== $org ? $org : ( '' !== $isp ? $isp : 'VPN provider' );
            $add( array(
                'type'    => 'vpn', 'label' => 'VPN GATEWAY', 'sub' => $provider_name, 'detail' => 'VPN entry, encrypted tunnel',
                'source'  => 'proxy-detector',
            ) );
            $add( array(
                'type'    => 'router', 'label' => 'BACKBONE', 'sub' => 'Transit routing', 'detail' => 'Tier-1 / regional backbone',
                'source'  => 'inferred',
            ) );
            $add( array(
                'type'    => 'server', 'label' => 'VPN EXIT',  'sub' => $provider_name, 'detail' => 'VPN exit / origin re-routed',
                'source'  => 'proxy-detector',
            ) );
        } elseif ( $isHosting ) {
            $add( array(
                'type'    => 'router',   'label' => 'DC BACKBONE', 'sub' => $org ?: 'Datacenter transit', 'detail' => 'Datacenter backbone router',
                'source'  => 'proxy-detector',
            ) );
            $add( array(
                'type'    => 'firewall', 'label' => 'EDGE FW',     'sub' => 'Origin firewall',           'detail' => 'Destination edge firewall',
                'source'  => 'inferred',
            ) );
        } else {
            // Residential / business. Real path inferred from intel.
            $add( array(
                'type'    => 'router',   'label' => 'BACKBONE',    'sub' => $org ?: 'Tier-1 transit', 'detail' => 'Tier-1 / regional backbone router',
                'source'  => 'inferred',
            ) );
            $add( array(
                'type'    => 'firewall', 'label' => 'EDGE FIREWALL', 'sub' => 'Origin firewall',        'detail' => 'Destination edge firewall',
                'source'  => 'inferred',
            ) );
        }

        // 6. Destination: the WP site the visitor actually loaded.
        $add( array(
            'type'    => 'destination',
            'label'   => 'DESTINATION',
            'sub'     => $destination ?: $ipv4,
            'detail'  => 'End of network path',
            'source'  => 'request',
        ) );

        return $hops;
    }
}
