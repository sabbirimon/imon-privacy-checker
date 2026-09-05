<?php
/**
 * Scanner orchestrator.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Coordinates the various detection modules into a single privacy report.
 */
final class ScannerOrchestrator {

    /**
     * Run a full scan for the current request.
     *
     * @param array<string,mixed> $client_signals Browser-collected signals.
     * @return array<string,mixed>
     */
    public static function scan( array $client_signals = array() ): array {
        $detected = IpDetector::detect();
        $ipv4     = $detected['ipv4'];
        $ipv6     = $detected['ipv6'];

        $connection = array(
            'ipv4'   => $ipv4,
            'ipv6'   => $ipv6,
            'source' => $detected['source'],
        );

        if ( $ipv4 ) {
            $reverse = IpDetector::reverse_dns( $ipv4 );
            $connection['reverse_dns'] = $reverse['hostname'];
            $connection['reverse_dns_error'] = $reverse['error'];

            $intel = IpFallback::lookup( $ipv4 );
            $connection['intel'] = $intel;

            // Proxy / VPN / Tor / Hosting classification (best-effort).
            // Also consult any uploaded exit lists (Tor / VPN / proxy / etc.)
            // so admins who have dropped their own lists get exact verdicts.
            try {
                $intel_with_ip = array_merge( $intel, array( 'ip' => $ipv4 ) );
                $connection['proxy'] = ProxyDetector::classify_with_lists( $intel_with_ip );
            } catch ( \Throwable $e ) {
                $connection['proxy'] = array( 'category' => 'unknown', 'label' => 'Unknown', 'confidence' => 'low', 'reasons' => array(), 'score' => 0 );
            }

            // Real backend-derived network-path hop list. JS consumes this
            // instead of synthesizing hops from heuristics.
            try {
                $destination = (string) ( $_SERVER['HTTP_HOST'] ?? '' );
                $connection['path_hops'] = NetworkProbe::path_hops(
                    $intel,
                    $connection['proxy'],
                    array_merge( $connection, array( 'ipv4' => $ipv4 ) ),
                    $destination
                );
            } catch ( \Throwable $e ) {
                $connection['path_hops'] = array();
            }
        }
        if ( $ipv6 ) {
            $reverse_v6 = IpDetector::reverse_dns( $ipv6 );
            $connection['reverse_dns_v6'] = $reverse_v6['hostname'];
            $connection['reverse_dns_v6_error'] = $reverse_v6['error'];
        }

        $reputation = $ipv4 ? Reputation::check( $ipv4 ) : array(
            'status'  => 'unknown',
            'message' => 'No IPv4 address available to check.',
        );

        $ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        $ua_parsed = Fingerprint::parse_user_agent( $ua );

        // Security posture — TLS info for the current request + browser
        // EOL advisory. Both classes are pure data, no I/O. Reuses the
        // already-parsed $ua_parsed so we don't re-parse the UA.
        $security_posture = array(
            'tls'     => TlsInfo::current_request_info(),
            'browser' => BrowserVersions::check(
                (string) ( $ua_parsed['browser'] ?? '' ),
                self::major_version_from_string( $ua_parsed['version'] ?? null )
            ),
        );

        $visibility = Fingerprint::estimate_visibility( $client_signals );

        // Surface the raw Phase 3 fingerprint signals alongside the score
        // so the JS card can render them (canvas/audio hashes, WebGL
        // renderer/vendor, font list). These are echoed back verbatim —
        // no transformation here; the entropy estimator already folded
        // them into $visibility['entropy'].
        $fingerprint_hashes = array(
            'canvas_hash'    => isset( $client_signals['canvas_hash'] )    ? (string) $client_signals['canvas_hash'] : '',
            'audio_hash'     => isset( $client_signals['audio_hash'] )     ? (string) $client_signals['audio_hash']  : '',
            'webgl_renderer' => isset( $client_signals['webgl_renderer'] ) ? (string) $client_signals['webgl_renderer'] : '',
            'webgl_vendor'   => isset( $client_signals['webgl_vendor'] )   ? (string) $client_signals['webgl_vendor']   : '',
            'font_list'      => ( isset( $client_signals['font_list'] ) && is_array( $client_signals['font_list'] ) )
                ? array_values( array_map( 'strval', $client_signals['font_list'] ) )
                : array(),
        );

        // Connection quality — the visitor's own browser is the only
        // observer with meaningful end-to-end latency numbers (the server
        // can only see its own hop). The client POSTs a small payload
        // from connectionQualityProbe() + navigatorConnectionSnapshot()
        // under the `connection_quality` key. We carry it onto the scan
        // verbatim (after light structural validation) so the privacy
        // report's connection_quality category — added in Phase 6 —
        // can populate. The dedicated connectionQualityCard() reads
        // from the same field client-side, so this is one source of
        // truth for the whole report.
        $connection_quality = array();
        if ( isset( $client_signals['connection_quality'] ) && is_array( $client_signals['connection_quality'] ) ) {
            $cq = $client_signals['connection_quality'];
            if ( isset( $cq['latency'] ) && is_array( $cq['latency'] ) && isset( $cq['latency']['avg_ms'] ) && is_numeric( $cq['latency']['avg_ms'] ) ) {
                $connection_quality['latency'] = array(
                    'min_ms'    => isset( $cq['latency']['min_ms'] )    && is_numeric( $cq['latency']['min_ms'] )    ? (float) $cq['latency']['min_ms']    : null,
                    'max_ms'    => isset( $cq['latency']['max_ms'] )    && is_numeric( $cq['latency']['max_ms'] )    ? (float) $cq['latency']['max_ms']    : null,
                    'avg_ms'    => (float) $cq['latency']['avg_ms'],
                    'jitter_ms' => isset( $cq['latency']['jitter_ms'] ) && is_numeric( $cq['latency']['jitter_ms'] ) ? (float) $cq['latency']['jitter_ms'] : null,
                    'count'     => isset( $cq['latency']['count'] )     && is_numeric( $cq['latency']['count'] )     ? (int)   $cq['latency']['count']     : null,
                );
            }
            if ( isset( $cq['network'] ) && is_array( $cq['network'] ) ) {
                $connection_quality['network'] = array(
                    'available'      => ! empty( $cq['network']['available'] ),
                    'downlink_mbps'  => isset( $cq['network']['downlink_mbps'] )  && is_numeric( $cq['network']['downlink_mbps'] )  ? (float) $cq['network']['downlink_mbps']  : null,
                    'effective_type' => isset( $cq['network']['effective_type'] ) && is_string(  $cq['network']['effective_type'] )   ? (string) $cq['network']['effective_type'] : null,
                    'rtt_ms'         => isset( $cq['network']['rtt_ms'] )         && is_numeric( $cq['network']['rtt_ms'] )         ? (int)   $cq['network']['rtt_ms']         : null,
                );
            }
        }

        $webrtc_summary = Webrtc::summarize( $client_signals['webrtc'] ?? array() );

        // Anonymity consistency — correlates IP-geo timezone, browser-reported
        // timezone, WebRTC leak result, and proxy classification into one
        // composite score + mismatch list. The orchestrator already has every
        // input it needs; AnonymityScorer does no I/O of its own. DNS-leak
        // correlation is included only when a completed test result is passed
        // in; the synchronous scan request doesn't run the DNS test itself.
        try {
            $anonymity = AnonymityScorer::score(
                $connection['intel'] ?? array(),
                $webrtc_summary,
                $connection['proxy']   ?? array(),
                (string) ( $client_signals['timezone'] ?? '' ),
                is_array( $client_signals['dns_test_result'] ?? null ) ? $client_signals['dns_test_result'] : null
            );
        } catch ( \Throwable $e ) {
            // Never let a correlation failure break the scan response.
            $anonymity = array(
                'consistent' => null,
                'score'      => null,
                'mismatches' => array(),
                'summary'    => __( 'Unable to determine.', 'privacy-checker' ),
            );
        }
        $connection['anonymity'] = $anonymity;

        $dns_test_state = array(
            'configured' => DnsTest::is_configured(),
            'note'       => DnsTest::is_configured()
                ? 'DNS leak test is configured. Issue a token to begin.'
                : 'Full DNS leak testing requires an external DNS test service. Not configured on this server.',
        );

        $score = self::compute_score( array(
            'connection' => $connection,
            'reputation' => $reputation,
            'visibility' => $visibility,
            'webrtc'     => $webrtc_summary,
        ) );

        $report = array(
            'generated_at'  => gmdate( 'c' ),
            'request_ip'    => array(
                'ipv4'      => $ipv4,
                'ipv6'      => $ipv6,
                'is_mock'   => Plugin::instance()->is_dev_mode(),
            ),
            'connection'    => $connection,
            'security_posture' => $security_posture,
            'reputation'    => $reputation,
            'user_agent'    => $ua_parsed,
            'fingerprint'      => $visibility,
            'fingerprint_hashes' => $fingerprint_hashes,
            'webrtc'        => $webrtc_summary,
            'dns_test'      => $dns_test_state,
            'connection_quality' => $connection_quality,
            'scores'        => $score,
            'recommendations' => self::recommendations( array(
                'connection' => $connection,
                'reputation' => $reputation,
                'visibility' => $visibility,
                'webrtc'     => $webrtc_summary,
            ) ),
        );

        // Detailed privacy report (Whoer-style breakdown) — built last so it
        // sees every signal above.
        try {
            $report['privacy_report'] = PrivacyReport::build( $report );
        } catch ( \Throwable $e ) {
            // Never let a reporting failure break the scan response.
            $report['privacy_report'] = array(
                'overall'    => 0,
                'grade'      => 'F',
                'confidence' => 'low',
                'headline'   => __( 'Detailed report unavailable.', 'privacy-checker' ),
                'categories' => array(),
                'recommendations' => array(),
                'generated_at' => gmdate( 'c' ),
                'error'      => $e->getMessage(),
            );
        }

        return $report;
    }

    /**
     * Map verification status to a numeric score (0-100).
     *
     * @param array<string,mixed> $context
     * @return array{privacy:int, anonymity:int, breakdown:array<string,int>}
     */
    private static function compute_score( array $context ): array {
        $privacy = 50;
        $breakdown = array();

        // Reputation impact.
        $reputation_status = $context['reputation']['status'] ?? 'unknown';
        switch ( $reputation_status ) {
            case 'clean':
                $privacy += 12; $breakdown['reputation'] = 12; break;
            case 'listed':
                $privacy -= 18; $breakdown['reputation'] = -18; break;
            case 'suspicious':
                $privacy -= 10; $breakdown['reputation'] = -10; break;
            case 'unknown':
                $privacy += 0; $breakdown['reputation'] = 0; break;
            default:
                $breakdown['reputation'] = 0;
        }

        // Fingerprint visibility impact.
        $level = $context['visibility']['level'] ?? 'low';
        switch ( $level ) {
            case 'low':      $privacy += 18; $breakdown['fingerprint'] = 18; break;
            case 'moderate': $privacy += 6;  $breakdown['fingerprint'] = 6; break;
            case 'high':     $privacy -= 12; $breakdown['fingerprint'] = -12; break;
            default:         $breakdown['fingerprint'] = 0;
        }

        // WebRTC impact.
        $verdict = $context['webrtc']['verdict'] ?? 'unknown';
        switch ( $verdict ) {
            case 'protected':         $privacy += 12; $breakdown['webrtc'] = 12; break;
            case 'potential_exposure':$privacy -= 10; $breakdown['webrtc'] = -10; break;
            case 'not_supported':     $privacy += 2;  $breakdown['webrtc'] = 2; break;
            default:                  $breakdown['webrtc'] = 0;
        }

        // Clamp.
        $privacy = max( 0, min( 100, $privacy ) );

        $anonymity = (int) round( $privacy * 0.9 );

        return array(
            'privacy'   => $privacy,
            'anonymity' => $anonymity,
            'breakdown' => $breakdown,
        );
    }

    /**
     * Convert a Fingerprint::parse_user_agent()['version'] string like
     * "130.0.1" into a major-version integer (130). Returns null for
     * null/empty/non-numeric input.
     *
     * @param mixed $version
     * @return int|null
     */
    private static function major_version_from_string( $version ): ?int {
        if ( ! is_string( $version ) || '' === $version ) {
            return null;
        }
        $head = explode( '.', $version, 2 )[0];
        return ctype_digit( $head ) ? (int) $head : null;
    }

    /**
     * Build a list of privacy recommendations based on observed signals.
     *
     * @param array<string,mixed> $context
     * @return string[]
     */
    private static function recommendations( array $context ): array {
        $recs = array(
            __( 'Use HTTPS for all sites that handle credentials or personal data.', 'privacy-checker' ),
            __( 'Review browser privacy settings and disable third-party cookies where appropriate.', 'privacy-checker' ),
            __( 'Keep your browser and operating system up to date.', 'privacy-checker' ),
        );

        if ( ( $context['visibility']['level'] ?? '' ) === 'high' ) {
            $recs[] = __( 'Consider browser extensions that limit fingerprinting surface (e.g. randomizing User-Agent or blocking WebGL).', 'privacy-checker' );
        }

        if ( ( $context['webrtc']['verdict'] ?? '' ) === 'potential_exposure' ) {
            $recs[] = __( 'Review WebRTC behavior if you use a VPN; some browsers expose network information through WebRTC APIs.', 'privacy-checker' );
        }

        if ( ( $context['reputation']['status'] ?? '' ) === 'listed' ) {
            $recs[] = __( 'Your IP appears on at least one reputation list. Contact your ISP if this is unexpected.', 'privacy-checker' );
        }

        return $recs;
    }
}