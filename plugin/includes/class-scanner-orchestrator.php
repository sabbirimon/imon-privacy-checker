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

        $visibility = Fingerprint::estimate_visibility( $client_signals );

        $webrtc_summary = Webrtc::summarize( $client_signals['webrtc'] ?? array() );

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
            'reputation'    => $reputation,
            'user_agent'    => $ua_parsed,
            'fingerprint'   => $visibility,
            'webrtc'        => $webrtc_summary,
            'dns_test'      => $dns_test_state,
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