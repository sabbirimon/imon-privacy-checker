<?php
/**
 * AnonymityScorer — correlates signals that already exist elsewhere in the
 * plugin (IP-geo timezone, browser-reported timezone, WebRTC leak result,
 * ProxyDetector's classification) into one "anonymity consistency" score,
 * rather than leaving the visitor to mentally cross-reference four separate
 * report sections themselves.
 *
 * Pure correlation/scoring — no I/O of its own, every input is data the
 * orchestrator has already fetched for other parts of the report. The
 * composite "anonymity" score and its list of mismatches are then surfaced
 * in the report under `connection.anonymity` and rendered by the
 * `anonymityConsistencyCard()` JS module.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Pure correlation/scoring — no network calls, no external state.
 */
final class AnonymityScorer {

    /**
     * Per-signal deductions applied to the 100-point anonymity base.
     *
     * These are INTENTIONALLY HARDCODED — they're not user-overridable.
     * Exposed via signal_weights() so the Phase 8 admin "Scoring
     * Parameters" reference card can render the values from this
     * single source of truth rather than duplicating them in admin
     * HTML.
     *
     * - timezone:    medium-severity mismatch between IP-geo and
     *                browser-reported timezone.
     * - webrtc:      high-severity — public IP leak through WebRTC.
     *                Heaviest because it's an active exposure.
     * - dns:         high-severity — DNS resolvers on a different
     *                network than the visible connection (tunnel
     *                bypass).
     * - proxy:       0 — confirmed VPN/proxy is not penalised on its
     *                own (often the user's intent). It only matters
     *                in combination with the leaks above.
     *
     * @var array<string,int>
     */
    private const SIGNAL_WEIGHTS = array(
        'timezone' => 20,
        'webrtc'   => 40,
        'dns'      => 30,
        'proxy'    => 0,
    );

    /**
     * Public getter for the per-signal weight table.
     *
     * @return array<string,int>
     */
    public static function signal_weights(): array {
        return self::SIGNAL_WEIGHTS;
    }

    /**
     * Score anonymity consistency across the four signals that already exist
     * in an ordinary scan report.
     *
     * Scoring weights (each is a deduction from the 100-point base):
     *   - timezone mismatch (different UTC offset):     -20 (medium)
     *   - WebRTC leaked public IP:                       -40 (high)
     *   - DNS resolver on a different network than the  -30 (high)
     *     visible connection
     *   - confirmed proxy/VPN:                           +0  (intentional
     *     use is not penalised on its own; only matters
     *     in combination with the leaks above)
     *
     * @param array<string,mixed>  $ip_intel        IP intel array (must include 'timezone' if known).
     * @param array<string,mixed>  $webrtc_summary  Output of Webrtc::summarize().
     * @param array<string,mixed>  $proxy_result    Output of ProxyDetector::classify_with_lists().
     * @param string               $browser_timezone Client-reported IANA timezone (from collectFingerprint()).
     * @param array<string,mixed>|null $dns_test_result Optional. Output of a completed DNS leak test, if one
     *                                                    has been run this session and its result was passed
     *                                                    back in with the scan request. Null = not yet run;
     *                                                    the DNS-leak check below is simply skipped, it does
     *                                                    not count against the score either way.
     * @return array{consistent:bool,score:int,mismatches:array<int,array{signal:string,detail:string,severity:string}>,summary:string}
     */
    public static function score(
        array $ip_intel,
        array $webrtc_summary,
        array $proxy_result,
        string $browser_timezone,
        ?array $dns_test_result = null
    ): array {
        $mismatches = array();
        $score      = 100;

        // 1. IP-geo timezone vs browser-reported timezone.
        $ip_timezone = (string) ( $ip_intel['timezone'] ?? '' );
        if ( '' !== $ip_timezone && '' !== $browser_timezone && $ip_timezone !== $browser_timezone ) {
            $same_offset = self::timezones_share_offset( $ip_timezone, $browser_timezone );
            if ( ! $same_offset ) {
                $mismatches[] = array(
                    'signal'   => 'timezone',
                    'detail'   => sprintf(
                        /* translators: 1: IP-based timezone, 2: browser-reported timezone */
                        __( 'Your IP address geolocates to the %1$s timezone, but your browser reports %2$s.', 'privacy-checker' ),
                        $ip_timezone,
                        $browser_timezone
                    ),
                    'severity' => 'medium',
                );
                $score -= 20;
            }
        }

        // 2. WebRTC leak. This is the strongest single signal — a leaked
        // public IP behind an assumed VPN/proxy is a real, active exposure,
        // not just an inconsistency, so it is weighted heaviest.
        if ( 'potential_exposure' === ( $webrtc_summary['verdict'] ?? '' ) ) {
            $leaked_ip     = (string) ( $webrtc_summary['public_addrs'][0] ?? '' );
            $connection_ip = (string) ( $ip_intel['query'] ?? $ip_intel['ip'] ?? '' );
            $different_ip  = '' !== $leaked_ip && '' !== $connection_ip && $leaked_ip !== $connection_ip;

            $mismatches[] = array(
                'signal'   => 'webrtc',
                'detail'   => $different_ip
                    ? sprintf(
                        /* translators: 1: IP leaked via WebRTC, 2: IP the server sees */
                        __( 'WebRTC revealed %1$s, which differs from the %2$s address this server sees — likely a VPN/proxy leak.', 'privacy-checker' ),
                        $leaked_ip,
                        $connection_ip
                    )
                    : __( 'WebRTC revealed a public IP address during this test.', 'privacy-checker' ),
                'severity' => 'high',
            );
            $score -= 40;
        }

        // 3. DNS leak, only if a completed test result was supplied.
        if ( null !== $dns_test_result && ! empty( $dns_test_result['resolver_org'] ) ) {
            $resolver_org   = (string) $dns_test_result['resolver_org'];
            $connection_org = (string) ( $ip_intel['org'] ?? $ip_intel['isp'] ?? '' );
            if ( '' !== $resolver_org && '' !== $connection_org && stripos( $resolver_org, $connection_org ) === false
                && stripos( $connection_org, $resolver_org ) === false ) {
                $mismatches[] = array(
                    'signal'   => 'dns',
                    'detail'   => sprintf(
                        /* translators: 1: network the DNS resolver belongs to, 2: network the visible connection belongs to */
                        __( 'Your DNS queries appear to exit via %1$s, a different network than your visible connection (%2$s) — DNS may be leaking outside your VPN tunnel.', 'privacy-checker' ),
                        $resolver_org,
                        $connection_org
                    ),
                    'severity' => 'high',
                );
                $score -= 30;
            }
        }

        // 4. Fold in ProxyDetector's own confidence as a lighter input —
        // this does not add a new mismatch entry (it already has its own
        // dedicated report section), it only nudges the composite score so
        // a "confirmed proxy/VPN" isn't scored as if nothing were detected.
        $proxy_confidence = (string) ( $proxy_result['confidence'] ?? 'low' );
        if ( 'high' === $proxy_confidence && 'unknown' !== ( $proxy_result['category'] ?? 'unknown' ) ) {
            // Being on a known VPN/proxy is often the user's *intent*, not a
            // failure — so this only matters in combination with the leaks
            // above. On its own, detected-and-intentional proxy use is not
            // penalised further here.
            $score = min( $score + 0, 100 );
        }

        $score = max( 0, min( 100, $score ) );

        if ( empty( $mismatches ) ) {
            $summary = __( 'No inconsistencies detected between your IP, timezone, and connection signals.', 'privacy-checker' );
        } elseif ( $score < 50 ) {
            $summary = __( 'Multiple signals disagree with each other — your real network details may be exposed despite a VPN or proxy.', 'privacy-checker' );
        } else {
            $summary = __( 'Minor inconsistencies detected. Review the details below.', 'privacy-checker' );
        }

        return array(
            'consistent' => empty( $mismatches ),
            'score'      => $score,
            'mismatches' => $mismatches,
            'summary'    => $summary,
        );
    }

    /**
     * Rough same-UTC-offset check between two IANA timezone names, using
     * PHP's own timezone database — avoids treating e.g. "Europe/Berlin"
     * vs "Europe/Paris" (same offset, different city) as a mismatch.
     */
    private static function timezones_share_offset( string $tz_a, string $tz_b ): bool {
        try {
            $now      = new \DateTime( 'now' );
            $offset_a = ( new \DateTimeZone( $tz_a ) )->getOffset( $now );
            $offset_b = ( new \DateTimeZone( $tz_b ) )->getOffset( $now );
            return $offset_a === $offset_b;
        } catch ( \Throwable $e ) {
            // Unknown/invalid timezone name — can't confirm they match, but
            // also shouldn't confidently flag a mismatch on bad data.
            return true;
        }
    }
}
