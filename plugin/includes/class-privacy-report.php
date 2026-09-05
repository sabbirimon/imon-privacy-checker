<?php
/**
 * Detailed privacy report — Whoer.net style breakdown.
 *
 * Aggregates every signal produced by the scan and emits:
 *   - `overall`: 0-100 score, grade (A-F), confidence (high/medium/low).
 *   - `categories`: per-component percentages with status (good | warning | bad).
 *   - `headline`: short sentence for the result card.
 *   - `recommendations`: deduplicated, prioritized tips.
 *
 * The score is intentionally additive so each component contributes
 * weighted points. The final value is clamped to [0, 100] and never
 * presented as a guarantee — it's a hint.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static report builder.
 */
final class PrivacyReport {

    /**
     * Build the full report from a scan result.
     *
     * @param array<string,mixed> $scan Full ScannerOrchestrator::scan() output.
     * @return array<string,mixed>
     */
    public static function build( array $scan ): array {
        $categories = array(
            'ip'          => self::score_ip(          $scan ),
            'reputation'  => self::score_reputation(  $scan ),
            'dns'         => self::score_dns(         $scan ),
            'webrtc'      => self::score_webrtc(      $scan ),
            'fingerprint' => self::score_fingerprint( $scan ),
            'user_agent'  => self::score_user_agent(  $scan ),
            'ipv6'        => self::score_ipv6(        $scan ),
            'consistency' => self::score_consistency( $scan ),
            'proxy'       => self::score_proxy(       $scan ),
        );

        // Carry the proxy detection result on the top-level report so the UI
        // can show a vendor badge without recomputing anything client-side.
        $proxy_meta = $scan['connection']['proxy'] ?? null;
        if ( is_array( $proxy_meta ) ) {
            $scan['privacy_report_proxy_meta'] = $proxy_meta;
        }

        // Weighted average over categories. Each category contributes its
        // own percentage scaled by its weight, then we sum and renormalize.
        $total_weight  = 0;
        $weighted_sum  = 0;
        $worst         = null;
        $worst_pct     = 101;

        foreach ( $categories as $key => $row ) {
            $weight  = (int) ( $row['weight'] ?? 1 );
            $pct     = (int) ( $row['percent'] ?? 0 );
            $total_weight += $weight;
            $weighted_sum += $pct * $weight;
            if ( $pct < $worst_pct ) {
                $worst_pct = $pct;
                $worst     = $key;
            }
        }

        $overall = $total_weight > 0
            ? (int) round( $weighted_sum / $total_weight )
            : 0;
        $overall = max( 0, min( 100, $overall ) );

        $grade = self::grade_for( $overall );
        $confidence = self::confidence_for( $categories );

        return array(
            'overall'      => $overall,
            'grade'        => $grade,
            'confidence'   => $confidence,
            'headline'     => self::headline_for( $overall, $worst, $categories ),
            'categories'   => $categories,
            'proxy'        => is_array( $proxy_meta ) ? $proxy_meta : null,
            'recommendations' => self::recommendations( $categories, $scan ),
            'generated_at' => gmdate( 'c' ),
        );
    }

    /**
     * Map a 0-100 score to a letter grade.
     */
    private static function grade_for( int $score ): string {
        if ( $score >= 90 ) { return 'A'; }
        if ( $score >= 80 ) { return 'B'; }
        if ( $score >= 65 ) { return 'C'; }
        if ( $score >= 50 ) { return 'D'; }
        if ( $score >= 30 ) { return 'E'; }
        return 'F';
    }

    /**
     * Confidence label based on how many components have a real signal.
     */
    private static function confidence_for( array $categories ): string {
        $unknown = 0;
        foreach ( $categories as $row ) {
            if ( isset( $row['status_source'] ) && 'unknown' === $row['status_source'] ) {
                $unknown++;
            }
        }
        if ( $unknown <= 1 ) { return 'high'; }
        if ( $unknown <= 3 ) { return 'medium'; }
        return 'low';
    }

    /**
     * One-line summary shown above the detailed report.
     */
    private static function headline_for( int $overall, ?string $worst, array $categories ): string {
        if ( $overall >= 90 ) {
            return __( 'Excellent privacy posture. Most signals are clean.', 'privacy-checker' );
        }
        if ( $overall >= 70 ) {
            return __( 'Good privacy with a few items worth reviewing.', 'privacy-checker' );
        }
        if ( $overall >= 50 ) {
            return __( 'Mixed results. Several components warrant attention.', 'privacy-checker' );
        }
        if ( $overall >= 30 ) {
            return __( 'Significant privacy concerns detected.', 'privacy-checker' );
        }
        return __( 'Severe privacy issues detected across most components.', 'privacy-checker' );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_ip( array $scan ): array {
        $intel    = $scan['connection']['intel'] ?? array();
        $status   = (string) ( $intel['status']  ?? 'unknown' );
        $has_geo  = ! empty( $intel['country'] ) || ! empty( $intel['country_name'] ) || ! empty( $intel['city'] );
        $has_asn  = ! empty( $intel['asn'] ) || ! empty( $intel['org'] ) || ! empty( $intel['isp'] );

        if ( 'ok' === $status && $has_geo && $has_asn ) {
            return self::row( 75, 'warning', 'ip',
                __( 'IP geolocation and ASN are visible. Anyone you contact can see your approximate location and provider.', 'privacy-checker' ),
                array( 'country' => $intel['country'] ?? '', 'asn' => $intel['asn'] ?? '' ),
                2
            );
        }
        if ( 'ok' === $status ) {
            return self::row( 80, 'warning', 'ip',
                __( 'IP intel partially resolved.', 'privacy-checker' ),
                array(),
                2
            );
        }
        if ( 'mock' === $status || ( ! empty( $scan['request_ip']['is_mock'] ) ) ) {
            return self::row( 100, 'good', 'ip',
                __( 'Running in mock / dev mode. Real IP intel is not gathered.', 'privacy-checker' ),
                array(),
                1
            );
        }
        return self::row( 50, 'warning', 'ip',
            __( 'IP intelligence provider did not respond. Cannot fully evaluate exposure.', 'privacy-checker' ),
            array(),
            2
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_reputation( array $scan ): array {
        $status = (string) ( $scan['reputation']['status'] ?? 'unknown' );
        switch ( $status ) {
            case 'clean':
                return self::row( 100, 'good', 'reputation',
                    __( 'IP is clean across reputation lists.', 'privacy-checker' ),
                    array(),
                    3
                );
            case 'suspicious':
                return self::row( 55, 'warning', 'reputation',
                    __( 'IP is flagged as suspicious on at least one list.', 'privacy-checker' ),
                    array( 'lists' => $scan['reputation']['lists'] ?? array() ),
                    3
                );
            case 'listed':
                return self::row( 15, 'bad', 'reputation',
                    __( 'IP appears on reputation lists. Some services may block or challenge you.', 'privacy-checker' ),
                    array( 'lists' => $scan['reputation']['lists'] ?? array() ),
                    3
                );
            case 'unknown':
            default:
                return self::row( 50, 'warning', 'reputation',
                    __( 'Reputation provider did not return a verdict.', 'privacy-checker' ),
                    array(),
                    2,
                    'unknown'
                );
        }
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_dns( array $scan ): array {
        $state = $scan['dns_test'] ?? array();
        if ( empty( $state['configured'] ) ) {
            return self::row( 60, 'warning', 'dns',
                __( 'DNS leak test not configured. Real resolver analysis is unavailable.', 'privacy-checker' ),
                array(),
                2,
                'unknown'
            );
        }
        $consistent = (bool) ( $state['consistent'] ?? true );
        $leak       = (float) ( $state['leak_score'] ?? 0.0 );
        $status     = (string) ( $state['status'] ?? 'unknown' );

        if ( 'ok' === $status && $consistent && $leak <= 0.0 ) {
            return self::row( 100, 'good', 'dns',
                __( 'Resolvers agree — no DNS leak detected.', 'privacy-checker' ),
                array( 'leak_score' => $leak ),
                2
            );
        }
        if ( 'ok' === $status && $leak < 0.5 ) {
            return self::row( 70, 'warning', 'dns',
                __( 'Some resolver disagreement observed.', 'privacy-checker' ),
                array( 'leak_score' => $leak ),
                2
            );
        }
        if ( 'ok' === $status ) {
            return self::row( 30, 'bad', 'dns',
                __( 'Resolvers disagree significantly — possible DNS leak.', 'privacy-checker' ),
                array( 'leak_score' => $leak ),
                3
            );
        }
        return self::row( 40, 'bad', 'dns',
            __( 'DNS probe failed.', 'privacy-checker' ),
            array(),
            2
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_webrtc( array $scan ): array {
        $verdict = (string) ( $scan['webrtc']['verdict'] ?? 'unknown' );
        switch ( $verdict ) {
            case 'protected':
                return self::row( 100, 'good', 'webrtc',
                    __( 'WebRTC does not expose public IPs.', 'privacy-checker' ),
                    array(),
                    2
                );
            case 'potential_exposure':
                $exposed = $scan['webrtc']['public_ips'] ?? array();
                return self::row( 20, 'bad', 'webrtc',
                    __( 'WebRTC exposes public IP(s). VPN users are particularly exposed.', 'privacy-checker' ),
                    array( 'exposed_ips' => $exposed ),
                    3
                );
            case 'not_supported':
                return self::row( 95, 'good', 'webrtc',
                    __( 'WebRTC is not supported in this browser.', 'privacy-checker' ),
                    array(),
                );
            default:
                return self::row( 60, 'warning', 'webrtc',
                    __( 'WebRTC status unknown — no client signal was provided.', 'privacy-checker' ),
                    array(),
                    1,
                    'unknown'
                );
        }
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_fingerprint( array $scan ): array {
        $level = (string) ( $scan['fingerprint']['level'] ?? 'unknown' );
        $bits  = isset( $scan['fingerprint']['bits'] ) ? (int) $scan['fingerprint']['bits'] : 0;
        switch ( $level ) {
            case 'low':
                return self::row( 100, 'good', 'fingerprint',
                    __( 'Browser fingerprint is low-entropy and hard to distinguish.', 'privacy-checker' ),
                    array( 'bits' => $bits ),
                    3
                );
            case 'moderate':
                return self::row( 65, 'warning', 'fingerprint',
                    __( 'Browser fingerprint has moderate entropy.', 'privacy-checker' ),
                    array( 'bits' => $bits ),
                    3
                );
            case 'high':
                return self::row( 20, 'bad', 'fingerprint',
                    __( 'Browser fingerprint is highly unique — easily trackable across sites.', 'privacy-checker' ),
                    array( 'bits' => $bits ),
                    3
                );
            default:
                return self::row( 60, 'warning', 'fingerprint',
                    __( 'Browser fingerprint signal unavailable.', 'privacy-checker' ),
                    array(),
                    1,
                    'unknown'
                );
        }
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_user_agent( array $scan ): array {
        $ua = (string) ( $scan['user_agent']['ua'] ?? '' );
        if ( '' === $ua ) {
            return self::row( 70, 'warning', 'user_agent',
                __( 'No User-Agent string was sent.', 'privacy-checker' ),
                array(),
                1,
                'unknown'
            );
        }
        $bot = ! empty( $scan['user_agent']['bot'] );
        if ( $bot ) {
            return self::row( 30, 'bad', 'user_agent',
                __( 'User-Agent matches a known bot/crawler pattern.', 'privacy-checker' ),
                array( 'bot' => $scan['user_agent']['bot_name'] ?? '' ),
                2
            );
        }
        $extras = 0;
        if ( ! empty( $scan['user_agent']['browser_version'] ) ) { $extras++; }
        if ( ! empty( $scan['user_agent']['os_version'] ) )        { $extras++; }
        if ( ! empty( $scan['user_agent']['device'] ) )           { $extras++; }

        if ( $extras >= 3 ) {
            return self::row( 40, 'warning', 'user_agent',
                __( 'User-Agent exposes detailed browser, OS, and device versions.', 'privacy-checker' ),
                $scan['user_agent'],
                2
            );
        }
        if ( $extras >= 1 ) {
            return self::row( 70, 'warning', 'user_agent',
                __( 'User-Agent leaks some version detail.', 'privacy-checker' ),
                $scan['user_agent'],
                2
            );
        }
        return self::row( 90, 'good', 'user_agent',
            __( 'User-Agent is minimal.', 'privacy-checker' ),
            $scan['user_agent'],
            1
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_ipv6( array $scan ): array {
        $ipv6 = (string) ( $scan['connection']['ipv6'] ?? '' );
        if ( '' === $ipv6 ) {
            return self::row( 100, 'good', 'ipv6',
                __( 'No IPv6 address detected.', 'privacy-checker' ),
                array(),
                1
            );
        }
        return self::row( 60, 'warning', 'ipv6',
            __( 'IPv6 is exposed. Your provider may see two distinct addresses.', 'privacy-checker' ),
            array( 'ipv6' => $ipv6 ),
            2
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_proxy( array $scan ): array {
        // score_proxy uses ProxyDetector's "score" field (higher = more likely
        // to be a masking service). We invert it for the privacy percentage:
        // a residential IP is a good privacy posture only if the user actively
        // wants anonymity. For most users, "the IP clearly belongs to a
        // consumer ISP" is neutral. Forcing VPN on residential users is not
        // our call.
        $proxy = $scan['connection']['proxy'] ?? array();
        $cat   = (string) ( $proxy['category'] ?? 'unknown' );
        $conf  = (string) ( $proxy['confidence'] ?? 'low' );
        $mask  = (int)   ( $proxy['score']     ?? 0 );
        $label = (string) ( $proxy['label']    ?? 'Unknown' );

        if ( 'residential' === $cat ) {
            return self::row( 80, 'good', 'proxy',
                __( 'Connection is from a residential ISP. Either you have a clean setup or your IP is not on any known masking list.', 'privacy-checker' ),
                array( 'category' => $cat, 'confidence' => $conf, 'label' => $label ),
                2
            );
        }
        if ( 'hosting' === $cat || 'datacenter' === $cat ) {
            return self::row( 40, 'bad', 'proxy',
                __( 'Your IP belongs to a hosting/datacenter network. This often indicates a VPN, VPS, or server-based connection — not a consumer ISP.', 'privacy-checker' ),
                array( 'category' => $cat, 'confidence' => $conf, 'label' => $label, 'vendor' => $proxy['vendor'] ?? '' ),
                2
            );
        }
        if ( 'vpn' === $cat ) {
            return self::row( 90, 'good', 'proxy',
                __( 'A commercial VPN is in use. Anonymity is improved; some services may treat the connection as suspicious.', 'privacy-checker' ),
                array( 'category' => $cat, 'confidence' => $conf, 'label' => $label, 'vendor' => $proxy['vendor'] ?? '' ),
                2
            );
        }
        if ( 'proxy' === $cat ) {
            return self::row( 70, 'warning', 'proxy',
                __( 'A commercial proxy or web-scraping provider is detected. These services are often abused and may already be reputation-flagged.', 'privacy-checker' ),
                array( 'category' => $cat, 'confidence' => $conf, 'label' => $label, 'vendor' => $proxy['vendor'] ?? '' ),
                2
            );
        }
        if ( 'tor' === $cat ) {
            return self::row( 100, 'good', 'proxy',
                __( 'Tor exit relay detected. Maximum anonymity from the IP layer; many sites will challenge the connection.', 'privacy-checker' ),
                array( 'category' => $cat, 'confidence' => $conf, 'label' => $label ),
                2
            );
        }
        return self::row( 60, 'warning', 'proxy',
            __( 'Could not determine proxy/VPN/hosting status from network intelligence.', 'privacy-checker' ),
            array( 'category' => $cat, 'confidence' => $conf, 'label' => $label ),
            1,
            'unknown'
        );
    }

    /**
     * @return array<string,mixed>
     */
    private static function score_consistency( array $scan ): array {
        // Consistency cross-check: does the IP intel country match the timezone?
        $tz     = isset( $scan['fingerprint']['timezone'] ) ? (string) $scan['fingerprint']['timezone'] : '';
        $intel  = $scan['connection']['intel'] ?? array();
        $country = strtolower( (string) ( $intel['country'] ?? '' ) );

        if ( '' === $tz || '' === $country ) {
            return self::row( 80, 'good', 'consistency',
                __( 'Insufficient data to cross-check IP and timezone.', 'privacy-checker' ),
                array(),
                1,
                'unknown'
            );
        }
        // Cheap heuristic — if timezone includes a country code we recognize,
        // we expect intel.country to roughly match. We can't truly geolocate
        // a timezone, so we only flag clearly mismatched pairs.
        $tz_country_map = array(
            'america/'  => array( 'us', 'ca', 'mx', 'br', 'ar' ),
            'europe/'   => array( 'gb', 'de', 'fr', 'es', 'it', 'nl', 'pl', 'se', 'no', 'fi', 'dk', 'ie' ),
            'asia/'     => array( 'jp', 'cn', 'kr', 'in', 'th', 'sg', 'hk', 'tw', 'id', 'ph', 'my', 'vn' ),
            'africa/'   => array( 'za', 'ng', 'eg', 'ke', 'ma' ),
            'australia/' => array( 'au', 'nz' ),
            'pacific/'  => array( 'nz', 'au', 'fj' ),
        );
        $tz_lower = strtolower( $tz );
        $expected = array();
        foreach ( $tz_country_map as $prefix => $countries ) {
            if ( str_starts_with( $tz_lower, $prefix ) ) {
                $expected = $countries;
                break;
            }
        }
        if ( empty( $expected ) ) {
            return self::row( 80, 'good', 'consistency',
                __( 'Timezone region unknown.', 'privacy-checker' ),
                array(),
                1,
                'unknown'
            );
        }
        if ( in_array( $country, $expected, true ) ) {
            return self::row( 100, 'good', 'consistency',
                __( 'IP and timezone are consistent.', 'privacy-checker' ),
                array( 'country' => $country, 'timezone' => $tz ),
                2
            );
        }
        return self::row( 35, 'warning', 'consistency',
            __( 'IP country and timezone disagree — possible VPN or proxy in use.', 'privacy-checker' ),
            array( 'country' => $country, 'timezone' => $tz ),
            2
        );
    }

    /**
     * Build a per-category row.
     *
     * @param array<string,mixed> $details
     * @return array<string,mixed>
     */
    private static function row( int $percent, string $status, string $key, string $message, array $details, int $weight = 1, string $source = 'measured' ): array {
        // Normalize status.
        if ( ! in_array( $status, array( 'good', 'warning', 'bad' ), true ) ) {
            $status = 'warning';
        }
        return array(
            'key'           => $key,
            'percent'       => max( 0, min( 100, $percent ) ),
            'status'        => $status,
            'weight'        => max( 1, $weight ),
            'message'       => $message,
            'details'       => $details,
            'status_source' => $source,
        );
    }

    /**
     * Prioritized, deduplicated recommendations.
     *
     * @param array<string,mixed> $categories
     * @param array<string,mixed> $scan
     * @return array<int,array{key:string, priority:string, message:string}>
     */
    private static function recommendations( array $categories, array $scan ): array {
        $recs = array();

        $map = array(
            'reputation'  => array(
                'listed' => array(
                    'priority' => 'high',
                    'message'  => __( 'Your IP is listed on a reputation blocklist. Contact your ISP or hosting provider.', 'privacy-checker' ),
                ),
                'suspicious' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Your IP is flagged as suspicious. Avoid new account creation from this network until cleared.', 'privacy-checker' ),
                ),
            ),
            'webrtc'      => array(
                'bad' => array(
                    'priority' => 'high',
                    'message'  => __( 'Disable WebRTC in your browser or use an extension that masks WebRTC leaks (uBlock Origin, WebRTC Leak Prevent).', 'privacy-checker' ),
                ),
            ),
            'dns'         => array(
                'bad' => array(
                    'priority' => 'high',
                    'message'  => __( 'A DNS leak was detected. Configure your VPN client to push DNS through the tunnel and verify with this tool again.', 'privacy-checker' ),
                ),
                'warning' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Some resolver disagreement observed. Re-run the DNS leak test to confirm.', 'privacy-checker' ),
                ),
            ),
            'fingerprint' => array(
                'bad' => array(
                    'priority' => 'high',
                    'message'  => __( 'Your browser fingerprint is highly unique. Use Tor Browser or Firefox with `privacy.resistFingerprinting` enabled.', 'privacy-checker' ),
                ),
                'warning' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Reduce fingerprint surface: disable WebGL, block canvas readback, limit installed fonts.', 'privacy-checker' ),
                ),
            ),
            'ip'          => array(
                'warning' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Your IP reveals your country, region, and provider. A reputable VPN or Tor reduces this exposure.', 'privacy-checker' ),
                ),
            ),
            'consistency' => array(
                'warning' => array(
                    'priority' => 'medium',
                    'message'  => __( 'IP country and timezone do not match. This is expected when using a VPN, but verify the VPN is actually active.', 'privacy-checker' ),
                ),
            ),
            'ipv6'        => array(
                'warning' => array(
                    'priority' => 'low',
                    'message'  => __( 'IPv6 is exposed. Either disable IPv6 at the OS level or make sure your VPN tunnels IPv6 as well.', 'privacy-checker' ),
                ),
            ),
            'user_agent'  => array(
                'warning' => array(
                    'priority' => 'low',
                    'message'  => __( 'Your User-Agent leaks detailed version info. Consider an extension that randomizes it.', 'privacy-checker' ),
                ),
            ),
            'proxy'       => array(
                'bad' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Your IP belongs to a hosting network. If this is unexpected, run an antivirus scan — your device may be using a proxy you did not intend to enable.', 'privacy-checker' ),
                ),
                'warning' => array(
                    'priority' => 'medium',
                    'message'  => __( 'Commercial proxy detected. Some sites will already block or challenge this traffic.', 'privacy-checker' ),
                ),
            ),
        );

        foreach ( $categories as $key => $row ) {
            $status = $row['status'] ?? 'warning';
            if ( isset( $map[ $key ][ $status ] ) ) {
                $recs[] = array_merge(
                    array( 'key' => $key ),
                    $map[ $key ][ $status ]
                );
            }
        }

        // Always-on baseline.
        $recs[] = array(
            'key'      => 'baseline',
            'priority' => 'low',
            'message'  => __( 'Use HTTPS for all sensitive sites and keep your browser up to date.', 'privacy-checker' ),
        );

        // Sort by priority: high → medium → low.
        usort( $recs, function ( array $a, array $b ): int {
            $order = array( 'high' => 0, 'medium' => 1, 'low' => 2 );
            $pa    = $order[ $a['priority'] ] ?? 3;
            $pb    = $order[ $b['priority'] ] ?? 3;
            return $pa <=> $pb;
        } );

        return $recs;
    }
}
