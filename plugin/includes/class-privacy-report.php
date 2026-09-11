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
     * Canonical category weights, keyed by category.
     *
     * These are the "primary" weights shown in the Phase 8 admin
     * reference card. Per-category score_*() methods may pass a
     * different weight for a specific verdict (e.g. dns_bad = 3 vs
     * the dns_did_not_run default of 2). This map is the canonical
     * source-of-truth reference for admins — the per-verdict
     * overrides are documented inline in the score_*() methods.
     *
     * Per IMON-BUILD-GUIDE.md Phase 6:
     *   - consistency (4)        highest — "are you actually private"
     *   - security_posture (3)   outdated TLS / very-old browser
     *   - webrtc (3)             public-IP leak
     *   - dns (3)                resolver leak
     *   - reputation (3)         listed / suspicious IPs
     *   - fingerprint (2)        entropy / uniqueness
     *   - ip (2)                 geo + ASN visibility
     *   - proxy (2)              VPN/hosting/tor detection
     *   - user_agent (2)         detail in UA string
     *   - ipv6 (2)               v6 leakage
     *   - connection_quality (0) surface-only — connection health
     *   - local_network (0)      surface-only — LAN exposure
     *
     * @var array<string,int>
     */
    private const CATEGORY_WEIGHTS = array(
        'consistency'        => 4,
        'security_posture'   => 3,
        'webrtc'             => 3,
        'dns'                => 3,
        'reputation'         => 3,
        'fingerprint'        => 2,
        'ip'                 => 2,
        'proxy'              => 2,
        'user_agent'         => 2,
        'ipv6'               => 2,
        'connection_quality' => 0,
        'local_network'      => 0,
    );

    /**
     * Public getter — used by the Phase 8 admin "Scoring Parameters"
     * reference card and by the Privacy Report inspector's
     * weighted-avg transparency panel.
     *
     * @return array<string,int>
     */
    public static function category_weights(): array {
        return self::CATEGORY_WEIGHTS;
    }

    /**
     * Build the full report from a scan result.
     *
     * @param array<string,mixed> $scan Full ScannerOrchestrator::scan() output.
     * @return array<string,mixed>
     */
    public static function build( array $scan ): array {
        $categories = array(
            'ip'                  => self::score_ip(                  $scan ),
            'reputation'          => self::score_reputation(          $scan ),
            'dns'                 => self::score_dns(                 $scan ),
            'webrtc'              => self::score_webrtc(              $scan ),
            'fingerprint'         => self::score_fingerprint(         $scan ),
            'user_agent'          => self::score_user_agent(          $scan ),
            'ipv6'                => self::score_ipv6(                $scan ),
            'consistency'         => self::score_consistency(         $scan ),
            'security_posture'    => self::score_security_posture(    $scan ),
            'proxy'               => self::score_proxy(               $scan ),
            // Surface-only — appear in the breakdown but excluded from
            // the weighted overall. Per IMON-BUILD-GUIDE.md Phase 6: a
            // slow connection or a chatty LAN isn't a privacy problem,
            // so we surface them under a separate "connection health"
            // heading rather than letting them move the privacy score.
            'connection_quality'  => self::score_connection_quality(  $scan ),
            'local_network'       => self::score_local_network(       $scan ),
        );

        // Carry the proxy detection result on the top-level report so the UI
        // can show a vendor badge without recomputing anything client-side.
        $proxy_meta = $scan['connection']['proxy'] ?? null;
        if ( is_array( $proxy_meta ) ) {
            $scan['privacy_report_proxy_meta'] = $proxy_meta;
        }

        // Weighted average over categories. Each category contributes its
        // own percentage scaled by its weight, then we sum and renormalize.
        // Categories with weight 0 are SURFACE-ONLY — they appear in the
        // breakdown but don't move the privacy overall (per
        // IMON-BUILD-GUIDE.md Phase 6: connection quality + local network
        // exposure are "connection health", not privacy).
        $total_weight  = 0;
        $weighted_sum  = 0;
        $worst         = null;
        $worst_pct     = 101;

        foreach ( $categories as $key => $row ) {
            $weight  = (int) ( $row['weight'] ?? 1 );
            $pct     = (int) ( $row['percent'] ?? 0 );
            if ( $weight <= 0 ) {
                continue; // surface-only — exclude from weighted overall
            }
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

        // Phase 40: a high score alone shouldn't buy you a "Good privacy"
        // headline if several categories came back Bad. Count weighted bad
        // categories and pull the headline down (and the grade, where the
        // weighted bad count is high enough to matter). The numeric score
        // stays the same — it's still a weighted average — but the words
        // we wrap around it get honest.
        $bad_count  = 0;
        $warn_count = 0;
        $good_count = 0;
        foreach ( $categories as $row ) {
            $weight = (int) ( $row['weight'] ?? 1 );
            if ( $weight <= 0 ) {
                continue;
            }
            $st = (string) ( $row['status'] ?? '' );
            if ( 'bad' === $st ) {
                $bad_count++;
            } elseif ( 'warning' === $st ) {
                $warn_count++;
            } else {
                $good_count++;
            }
        }

        $grade = self::grade_for( $overall, $bad_count, $warn_count );

        // Phase 41: identity leak despite using a VPN/proxy is the
        // worst possible privacy outcome — the masking tool is on but
        // signals are still exposing the visitor. Force the grade to F
        // regardless of the weighted average. The numeric overall still
        // reflects what was measured (for transparency), but the letter
        // grade must be unmistakable. We also surface a flag in the
        // report so the UI can highlight the leak prominently.
        $leak_despite_proxy = self::leak_despite_proxy( $scan, $categories );
        if ( $leak_despite_proxy ) {
            $grade = 'F';
        }

        $confidence = self::confidence_for( $categories );

        // Build the headline AFTER we've decided whether the visitor is
        // leaking identity through their VPN/proxy — that condition
        // overrides everything else in the wording. The numeric
        // overall/grade pair tells the same story one block above.
        $headline = self::headline_for( $overall, $worst, $categories, $leak_despite_proxy );

        return array(
            'overall'              => $overall,
            'grade'                => $grade,
            'confidence'           => $confidence,
            'headline'             => $headline,
            'categories'           => $categories,
            'proxy'                => is_array( $proxy_meta ) ? $proxy_meta : null,
            'leak_despite_proxy'   => $leak_despite_proxy,
            'recommendations'      => self::recommendations( $categories, $scan ),
            'generated_at'         => gmdate( 'c' ),
        );
    }

    /**
     * Map a 0-100 score to a letter grade.
     *
     * Phase 40: the grade must also reflect the number of BAD-flagged
     * categories. A score of 72% with two Bad categories is not a "C"
     * — it's at best a "D" because real failures are being averaged
     * down by clean signals that are easy wins. The thresholds below
     * keep a 100% all-good run at A but pull a "two bad + DNS failing"
     * run from C to D.
     */
    private static function grade_for( int $score, int $bad_count = 0, int $warn_count = 0 ): string {
        // Hard cap: a D grade should mean "below average" — below 60.
        // Two weighted-BAD categories with a 78% overall used to read
        // as a C ("good"), which is misleading. The buckets below
        // guarantee that 2+ BADs can never grade above E and 1 BAD can
        // never grade above D.
        if ( $bad_count >= 2 ) {
            // 2+ true failures drag the grade down hard. Below 40 is F,
            // 40-59 is E, and even a clean-looking 80 is still E.
            if ( $score >= 80 ) { return 'E'; }
            if ( $score >= 60 ) { return 'E'; }
            if ( $score >= 40 ) { return 'F'; }
            return 'F';
        }
        if ( $bad_count === 1 ) {
            // One failure: cap at D unless the score is below 30.
            if ( $score >= 75 ) { return 'D'; }
            if ( $score >= 60 ) { return 'D'; }
            if ( $score >= 40 ) { return 'E'; }
            if ( $score >= 20 ) { return 'F'; }
            return 'F';
        }
        // No bad categories — use the clean baselines. D is reserved
        // for 50-64 so a passing scan with warnings still reads honestly.
        if ( $score >= 90 ) { return 'A'; }
        if ( $score >= 80 ) { return 'B'; }
        if ( $score >= 65 ) { return 'C'; }
        if ( $score >= 50 ) { return 'D'; }
        if ( $score >= 30 ) { return 'E'; }
        return 'F';
    }

    /**
     * Confidence label based on how many WEIGHTED components have a real
     * signal. Surface-only categories (weight 0) are excluded — they
     * don't affect the privacy score so they shouldn't drag confidence
     * either.
     */
    private static function confidence_for( array $categories ): string {
        $unknown = 0;
        foreach ( $categories as $row ) {
            $weight = (int) ( $row['weight'] ?? 1 );
            if ( $weight <= 0 ) {
                continue;
            }
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
     *
     * Phase 40: the headline counts the BAD-flagged categories (not just
     * the weighted score) so a 72% with two Bad signals doesn't get the
     * "Good privacy with a few items" copy. A grade C with two Bad
     * categories is at best "Mixed results — multiple components failed."
     */
    private static function headline_for( int $overall, ?string $worst, array $categories, bool $leak_despite_proxy = false ): string {
        // Phase 41: identity leak despite a VPN/proxy is the headline
        // case. Don't dress it up — say so in plain language.
        if ( $leak_despite_proxy ) {
            return __( 'Identity is leaking despite your VPN / proxy — your real network details are exposed.', 'privacy-checker' );
        }

        $bad_count  = 0;
        $warn_count = 0;
        foreach ( $categories as $row ) {
            $weight = (int) ( $row['weight'] ?? 1 );
            if ( $weight <= 0 ) {
                continue;
            }
            $st = (string) ( $row['status'] ?? '' );
            if ( 'bad' === $st ) {
                $bad_count++;
            } elseif ( 'warning' === $st ) {
                $warn_count++;
            }
        }
        // Multiple Bad categories overrides any score-based praise.
        if ( $bad_count >= 2 ) {
            return __( 'Multiple components failed — privacy is materially compromised.', 'privacy-checker' );
        }
        if ( $bad_count === 1 ) {
            return __( 'One component failed — review the highlighted category below.', 'privacy-checker' );
        }
        if ( $warn_count >= 3 ) {
            return __( 'Mostly clean with several warnings worth reviewing.', 'privacy-checker' );
        }
        if ( $overall >= 90 ) {
            return __( 'Excellent privacy posture. Most signals are clean.', 'privacy-checker' );
        }
        if ( $overall >= 70 ) {
            return __( 'Good privacy posture.', 'privacy-checker' );
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
                    2
                );
            case 'moderate':
                return self::row( 65, 'warning', 'fingerprint',
                    __( 'Browser fingerprint has moderate entropy.', 'privacy-checker' ),
                    array( 'bits' => $bits ),
                    2
                );
            case 'high':
                return self::row( 20, 'bad', 'fingerprint',
                    __( 'Browser fingerprint is highly unique — easily trackable across sites.', 'privacy-checker' ),
                    array( 'bits' => $bits ),
                    2
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
     * Anonymity consistency — now backed by AnonymityScorer::score() which
     * correlates IP-geo timezone, browser-reported timezone, WebRTC leak
     * verdict, proxy classification, and (optionally) DNS resolver org.
     *
     * Highest weight (4) per IMON-BUILD-GUIDE.md Phase 6: this is the
     * "are you actually as private as you think" signal — more than one
     * channel agreeing on the same answer is the whole point of the
     * correlation. The standalone score_consistency() previously used a
     * cheap IP/timezone country heuristic that missed WebRTC + DNS
     * correlation entirely.
     *
     * The mapper here only translates the scorer's already-baked score +
     * mismatch list into a category row. The category's weight in the
     * weighted overall is what amplifies its importance — not anything
     * we add here.
     *
     * @return array<string,mixed>
     */
    private static function score_consistency( array $scan ): array {
        $anon = $scan['connection']['anonymity'] ?? array();

        // AnonymityScorer wasn't run (older builds, error path) — keep
        // "unknown" honest, don't manufacture a verdict.
        if ( ! is_array( $anon ) || ! isset( $anon['score'] ) || null === $anon['score'] ) {
            return self::row( 70, 'warning', 'consistency',
                __( 'Anonymity consistency not evaluated (no signals correlated on this run).', 'privacy-checker' ),
                array(),
                4,
                'unknown'
            );
        }

        $score      = (int)   $anon['score'];
        $mismatches = is_array( $anon['mismatches'] ?? null ) ? $anon['mismatches'] : array();
        $summary    = (string) ( $anon['summary'] ?? '' );
        $consistent = (bool)   ( $anon['consistent'] ?? false );

        // Phase 40: signal-availability penalty. If anonymity was scored
        // with very few real signals (no IP timezone, no browser timezone,
        // no WebRTC verdict, no DNS test result, no proxy signal) then
        // claiming "100 — no inconsistencies" is dishonest because we
        // didn't actually correlate anything. Count the real signals and
        // cap the score at 60 if we couldn't correlate at least 2 inputs
        // (the minimum for any "agreement between X and Y" statement).
        $intel  = $scan['connection']['intel'] ?? array();
        $webrtc = $scan['webrtc'] ?? array();
        $webrtc_verdict = (string) ( $webrtc['verdict'] ?? '' );
        $has_ip_tz       = '' !== (string) ( $intel['timezone'] ?? '' );
        $has_browser_tz  = '' !== (string) ( $scan['client']['timezone'] ?? '' );
        $has_webrtc      = '' !== $webrtc_verdict && 'unknown' !== $webrtc_verdict;
        $has_dns         = is_array( $scan['dns_test'] ?? null ) && ! empty( $scan['dns_test']['configured'] ) && 'ok' === ( $scan['dns_test']['status'] ?? '' );
        $has_proxy       = is_array( $scan['connection']['proxy'] ?? null ) && ! empty( $scan['connection']['proxy']['confidence'] ?? '' );
        $signals_present = ( $has_ip_tz ? 1 : 0 ) + ( $has_browser_tz ? 1 : 0 ) + ( $has_webrtc ? 1 : 0 ) + ( $has_dns ? 1 : 0 ) + ( $has_proxy ? 1 : 0 );

        if ( $signals_present < 2 ) {
            // Insufficient signal to claim consistency. Surface as warning
            // so the privacy score can't be lifted to 100 on weak data.
            return self::row( 55, 'warning', 'consistency',
                __( 'Anonymity could not be evaluated — multiple detectors were unavailable. Run a scan with all providers enabled for a real consistency verdict.', 'privacy-checker' ),
                array(
                    'consistent' => false,
                    'mismatches' => $mismatches,
                    'signals_present' => $signals_present,
                    'weak_signal' => true,
                ),
                4,
                'unknown'
            );
        }

        // Map the scorer's score → our category status. Tighter buckets
        // than other categories because consistency is the highest-weighted
        // signal: a single 100 must mean "no mismatches at all", not
        // "score happens to be high".
        if ( $consistent && 100 === $score ) {
            $status = 'good';
            $msg    = $summary !== '' ? $summary : __( 'No inconsistencies detected between your IP, timezone and connection signals.', 'privacy-checker' );
        } elseif ( $score >= 70 ) {
            $status = 'good';
            $msg    = $summary !== '' ? $summary : __( 'Minor inconsistencies, well within expected VPN/proxy behavior.', 'privacy-checker' );
        } elseif ( $score >= 40 ) {
            $status = 'warning';
            $msg    = $summary !== '' ? $summary : __( 'Several signals disagree. Review the mismatch list below.', 'privacy-checker' );
        } else {
            $status = 'bad';
            $msg    = $summary !== '' ? $summary : __( 'Multiple signals disagree with each other — your real network details may be exposed despite a masking service.', 'privacy-checker' );
        }

        return self::row( $score, $status, 'consistency', $msg,
            array(
                'consistent' => $consistent,
                'mismatches' => $mismatches,
                'signals_present' => $signals_present,
            ),
            4
        );
    }

    /**
     * Phase 41 — detect "identity leak despite using a masking
     * service". This is the worst possible privacy outcome: the user
     * has gone to the trouble of turning on a VPN or proxy but one of
     * the leak channels is still exposing their real network. The
     * grade for that scenario is forced to F.
     *
     * "Using a masking service" means the proxy category is one of
     *   vpn | proxy | tor | hosting | datacenter
     * at confidence medium or higher. (We don't count residential
     * connections here — that's the user NOT using a mask.)
     *
     * "Leak" means at least one of:
     *   - WebRTC exposes a public IP that differs from the connection IP
     *   - DNS resolvers exit via a different org than the visible IP
     *   - The anonymity scorer found a high-severity mismatch
     *
     * @return bool True when the visitor is leaking through their
     *              masking service and the grade must be F.
     */
    private static function leak_despite_proxy( array $scan, array $categories ): bool {
        $proxy = $scan['connection']['proxy'] ?? array();
        $cat   = (string) ( $proxy['category'] ?? '' );
        $conf  = (string) ( $proxy['confidence'] ?? '' );
        $masking_categories = array( 'vpn', 'proxy', 'tor', 'hosting', 'datacenter' );
        if ( ! in_array( $cat, $masking_categories, true ) ) {
            return false;
        }
        // Only medium-confidence (or better) detections count — we
        // don't want a guessed "vpn" with low confidence to flip a
        // borderline scan to F.
        if ( ! in_array( $conf, array( 'medium', 'high' ), true ) ) {
            return false;
        }

        // 1. WebRTC leak: WebRTC verdict is "potential_exposure" AND
        //    the leaked public IP differs from the connection IP.
        $webrtc = $scan['webrtc'] ?? array();
        if ( 'potential_exposure' === (string) ( $webrtc['verdict'] ?? '' ) ) {
            $leaked_ip     = (string) ( $webrtc['public_ips'][0] ?? '' );
            $connection_ip = (string) ( $scan['connection']['ipv4'] ?? $scan['connection']['ipv6'] ?? $scan['request_ip']['ipv4'] ?? '' );
            if ( '' !== $leaked_ip && '' !== $connection_ip && $leaked_ip !== $connection_ip ) {
                return true;
            }
        }

        // 2. DNS leak: resolvers exit via a different org than the
        //    visible connection. The dns_test must have completed
        //    with status=ok and the resolver_org must differ from the
        //    IP-intel org/isp.
        $dns    = $scan['dns_test'] ?? array();
        $intel  = $scan['connection']['intel'] ?? array();
        if ( 'ok' === (string) ( $dns['status'] ?? '' ) && ! empty( $dns['resolver_org'] ) ) {
            $resolver_org   = (string) $dns['resolver_org'];
            $connection_org = (string) ( $intel['org'] ?? $intel['isp'] ?? '' );
            if ( '' !== $resolver_org && '' !== $connection_org
                && stripos( $resolver_org, $connection_org ) === false
                && stripos( $connection_org, $resolver_org ) === false ) {
                return true;
            }
        }

        // 3. High-severity anonymity mismatch surfaced by the scorer.
        $anon_mismatches = is_array( $scan['connection']['anonymity']['mismatches'] ?? null )
            ? $scan['connection']['anonymity']['mismatches']
            : array();
        foreach ( $anon_mismatches as $m ) {
            if ( isset( $m['severity'] ) && 'high' === $m['severity'] ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Security posture — TLS version + cipher for the current connection
     * + browser EOL status. Second-highest weight (3) per
     * IMON-BUILD-GUIDE.md Phase 6: outdated TLS or a very-outdated
     * browser is a real-world risk, not an aesthetic one.
     *
     * Worst-case rolls up: if either TLS or browser is `outdated`-class,
     * the category status follows the worse of the two. The numeric
     * percent is the *average* of the two sub-percent scores — that's
     * fair enough since both sub-signals are independent risk vectors.
     *
     * @return array<string,mixed>
     */
    private static function score_security_posture( array $scan ): array {
        $sp = $scan['security_posture'] ?? array();
        if ( ! is_array( $sp ) || ( empty( $sp['tls'] ) && empty( $sp['browser'] ) ) ) {
            return self::row( 70, 'warning', 'security_posture',
                __( 'Security posture could not be evaluated.', 'privacy-checker' ),
                array(),
                3,
                'unknown'
            );
        }

        $tls_pct     = self::tls_percent(  $sp['tls']     ?? array() );
        $browser_pct = self::browser_percent( $sp['browser'] ?? array() );

        // Worst-of mapping for status. Ties go to the more conservative.
        $pcts = array( $tls_pct, $browser_pct );
        $worst = min( $pcts );

        if ( $worst >= 90 ) {
            $status = 'good';
            $msg    = __( 'TLS and browser are current.', 'privacy-checker' );
        } elseif ( $worst >= 60 ) {
            $status = 'warning';
            $msg    = __( 'One or both security-posture signals are below current. Review the details.', 'privacy-checker' );
        } else {
            $status = 'bad';
            $msg    = __( 'Outdated TLS or very-outdated browser — upgrade is strongly recommended.', 'privacy-checker' );
        }

        // Source is "measured" when we have at least one real verdict,
        // "unknown" only when both are missing.
        $source = ( 0 === $tls_pct && 0 === $browser_pct ) ? 'unknown' : 'measured';

        return self::row(
            (int) round( ( $tls_pct + $browser_pct ) / 2 ),
            $status,
            'security_posture',
            $msg,
            array(
                'tls'     => $sp['tls']     ?? array(),
                'browser' => $sp['browser'] ?? array(),
            ),
            3,
            $source
        );
    }

    /**
     * Map TlsInfo::current_request_info() status → 0-100 percent.
     */
    private static function tls_percent( array $tls ): int {
        $status = (string) ( $tls['status'] ?? 'unknown' );
        switch ( $status ) {
            case 'modern':     return 100;
            case 'acceptable': return 75;
            case 'outdated':   return 25;
            case 'unknown':
            default:           return 70; // don't punish what we can't measure
        }
    }

    /**
     * Map BrowserVersions::check() status → 0-100 percent.
     */
    private static function browser_percent( array $browser ): int {
        $status = (string) ( $browser['status'] ?? 'unknown' );
        switch ( $status ) {
            case 'current':         return 100;
            case 'outdated':        return 65;
            case 'very_outdated':   return 25;
            case 'unknown_family':
            case 'unknown_version':
            default:                return 70; // see tls_percent
        }
    }

    /**
     * Connection Quality — surface-only category (weight 0).
     *
     * Surfaces latency / jitter / IP-family reachability from the
     * client-side probe but explicitly DOES NOT roll into the privacy
     * overall. A slow connection is a health observation, not a privacy
     * problem — folding it into the privacy score would punish visitors
     * on bad residential Wi-Fi without telling them anything useful
     * about their actual anonymity.
     *
     * @return array<string,mixed>
     */
    private static function score_connection_quality( array $scan ): array {
        $cq = $scan['connection_quality'] ?? null;
        if ( ! is_array( $cq ) ) {
            return self::row( 70, 'warning', 'connection_quality',
                __( 'Connection quality probe did not run.', 'privacy-checker' ),
                array(),
                0, // surface-only — even when missing, weight stays 0
                'unknown'
            );
        }

        // Map jitter to a soft health score. The probe may not have run
        // at all (e.g. CORS blocked the echo endpoint) — fall back to
        // unknown rather than fabricating a number.
        $latency = $cq['latency'] ?? null;
        if ( ! is_array( $latency ) || ! isset( $latency['avg_ms'] ) ) {
            return self::row( 70, 'warning', 'connection_quality',
                __( 'Connection quality probe did not produce a reading.', 'privacy-checker' ),
                $cq,
                0,
                'unknown'
            );
        }

        $avg    = (float) $latency['avg_ms'];
        $jitter = (float) $latency['jitter_ms'];

        // Soft health bands — these are NOT a privacy verdict. They're
        // surfaced so a visitor can see "your connection is a bit
        // chatty today" without it dragging down their anonymity score.
        if ( $avg < 100 && $jitter < 30 ) {
            $status = 'good';
            $msg    = __( 'Connection is fast and stable.', 'privacy-checker' );
        } elseif ( $avg < 250 && $jitter < 80 ) {
            $status = 'warning';
            $msg    = __( 'Connection is acceptable but jitter is noticeable.', 'privacy-checker' );
        } else {
            $status = 'warning';
            $msg    = __( 'Connection is slow or unstable — this is a health signal, not a privacy problem.', 'privacy-checker' );
        }

        return self::row( 80, $status, 'connection_quality', $msg, $cq, 0 );
    }

    /**
     * Local Network Exposure — surface-only category (weight 0).
     *
     * Per IMON-BUILD-GUIDE.md Phase 6: a noisy LAN isn't a privacy
     * problem from the visitor's own perspective (they're testing
     * their own network from their own browser). We surface the
     * reachability count so the visitor knows about it, but it doesn't
     * move the privacy overall — only the LAN exposure card does that
     * visually, with a clearly separate heading.
     *
     * @return array<string,mixed>
     */
    private static function score_local_network( array $scan ): array {
        $ln = $scan['local_network'] ?? null;
        if ( ! is_array( $ln ) ) {
            return self::row( 80, 'good', 'local_network',
                __( 'Local network probe did not run.', 'privacy-checker' ),
                array(),
                0,
                'unknown'
            );
        }

        $reachable = is_array( $ln['reachable'] ?? null ) ? $ln['reachable'] : array();
        $count     = count( $reachable );

        if ( 0 === $count ) {
            return self::row( 90, 'good', 'local_network',
                __( 'No common gateway responded on admin ports.', 'privacy-checker' ),
                $ln,
                0
            );
        }
        if ( $count <= 2 ) {
            return self::row( 80, 'warning', 'local_network',
                __( 'A few local devices answered on admin ports. Not a privacy issue, but worth reviewing.', 'privacy-checker' ),
                $ln,
                0
            );
        }
        return self::row( 70, 'warning', 'local_network',
            __( 'Several local devices answered on admin ports. Review your router firewall.', 'privacy-checker' ),
            $ln,
            0
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
        // Weight 0 means "surface-only" — explicitly preserved. Any
        // other negative or zero is clamped to 1.
        $weight = $weight <= 0 ? $weight : max( 1, $weight );
        return array(
            'key'           => $key,
            'percent'       => max( 0, min( 100, $percent ) ),
            'status'        => $status,
            'weight'        => $weight,
            'message'       => $message,
            'details'       => $details,
            'status_source' => $source,
            // Scoring rubric shown in the expandable "Show details"
            // panel. Each entry is a (signal, score, condition) triple
            // the user can read to understand why this category got
            // the score it did. The first matching band is the one
            // that produced the score.
            'criteria'      => self::criteria_for( $key ),
        );
    }

    /**
     * Build a human-readable scoring rubric for a category.
     *
     * Each entry is a (label, range, condition) triple. The UI shows
     * the band that was hit at the top, and the full rubric below so
     * users can verify the score wasn't arbitrary. Conditions are
     * short English so they don't have to be translated.
     *
     * @return array<int,array{score:int, label:string, condition:string}>
     */
    private static function criteria_for( string $key ): array {
        switch ( $key ) {
            case 'ip':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Mock / dev mode — real IP intel is not gathered.' ),
                    array( 'score' =>  80, 'label' => 'Warning', 'condition' => 'IP intel partially resolved (geo or ASN missing).' ),
                    array( 'score' =>  75, 'label' => 'Warning', 'condition' => 'IP geolocation and ASN both visible to the public.' ),
                    array( 'score' =>  50, 'label' => 'Warning', 'condition' => 'IP intelligence provider did not respond.' ),
                );
            case 'reputation':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'IP is clean across reputation lists.' ),
                    array( 'score' =>  55, 'label' => 'Warning', 'condition' => 'IP flagged as suspicious on at least one list.' ),
                    array( 'score' =>  50, 'label' => 'Warning', 'condition' => 'Reputation provider returned no verdict.' ),
                    array( 'score' =>  15, 'label' => 'Bad',     'condition' => 'IP appears on reputation lists.' ),
                );
            case 'dns':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Resolvers agree — no DNS leak detected.' ),
                    array( 'score' =>  70, 'label' => 'Warning', 'condition' => 'Some resolver disagreement observed (leak_score < 0.5).' ),
                    array( 'score' =>  60, 'label' => 'Warning', 'condition' => 'DNS leak test not configured.' ),
                    array( 'score' =>  40, 'label' => 'Bad',     'condition' => 'DNS probe failed (provider unreachable or error).' ),
                    array( 'score' =>  30, 'label' => 'Bad',     'condition' => 'Resolvers disagree significantly — possible DNS leak.' ),
                );
            case 'webrtc':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'WebRTC does not expose public IPs.' ),
                    array( 'score' =>  95, 'label' => 'Good',    'condition' => 'WebRTC is not supported in this browser.' ),
                    array( 'score' =>  60, 'label' => 'Warning', 'condition' => 'WebRTC status unknown — no client signal was provided.' ),
                    array( 'score' =>  20, 'label' => 'Bad',     'condition' => 'WebRTC exposes public IP(s).' ),
                );
            case 'fingerprint':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Browser fingerprint is low-entropy and hard to distinguish.' ),
                    array( 'score' =>  65, 'label' => 'Warning', 'condition' => 'Browser fingerprint has moderate entropy.' ),
                    array( 'score' =>  60, 'label' => 'Warning', 'condition' => 'Browser fingerprint signal unavailable.' ),
                    array( 'score' =>  20, 'label' => 'Bad',     'condition' => 'Browser fingerprint is highly unique — easily trackable.' ),
                );
            case 'user_agent':
                return array(
                    array( 'score' =>  90, 'label' => 'Good',    'condition' => 'User-Agent is minimal.' ),
                    array( 'score' =>  70, 'label' => 'Warning', 'condition' => 'No User-Agent string was sent.' ),
                    array( 'score' =>  70, 'label' => 'Warning', 'condition' => 'User-Agent leaks one version detail.' ),
                    array( 'score' =>  40, 'label' => 'Warning', 'condition' => 'User-Agent exposes detailed browser, OS, and device versions.' ),
                    array( 'score' =>  30, 'label' => 'Bad',     'condition' => 'User-Agent matches a known bot/crawler pattern.' ),
                );
            case 'ipv6':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'No IPv6 address present.' ),
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'IPv6 present but matches IPv4 country (consistent).' ),
                    array( 'score' =>  40, 'label' => 'Warning', 'condition' => 'IPv6 present and leaks a different country than IPv4.' ),
                );
            case 'consistency':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Browser timezone, language, and geo signals all match.' ),
                    array( 'score' =>  60, 'label' => 'Warning', 'condition' => 'One of timezone / language / geo disagrees.' ),
                    array( 'score' =>  30, 'label' => 'Bad',     'condition' => 'Multiple signals disagree — likely masking.' ),
                );
            case 'security_posture':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'TLS 1.3+ and current browser version.' ),
                    array( 'score' =>  85, 'label' => 'Warning', 'condition' => 'One or both security-posture signals are below current.' ),
                    array( 'score' =>  40, 'label' => 'Bad',     'condition' => 'TLS 1.0/1.1 or very outdated browser detected.' ),
                );
            case 'proxy':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'No proxy / VPN / Tor signal detected.' ),
                    array( 'score' =>  80, 'label' => 'Warning', 'condition' => 'Connection is from a residential ISP (could be clean or masked).' ),
                    array( 'score' =>  70, 'label' => 'Warning', 'condition' => 'Hosting provider — typical for VPNs and proxies.' ),
                    array( 'score' =>  30, 'label' => 'Bad',     'condition' => 'Tor exit node detected.' ),
                );
            case 'connection_quality':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Connection quality probe succeeded with healthy latency.' ),
                    array( 'score' =>  70, 'label' => 'Warning', 'condition' => 'Connection quality probe did not produce a reading.' ),
                    array( 'score' =>  40, 'label' => 'Bad',     'condition' => 'High latency or packet loss detected.' ),
                );
            case 'local_network':
                return array(
                    array( 'score' => 100, 'label' => 'Good',    'condition' => 'Local network probe succeeded.' ),
                    array( 'score' =>  80, 'label' => 'Warning', 'condition' => 'Local network probe did not run (browser blocked it).' ),
                    array( 'score' =>  40, 'label' => 'Bad',     'condition' => 'Multiple LAN endpoints visible to the browser.' ),
                );
            default:
                return array();
        }
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
