<?php
/**
 * Public-facing assets and shortcode rendering.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Enqueues scanner assets and registers the dashboard shortcode.
 */
final class PublicAssets {

    /**
     * Page slugs whose pages should always load scanner assets.
     *
     * Single source of truth for: (a) the `is_page()` allowlist inside
     * `enqueue()`, (b) the URI-substring fallback for sites without pretty
     * permalinks, and (c) the derived shortcode-tag list. The value is the
     * shortcode suffix (without the `privacy_checker_` prefix); use an empty
     * string for the bare `privacy_checker` dashboard shortcode tag.
     * Adding a new tool now requires one entry here and one shortcode
     * registration above — `enqueue()` updates itself.
     *
     * @var array<string, string>
     */
    private const TOOLS = array(
        'ip-lookup'        => 'ip_lookup',
        'whois'            => 'whois',
        'user-agent'       => 'user_agent',
        'fingerprint'      => 'fingerprint',
        'dns-leak-test'    => 'dns_test',
        'webrtc-test'      => 'webrtc',
        'security-headers' => 'security_headers',
        'ping'             => 'ping',
        'port-scan'        => 'port_scan',
        'anonymity-tips'   => 'anonymity_tips',
        'geotraceroute'    => 'geotraceroute',
        'user-guide'       => 'user_guide',
    );

    /**
     * Just the slug list (preserves insertion order). Used by `is_page()` and
     * the URI-substring fallback — neither cares about shortcode tags.
     *
     * @return string[]
     */
    private static function tool_slugs(): array {
        return array_keys( self::TOOLS );
    }

    /**
     * Shortcode tags for the dashboard plus every tool. The first entry is
     * always the bare `privacy_checker` dashboard shortcode.
     *
     * @return string[]
     */
    private static function tool_shortcode_tags(): array {
        $tags = array( 'privacy_checker' );
        foreach ( self::TOOLS as $suffix ) {
            if ( '' === $suffix ) {
                continue;
            }
            $tags[] = 'privacy_checker_' . $suffix;
        }
        return $tags;
    }

    /**
     * Register hooks.
     */
    public function register(): void {
        add_action( 'wp_enqueue_scripts', array( $this, 'enqueue' ) );
        add_shortcode( 'privacy_checker', array( $this, 'shortcode' ) );
        add_shortcode( 'privacy_checker_fingerprint', array( $this, 'fingerprint_shortcode' ) );
        add_shortcode( 'privacy_checker_ip_lookup', array( $this, 'ip_lookup_shortcode' ) );
        add_shortcode( 'privacy_checker_whois', array( $this, 'whois_shortcode' ) );
        add_shortcode( 'privacy_checker_user_agent', array( $this, 'user_agent_shortcode' ) );
        add_shortcode( 'privacy_checker_security_headers', array( $this, 'security_headers_shortcode' ) );
        add_shortcode( 'privacy_checker_dns_test', array( $this, 'dns_test_shortcode' ) );
        add_shortcode( 'privacy_checker_webrtc', array( $this, 'webrtc_shortcode' ) );
        add_shortcode( 'privacy_checker_ping', array( $this, 'ping_shortcode' ) );
        add_shortcode( 'privacy_checker_port_scan', array( $this, 'port_scan_shortcode' ) );
        add_shortcode( 'privacy_checker_anonymity_tips', array( $this, 'anonymity_tips_shortcode' ) );
        add_shortcode( 'privacy_checker_geotraceroute', array( $this, 'geotraceroute_shortcode' ) );
        add_shortcode( 'privacy_checker_user_guide', array( $this, 'user_guide_shortcode' ) );
    }

    /**
     * Enqueue frontend assets only on pages that include our shortcodes.
     */
    public function enqueue(): void {
        if ( is_admin() ) {
            return;
        }
        $should_load = ( is_singular() && has_shortcode( get_post()->post_content ?? '', 'privacy_checker' ) )
            || is_front_page()
            || is_page( self::tool_slugs() );

        // Some WP installs don't have pretty permalinks enabled. Fall back to checking
        // by request URI as well, so the scanner assets always load on the tool pages.
        if ( ! $should_load ) {
            $req_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
            foreach ( self::tool_slugs() as $slug ) {
                if ( '' !== $req_uri && false !== strpos( $req_uri, '/' . $slug . '/' ) ) {
                    $should_load = true;
                    break;
                }
            }
        }

        if ( ! $should_load ) {
            global $post;
            if ( $post instanceof \WP_Post ) {
                $content = $post->post_content ?? '';
                foreach ( self::tool_shortcode_tags() as $tag ) {
                    if ( has_shortcode( $content, $tag ) ) {
                        $should_load = true;
                        break;
                    }
                }
            }
        }

        // Last-resort: when the active theme is privacy-checker-theme and the
        // request URI is `/`, the theme's `front-page.php` template renders
        // the dashboard hero even though `is_front_page()` is false (e.g.
        // when WP is configured to show latest posts on the homepage).
        // Always load scanner assets in that case so the hero CTA + the
        // embedded shortcode actually wire up.
        if ( ! $should_load ) {
            $theme  = wp_get_theme();
            $slug   = $theme ? (string) $theme->get_stylesheet() : '';
            $is_pc_theme = ( 'privacy-checker-theme' === $slug );
            $req_uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_parse_url( (string) $_SERVER['REQUEST_URI'], PHP_URL_PATH ) : '';
            if ( $is_pc_theme && ( '/' === $req_uri || '/index.php' === $req_uri ) ) {
                $should_load = true;
            }
        }

        if ( ! $should_load ) {
            return;
        }

        wp_enqueue_style(
            'pc-scanner',
            PRIVACY_CHECKER_URL . 'public/assets/css/scanner.css',
            array(),
            PRIVACY_CHECKER_VERSION
        );

        // Leaflet (free OpenStreetMap tiles) for the location map.
        // Loaded only with the scanner to avoid extra requests on plain pages.
        wp_enqueue_style(
            'pc-leaflet',
            'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css',
            array( 'pc-scanner' ),
            '1.9.4'
        );

        wp_enqueue_script(
            'pc-leaflet',
            'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js',
            array(),
            '1.9.4',
            true
        );

        // Optional 3D globe for Geo Traceroute. The existing Leaflet map is
        // retained as a fallback when WebGL or these CDN assets are blocked.
        // We prefer the locally bundled copies under assets/js/ when present
        // so the globe works on locked-down networks (corporate / airgapped /
        // GDPR-strict EU hosting where unpkg.com is unreachable).
        if ( false !== strpos( (string) ( $_SERVER['REQUEST_URI'] ?? '' ), 'geotraceroute' )
            || ( is_singular() && has_shortcode( get_post()->post_content ?? '', 'privacy_checker_geotraceroute' ) ) ) {
            $local_three = PRIVACY_CHECKER_DIR . 'public/assets/js/three.min.js';
            $local_globe = PRIVACY_CHECKER_DIR . 'public/assets/js/three-globe.min.js';
            $three_src   = is_readable( $local_three ) ? PRIVACY_CHECKER_URL . 'public/assets/js/three.min.js' : 'https://unpkg.com/three@0.160.0/build/three.min.js';
            $globe_src   = is_readable( $local_globe ) ? PRIVACY_CHECKER_URL . 'public/assets/js/three-globe.min.js' : 'https://unpkg.com/three-globe@2.33.0/dist/three-globe.min.js';
            $three_ver   = is_readable( $local_three ) ? filemtime( $local_three ) : '0.160.0';
            $globe_ver   = is_readable( $local_globe ) ? filemtime( $local_globe ) : '2.33.0';
            wp_enqueue_script(
                'pc-three',
                $three_src,
                array(),
                $three_ver,
                true
            );
            wp_enqueue_script(
                'pc-three-globe',
                $globe_src,
                array( 'pc-three' ),
                $globe_ver,
                true
            );
        }

        wp_register_script(
            'pc-scanner',
            PRIVACY_CHECKER_URL . 'public/assets/js/scanner.js',
            array( 'pc-leaflet' ),
            PRIVACY_CHECKER_VERSION,
            true
        );

        wp_enqueue_script( 'pc-scanner' );

        wp_localize_script( 'pc-scanner', 'PC_SCAN', array(
            'restUrl'      => esc_url_raw( rest_url( PRIVACY_CHECKER_REST_NS . '/' ) ),
            'restNonce'    => wp_create_nonce( 'wp_rest' ),
            'isMock'       => Plugin::instance()->is_dev_mode(),
            'assetUrl'     => esc_url_raw( PRIVACY_CHECKER_URL . 'public/assets/' ),
            'dnsPageUrl'   => esc_url_raw( home_url( '/dns-leak-test/' ) ),
            'webrtcPageUrl'=> esc_url_raw( home_url( '/webrtc-test/' ) ),
            'pingPageUrl'  => esc_url_raw( home_url( '/ping/' ) ),
            'portPageUrl'  => esc_url_raw( home_url( '/port-scan/' ) ),
            'tipsPageUrl'  => esc_url_raw( home_url( '/anonymity-tips/' ) ),
            'geoPageUrl'   => esc_url_raw( home_url( '/geotraceroute/' ) ),
            'guidePageUrl' => esc_url_raw( home_url( '/user-guide/' ) ),
            'i18n'      => array(
                'scanning'        => __( 'Scanning…', 'privacy-checker' ),
                'rescan'          => __( 'Run Privacy Check', 'privacy-checker' ),
                'copyReport'      => __( 'Copy report', 'privacy-checker' ),
                'downloadReport'  => __( 'Download JSON', 'privacy-checker' ),
                'printReport'     => __( 'Print report', 'privacy-checker' ),
                'copied'          => __( 'Copied', 'privacy-checker' ),
                'failed'          => __( 'Copy failed', 'privacy-checker' ),
                'errorTitle'      => __( 'Something went wrong', 'privacy-checker' ),
                'errorBody'       => __( 'Please retry. The page will stay usable.', 'privacy-checker' ),
                'detectIp'        => __( 'Detecting IP…', 'privacy-checker' ),
                'detectIntel'     => __( 'Resolving geolocation…', 'privacy-checker' ),
                'detectReputation'=> __( 'Checking IP reputation…', 'privacy-checker' ),
                'detectFingerprint'=> __( 'Estimating fingerprint visibility…', 'privacy-checker' ),
                'detectWebrtc'    => __( 'Testing WebRTC…', 'privacy-checker' ),
                'detectScore'     => __( 'Calculating score…', 'privacy-checker' ),
                'unknownProvider' => __( 'Unknown provider.', 'privacy-checker' ),
                'ipLabel'         => __( 'IP Address', 'privacy-checker' ),
                'reverseDnsLabel' => __( 'Reverse DNS', 'privacy-checker' ),
                'ispLabel'        => __( 'ISP', 'privacy-checker' ),
                'orgLabel'        => __( 'Organization', 'privacy-checker' ),
                'asnLabel'        => __( 'ASN', 'privacy-checker' ),
                'countryLabel'    => __( 'Country', 'privacy-checker' ),
                'regionLabel'     => __( 'Region', 'privacy-checker' ),
                'cityLabel'       => __( 'City', 'privacy-checker' ),
                'timezoneLabel'   => __( 'Timezone', 'privacy-checker' ),
                'noReverseDns'    => __( 'No reverse DNS record detected.', 'privacy-checker' ),
                'mockBadge'       => __( 'DEVELOPMENT DATA', 'privacy-checker' ),
                'unable'          => __( 'Unable to determine', 'privacy-checker' ),
                'estimatedScore'  => __( 'Scores are estimates based on observable signals.', 'privacy-checker' ),
                'ipIntelMissing'  => __( 'Location information temporarily unavailable.', 'privacy-checker' ),
                'reputationUnknown'=> __( 'Reputation data unavailable.', 'privacy-checker' ),
                'dnsNotConfigured'=> __( 'DNS leak testing requires an external DNS test service. Not configured on this server.', 'privacy-checker' ),
                'dnsConfigured'   => __( 'DNS leak test is configured. Run it to see results.', 'privacy-checker' ),
                'webrtcProtected' => __( 'Protected', 'privacy-checker' ),
                'webrtcExposure'  => __( 'Potential Exposure', 'privacy-checker' ),
                'webrtcUnsupported'=> __( 'Not Supported', 'privacy-checker' ),
                'webrtcError'     => __( 'Unable to Test', 'privacy-checker' ),
                'recommendations' => __( 'Recommendations', 'privacy-checker' ),
                'privacyScore'    => __( 'Privacy Score', 'privacy-checker' ),
                'anonymityScore'  => __( 'Anonymity Score', 'privacy-checker' ),
                'footerNote'      => __( 'Privacy scores are estimates based on observable signals.', 'privacy-checker' ),
                'vpnDetected'     => __( 'VPN detected', 'privacy-checker' ),
                'proxyDetected'   => __( 'Proxy detected', 'privacy-checker' ),
                'torDetected'     => __( 'Tor detected', 'privacy-checker' ),
                'datacenter'      => __( 'Datacenter IP', 'privacy-checker' ),
                'residential'     => __( 'Residential IP', 'privacy-checker' ),
                'hosting'         => __( 'Hosting provider', 'privacy-checker' ),
                'vpnUntestable'   => __( 'VPN detection is probabilistic and depends on available network intelligence.', 'privacy-checker' ),
                'pingTitle'       => __( 'Ping / Latency', 'privacy-checker' ),
                'pingLede'        => __( 'TCP-connect latency to public hosts. Useful for measuring network reachability, not VPN-detection.', 'privacy-checker' ),
                'pingRun'         => __( 'Run Ping', 'privacy-checker' ),
                'pingLatency'     => __( 'Latency', 'privacy-checker' ),
                'pingTarget'      => __( 'Target', 'privacy-checker' ),
                'pingCustom'      => __( 'Custom host (e.g. cloudflare.com:443)', 'privacy-checker' ),
                'pingDenied'      => __( 'This target is not allowed.', 'privacy-checker' ),
                'pingUnavailable' => __( 'Host not reachable.', 'privacy-checker' ),
                'portTitle'       => __( 'Port Scan', 'privacy-checker' ),
                'portLede'        => __( 'Probe a single host for open, closed, or filtered TCP ports. By default only your own WP server is allowed.', 'privacy-checker' ),
                'portRun'         => __( 'Probe Port', 'privacy-checker' ),
                'portHost'        => __( 'Host', 'privacy-checker' ),
                'portNumber'      => __( 'Port', 'privacy-checker' ),
                'portOpen'        => __( 'Open', 'privacy-checker' ),
                'portClosed'      => __( 'Closed', 'privacy-checker' ),
                'portFiltered'    => __( 'Filtered', 'privacy-checker' ),
                'portDenied'      => __( 'Denied', 'privacy-checker' ),
                'portDeniedLong'  => __( 'The target host failed the allowlist check. By default only the WP server itself may be probed.', 'privacy-checker' ),
                'detailedTitle'   => __( 'Detailed Report', 'privacy-checker' ),
                'detailedToggle'  => __( 'Show full breakdown', 'privacy-checker' ),
                'detailedHide'    => __( 'Hide breakdown', 'privacy-checker' ),
                'categoryGood'    => __( 'Good', 'privacy-checker' ),
                'categoryWarning' => __( 'Warning', 'privacy-checker' ),
                'categoryBad'     => __( 'Bad', 'privacy-checker' ),
                'gradeLabel'      => __( 'Grade', 'privacy-checker' ),
                'confidenceLabel' => __( 'Confidence', 'privacy-checker' ),
                'proxyTitle'      => __( 'Proxy / VPN / Hosting Detection', 'privacy-checker' ),
                'proxyBadge'      => __( 'Proxy / VPN / Tor / Hosting', 'privacy-checker' ),
                'tipsTitle'       => __( 'Anonymity Tips', 'privacy-checker' ),
                'tipsLede'        => __( 'Practical, prioritized techniques for staying private online. Not legal advice.', 'privacy-checker' ),
                'tipsFoundational'=> __( 'Foundational', 'privacy-checker' ),
                'tipsStrong'      => __( 'Strong', 'privacy-checker' ),
                'tipsIdentity'    => __( 'Identity & Accounts', 'privacy-checker' ),
                'tipsHardening'   => __( 'Hardening', 'privacy-checker' ),
                'tipsHabits'      => __( 'Habits', 'privacy-checker' ),
                'tipsEffortLow'   => __( 'Low effort', 'privacy-checker' ),
                'tipsEffortMedium'=> __( 'Medium effort', 'privacy-checker' ),
                'tipsEffortHigh'  => __( 'High effort', 'privacy-checker' ),
                'yourIpShort'     => __( 'Your IP is shown above.', 'privacy-checker' ),
                'proxyNone'       => __( 'No proxy / VPN / Tor signals detected', 'privacy-checker' ),
                'webrtcSupported' => __( 'Supported', 'privacy-checker' ),
                'dnsStatus'       => __( 'Status', 'privacy-checker' ),
                'dnsProvider'     => __( 'Provider', 'privacy-checker' ),
                'dnsGo'           => __( 'Go', 'privacy-checker' ),
                'levelExcellent'  => __( 'Excellent', 'privacy-checker' ),
                'levelGood'       => __( 'Good', 'privacy-checker' ),
                'levelModerate'   => __( 'Moderate', 'privacy-checker' ),
                'levelPoor'       => __( 'Poor', 'privacy-checker' ),
                'levelVeryPoor'   => __( 'Very Poor', 'privacy-checker' ),
                'scoreGood'       => __( 'Your privacy measures are safe or you don\'t use them.', 'privacy-checker' ),
                'scoreMid'        => __( 'Some details are exposed. Review the recommendations below.', 'privacy-checker' ),
                'scoreBad'        => __( 'Significant details are exposed. Follow the priority fixes.', 'privacy-checker' ),
                'ipReputationLabel'=> __( 'IP Reputation', 'privacy-checker' ),

                // Connection-quality card (Phase 1 of IMON-BUILD-GUIDE.md).
                // Latency is measured end-to-end in the visitor's browser via
                // 3 sequential fetches to /scan/connection/echo, timed with
                // performance.now(). Network Information API is Chromium-only —
                // Safari / Firefox get an explicit "Not available in this
                // browser" message rather than a blank/zero row.
                'cqTitle'              => __( 'Connection Quality', 'privacy-checker' ),
                'cqLede'               => __( 'End-to-end latency, jitter, and your browser\'s view of the connection.', 'privacy-checker' ),
                'cqLatencyAvg'         => __( 'Average latency', 'privacy-checker' ),
                'cqLatencyMin'         => __( 'Minimum latency', 'privacy-checker' ),
                'cqLatencyMax'         => __( 'Maximum latency', 'privacy-checker' ),
                'cqLatencyJitter'      => __( 'Jitter', 'privacy-checker' ),
                'cqSamples'            => __( 'Samples', 'privacy-checker' ),
                'cqReachability'       => __( 'IP family', 'privacy-checker' ),
                'cqIPv4'               => __( 'IPv4', 'privacy-checker' ),
                'cqIPv6'               => __( 'IPv6', 'privacy-checker' ),
                'cqNetInfo'            => __( 'Browser network info', 'privacy-checker' ),
                'cqNetInfoUnavailable' => __( 'Not available in this browser.', 'privacy-checker' ),

                // Anonymity Consistency card (Phase 2 of IMON-BUILD-GUIDE.md).
                'anonymityTitle'         => __( 'Anonymity Consistency', 'privacy-checker' ),
                'anonymityLede'          => __( 'Cross-checks your IP, timezone, WebRTC, and DNS signals for agreement.', 'privacy-checker' ),
                'anonymityScoreLabel'    => __( 'Score', 'privacy-checker' ),
                'anonymityUnknown'       => __( 'Unknown', 'privacy-checker' ),
                'anonymityAllConsistent' => __( 'No inconsistencies found between the signals checked.', 'privacy-checker' ),
                'anonymityNoData'        => __( 'No completed signal checks yet.', 'privacy-checker' ),

                // Advanced fingerprint card (Phase 3 of IMON-BUILD-GUIDE.md).
                'fpCanvasHash'         => __( 'Canvas hash', 'privacy-checker' ),
                'fpAudioHash'          => __( 'Audio hash', 'privacy-checker' ),
                'fpWebglRenderer'      => __( 'WebGL renderer', 'privacy-checker' ),
                'fpWebglVendor'        => __( 'WebGL vendor', 'privacy-checker' ),
                'fpWebglMasked'        => __( 'browser is blocking this — good sign', 'privacy-checker' ),
                'fpFontCount'          => __( 'Installed fonts', 'privacy-checker' ),
                'fpFontCountInstalled' => __( 'fonts detected', 'privacy-checker' ),
                'fpShowFonts'          => __( 'Show list', 'privacy-checker' ),
                'fpHideFonts'          => __( 'Hide list', 'privacy-checker' ),
                'fpEntropyLabel'       => __( 'Fingerprint entropy', 'privacy-checker' ),
                'fpUnavailable'        => __( 'unavailable', 'privacy-checker' ),

                // Security posture card (Phase 4 of IMON-BUILD-GUIDE.md).
                'spTitle'              => __( 'Security Posture', 'privacy-checker' ),
                'spLede'               => __( 'TLS version, cipher, and your browser\'s update status — for the connection you\'re using right now.', 'privacy-checker' ),
                'spTlsLabel'           => __( 'TLS', 'privacy-checker' ),
                'spTlsNote'            => __( 'Note', 'privacy-checker' ),
                'spBrowserLabel'       => __( 'Browser status', 'privacy-checker' ),
                'spBrowserNote'        => __( 'Advisory', 'privacy-checker' ),
                'spStatusCurrent'      => __( 'Current', 'privacy-checker' ),
                'spStatusOutdated'     => __( 'Outdated', 'privacy-checker' ),
                'spStatusVeryOutdated' => __( 'Very outdated', 'privacy-checker' ),
                'spStatusUnknown'      => __( 'Unknown', 'privacy-checker' ),

                // Local network exposure card (Phase 5 of IMON-BUILD-GUIDE.md).
                'lnTitle'             => __( 'Local Network Exposure', 'privacy-checker' ),
                'lnLede'              => __( 'Tests devices on YOUR OWN local network, from YOUR OWN browser — not external scanning.', 'privacy-checker' ),
                'lnScopeLabel'        => __( 'Probe scope', 'privacy-checker' ),
                'lnProbesWord'        => __( 'probes', 'privacy-checker' ),
                'lnProbing'           => __( 'probing local gateway addresses', 'privacy-checker' ),
                'lnReachableLabel'    => __( 'Reachable on admin ports', 'privacy-checker' ),
                'lnNone'              => __( 'none', 'privacy-checker' ),
                'lnNotRun'            => __( 'Probe did not run.', 'privacy-checker' ),
                'lnNoReachable'       => __( 'No common gateway responded — local network looks quiet.', 'privacy-checker' ),
                'lnReachable'         => __( 'Some local devices answered on admin ports.', 'privacy-checker' ),
                'lnManyReachable'     => __( 'Many local devices answered on admin ports — review your router firewall.', 'privacy-checker' ),
                'lnStatusOpen'        => __( 'open', 'privacy-checker' ),
                'lnStatusCors'        => __( 'answered (CORS)', 'privacy-checker' ),
                'lnStatusRefused'     => __( 'closed', 'privacy-checker' ),
                'lnStatusTimeout'     => __( 'no response', 'privacy-checker' ),
                'lnStatusUnreachable' => __( 'unreachable', 'privacy-checker' ),
                'lnScopeNote'         => __( 'Scope is hardcoded to RFC1918 private ranges only. Nothing was probed off your local network.', 'privacy-checker' ),

                'geoTitle'        => __( 'Geo Traceroute', 'privacy-checker' ),
                'geoLede'         => __( 'Project your connection hops onto a world map. Animated packets trace the path between your device and the destination.', 'privacy-checker' ),
                'geoRun'          => __( 'Trace Route', 'privacy-checker' ),
                'geoReset'        => __( 'Reset', 'privacy-checker' ),
                'geoHopsLabel'    => __( 'Hops', 'privacy-checker' ),
                'geoDistanceLabel'=> __( 'Total distance', 'privacy-checker' ),
                'geoAsPathLabel'  => __( 'AS path', 'privacy-checker' ),
                'geoDurationLabel'=> __( 'Duration', 'privacy-checker' ),
                'geoOrigin'       => __( 'Origin', 'privacy-checker' ),
                'geoDestination'  => __( 'Destination', 'privacy-checker' ),
                'geoMsFromPrev'   => __( 'ms from prev', 'privacy-checker' ),
                'geoKmFromPrev'   => __( 'km from prev', 'privacy-checker' ),
                'geoAnimate'      => __( 'Animate', 'privacy-checker' ),
                'geoPause'        => __( 'Pause', 'privacy-checker' ),
                'geoProbe'        => __( 'Probe', 'privacy-checker' ),
                'geoTargetHost'   => __( 'Target host', 'privacy-checker' ),
                'geoResolving'    => __( 'Resolving hops…', 'privacy-checker' ),
                'geoNoData'       => __( 'No traceroute data available. Run a scan first.', 'privacy-checker' ),
                'geoEstimated'    => __( 'Hop locations are estimated from latency, ASN, and rDNS hints. Accuracy varies by region.', 'privacy-checker' ),
                'geoPasteTitle'   => __( 'Paste a traceroute', 'privacy-checker' ),
                'geoPasteLede'    => __( 'Already have traceroute output? Paste Linux traceroute, Windows tracert, or MTR output and we will visualize it on the map.', 'privacy-checker' ),
                'geoPasteRun'     => __( 'Visualize!', 'privacy-checker' ),
                'geoPastePh'      => __( "1  192.0.2.1 (192.0.2.1)  1.123 ms  ...", 'privacy-checker' ),
                'geoPasteEmpty'   => __( 'Paste traceroute output first.', 'privacy-checker' ),
                'geoPasteBad'     => __( 'Could not parse that traceroute. Linux / Windows / MTR formats only.', 'privacy-checker' ),
                'geoProbeTitle'   => __( 'Probe Network', 'privacy-checker' ),
                'geoProbeLede'    => __( 'Lightweight nodes used for tracerouting. Run from your own server to add one.', 'privacy-checker' ),
                'geoRecentTitle'  => __( 'Recent traceroutes', 'privacy-checker' ),
                'geoRecentEmpty'  => __( 'No recent traceroutes yet.', 'privacy-checker' ),
                'geoMethodology'  => __( 'Methodology', 'privacy-checker' ),
                'geoMethodologyBody' => __( 'Hop locations are inferred from reverse DNS, GeoIP consistency across multiple databases, latency-based plausibility, and a Bayesian weighting pass. No hops are stored. ML-assisted rDNS parsing is used as a last resort.', 'privacy-checker' ),
                'geoLegendTitle'  => __( 'Latency color scale', 'privacy-checker' ),

                // User-guide onboarding tour (manual-only; launched via the
                // floating "?" button — never auto-shown).
                'guideButtonTitle'   => __( 'Open user guide', 'privacy-checker' ),
                'guideAriaLabel'     => __( 'User guide', 'privacy-checker' ),
                'guideTitle'         => __( 'Welcome to IMON', 'privacy-checker' ),
                'guideSubtitle'      => __( 'A short tour of what each card on this page tells you. Open this guide any time from the ? button.', 'privacy-checker' ),
                'guideNext'          => __( 'Next', 'privacy-checker' ),
                'guidePrev'          => __( 'Previous', 'privacy-checker' ),
                'guideDone'          => __( 'Got it', 'privacy-checker' ),
                'guideClose'         => __( 'Close', 'privacy-checker' ),
                'guideStepOf'        => __( 'Step %1$d of %2$d', 'privacy-checker' ),
                'guideSkip'          => __( 'Skip tour', 'privacy-checker' ),
                'guideRestart'       => __( 'Restart tour', 'privacy-checker' ),
                'geoLegendFast'   => __( 'fast', 'privacy-checker' ),
                'geoLegendAvg'    => __( 'average', 'privacy-checker' ),
                'geoLegendSlow'   => __( 'slow', 'privacy-checker' ),
                'geoToastTimeout' => __( 'Traceroute timed out.', 'privacy-checker' ),
                'geoToastDown'    => __( 'Probe node is down.', 'privacy-checker' ),
                'geoToastPrivate' => __( 'Private IP detected — using default host.', 'privacy-checker' ),
                'geoToastBad'     => __( 'Bad host provided — using default host.', 'privacy-checker' ),
                'geoToastCopied'  => __( 'Copied!', 'privacy-checker' ),
                'geoToastShareFail'=> __( 'Share failed.', 'privacy-checker' ),
                'geoKmFromPrev'   => __( 'km from previous city', 'privacy-checker' ),
                'geoPathVia'      => __( 'Path via:', 'privacy-checker' ),
                'geoPathTo'       => __( 'Path to:', 'privacy-checker' ),
                'geoAsPathColon'  => __( 'AS Path:', 'privacy-checker' ),
                'geoRunAnother'   => __( 'Run another traceroute', 'privacy-checker' ),
                'geoProbeJoin'    => __( 'Join the network', 'privacy-checker' ),
                'geoPreferences'  => __( 'Preferences', 'privacy-checker' ),
                'geoSavePrefs'    => __( 'Save', 'privacy-checker' ),
                'geoPrefSource'   => __( 'Default source node', 'privacy-checker' ),
                'geoPrefMapStyle' => __( 'Map style', 'privacy-checker' ),
                'geoPrefCable'    => __( 'Route along submarine cables', 'privacy-checker' ),
                'geoPrefCities'   => __( 'Show cities', 'privacy-checker' ),
                'geoPrefGeek'     => __( 'Geek mode', 'privacy-checker' ),
                'geoLanguages'    => __( 'Language', 'privacy-checker' ),
                'geoConnectedHops'=> __( 'Connected (%s hops received)', 'privacy-checker' ),
                'geoLongWait'     => __( 'Taking longer than expected… still working!', 'privacy-checker' ),
                'geoInferring'    => __( 'Inferring physical path…', 'privacy-checker' ),
            ),
        ) );

        // Tour config — manual-only. The tour is launched by the floating "?"
        // button. Steps map to live CSS selectors that exist on the homepage
        // dashboard; selectors that don't match a node simply skip without
        // breaking the tour.
        wp_localize_script( 'pc-scanner', 'PC_GUIDE', array(
            'tour' => array(
                array(
                    'id'      => 'intro',
                    'title'   => __( 'Welcome to IMON', 'privacy-checker' ),
                    'body'    => __( 'IMON shows what your connection looks like to the websites you visit. Click through this 8-step tour to see what every card on the page means — or close it and explore on your own.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="dashboard"]',
                    'place'   => 'center',
                ),
                array(
                    'id'      => 'run',
                    'title'   => __( 'Run the scan', 'privacy-checker' ),
                    'body'    => __( 'Click "Run Privacy Check" to collect your connection data. Nothing leaves your browser except what is required to look up the public IP — no analytics, no trackers.', 'privacy-checker' ),
                    'target'  => '[data-pc-action="run-scan"], [data-pc-action="rescan"]',
                    'place'   => 'bottom',
                ),
                array(
                    'id'      => 'connection',
                    'title'   => __( 'Your connection', 'privacy-checker' ),
                    'body'    => __( 'This card shows your public IP, reverse DNS, ISP, ASN, country, region, and city. Every field has a country flag next to it. The flag is a regional-indicator emoji derived from the ISO country code.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="connection"]',
                    'place'   => 'right',
                ),
                array(
                    'id'      => 'reputation',
                    'title'   => __( 'IP reputation', 'privacy-checker' ),
                    'body'    => __( 'We check your IP against Spamhaus and Iphub. A "clean" verdict means you are not on any of the lists we cross-reference. "Listed" means your IP is flagged somewhere — that is not always a bad thing; many ISP customers are.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="reputation"]',
                    'place'   => 'right',
                ),
                array(
                    'id'      => 'fingerprint',
                    'title'   => __( 'Browser fingerprint', 'privacy-checker' ),
                    'body'    => __( 'Your browser leaks dozens of passive signals: language, timezone, screen size, fonts, Canvas/WebGL hashes. This card shows the exposure level so you know what tracking systems can see.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="fingerprint"]',
                    'place'   => 'right',
                ),
                array(
                    'id'      => 'webrtc',
                    'title'   => __( 'WebRTC leaks', 'privacy-checker' ),
                    'body'    => __( 'WebRTC can reveal your real local network address (and sometimes your public IP) even behind a VPN. This card runs locally in your browser — no remote STUN/TURN servers are contacted.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="webrtc"]',
                    'place'   => 'right',
                ),
                array(
                    'id'      => 'dns',
                    'title'   => __( 'DNS leak test', 'privacy-checker' ),
                    'body'    => __( 'Click "Run DNS Leak Test" to query Cloudflare, Google, and Quad9 over DNS-over-HTTPS and confirm your resolver answers match your expected network. We never log the responses — only the resolver and round-trip time.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="dns-leak"], [data-pc-action="dns-test-run"], [data-pc-action="dns-run"]',
                    'place'   => 'left',
                ),
                array(
                    'id'      => 'path',
                    'title'   => __( 'Network Path', 'privacy-checker' ),
                    'body'    => __( 'The path card shows the real backend-derived hops your connection crosses: PTR (reverse DNS), the ISP/ASN edge, the destination. A green pill means "Real backend data"; an amber pill means estimated.', 'privacy-checker' ),
                    'target'  => '.pc-network',
                    'place'   => 'top',
                ),
                array(
                    'id'      => 'map',
                    'title'   => __( 'Approximate location & path', 'privacy-checker' ),
                    'body'    => __( 'Your IP-derived location on a 2D world map with a stylized traceroute. Open the Geo Traceroute page for a fully interactive experience, including a 3D globe.', 'privacy-checker' ),
                    'target'  => '.pc-map-card',
                    'place'   => 'top',
                ),
                array(
                    'id'      => 'report',
                    'title'   => __( 'Detailed privacy report', 'privacy-checker' ),
                    'body'    => __( 'A Whoer-style breakdown with a grade (A–F), per-category scores, and prioritised recommendations. Use the Export menu for JSON / CSV / TXT / HTML, or Share to publish a redacted, short-lived link.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="detailed-report"]',
                    'place'   => 'top',
                ),
                array(
                    'id'      => 'tips',
                    'title'   => __( 'Anonymity tips', 'privacy-checker' ),
                    'body'    => __( 'Concrete, prioritised steps to improve your setup — VPN selection, browser hardening, Tor, anti-detect browsers, email aliases, virtual phone numbers, and dedicated OSes like Tails and Whonix.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="anonymity-tips"]',
                    'place'   => 'top',
                ),
                array(
                    'id'      => 'finished',
                    'title'   => __( 'That is the whole page', 'privacy-checker' ),
                    'body'    => __( 'You can re-open this guide from the ? button in the bottom-right corner. Each tool has its own dedicated page (DNS leak, WebRTC, IP lookup, WHOIS, ping, port scan, Geo Traceroute) linked from the navigation.', 'privacy-checker' ),
                    'target'  => '[data-pc-component="dashboard"]',
                    'place'   => 'center',
                ),
            ),
        ) );
    }

    /**
     * Render the dashboard shortcode.
     */
    public function shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-dashboard" data-pc-component="dashboard">
            <ol class="pc-progress" data-pc-region="progress" aria-label="<?php esc_attr_e( 'Scan progress', 'privacy-checker' ); ?>">
                <li data-pc-step="ip"><?php esc_html_e( 'Detecting IP', 'privacy-checker' ); ?></li>
                <li data-pc-step="intel"><?php esc_html_e( 'Resolving geolocation', 'privacy-checker' ); ?></li>
                <li data-pc-step="reputation"><?php esc_html_e( 'Checking reputation', 'privacy-checker' ); ?></li>
                <li data-pc-step="fingerprint"><?php esc_html_e( 'Estimating fingerprint', 'privacy-checker' ); ?></li>
                <li data-pc-step="webrtc"><?php esc_html_e( 'Testing WebRTC', 'privacy-checker' ); ?></li>
                <li data-pc-step="score"><?php esc_html_e( 'Calculating score', 'privacy-checker' ); ?></li>
            </ol>

            <div class="pc-dashboard__cta-row">
                <button type="button" class="pc-btn pc-btn--primary" data-pc-action="rescan">
                    <?php esc_html_e( 'Run Privacy Check', 'privacy-checker' ); ?>
                </button>
            </div>

            <div class="pc-cards" data-pc-region="report" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Standalone fingerprint shortcode.
     */
    public function fingerprint_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool pc-fingerprint" data-pc-component="fingerprint">
            <h2 class="pc-section__title"><?php esc_html_e( 'Browser Fingerprint', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e(
                    'A browser fingerprint is the set of signals your browser exposes automatically: user agent, language, timezone, installed fonts, screen, and more. Click below to collect these locally in your browser and see what a website can read without any permission prompts.',
                    'privacy-checker'
                ); ?>
            </p>
            <button type="button" class="pc-btn pc-btn--primary" data-pc-action="fingerprint">
                <?php esc_html_e( 'Run Browser Test', 'privacy-checker' ); ?>
            </button>
            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * IP lookup form.
     */
    public function ip_lookup_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="ip-lookup">
            <h2 class="pc-section__title"><?php esc_html_e( 'IP Lookup', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede"><?php esc_html_e( 'Look up geolocation, ASN, and reverse DNS for any public IPv4 or IPv6 address.', 'privacy-checker' ); ?></p>

            <form class="pc-tool__form" data-pc-action="ip-lookup">
                <label for="pc-ip-lookup-input" class="pc-sr-only"><?php esc_html_e( 'IP address', 'privacy-checker' ); ?></label>
                <input
                    id="pc-ip-lookup-input"
                    type="text"
                    name="ip"
                    inputmode="text"
                    autocomplete="off"
                    placeholder="<?php esc_attr_e( 'e.g. 1.1.1.1 or 2001:4860:4860::8888', 'privacy-checker' ); ?>"
                    required
                />
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Lookup', 'privacy-checker' ); ?></button>
            </form>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * WHOIS form.
     */
    public function whois_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="whois">
            <h2 class="pc-section__title"><?php esc_html_e( 'WHOIS / Network Lookup', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede"><?php esc_html_e( 'Look up registration data for a domain, IP, or ASN via RDAP.', 'privacy-checker' ); ?></p>

            <form class="pc-tool__form" data-pc-action="whois">
                <label for="pc-whois-input" class="pc-sr-only"><?php esc_html_e( 'Query', 'privacy-checker' ); ?></label>
                <input
                    id="pc-whois-input"
                    type="text"
                    name="query"
                    autocomplete="off"
                    placeholder="<?php esc_attr_e( 'e.g. example.com, 1.1.1.1, AS13335', 'privacy-checker' ); ?>"
                    required
                />
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Lookup', 'privacy-checker' ); ?></button>
            </form>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * User-agent lookup.
     */
    public function user_agent_shortcode( $atts = array() ): string {
        $current_ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="user-agent">
            <h2 class="pc-section__title"><?php esc_html_e( 'User-Agent Lookup', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede"><?php esc_html_e( 'Parse a User-Agent string into browser, OS, engine, and device.', 'privacy-checker' ); ?></p>

            <form class="pc-tool__form" data-pc-action="user-agent">
                <label for="pc-ua-input" class="pc-sr-only"><?php esc_html_e( 'User-Agent', 'privacy-checker' ); ?></label>
                <textarea id="pc-ua-input" name="ua" rows="3" placeholder="<?php esc_attr_e( 'Paste a User-Agent string (leave blank to use yours)', 'privacy-checker' ); ?>"></textarea>
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Parse', 'privacy-checker' ); ?></button>
            </form>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>

            <details class="pc-tool__details">
                <summary><?php esc_html_e( 'Your current User-Agent', 'privacy-checker' ); ?></summary>
                <pre class="pc-mono pc-tool__pre"><?php echo esc_html( $current_ua ); ?></pre>
            </details>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Security-headers checker form.
     */
    public function security_headers_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="security-headers">
            <h2 class="pc-section__title"><?php esc_html_e( 'Check a Site’s Security Headers', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede"><?php esc_html_e( 'Submit a public URL to inspect its HTTP security headers. Requests to private or internal addresses are blocked.', 'privacy-checker' ); ?></p>

            <form class="pc-tool__form" data-pc-action="security-headers">
                <label for="pc-sec-input" class="pc-sr-only"><?php esc_html_e( 'URL', 'privacy-checker' ); ?></label>
                <input
                    id="pc-sec-input"
                    type="url"
                    name="url"
                    inputmode="url"
                    placeholder="https://example.com"
                    required
                />
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Check', 'privacy-checker' ); ?></button>
            </form>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * DNS leak test shortcode.
     */
    public function dns_test_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="dns-test">
            <h2 class="pc-section__title"><?php esc_html_e( 'DNS Leak Test', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e(
                    'A DNS-over-HTTPS fan-out across Cloudflare, Google, and Quad9. We record the resolver that answered, the IP it returned, and the round-trip latency. The leak score compares the answers to your advertised IP.',
                    'privacy-checker'
                ); ?>
            </p>
            <form class="pc-tool__form" data-pc-action="dns-test">
                <label for="pc-dns-hostname" class="pc-sr-only"><?php esc_html_e( 'Hostname', 'privacy-checker' ); ?></label>
                <input id="pc-dns-hostname" name="hostname" type="text" placeholder="<?php esc_attr_e( 'cloudflare.com', 'privacy-checker' ); ?>" value="cloudflare.com" />
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Run Leak Test', 'privacy-checker' ); ?></button>
            </form>
            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * WebRTC test shortcode.
     */
    public function webrtc_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="webrtc">
            <h2 class="pc-section__title"><?php esc_html_e( 'WebRTC Test', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e(
                    'Browsers can expose local and public addresses through WebRTC. This test detects whether additional public addresses were revealed.',
                    'privacy-checker'
                ); ?>
            </p>
            <button type="button" class="pc-btn pc-btn--primary" data-pc-action="webrtc">
                <?php esc_html_e( 'Run WebRTC Test', 'privacy-checker' ); ?>
            </button>
            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Ping / latency shortcode.
     */
    public function ping_shortcode( $atts = array() ): string {
        $targets = (array) Plugin::instance()->setting( 'ping_targets', NetworkProbe::default_ping_targets() );
        $opts    = '';
        foreach ( $targets as $t ) {
            $opts .= '<option value="' . esc_attr( $t ) . '">' . esc_html( $t ) . '</option>';
        }
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="ping">
            <h2 class="pc-section__title"><?php esc_html_e( 'Ping / Latency', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e(
                    'TCP-connect latency to a public host:port. The default targets are common CDN endpoints. Custom hosts must pass the admin allowlist.',
                    'privacy-checker'
                ); ?>
            </p>

            <form class="pc-tool__form" data-pc-action="ping">
                <label for="pc-ping-target" class="pc-sr-only"><?php esc_html_e( 'Target', 'privacy-checker' ); ?></label>
                <select id="pc-ping-target" name="target">
                    <?php echo $opts; // already escaped per-option. ?>
                </select>
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Run Ping', 'privacy-checker' ); ?></button>
            </form>

            <p class="pc-tool__hint">
                <?php esc_html_e( 'Custom host (admin allowlist required):', 'privacy-checker' ); ?>
                <input type="text" placeholder="host:port" data-pc-input="ping-custom" />
            </p>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Port scan shortcode.
     */
    public function port_scan_shortcode( $atts = array() ): string {
        $ports = (array) Plugin::instance()->setting( 'port_scan_default_ports', NetworkProbe::default_port_scan_ports() );
        $chips = '';
        foreach ( $ports as $p ) {
            $chips .= '<button type="button" class="pc-chip" data-pc-port="' . esc_attr( $p ) . '">' . esc_html( $p ) . '</button>';
        }
        ob_start();
        ?>
        <section class="pc-tool" data-pc-component="port-scan">
            <h2 class="pc-section__title"><?php esc_html_e( 'Port Scan', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e(
                    'Probe a single host for an open, closed, or filtered TCP port. By default only your own WP server is allowed. SSH (22), SMTP (25), and RDP (3389) are always blocked.',
                    'privacy-checker'
                ); ?>
            </p>

            <form class="pc-tool__form" data-pc-action="port-scan">
                <label for="pc-port-host" class="pc-sr-only"><?php esc_html_e( 'Host', 'privacy-checker' ); ?></label>
                <input
                    id="pc-port-host"
                    type="text"
                    name="host"
                    placeholder="example.com or 1.1.1.1"
                    required
                />
                <label for="pc-port-number" class="pc-sr-only"><?php esc_html_e( 'Port', 'privacy-checker' ); ?></label>
                <input
                    id="pc-port-number"
                    type="number"
                    name="port"
                    min="1"
                    max="65535"
                    placeholder="443"
                    required
                />
                <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Probe Port', 'privacy-checker' ); ?></button>
            </form>

            <div class="pc-tool__chips" role="group" aria-label="<?php esc_attr_e( 'Quick-select ports', 'privacy-checker' ); ?>">
                <?php echo $chips; // already escaped per-chip. ?>
            </div>

            <div class="pc-tool__result" data-pc-region="result" hidden></div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Anonymity tips shortcode.
     *
     * Renders a tiered, categorized list of practical anonymity techniques.
     * Used as a standalone page and also auto-injected into the scanner
     * dashboard by scanner.js.
     */
    public function anonymity_tips_shortcode( $atts = array() ): string {
        $by_tier      = \PrivacyChecker\AnonymityTips::by_tier();
        $tier_labels  = \PrivacyChecker\AnonymityTips::tier_labels();
        $effort_labels = \PrivacyChecker\AnonymityTips::effort_labels();
        ob_start();
        ?>
        <section class="pc-tool pc-tips" data-pc-component="anonymity-tips">
            <h2 class="pc-section__title"><?php esc_html_e( 'Anonymity Tips', 'privacy-checker' ); ?></h2>
            <p class="pc-section__lede">
                <?php esc_html_e( 'Practical, prioritized techniques for staying private online. Not legal advice.', 'privacy-checker' ); ?>
            </p>
            <?php foreach ( $by_tier as $tier => $tips ) :
                if ( empty( $tips ) ) { continue; }
                ?>
                <section class="pc-tips__tier" data-pc-tier="<?php echo esc_attr( $tier ); ?>">
                    <h3 class="pc-tips__tier-title"><?php echo esc_html( $tier_labels[ $tier ] ?? $tier ); ?></h3>
                    <ol class="pc-tips__list">
                        <?php foreach ( $tips as $tip ) :
                            $effort = (string) ( $tip['effort'] ?? 'low' );
                            ?>
                            <li class="pc-tips__tip">
                                <header class="pc-tips__head">
                                    <span class="pc-tips__priority">#<?php echo (int) ( $tip['priority'] ?? 0 ); ?></span>
                                    <h4 class="pc-tips__title"><?php echo esc_html( $tip['title'] ?? '' ); ?></h4>
                                    <span class="pc-tips__effort pc-tips__effort--<?php echo esc_attr( $effort ); ?>">
                                        <?php echo esc_html( $effort_labels[ $effort ] ?? $effort ); ?>
                                    </span>
                                </header>
                                <p class="pc-tips__summary"><?php echo esc_html( $tip['summary'] ?? '' ); ?></p>
                                <?php if ( ! empty( $tip['examples'] ) ) : ?>
                                    <p class="pc-tips__examples">
                                        <strong><?php esc_html_e( 'Examples:', 'privacy-checker' ); ?></strong>
                                        <?php echo esc_html( implode( ', ', (array) $tip['examples'] ) ); ?>
                                    </p>
                                <?php endif; ?>
                                <?php if ( ! empty( $tip['why'] ) ) : ?>
                                    <p class="pc-tips__why">
                                        <strong><?php esc_html_e( 'Why:', 'privacy-checker' ); ?></strong>
                                        <?php echo esc_html( $tip['why'] ); ?>
                                    </p>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                </section>
            <?php endforeach; ?>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Geo Traceroute shortcode. Mirrors the geotraceroute.com style:
     *   - dark starfield background
     *   - full-width world map (left/center)
     *   - sidebar with hop cards + AS path / total distance summary
     *   - animated packet pulses along the polyline
     */
    public function geotraceroute_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <section class="pc-tool pc-geo" data-pc-component="geotraceroute">
            <header class="pc-geo__header">
                <div class="pc-geo__title-block">
                    <h2 class="pc-section__title pc-geo__title"><?php esc_html_e( 'Geo Traceroute', 'privacy-checker' ); ?></h2>
                    <p class="pc-geo__lede">
                        <?php esc_html_e(
                            'Project your connection hops onto a world map. Animated packets trace the path between your device and the destination.',
                            'privacy-checker'
                        ); ?>
                    </p>
                </div>
                <div class="pc-geo__controls">
                    <label for="pc-geo-target" class="pc-sr-only"><?php esc_html_e( 'Target host', 'privacy-checker' ); ?></label>
                    <input
                        id="pc-geo-target"
                        type="text"
                        name="host"
                        placeholder="<?php esc_attr_e( 'example.com', 'privacy-checker' ); ?>"
                        value="<?php echo esc_attr( home_url() ); ?>"
                    />
                    <button type="button" class="pc-btn pc-btn--primary" data-pc-action="geo-run">
                        <?php esc_html_e( 'Trace Route', 'privacy-checker' ); ?>
                    </button>
                    <button type="button" class="pc-btn pc-btn--ghost" data-pc-action="geo-reset">
                        <?php esc_html_e( 'Reset', 'privacy-checker' ); ?>
                    </button>
                    <button type="button" class="pc-btn pc-btn--ghost pc-geo__view-toggle" data-pc-action="geo-view" aria-pressed="false">
                        <?php esc_html_e( '3D Globe', 'privacy-checker' ); ?>
                    </button>
                    <button type="button" class="pc-btn pc-btn--icon" data-pc-action="geo-toggle" aria-label="<?php esc_attr_e( 'Animate', 'privacy-checker' ); ?>" aria-pressed="true">
                        <span data-pc-geo-icon-play>&#9658;</span>
                        <span data-pc-geo-icon-pause hidden>&#10074;&#10074;</span>
                    </button>
                </div>
            </header>

            <div class="pc-geo__layout">
                <div class="pc-geo__stage">
                    <canvas class="pc-geo__stars" aria-hidden="true"></canvas>
                    <div class="pc-geo__map" data-pc-region="map"></div>
                    <div class="pc-geo__globe" data-pc-region="globe" hidden aria-label="3D route globe"></div>
                    <div class="pc-geo__overlay">
                        <span class="pc-geo__status" data-pc-region="status"><?php esc_html_e( 'Idle', 'privacy-checker' ); ?></span>
                    </div>
                </div>

                <aside class="pc-geo__sidebar">
                    <div class="pc-geo__summary">
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'Origin', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value" data-pc-region="origin">—</span>
                        </div>
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'Destination', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value" data-pc-region="destination">—</span>
                        </div>
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'Hops', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value" data-pc-region="hops">—</span>
                        </div>
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'Total distance', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value" data-pc-region="distance">—</span>
                        </div>
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'AS path', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value pc-geo__as-path" data-pc-region="aspath">—</span>
                        </div>
                        <div class="pc-geo__summary-row">
                            <span class="pc-geo__summary-label"><?php esc_html_e( 'Duration', 'privacy-checker' ); ?></span>
                            <span class="pc-geo__summary-value" data-pc-region="duration">—</span>
                        </div>
                    </div>

                    <div class="pc-geo__hop-reveal">
                        <ol class="pc-geo__hops" data-pc-region="hops" aria-label="<?php esc_attr_e( 'Hop list', 'privacy-checker' ); ?>"></ol>
                    </div>

                    <p class="pc-geo__disclaimer">
                        <?php esc_html_e(
                            'Hop locations are estimated from latency, ASN, and rDNS hints. Accuracy varies by region.',
                            'privacy-checker'
                        ); ?>
                    </p>
                </aside>
            </div>

            <footer class="pc-geo__credits" aria-labelledby="pc-geo-credits-title">
                <h3 class="pc-geo__credits-title" id="pc-geo-credits-title"><?php esc_html_e( 'Credits', 'privacy-checker' ); ?></h3>
                <ul class="pc-geo__credits-list">
                    <li><strong>IconDrawer.com</strong> — <?php esc_html_e( 'flag icons.', 'privacy-checker' ); ?></li>
                    <li><strong>IP2Location</strong> — <?php esc_html_e( 'free GeoIP database.', 'privacy-checker' ); ?></li>
                    <li><strong>IPInfo</strong> — <?php esc_html_e( 'an amazing GeoIP database.', 'privacy-checker' ); ?></li>
                    <li><strong>Maxmind</strong> — <?php esc_html_e( 'GeoLite2 database.', 'privacy-checker' ); ?></li>
                    <li><strong>NASA</strong> — <?php esc_html_e( 'earth images.', 'privacy-checker' ); ?></li>
                    <li><strong>NLNOG</strong> — <?php esc_html_e( 'nodes used for tracerouting.', 'privacy-checker' ); ?></li>
                    <li><strong>PyTorch</strong> — <?php esc_html_e( 'deep learning framework.', 'privacy-checker' ); ?></li>
                    <li><strong>Submarine Cable Map</strong> — <?php esc_html_e( 'submarine cables data.', 'privacy-checker' ); ?></li>
                    <li><strong>Three.js</strong> — <?php esc_html_e( 'JavaScript 3D library.', 'privacy-checker' ); ?></li>
                    <li><strong>USNO Dept.</strong> — <?php esc_html_e( 'earth images.', 'privacy-checker' ); ?></li>
                    <li><strong>Michel PY</strong> — <?php esc_html_e( 'suggestions and help.', 'privacy-checker' ); ?></li>
                </ul>
            </footer>

            <section class="pc-geo__panels" aria-label="<?php esc_attr_e( 'Geo traceroute panels', 'privacy-checker' ); ?>">
                <div class="pc-geo__panel" data-pc-panel="paste">
                    <button type="button" class="pc-geo__panel-toggle" data-pc-action="geo-paste-toggle" aria-expanded="false">
                        <?php esc_html_e( 'Paste a traceroute', 'privacy-checker' ); ?>
                    </button>
                    <div class="pc-geo__panel-body" hidden>
                        <p class="pc-geo__panel-lede"><?php esc_html_e( 'Already have traceroute output? Paste Linux traceroute, Windows tracert, or MTR output and we will visualize it on the map.', 'privacy-checker' ); ?></p>
                        <form class="pc-geo__paste-form" data-pc-action="geo-paste">
                            <label for="pc-geo-paste" class="pc-sr-only"><?php esc_html_e( 'Traceroute text', 'privacy-checker' ); ?></label>
                            <textarea id="pc-geo-paste" name="trace" rows="6" placeholder="1  192.0.2.1 (192.0.2.1)  1.123 ms  1.245 ms  1.301 ms"></textarea>
                            <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Visualize!', 'privacy-checker' ); ?></button>
                        </form>
                    </div>
                </div>

                <div class="pc-geo__panel" data-pc-panel="probes">
                    <button type="button" class="pc-geo__panel-toggle" data-pc-action="geo-probes-toggle" aria-expanded="false">
                        <?php esc_html_e( 'Probe Network', 'privacy-checker' ); ?>
                    </button>
                    <div class="pc-geo__panel-body" hidden>
                        <p class="pc-geo__panel-lede"><?php esc_html_e( 'Lightweight nodes used for tracerouting. Run from your own server to add one.', 'privacy-checker' ); ?></p>
                        <ul class="pc-geo__probes" data-pc-region="probes"></ul>
                    </div>
                </div>

                <div class="pc-geo__panel" data-pc-panel="recent">
                    <button type="button" class="pc-geo__panel-toggle" data-pc-action="geo-recent-toggle" aria-expanded="false">
                        <?php esc_html_e( 'Recent traceroutes', 'privacy-checker' ); ?>
                    </button>
                    <div class="pc-geo__panel-body" hidden>
                        <ul class="pc-geo__recent" data-pc-region="recent"></ul>
                    </div>
                </div>

                <div class="pc-geo__legend" aria-label="<?php esc_attr_e( 'Latency color scale', 'privacy-checker' ); ?>">
                    <h3 class="pc-geo__legend-title"><?php esc_html_e( 'Latency color scale', 'privacy-checker' ); ?></h3>
                    <div class="pc-geo__legend-bar" aria-hidden="true">
                        <span style="background:#3fb950"></span>
                        <span style="background:#3fb950"></span>
                        <span style="background:#84b84a"></span>
                        <span style="background:#d9b88a"></span>
                        <span style="background:#f0a020"></span>
                        <span style="background:#dc3545"></span>
                        <span style="background:#dc3545"></span>
                    </div>
                    <div class="pc-geo__legend-axis" aria-hidden="true">
                        <span><?php esc_html_e( 'fast', 'privacy-checker' ); ?></span>
                        <span><?php esc_html_e( 'average', 'privacy-checker' ); ?></span>
                        <span><?php esc_html_e( 'slow', 'privacy-checker' ); ?></span>
                    </div>
                </div>
            </section>

            <div class="pc-geo__toast" data-pc-region="toast" role="status" aria-live="polite" hidden></div>

            <div class="pc-geo__modal" data-pc-modal="methodology" hidden role="dialog" aria-modal="true" aria-labelledby="pc-geo-meth-title">
                <div class="pc-geo__modal-backdrop" data-pc-action="modal-close"></div>
                <div class="pc-geo__modal-card">
                    <h3 class="pc-geo__modal-title" id="pc-geo-meth-title"><?php esc_html_e( 'Methodology', 'privacy-checker' ); ?></h3>
                    <p><?php esc_html_e( 'Hop locations are inferred from reverse DNS, GeoIP consistency across multiple databases, latency-based plausibility, and a Bayesian weighting pass. No hops are stored. ML-assisted rDNS parsing is used as a last resort.', 'privacy-checker' ); ?></p>
                    <p><?php esc_html_e( 'Browsers cannot send raw ICMP, so hop visualisation combines server-side TCP-connect probes with the visitor-side intel (IP / ASN / city / ISP / proxy signals) to synthesise a likely path. Where a hop IP is known we display it; where it is not, we render the inferred hop from the GeoIP + latency envelope.', 'privacy-checker' ); ?></p>
                    <p class="pc-geo__modal-credit">
                        <?php esc_html_e( 'Inspired by', 'privacy-checker' ); ?>
                        <a href="https://github.com/jdoiro3/GeoTraceroute" target="_blank" rel="noopener noreferrer">jdoiro3/GeoTraceroute</a>
                        <?php esc_html_e( '(traceroute + globe.gl + IPinfo.io).', 'privacy-checker' ); ?>
                    </p>
                    <button type="button" class="pc-btn pc-btn--ghost" data-pc-action="modal-close"><?php esc_html_e( 'Close', 'privacy-checker' ); ?></button>
                </div>
            </div>

            <div class="pc-geo__modal" data-pc-modal="preferences" hidden role="dialog" aria-modal="true" aria-labelledby="pc-geo-prefs-title">
                <div class="pc-geo__modal-backdrop" data-pc-action="modal-close"></div>
                <div class="pc-geo__modal-card pc-geo__modal-card--wide">
                    <h3 class="pc-geo__modal-title" id="pc-geo-prefs-title"><?php esc_html_e( 'Preferences', 'privacy-checker' ); ?></h3>
                    <form class="pc-geo__prefs" data-pc-action="prefs-save">
                        <label class="pc-geo__prefs-row">
                            <span><?php esc_html_e( 'Default source node', 'privacy-checker' ); ?></span>
                            <select data-pc-pref="source">
                                <option value="self">FR-Strasbourg (self)</option>
                                <option value="nl">NL-Amsterdam</option>
                                <option value="de">DE-Frankfurt</option>
                                <option value="us">US-New York</option>
                                <option value="br">BR-Sao Paulo</option>
                            </select>
                        </label>
                        <label class="pc-geo__prefs-row">
                            <span><?php esc_html_e( 'Map style', 'privacy-checker' ); ?></span>
                            <select data-pc-pref="mapStyle">
                                <option value="dark">Dark (default)</option>
                                <option value="light">Light</option>
                                <option value="atlas">Atlas</option>
                                <option value="night">Night</option>
                            </select>
                        </label>
                        <label class="pc-geo__prefs-row pc-geo__prefs-row--check">
                            <span><?php esc_html_e( 'Route along submarine cables', 'privacy-checker' ); ?></span>
                            <input type="checkbox" data-pc-pref="cable" />
                        </label>
                        <label class="pc-geo__prefs-row pc-geo__prefs-row--check">
                            <span><?php esc_html_e( 'Show cities', 'privacy-checker' ); ?></span>
                            <input type="checkbox" data-pc-pref="cities" checked />
                        </label>
                        <label class="pc-geo__prefs-row pc-geo__prefs-row--check">
                            <span><?php esc_html_e( 'Geek mode', 'privacy-checker' ); ?></span>
                            <input type="checkbox" data-pc-pref="geek" />
                        </label>
                        <div class="pc-geo__prefs-actions">
                            <button type="submit" class="pc-btn pc-btn--primary"><?php esc_html_e( 'Save', 'privacy-checker' ); ?></button>
                            <button type="button" class="pc-btn pc-btn--ghost" data-pc-action="modal-close"><?php esc_html_e( 'Close', 'privacy-checker' ); ?></button>
                        </div>
                    </form>
                </div>
            </div>

            <div class="pc-geo__toolbar">
                <button type="button" class="pc-geo__icon-btn" data-pc-action="open-prefs" title="<?php esc_attr_e( 'Preferences', 'privacy-checker' ); ?>" aria-label="<?php esc_attr_e( 'Preferences', 'privacy-checker' ); ?>">⚙</button>
                <button type="button" class="pc-geo__icon-btn" data-pc-action="open-methodology" title="<?php esc_attr_e( 'Methodology', 'privacy-checker' ); ?>" aria-label="<?php esc_attr_e( 'Methodology', 'privacy-checker' ); ?>">?</button>
                <select class="pc-geo__lang" data-pc-action="set-lang" aria-label="<?php esc_attr_e( 'Language', 'privacy-checker' ); ?>">
                    <option value="en">EN</option>
                    <option value="de">DE</option>
                    <option value="es">ES</option>
                    <option value="fr">FR</option>
                    <option value="it">IT</option>
                    <option value="pt">PT</option>
                    <option value="ro">RO</option>
                    <option value="ru">RU</option>
                    <option value="zh">ZH</option>
                    <option value="ja">JA</option>
                    <option value="ko">KO</option>
                    <option value="hi">HI</option>
                </select>
            </div>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * User-guide onboarding tour — MANUAL-ONLY.
     *
     * Renders a floating "?" action button plus the tour overlay shell. The
     * tour is NEVER auto-launched. It opens only when the user clicks the
     * floating button (or an in-page trigger with `data-pc-action="open-guide"`).
     * There is no first-visit detection, no localStorage flag, no scheduled
     * timer, and no autoshow on any hook.
     */
    public function user_guide_shortcode( $atts = array() ): string {
        ob_start();
        ?>
        <!-- Floating manual launcher. Always visible when the shortcode is
             rendered. The tour itself is opt-in: nothing fires until the user
             clicks this button or an in-page trigger with the same action. -->
        <button
            type="button"
            class="pc-guide-fab"
            data-pc-action="open-guide"
            aria-label="<?php esc_attr_e( 'User guide', 'privacy-checker' ); ?>"
            title="<?php esc_attr_e( 'Open user guide', 'privacy-checker' ); ?>"
        >
            <span class="pc-guide-fab__icon" aria-hidden="true">?</span>
        </button>

        <!-- Overlay shell. Hidden by default. JS toggles `hidden` only when
             the user explicitly opens the guide, and restores it on close. -->
        <div
            class="pc-guide-overlay"
            data-pc-component="user-guide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="pc-guide-title"
            aria-describedby="pc-guide-body"
            hidden
        >
            <div class="pc-guide-backdrop" data-pc-action="close-guide" aria-hidden="true"></div>
            <div
                class="pc-guide-card"
                role="document"
                tabindex="-1"
                data-pc-region="tour-card"
            >
                <header class="pc-guide-card__header">
                    <h2 class="pc-guide-card__title" id="pc-guide-title" data-pc-region="tour-title"><?php esc_html_e( 'Welcome to IMON', 'privacy-checker' ); ?></h2>
                    <button
                        type="button"
                        class="pc-guide-card__close"
                        data-pc-action="close-guide"
                        aria-label="<?php esc_attr_e( 'Close', 'privacy-checker' ); ?>"
                        title="<?php esc_attr_e( 'Close', 'privacy-checker' ); ?>"
                    >&times;</button>
                </header>

                <div class="pc-guide-card__body" id="pc-guide-body" data-pc-region="tour-body">
                    <!-- Step body content injected by JS from PC_GUIDE.tour. -->
                </div>

                <footer class="pc-guide-card__footer">
                    <span class="pc-guide-card__step" data-pc-region="tour-step"><?php esc_html_e( 'Step 1 of 1', 'privacy-checker' ); ?></span>
                    <div class="pc-guide-card__actions">
                        <button type="button" class="pc-btn pc-btn--ghost" data-pc-action="prev-step"><?php esc_html_e( 'Previous', 'privacy-checker' ); ?></button>
                        <button type="button" class="pc-btn pc-btn--primary" data-pc-action="next-step"><?php esc_html_e( 'Next', 'privacy-checker' ); ?></button>
                        <button type="button" class="pc-btn pc-btn--primary" data-pc-action="end-tour" hidden><?php esc_html_e( 'Got it', 'privacy-checker' ); ?></button>
                    </div>
                </footer>
            </div>
        </div>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Wrap content with a region marker for the JS to find.
     */
    private function wrap( string $html, string $region ): string {
        return '<div data-pc-region-extra="' . esc_attr( $region ) . '">' . $html . '</div>';
    }
}