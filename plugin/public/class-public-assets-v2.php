<?php
/**
 * Public-facing assets and shortcode rendering for the v2 (experimental) UI.
 *
 * The v2 build lives entirely in separate files and registers its own
 * shortcode (`[privacy_checker_v2]`) and DOM hooks (`data-pcv2-*`).
 * v1 is left fully intact: deleting the v2 files removes v2 entirely
 * without touching v1.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Enqueues the v2 dashboard assets and renders the v2 shortcode.
 *
 * v2 is opt-in: it is only enqueued when either (a) the user has the
 * `pc_ui_v2` cookie set or (b) the request carries `?v=2`. v1 stays the
 * default and is unaffected.
 */
final class PublicAssetsV2 {

    /**
     * Cookie name that opts the visitor into the v2 UI.
     */
    private const COOKIE = 'pc_ui_v2';

    /**
     * Cookie lifetime (30 days).
     */
    private const COOKIE_TTL = 30 * DAY_IN_SECONDS;

    /**
     * Register hooks.
     */
    public function register(): void {
        add_action( 'wp_enqueue_scripts', array( $this, 'maybe_enqueue' ) );
        add_action( 'wp_enqueue_scripts', array( $this, 'set_cookie_from_query' ), 5 );
        add_action( 'init', array( $this, 'set_cookie_from_query' ) );
        add_shortcode( 'privacy_checker_v2', array( $this, 'shortcode' ) );
        add_shortcode( 'privacy_checker_v2_toggle', array( $this, 'toggle_shortcode' ) );
        add_shortcode( 'privacy_checker_v2_theme', array( $this, 'theme_toggle_shortcode' ) );
        add_shortcode( 'privacy_checker_v2_geotrace', array( $this, 'geotrace_shortcode' ) );
    }

    /**
     * Sets / clears the `pc_ui_v2` cookie based on `?v=2` / `?v=1` query args.
     *
     * Wired at `init` so the cookie is set on the very first request — the
     * enqueue logic downstream uses `$_COOKIE` to decide whether to load
     * v2 assets, and that needs to be populated before `wp_enqueue_scripts`.
     */
    public function set_cookie_from_query(): void {
        if ( ! isset( $_GET['v'] ) ) {
            return;
        }
        $flag = (string) wp_unslash( $_GET['v'] );
        if ( '2' === $flag ) {
            setcookie( self::COOKIE, '1', time() + self::COOKIE_TTL, COOKIEPATH ?: '/', COOKIE_DOMAIN ?: '', is_ssl(), true );
            $_COOKIE[ self::COOKIE ] = '1';
        } elseif ( '1' === $flag ) {
            setcookie( self::COOKIE, '', time() - 3600, COOKIEPATH ?: '/', COOKIE_DOMAIN ?: '', is_ssl(), true );
            unset( $_COOKIE[ self::COOKIE ] );
        }
    }

    /**
     * Decide whether to load v2 assets on this request.
     *
     * v2 assets load when ANY of:
     *   - The shortcode `[privacy_checker_v2]` is in the post content.
     *   - The request URI matches `?v=2` (cookie was set this request).
     *   - The `pc_ui_v2` cookie is present and the user is on the front
     *     page (so the floating toggle pill is interactive everywhere).
     */
    public function maybe_enqueue(): void {
        if ( is_admin() ) {
            return;
        }
        $want_v2 = $this->user_wants_v2();
        $has_shortcode = is_singular() && has_shortcode( (string) ( get_post()->post_content ?? '' ), 'privacy_checker_v2' );
        if ( ! $want_v2 && ! $has_shortcode ) {
            return;
        }
        $this->enqueue_v2_assets();
    }

    /**
     * Force-load the v2 assets when the v2 shortcode is rendered — the
     * visitor may not have the cookie yet (first visit via deep link).
     */
    public function enqueue_v2_assets(): void {
        wp_enqueue_style(
            'pc-scanner-v2',
            PRIVACY_CHECKER_URL . 'public/assets/css/scanner-v2.css',
            array(),
            PRIVACY_CHECKER_VERSION
        );
        wp_register_script(
            'pc-scanner-v2',
            PRIVACY_CHECKER_URL . 'public/assets/js/scanner-v2.js',
            array(),
            PRIVACY_CHECKER_VERSION,
            true
        );
        wp_enqueue_script( 'pc-scanner-v2' );

        // Same REST config v1 uses — the scan backend is shared.
        wp_localize_script( 'pc-scanner-v2', 'PC_SCAN', array(
            'restUrl'    => esc_url_raw( rest_url( PRIVACY_CHECKER_REST_NS . '/' ) ),
            'restNonce'  => wp_create_nonce( 'wp_rest' ),
            'assetUrl'   => esc_url_raw( PRIVACY_CHECKER_URL . 'public/assets/' ),
            'i18n'       => array(
                'scanning'         => __( 'Scanning…', 'privacy-checker' ),
                'runCheck'         => __( 'Run Privacy Check', 'privacy-checker' ),
                'rescan'           => __( 'Re-run scan', 'privacy-checker' ),
                'themeLight'       => __( 'Light', 'privacy-checker' ),
                'themeDark'        => __( 'Dark', 'privacy-checker' ),
                'themeSystem'      => __( 'System', 'privacy-checker' ),
                'v2ToggleOn'       => __( 'Switch back to classic UI', 'privacy-checker' ),
                'v2ToggleOff'      => __( 'Try the new UI (Beta)', 'privacy-checker' ),
                'progressIp'       => __( 'Detecting IP', 'privacy-checker' ),
                'progressIntel'    => __( 'Resolving geolocation', 'privacy-checker' ),
                'progressRep'      => __( 'Checking IP reputation', 'privacy-checker' ),
                'progressFp'       => __( 'Estimating browser fingerprint', 'privacy-checker' ),
                'progressWebrtc'   => __( 'Testing WebRTC exposure', 'privacy-checker' ),
                'progressScore'    => __( 'Calculating privacy score', 'privacy-checker' ),
                'browserOnly'      => __( 'Browser-only · no network call', 'privacy-checker' ),
                'scoreLabel'       => __( 'Privacy Score', 'privacy-checker' ),
                'gradeLabel'       => __( 'Grade', 'privacy-checker' ),
                'confidenceLabel'  => __( 'Confidence', 'privacy-checker' ),
                'overviewTitle'    => __( 'Overview', 'privacy-checker' ),
                'connectionTitle'  => __( 'Connection', 'privacy-checker' ),
                'anonymityTitle'   => __( 'Anonymity', 'privacy-checker' ),
                'dnsTitle'         => __( 'DNS Resolver', 'privacy-checker' ),
                'browserTitle'     => __( 'Browser Privacy', 'privacy-checker' ),
                'securityTitle'    => __( 'Security Findings', 'privacy-checker' ),
                'findingsTitle'    => __( 'Privacy Findings', 'privacy-checker' ),
                'scoreGood'        => __( 'Your privacy measures are safe or you don\'t use them.', 'privacy-checker' ),
                'scoreMid'         => __( 'Some details are exposed. Review the recommendations below.', 'privacy-checker' ),
                'scoreBad'         => __( 'Significant details are exposed. Follow the priority fixes.', 'privacy-checker' ),
                'noData'           => __( 'Run the scan to see your results.', 'privacy-checker' ),
                'copyLabel'        => __( 'Copy', 'privacy-checker' ),
                'copiedLabel'      => __( 'Copied', 'privacy-checker' ),
                'privateBadge'     => __( 'Private', 'privacy-checker' ),
                'unansweredBadge'  => __( 'No response', 'privacy-checker' ),
                'noConfidence'     => __( 'Unknown', 'privacy-checker' ),
                'geoTitle'         => __( 'Geo Traceroute', 'privacy-checker' ),
                'geoRun'           => __( 'Trace route', 'privacy-checker' ),
                'geoPaste'         => __( 'Paste traceroute', 'privacy-checker' ),
                'geoVisualize'     => __( 'Visualize', 'privacy-checker' ),
                'geoProbeLabel'    => __( 'Probe', 'privacy-checker' ),
                'geoTargetLabel'   => __( 'Destination', 'privacy-checker' ),
                'geoHopsLabel'     => __( 'Hops', 'privacy-checker' ),
                'geoDisclaimer'    => __( 'Approximate geographic visualization of traceroute hops. IP geolocation is not GPS — coordinates show each hop IP\'s registered location, not its physical router.', 'privacy-checker' ),
                'geoUnavailable'   => __( 'Traceroute is not available on this server. Paste your own traceroute below to visualise it.', 'privacy-checker' ),
                'geoConfidence'    => __( 'Confidence', 'privacy-checker' ),
                'latencyJump'      => __( 'Latency jump', 'privacy-checker' ),
                'findingsHint'     => __( 'Click any row for scoring details and evidence.', 'privacy-checker' ),
                'rubricTitle'      => __( 'How this score was calculated', 'privacy-checker' ),
                'noRubric'         => __( 'No scoring rubric available for this category.', 'privacy-checker' ),
                'evidenceTitle'    => __( 'Evidence', 'privacy-checker' ),
                'sourceTitle'      => __( 'Data source', 'privacy-checker' ),
                'sourceUnknown'    => __( 'This category was scored from limited data — the underlying provider did not respond.', 'privacy-checker' ),
                'sourceEstimated'  => __( 'This category was estimated; no direct measurement was available.', 'privacy-checker' ),
                'recTitle'         => __( 'What you can do', 'privacy-checker' ),
                'scorePending'     => __( 'Score pending', 'privacy-checker' ),
                'radialAriaLabel'  => __( 'Sub-score breakdown chart', 'privacy-checker' ),
                'gradeLabel'       => __( 'Grade', 'privacy-checker' ),
                'copyIpLabel'      => __( 'Copy IP address', 'privacy-checker' ),
                'signalAriaLabel'  => __( 'Signal strength', 'privacy-checker' ),
                'signalPending'    => __( 'Awaiting connection…', 'privacy-checker' ),
                'geoPending'       => __( 'Geo lookup unavailable', 'privacy-checker' ),
                'dnsNotRun'        => __( 'DNS test not yet run — the probe runs automatically with each scan.', 'privacy-checker' ),
                // Plain-language (ELI5) labels — when the visitor flips the
                // "Explain simply" toggle, the card titles and finding
                // messages use these instead of the technical names.
                'eli5'             => array(
                    'ip'                 => __( 'Your Internet Address', 'privacy-checker' ),
                    'reputation'         => __( 'How others see your address', 'privacy-checker' ),
                    'dns'                => __( 'Who looks up websites for you', 'privacy-checker' ),
                    'webrtc'             => __( 'Video-call leak risk', 'privacy-checker' ),
                    'fingerprint'        => __( 'How unique your browser looks', 'privacy-checker' ),
                    'user_agent'         => __( 'What your browser tells websites', 'privacy-checker' ),
                    'ipv6'               => __( 'Modern Internet address', 'privacy-checker' ),
                    'consistency'        => __( 'Do your signals agree?', 'privacy-checker' ),
                    'security_posture'   => __( 'Are you using a secure browser?', 'privacy-checker' ),
                    'proxy'              => __( 'Are you hiding behind a relay?', 'privacy-checker' ),
                    'connection_quality' => __( 'How stable is your connection', 'privacy-checker' ),
                    'local_network'      => __( 'Your home network', 'privacy-checker' ),
                    'ip_exposure'        => __( 'How visible your address is', 'privacy-checker' ),
                    'dns_leak'           => __( 'Are DNS requests leaking', 'privacy-checker' ),
                    'connection'         => __( 'How you connect', 'privacy-checker' ),
                    'anonymity'          => __( 'How anonymous you look', 'privacy-checker' ),
                    'browser'            => __( 'About your browser', 'privacy-checker' )
                ),
                'eli5ToggleLabel'  => __( 'Explain simply', 'privacy-checker' ),
                'eli5ToggleOn'     => __( 'Showing plain-language explanations', 'privacy-checker' ),
                'eli5ToggleOff'    => __( 'Showing technical details', 'privacy-checker' ),
            ),
        ) );
    }

    /**
     * Render the v2 dashboard shortcode.
     */
    public function shortcode( $atts = array() ): string {
        // Make sure assets load even if the cookie dance didn't fire
        // (e.g. cached page rendered via a cron job, AMP, etc.).
        $this->enqueue_v2_assets();

        ob_start();
        ?>
        <section class="pcv2" data-pcv2-component="dashboard" data-pcv2-theme="system" data-pcv2-autostart="1">
            <span class="pcv2__orb pcv2__orb--bottom" aria-hidden="true"></span>
            <a class="pcv2__skip-link" href="#pcv2-main"><?php esc_html_e( 'Skip to main content', 'privacy-checker' ); ?></a>

            <header class="pcv2__header">
                <div class="pcv2__brand">
                    <span class="pcv2__brand-mark" aria-hidden="true">IMON</span>
                    <span class="pcv2__brand-tag"><?php esc_html_e( 'I AM ON', 'privacy-checker' ); ?></span>
                </div>
                <nav class="pcv2__nav" aria-label="<?php esc_attr_e( 'Primary', 'privacy-checker' ); ?>">
                    <a href="#pcv2-main"><?php esc_html_e( 'Home', 'privacy-checker' ); ?></a>
                    <a href="<?php echo esc_url( home_url( '/ip-lookup/' ) ); ?>"><?php esc_html_e( 'IP Check', 'privacy-checker' ); ?></a>
                    <a href="<?php echo esc_url( home_url( '/dns-leak-test/' ) ); ?>"><?php esc_html_e( 'DNS Leak', 'privacy-checker' ); ?></a>
                    <a href="<?php echo esc_url( home_url( '/webrtc-test/' ) ); ?>"><?php esc_html_e( 'Browser', 'privacy-checker' ); ?></a>
                    <a href="<?php echo esc_url( home_url( '/user-guide/' ) ); ?>"><?php esc_html_e( 'About', 'privacy-checker' ); ?></a>
                </nav>
                <div class="pcv2__header-actions">
                    <button
                        type="button"
                        class="pcv2__eli5-toggle"
                        data-pcv2-action="eli5-cycle"
                        aria-pressed="false"
                        title="<?php esc_attr_e( 'Explain simply', 'privacy-checker' ); ?>"
                    >
                        <span class="pcv2__eli5-toggle-label"><?php esc_html_e( 'ELI5', 'privacy-checker' ); ?></span>
                    </button>
                    <button
                        type="button"
                        class="pcv2__theme-toggle"
                        data-pcv2-action="theme-cycle"
                        aria-label="<?php esc_attr_e( 'Theme: System', 'privacy-checker' ); ?>"
                    >
                        <span class="pcv2__theme-toggle-icon" data-pcv2-region="theme-icon" aria-hidden="true"></span>
                    </button>
                    <a class="pcv2__btn pcv2__btn--primary" href="#pcv2-main"><?php esc_html_e( 'Run Check', 'privacy-checker' ); ?></a>
                </div>
            </header>

            <main id="pcv2-main" class="pcv2__main">
                <section class="pcv2__hero" aria-labelledby="pcv2-hero-title">
                    <p class="pcv2__eyebrow"><?php esc_html_e( 'Privacy &amp; anonymity diagnostic', 'privacy-checker' ); ?></p>
                    <h1 class="pcv2__hero-title" id="pcv2-hero-title">
                        <?php esc_html_e( 'How Private Are You Online?', 'privacy-checker' ); ?>
                    </h1>
                    <p class="pcv2__hero-subtitle">
                        <?php esc_html_e(
                            'See what your browser and network reveal about you. We analyze your IP, connection, proxy/VPN status, DNS exposure, browser signals, and privacy risks — entirely from your browser and our server. No analytics, no profiles.',
                            'privacy-checker'
                        ); ?>
                    </p>
                    <div class="pcv2__hero-cta">
                        <button type="button" class="pcv2__btn pcv2__btn--primary pcv2__btn--lg" data-pcv2-action="start-scan">
                            <span data-pcv2-region="cta-label"><?php esc_html_e( 'Run Privacy Check', 'privacy-checker' ); ?></span>
                        </button>
                    </div>
                </section>

                <section class="pcv2__progress" data-pcv2-region="progress" aria-label="<?php esc_attr_e( 'Scan progress', 'privacy-checker' ); ?>" hidden>
                    <ol class="pcv2__progress-list">
                        <li data-pcv2-step="ip"          data-pcv2-source="network"><?php esc_html_e( 'Detecting IP', 'privacy-checker' ); ?></li>
                        <li data-pcv2-step="intel"       data-pcv2-source="network"><?php esc_html_e( 'Resolving geolocation', 'privacy-checker' ); ?></li>
                        <li data-pcv2-step="reputation"  data-pcv2-source="network"><?php esc_html_e( 'Checking IP reputation', 'privacy-checker' ); ?></li>
                        <li data-pcv2-step="fingerprint" data-pcv2-source="browser"><?php esc_html_e( 'Estimating browser fingerprint', 'privacy-checker' ); ?><span class="pcv2__chip"><?php esc_html_e( 'Browser-only', 'privacy-checker' ); ?></span></li>
                        <li data-pcv2-step="webrtc"      data-pcv2-source="browser"><?php esc_html_e( 'Testing WebRTC exposure', 'privacy-checker' ); ?><span class="pcv2__chip"><?php esc_html_e( 'Browser-only', 'privacy-checker' ); ?></span></li>
                        <li data-pcv2-step="score"       data-pcv2-source="network"><?php esc_html_e( 'Calculating privacy score', 'privacy-checker' ); ?></li>
                    </ol>
                </section>

                <section class="pcv2__dashboard" data-pcv2-region="report" hidden>
                    <div class="pcv2__score-hero-host" data-pcv2-region="summary"></div>
                    <div class="pcv2__grid">
                        <article class="pcv2__card" data-pcv2-card="overview">    <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                        <article class="pcv2__card" data-pcv2-card="connection">  <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                        <article class="pcv2__card" data-pcv2-card="anonymity">   <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                        <article class="pcv2__card" data-pcv2-card="dns">         <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                        <article class="pcv2__card" data-pcv2-card="browser">     <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                        <article class="pcv2__card" data-pcv2-card="security">    <header class="pcv2__card-header"><h2 data-pcv2-region="card-title"></h2></header><div class="pcv2__card-body" data-pcv2-region="card-body"></div></article>
                    </div>
                    <div class="pcv2__findings" data-pcv2-region="findings"></div>
                    <div class="pcv2__actions-host"></div>
                </section>

                <?php $this->render_inline_geotrace(); ?>
            </main>

            <footer class="pcv2__footer">
                <p>
                    <?php esc_html_e(
                        'Privacy scores are estimates based on observable signals. We do not store personal data and we never share scan results with third parties.',
                        'privacy-checker'
                    ); ?>
                </p>
            </footer>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Inline GeoTrace section rendered at the bottom of the v2
     * dashboard (Phase 19 — moved from a separate shortcode so the
     * home page has the full privacy toolkit without dropping in
     * extra shortcodes). Reads from the same `/scan/geo/lookup` +
     * `/scan/geo/paste` endpoints the v1 page uses.
     */
    public function render_inline_geotrace(): void {
        ?>
        <section class="pcv2__geotrace" data-pcv2-component="geotrace" aria-labelledby="pcv2-geotrace-title">
            <header class="pcv2__geo-header">
                <div class="pcv2__geo-header-text">
                    <h2 id="pcv2-geotrace-title"><?php esc_html_e( 'Geo Traceroute', 'privacy-checker' ); ?></h2>
                    <p class="pcv2__geo-tagline"><?php esc_html_e( 'Trace the path your packets take — visualized on a 2D map.', 'privacy-checker' ); ?></p>
                </div>
                <form class="pcv2__geo-input" data-pcv2-action="geo-target">
                    <label class="pcv2__sr-only" for="pcv2-geo-target"><?php esc_html_e( 'Target host', 'privacy-checker' ); ?></label>
                    <input
                        id="pcv2-geo-target"
                        type="text"
                        data-pcv2-region="geo-target"
                        placeholder="<?php esc_attr_e( 'example.com', 'privacy-checker' ); ?>"
                        value="<?php echo esc_attr( home_url() ); ?>"
                    />
                    <button type="button" class="pcv2__btn pcv2__btn--primary" data-pcv2-action="geo-run">
                        <?php esc_html_e( 'Trace route', 'privacy-checker' ); ?>
                    </button>
                </form>
            </header>

            <p class="pcv2__geo-disclaimer" data-pcv2-region="geo-disclaimer">
                <?php esc_html_e(
                    'Approximate geographic visualization of traceroute hops. IP geolocation is not GPS — coordinates show each hop IP\'s registered location, not its physical router.',
                    'privacy-checker'
                ); ?>
            </p>

            <dl class="pcv2__geo-meta" data-pcv2-region="geo-meta"></dl>

            <div class="pcv2__geo-map" data-pcv2-region="geo-map">
                <div class="pcv2__geo-map-msg"><?php esc_html_e( 'Enter a target host and click Trace route, or paste traceroute output below.', 'privacy-checker' ); ?></div>
            </div>

            <div class="pcv2__geo-hops" data-pcv2-region="geo-hops"></div>

            <details class="pcv2__geo-paste">
                <summary><?php esc_html_e( 'Paste traceroute', 'privacy-checker' ); ?></summary>
                <form data-pcv2-action="geo-paste">
                    <label class="pcv2__sr-only" for="pcv2-geo-paste"><?php esc_html_e( 'Traceroute text', 'privacy-checker' ); ?></label>
                    <textarea id="pcv2-geo-paste" data-pcv2-region="geo-paste" placeholder="1  192.0.2.1 (192.0.2.1)  1.123 ms  1.245 ms  1.301 ms"></textarea>
                    <button type="submit" class="pcv2__btn pcv2__btn--primary"><?php esc_html_e( 'Visualize', 'privacy-checker' ); ?></button>
                </form>
            </details>
        </section>
        <?php
    }

    /**
     * Render the floating "Try the new UI" / "Switch back to classic UI"
     * toggle. v1 owners can drop `[privacy_checker_v2_toggle]` anywhere
     * in their homepage hero or footer; it self-hides when the user is
     * already in v2 mode.
     */
    public function toggle_shortcode( $atts = array() ): string {
        $this->enqueue_v2_assets();
        $on_v2 = $this->user_wants_v2();
        $url   = $on_v2 ? esc_url( remove_query_arg( 'v' ) ) : esc_url( add_query_arg( 'v', '2' ) );
        $label = $on_v2 ? __( 'Switch back to classic UI', 'privacy-checker' ) : __( 'Try the new UI (Beta)', 'privacy-checker' );
        ob_start();
        ?>
        <a class="pcv2__toggle" href="<?php echo $url; ?>" data-pcv2-toggle="<?php echo $on_v2 ? 'off' : 'on'; ?>" rel="nofollow">
            <span class="pcv2__toggle-dot" aria-hidden="true"></span>
            <span class="pcv2__toggle-label"><?php echo esc_html( $label ); ?></span>
        </a>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Render a stand-alone theme-cycle button (used in nav rows).
     */
    public function theme_toggle_shortcode( $atts = array() ): string {
        $this->enqueue_v2_assets();
        ob_start();
        ?>
        <button type="button" class="pcv2__theme-toggle pcv2__theme-toggle--inline" data-pcv2-action="theme-cycle" aria-label="<?php esc_attr_e( 'Theme: System', 'privacy-checker' ); ?>">
            <span class="pcv2__theme-toggle-icon" aria-hidden="true"></span>
        </button>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * Render the v2 GeoTrace widget. Self-contained: same canonical
     * route shape as the v1 endpoint, but laid out per design-system
     * pages/geotrace.md. Reads from the same `/scan/geo/lookup` +
     * `/scan/geo/paste` endpoints the v1 page uses.
     */
    public function geotrace_shortcode( $atts = array() ): string {
        $this->enqueue_v2_assets();
        ob_start();
        ?>
        <section class="pcv2 pcv2--geo" data-pcv2-component="geotrace" data-pcv2-theme="system">
            <header class="pcv2__geo-header">
                <h2><?php esc_html_e( 'Geo Traceroute', 'privacy-checker' ); ?></h2>
                <form class="pcv2__geo-input" data-pcv2-action="geo-target">
                    <label class="pcv2__sr-only" for="pcv2-geo-target"><?php esc_html_e( 'Target host', 'privacy-checker' ); ?></label>
                    <input
                        id="pcv2-geo-target"
                        type="text"
                        data-pcv2-region="geo-target"
                        placeholder="<?php esc_attr_e( 'example.com', 'privacy-checker' ); ?>"
                        value="<?php echo esc_attr( home_url() ); ?>"
                    />
                    <button type="button" class="pcv2__btn pcv2__btn--primary" data-pcv2-action="geo-run">
                        <?php esc_html_e( 'Trace route', 'privacy-checker' ); ?>
                    </button>
                </form>
            </header>

            <p class="pcv2__geo-disclaimer" data-pcv2-region="geo-disclaimer">
                <?php esc_html_e(
                    'Approximate geographic visualization of traceroute hops. IP geolocation is not GPS — coordinates show each hop IP\'s registered location, not its physical router.',
                    'privacy-checker'
                ); ?>
            </p>

            <dl class="pcv2__geo-meta" data-pcv2-region="geo-meta"></dl>

            <div class="pcv2__geo-map" data-pcv2-region="geo-map">
                <div class="pcv2__geo-map-msg"><?php esc_html_e( 'Enter a target host and click Trace route, or paste traceroute output below.', 'privacy-checker' ); ?></div>
            </div>

            <div class="pcv2__geo-hops" data-pcv2-region="geo-hops"></div>

            <details class="pcv2__geo-paste">
                <summary><?php esc_html_e( 'Paste traceroute', 'privacy-checker' ); ?></summary>
                <form data-pcv2-action="geo-paste">
                    <label class="pcv2__sr-only" for="pcv2-geo-paste"><?php esc_html_e( 'Traceroute text', 'privacy-checker' ); ?></label>
                    <textarea id="pcv2-geo-paste" data-pcv2-region="geo-paste" placeholder="1  192.0.2.1 (192.0.2.1)  1.123 ms  1.245 ms  1.301 ms"></textarea>
                    <button type="submit" class="pcv2__btn pcv2__btn--primary"><?php esc_html_e( 'Visualize', 'privacy-checker' ); ?></button>
                </form>
            </details>
        </section>
        <?php
        return (string) ob_get_clean();
    }

    /**
     * True if the visitor has opted into v2 via cookie or `?v=2` query arg.
     */
    private function user_wants_v2(): bool {
        if ( isset( $_GET['v'] ) && '2' === (string) wp_unslash( $_GET['v'] ) ) {
            return true;
        }
        if ( isset( $_COOKIE[ self::COOKIE ] ) && '1' === (string) $_COOKIE[ self::COOKIE ] ) {
            return true;
        }
        return false;
    }
}