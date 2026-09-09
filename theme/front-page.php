<?php
/**
 * Front page template. Hosts the hero + scanner dashboard.
 *
 * @package PrivacyCheckerTheme
 */

get_header();
?>

<section class="pc-hero pc-hero--marketing" aria-labelledby="pc-hero-title">
    <div class="pc-container">
        <div class="pc-hero__brand">
            <span class="pc-hero__brand-mark" aria-hidden="true">IMON</span>
            <span class="pc-hero__brand-tag"><?php esc_html_e( 'I AM ON', 'privacy-checker-theme' ); ?></span>
        </div>
        <p class="pc-hero__eyebrow"><?php esc_html_e( 'Privacy & anonymity diagnostic platform', 'privacy-checker-theme' ); ?></p>
        <h1 class="pc-hero__title" id="pc-hero-title">
            <?php esc_html_e( 'How Private Are You Online?', 'privacy-checker-theme' ); ?>
        </h1>
        <p class="pc-hero__subtitle">
            <?php esc_html_e(
                'Check your IP address, connection, browser fingerprint, WebRTC exposure, and other publicly visible information. Privacy scores are estimates based on the signals available to this website — not guarantees.',
                'privacy-checker-theme'
            ); ?>
        </p>
        <div class="pc-hero__cta">
            <a class="pc-btn pc-btn--primary" href="#pc-scanner" data-pc-action="start-scan">
                <?php esc_html_e( 'Run Privacy Check', 'privacy-checker-theme' ); ?>
            </a>
            <a class="pc-btn pc-btn--ghost" href="<?php echo esc_url( home_url( '/anonymity-tips/' ) ); ?>">
                <?php esc_html_e( 'Learn How It Works', 'privacy-checker-theme' ); ?>
            </a>
        </div>
    </div>

    <?php
    // Floating v2 toggle pill. Self-hides when already in v2 mode.
    // Lives in the theme so it works regardless of which shortcode is
    // active on the page.
    if ( shortcode_exists( 'privacy_checker_v2_toggle' ) ) {
        echo do_shortcode( '[privacy_checker_v2_toggle]' );
    }
    ?>
</section>

<section class="pc-scanner-section" id="pc-scanner" aria-labelledby="pc-scanner-title">
    <div class="pc-container">
        <h2 class="pc-section__title" id="pc-scanner-title">
            <?php esc_html_e( 'Your Privacy Report', 'privacy-checker-theme' ); ?>
        </h2>
        <p class="pc-section__lede">
            <?php esc_html_e(
                'The scan runs entirely in your browser and against our server. We do not create persistent profiles or sell scan data.',
                'privacy-checker-theme'
            ); ?>
        </p>

        <?php
        // Plugin shortcode renders the dashboard.
        if ( shortcode_exists( 'privacy_checker' ) ) {
            echo do_shortcode( '[privacy_checker]' );
        } else {
            echo '<p>' . esc_html__( 'The privacy checker plugin is not active.', 'privacy-checker-theme' ) . '</p>';
        }
        ?>
    </div>
</section>

<section class="pc-callouts" aria-labelledby="pc-callouts-title">
    <div class="pc-container">
        <h2 class="pc-section__title" id="pc-callouts-title">
            <?php esc_html_e( 'What we check', 'privacy-checker-theme' ); ?>
        </h2>
        <ul class="pc-callouts__grid">
            <li>
                <h3><?php esc_html_e( 'Network', 'privacy-checker-theme' ); ?></h3>
                <p><?php esc_html_e( 'Public IP addresses, geolocation, ISP, ASN, reverse DNS, and connection type.', 'privacy-checker-theme' ); ?></p>
            </li>
            <li>
                <h3><?php esc_html_e( 'Reputation', 'privacy-checker-theme' ); ?></h3>
                <p><?php esc_html_e( 'IP reputation and blacklist indicators from configurable providers.', 'privacy-checker-theme' ); ?></p>
            </li>
            <li>
                <h3><?php esc_html_e( 'Browser', 'privacy-checker-theme' ); ?></h3>
                <p><?php esc_html_e( 'Fingerprint visibility estimate from browser-exposed signals only.', 'privacy-checker-theme' ); ?></p>
            </li>
            <li>
                <h3><?php esc_html_e( 'WebRTC', 'privacy-checker-theme' ); ?></h3>
                <p><?php esc_html_e( 'Browser networking API exposure check with honest reporting.', 'privacy-checker-theme' ); ?></p>
            </li>
        </ul>
    </div>
</section>

<?php
get_footer();