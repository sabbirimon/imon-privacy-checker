<?php
/**
 * Footer template.
 *
 * @package PrivacyCheckerTheme
 */
?>
</main><!-- .pc-main -->

<footer class="pc-footer" role="contentinfo">
    <div class="pc-container">
        <div class="pc-footer__grid">
            <div>
                <h4><?php bloginfo( 'name' ); ?></h4>
                <p>
                    <?php
                    $desc = get_bloginfo( 'description', 'display' );
                    echo esc_html( $desc ?: __( 'A privacy & anonymity diagnostic platform.', 'privacy-checker-theme' ) );
                    ?>
                </p>
            </div>

            <div>
                <h4><?php esc_html_e( 'Tools', 'privacy-checker-theme' ); ?></h4>
                <?php
                if ( has_nav_menu( 'footer' ) ) {
                    wp_nav_menu( array(
                        'theme_location' => 'footer',
                        'container'      => false,
                        'menu_class'     => 'pc-footer-list',
                        'depth'          => 1,
                    ) );
                } else {
                    ?>
                    <ul>
                        <li><a href="<?php echo esc_url( home_url( '/ip-lookup/' ) ); ?>"><?php esc_html_e( 'IP Lookup', 'privacy-checker-theme' ); ?></a></li>
                        <li><a href="<?php echo esc_url( home_url( '/whois/' ) ); ?>"><?php esc_html_e( 'WHOIS', 'privacy-checker-theme' ); ?></a></li>
                        <li><a href="<?php echo esc_url( home_url( '/fingerprint/' ) ); ?>"><?php esc_html_e( 'Fingerprint', 'privacy-checker-theme' ); ?></a></li>
                        <li><a href="<?php echo esc_url( home_url( '/security-headers/' ) ); ?>"><?php esc_html_e( 'Security Headers', 'privacy-checker-theme' ); ?></a></li>
                    </ul>
                    <?php
                }
                ?>
            </div>

            <div>
                <h4><?php esc_html_e( 'Legal', 'privacy-checker-theme' ); ?></h4>
                <?php if ( is_active_sidebar( 'footer-1' ) ) : ?>
                    <?php dynamic_sidebar( 'footer-1' ); ?>
                <?php else : ?>
                    <ul>
                        <li><a href="<?php echo esc_url( home_url( '/privacy/' ) ); ?>"><?php esc_html_e( 'Privacy Policy', 'privacy-checker-theme' ); ?></a></li>
                        <li><a href="<?php echo esc_url( home_url( '/terms/' ) ); ?>"><?php esc_html_e( 'Terms of Service', 'privacy-checker-theme' ); ?></a></li>
                        <li><a href="<?php echo esc_url( home_url( '/cookies/' ) ); ?>"><?php esc_html_e( 'Cookie Policy', 'privacy-checker-theme' ); ?></a></li>
                    </ul>
                <?php endif; ?>
            </div>
        </div>

        <div class="pc-footer__bottom">
            <span>&copy; <?php echo esc_html( gmdate( 'Y' ) ); ?> <?php bloginfo( 'name' ); ?></span>
            <span><?php esc_html_e( 'Privacy scores are estimates based on observable signals.', 'privacy-checker-theme' ); ?></span>
        </div>
    </div>
</footer>

<?php wp_footer(); ?>
</body>
</html>