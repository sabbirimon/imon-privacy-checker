<?php
/**
 * 404 template.
 *
 * @package PrivacyCheckerTheme
 */

get_header();
?>

<section class="pc-page pc-page--404">
    <div class="pc-container">
        <h1 class="pc-page__title"><?php esc_html_e( '404 — Page Not Found', 'privacy-checker-theme' ); ?></h1>
        <p><?php esc_html_e( 'The page you requested could not be found.', 'privacy-checker-theme' ); ?></p>
        <p>
            <a class="pc-btn pc-btn--ghost" href="<?php echo esc_url( home_url( '/' ) ); ?>">
                <?php esc_html_e( 'Return home', 'privacy-checker-theme' ); ?>
            </a>
        </p>
    </div>
</section>

<?php
get_footer();