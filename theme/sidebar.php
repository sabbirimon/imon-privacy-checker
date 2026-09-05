<?php
/**
 * Sidebar template.
 *
 * @package PrivacyCheckerTheme
 */

if ( ! is_active_sidebar( 'sidebar-1' ) ) {
    return;
}
?>
<aside class="pc-sidebar" role="complementary" aria-label="<?php esc_attr_e( 'Sidebar', 'privacy-checker-theme' ); ?>">
    <?php dynamic_sidebar( 'sidebar-1' ); ?>
</aside>