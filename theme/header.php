<?php
/**
 * Header template.
 *
 * @package PrivacyCheckerTheme
 */
?><!DOCTYPE html>
<html <?php language_attributes(); ?> data-pc-theme="light">
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="theme-color" content="#17a2b8">
    <meta name="description" content="<?php echo esc_attr( get_bloginfo( 'description' ) ); ?>">
    <link rel="profile" href="https://gmpg.org/xfn/11">
    <script>
        // Apply theme synchronously to avoid a flash. Default light.
        (function () {
            try {
                var t = localStorage.getItem('pc-theme');
                if (t === 'dark' || t === 'light') {
                    document.documentElement.setAttribute('data-pc-theme', t);
                }
            } catch (e) { /* localStorage may be blocked; default to light */ }
        })();
    </script>
    <?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<?php wp_body_open(); ?>

<a class="pc-skip-link" href="#pc-main"><?php esc_html_e( 'Skip to content', 'privacy-checker-theme' ); ?></a>

<header class="pc-header" role="banner">
    <div class="pc-header__inner">
        <a class="pc-brand" href="<?php echo esc_url( home_url( '/' ) ); ?>" rel="home">
            <span class="pc-brand__mark" aria-hidden="true">IMON</span>
            <span class="pc-brand__name"><?php esc_html_e( 'I AM ON', 'privacy-checker-theme' ); ?></span>
        </a>

        <button class="pc-nav-toggle" type="button" aria-controls="pc-primary-nav" aria-expanded="false" aria-label="<?php esc_attr_e( 'Toggle menu', 'privacy-checker-theme' ); ?>">
            <span class="dot"></span>
            <span class="dot"></span>
            <span class="dot"></span>
        </button>

        <nav class="pc-nav" id="pc-primary-nav" aria-label="<?php esc_attr_e( 'Primary', 'privacy-checker-theme' ); ?>">
            <?php
            if ( has_nav_menu( 'primary' ) ) {
                wp_nav_menu( array(
                    'theme_location' => 'primary',
                    'container'      => false,
                    'menu_class'     => 'pc-nav-list',
                    'depth'          => 1,
                    'fallback_cb'    => 'pc_theme_fallback_menu',
                ) );
            } else {
                pc_theme_fallback_menu();
            }
            ?>
        </nav>

        <button type="button" class="pc-theme-toggle" data-pc-action="theme-toggle" aria-label="<?php esc_attr_e( 'Toggle dark mode', 'privacy-checker-theme' ); ?>" title="<?php esc_attr_e( 'Toggle dark mode', 'privacy-checker-theme' ); ?>">
            <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4"/>
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
            </svg>
            <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
            </svg>
        </button>
    </div>
</header>

<main id="pc-main" class="pc-main" role="main">
