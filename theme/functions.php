<?php
/**
 * Privacy Checker theme bootstrap.
 *
 * Theme is presentation-only. All scanner functionality lives in the privacy-checker plugin.
 *
 * @package PrivacyCheckerTheme
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! defined( 'PRIVACY_CHECKER_THEME_VERSION' ) ) {
    define( 'PRIVACY_CHECKER_THEME_VERSION', '1.1.0' );
}

/**
 * Theme setup: titles, menus, supports.
 */
function pc_theme_setup(): void {
    load_theme_textdomain( 'privacy-checker-theme', get_template_directory() . '/languages' );

    add_theme_support( 'title-tag' );
    add_theme_support( 'post-thumbnails' );
    add_theme_support( 'html5', array(
        'search-form',
        'comment-form',
        'comment-list',
        'gallery',
        'caption',
        'script',
        'style',
    ) );
    add_theme_support( 'automatic-feed-links' );
    add_theme_support( 'responsive-embeds' );
    add_theme_support( 'custom-logo', array(
        'height'      => 60,
        'width'       => 200,
        'flex-height' => true,
        'flex-width'  => true,
    ) );

    register_nav_menus( array(
        'primary' => __( 'Primary Menu', 'privacy-checker-theme' ),
        'footer'  => __( 'Footer Menu', 'privacy-checker-theme' ),
    ) );
}
add_action( 'after_setup_theme', 'pc_theme_setup' );

/**
 * Enqueue theme assets.
 */
function pc_theme_assets(): void {
    wp_enqueue_style(
        'pc-theme',
        get_template_directory_uri() . '/assets/css/theme.css',
        array(),
        PRIVACY_CHECKER_THEME_VERSION
    );

    wp_enqueue_script(
        'pc-theme',
        get_template_directory_uri() . '/assets/js/theme.js',
        array(),
        PRIVACY_CHECKER_THEME_VERSION,
        true
    );
}
add_action( 'wp_enqueue_scripts', 'pc_theme_assets' );

/**
 * Register widget areas.
 */
function pc_theme_widgets_init(): void {
    register_sidebar( array(
        'name'          => __( 'Footer Widgets', 'privacy-checker-theme' ),
        'id'            => 'footer-1',
        'description'   => __( 'Widgets displayed in the footer.', 'privacy-checker-theme' ),
        'before_widget' => '<section id="%1$s" class="pc-footer-widget %2$s">',
        'after_widget'  => '</section>',
        'before_title'  => '<h4>',
        'after_title'   => '</h4>',
    ) );
}
add_action( 'widgets_init', 'pc_theme_widgets_init' );

/**
 * Render fallback primary menu items when no menu is assigned.
 */
function pc_theme_fallback_menu(): void {
    $items = array(
        '/'                  => __( 'Home', 'privacy-checker-theme' ),
        '/ip-lookup/'        => __( 'IP Lookup', 'privacy-checker-theme' ),
        '/whois/'            => __( 'WHOIS', 'privacy-checker-theme' ),
        '/user-agent/'       => __( 'User Agent', 'privacy-checker-theme' ),
        '/fingerprint/'      => __( 'Fingerprint', 'privacy-checker-theme' ),
        '/dns-leak-test/'    => __( 'DNS Leak', 'privacy-checker-theme' ),
        '/webrtc-test/'      => __( 'WebRTC', 'privacy-checker-theme' ),
    );
    echo '<ul class="pc-nav-list">';
    foreach ( $items as $url => $label ) {
        printf(
            '<li><a href="%s">%s</a></li>',
            esc_url( home_url( $url ) ),
            esc_html( $label )
        );
    }
    echo '</ul>';
}

/**
 * Custom body classes.
 */
function pc_theme_body_class( array $classes ): array {
    $classes[] = 'pc-theme';
    if ( is_front_page() ) {
        $classes[] = 'is-front-page';
    }
    return $classes;
}
add_filter( 'body_class', 'pc_theme_body_class' );