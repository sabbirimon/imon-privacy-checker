<?php
/**
 * Settings page template.
 *
 * @package PrivacyChecker
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}
?>
<div class="wrap pc-admin">
    <h1><?php esc_html_e( 'IMON — Settings', 'privacy-checker' ); ?></h1>

    <p class="description">
        <?php esc_html_e(
            'Configure providers, API credentials, rate limits, and privacy defaults. All data is stored server-side only.',
            'privacy-checker'
        ); ?>
    </p>

    <form method="post" action="options.php">
        <?php
        settings_fields( 'pc_settings_group' );
        do_settings_sections( PrivacyChecker\Admin\Admin::MENU_SLUG );
        submit_button();
        ?>
    </form>

    <hr />

    <h2><?php esc_html_e( 'Honest-state disclosure', 'privacy-checker' ); ?></h2>
    <p>
        <?php esc_html_e(
            'The DNS leak test is the one feature that cannot be implemented reliably from a web page alone. It requires dedicated DNS infrastructure. Until such infrastructure is configured, the plugin will display "Not configured on this server." for that card. We never fabricate DNS results.',
            'privacy-checker'
        ); ?>
    </p>

    <h2><?php esc_html_e( 'Privacy defaults', 'privacy-checker' ); ?></h2>
    <ul>
        <li><?php esc_html_e( 'No IP addresses are stored unless you explicitly enable logging with a retention period.', 'privacy-checker' ); ?></li>
        <li><?php esc_html_e( 'Rate limiting uses SHA-256 hashes of (salt + IP + bucket + minute). The raw IP is never persisted.', 'privacy-checker' ); ?></li>
        <li><?php esc_html_e( 'Fingerprint signals are computed only for the current diagnostic session.', 'privacy-checker' ); ?></li>
        <li><?php esc_html_e( 'No third-party trackers are loaded by this plugin.', 'privacy-checker' ); ?></li>
    </ul>
</div>