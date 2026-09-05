<?php
/**
 * Search form.
 *
 * @package PrivacyCheckerTheme
 */
?>
<form role="search" method="get" class="pc-search-form" action="<?php echo esc_url( home_url( '/' ) ); ?>">
    <label for="pc-search-input" class="pc-sr-only">
        <?php esc_html_e( 'Search', 'privacy-checker-theme' ); ?>
    </label>
    <input
        type="search"
        id="pc-search-input"
        class="pc-search-form__input"
        placeholder="<?php esc_attr_e( 'Search…', 'privacy-checker-theme' ); ?>"
        value="<?php echo esc_attr( get_search_query() ); ?>"
        name="s"
    />
    <button type="submit" class="pc-btn pc-btn--primary">
        <?php esc_html_e( 'Search', 'privacy-checker-theme' ); ?>
    </button>
</form>