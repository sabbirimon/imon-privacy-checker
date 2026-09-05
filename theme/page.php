<?php
/**
 * Default page template.
 *
 * @package PrivacyCheckerTheme
 */

get_header();
?>

<section class="pc-page">
    <div class="pc-container">
        <?php
        while ( have_posts() ) :
            the_post();
            ?>
            <article id="post-<?php the_ID(); ?>" <?php post_class(); ?>>
                <header class="pc-page__header">
                    <h1 class="pc-page__title"><?php the_title(); ?></h1>
                </header>
                <div class="pc-page__content">
                    <?php
                    the_content();

                    wp_link_pages( array(
                        'before' => '<nav class="pc-page__pagination" aria-label="' . esc_attr__( 'Page', 'privacy-checker-theme' ) . '">',
                        'after'  => '</nav>',
                    ) );
                    ?>
                </div>
            </article>
            <?php
        endwhile;
        ?>
    </div>
</section>

<?php
get_footer();