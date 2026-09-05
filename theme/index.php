<?php
/**
 * Index template (fallback).
 *
 * @package PrivacyCheckerTheme
 */

get_header();
?>

<section class="pc-page">
    <div class="pc-container">
        <?php if ( have_posts() ) : ?>
            <h1 class="pc-page__title"><?php single_post_title(); ?></h1>
            <div class="pc-post-list">
                <?php
                while ( have_posts() ) :
                    the_post();
                    ?>
                    <article id="post-<?php the_ID(); ?>" <?php post_class(); ?>>
                        <h2><a href="<?php the_permalink(); ?>"><?php the_title(); ?></a></h2>
                        <div><?php the_excerpt(); ?></div>
                    </article>
                    <?php
                endwhile;
                ?>
            </div>

            <?php the_posts_pagination(); ?>
        <?php else : ?>
            <h1 class="pc-page__title"><?php esc_html_e( 'Nothing found', 'privacy-checker-theme' ); ?></h1>
            <p><?php esc_html_e( 'Sorry, no posts matched your criteria.', 'privacy-checker-theme' ); ?></p>
        <?php endif; ?>
    </div>
</section>

<?php
get_footer();