<?php
/**
 * Single post template.
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
                    <?php if ( get_post_type() === 'post' ) : ?>
                        <p class="pc-page__meta">
                            <time datetime="<?php echo esc_attr( get_the_date( 'c' ) ); ?>">
                                <?php echo esc_html( get_the_date() ); ?>
                            </time>
                        </p>
                    <?php endif; ?>
                </header>
                <div class="pc-page__content">
                    <?php the_content(); ?>
                </div>
            </article>
            <?php
        endwhile;
        ?>
    </div>
</section>

<?php
get_footer();