<?php
/**
 * Privacy Report Inspector — admin view.
 *
 * Renders the full PrivacyReport breakdown plus a weighted-avg
 * arithmetic transparency panel so the admin can sanity-check the
 * "how the overall was computed" math at a glance.
 *
 * Data sourced from $report (built by PrivacyReport::build() in
 * AdminPrivacyReport::render()). All locals are typed-by-convention.
 *
 * @package PrivacyChecker\Admin
 *
 * @var array<string,mixed> $scan
 * @var array<string,mixed> $report
 */

use PrivacyChecker\Admin\AdminDashboard;
use PrivacyChecker\PrivacyReport;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$overall    = (int)    ( $report['overall']    ?? 0 );
$grade      = (string) ( $report['grade']      ?? 'F' );
$confidence = (string) ( $report['confidence'] ?? 'low' );
$headline   = (string) ( $report['headline']   ?? '' );
$categories = (array)  ( $report['categories'] ?? array() );
$generated  = (string) ( $report['generated_at'] ?? gmdate( 'c' ) );

// Compute the transparency panel arithmetic from the actual category
// weights so the displayed formula matches what PrivacyReport::build()
// actually used to compute $overall.
$weights     = PrivacyReport::category_weights();
$weighted_sum = 0;
$total_weight = 0;
$rows         = array();
foreach ( $categories as $key => $row ) {
	$w = (int) ( $weights[ $key ] ?? (int) ( $row['weight'] ?? 1 ) );
	$p = (int) ( $row['percent'] ?? 0 );
	$rows[] = array(
		'key'     => $key,
		'percent' => $p,
		'weight'  => $w,
		'product' => $p * $w,
	);
	if ( $w > 0 ) {
		$total_weight += $w;
		$weighted_sum += $p * $w;
	}
}
$computed_overall = $total_weight > 0
	? (int) round( $weighted_sum / $total_weight )
	: 0;
?>
<div class="wrap pc-privacy-report-inspector">
	<h1><?php esc_html_e( 'Privacy Report Inspector', 'privacy-checker' ); ?></h1>

	<div class="pc-inspector-banner notice notice-info inline">
		<p>
			<?php esc_html_e( 'Server-side self-scan. Browser-side signals (fingerprint, WebRTC, connection quality, local network) are not collected on this page — only server-side categories have real values. Others will show as "unknown".', 'privacy-checker' ); ?>
		</p>
	</div>

	<div class="pc-inspector-summary">
		<div class="pc-inspector-score">
			<div class="pc-inspector-score__value"><?php echo (int) $overall; ?></div>
			<div class="pc-inspector-score__label"><?php esc_html_e( 'Overall', 'privacy-checker' ); ?></div>
		</div>
		<div class="pc-inspector-grade pc-inspector-grade--<?php echo esc_attr( strtolower( $grade ) ); ?>">
			<?php echo esc_html( $grade ); ?>
			<span class="pc-inspector-confidence"><?php
				printf(
					/* translators: %s: confidence level */
					esc_html__( 'confidence: %s', 'privacy-checker' ),
					esc_html( $confidence )
				);
			?></span>
		</div>
		<div class="pc-inspector-headline">
			<p><strong><?php esc_html_e( 'Headline', 'privacy-checker' ); ?>:</strong> <?php echo esc_html( $headline ); ?></p>
			<p class="description"><?php
				printf(
					/* translators: %s: ISO-8601 timestamp */
					esc_html__( 'Generated at %s', 'privacy-checker' ),
					esc_html( $generated )
				);
			?></p>
		</div>
	</div>

	<h2><?php esc_html_e( 'Categories', 'privacy-checker' ); ?></h2>
	<table class="widefat striped pc-inspector-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Category', 'privacy-checker' ); ?></th>
				<th scope="col" class="num"><?php esc_html_e( 'Percent', 'privacy-checker' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'privacy-checker' ); ?></th>
				<th scope="col" class="num"><?php esc_html_e( 'Weight', 'privacy-checker' ); ?></th>
				<th scope="col" class="num"><?php esc_html_e( 'Weighted', 'privacy-checker' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Message', 'privacy-checker' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $rows as $r ) : ?>
				<?php
				$status = (string) ( $categories[ $r['key'] ]['status'] ?? 'warning' );
				$source = (string) ( $categories[ $r['key'] ]['status_source'] ?? 'measured' );
				$msg    = (string) ( $categories[ $r['key'] ]['message'] ?? '' );
				$surface = $r['weight'] <= 0;
				?>
				<tr class="pc-inspector-row pc-inspector-row--<?php echo esc_attr( $status ); ?><?php echo $surface ? ' pc-inspector-row--surface' : ''; ?>">
					<th scope="row">
						<code><?php echo esc_html( $r['key'] ); ?></code>
						<?php if ( $surface ) : ?>
							<span class="pc-inspector-tag"><?php esc_html_e( 'surface-only', 'privacy-checker' ); ?></span>
						<?php endif; ?>
					</th>
					<td class="num"><?php echo (int) $r['percent']; ?></td>
					<td>
						<span class="pc-status pc-status--<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $status ); ?></span>
						<?php if ( 'unknown' === $source ) : ?>
							<span class="pc-inspector-source">(<?php esc_html_e( 'unknown source', 'privacy-checker' ); ?>)</span>
						<?php endif; ?>
					</td>
					<td class="num"><?php echo (int) $r['weight']; ?></td>
					<td class="num"><?php echo (int) $r['product']; ?></td>
					<td><?php echo esc_html( $msg ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
		<tfoot>
			<tr>
				<th scope="row"><?php esc_html_e( 'Weighted total', 'privacy-checker' ); ?></th>
				<td class="num"><?php echo (int) $computed_overall; ?>%</td>
				<td colspan="2"></td>
				<td class="num"><?php echo (int) $weighted_sum; ?> / <?php echo (int) $total_weight; ?></td>
				<td><?php esc_html_e( 'matches overall above', 'privacy-checker' ); ?></td>
			</tr>
		</tfoot>
	</table>

	<h2><?php esc_html_e( 'Weighted-avg arithmetic (transparency)', 'privacy-checker' ); ?></h2>
	<p>
		<?php esc_html_e( 'The overall score is a weighted average across the categories above. Surface-only categories (weight 0) are excluded from the calculation:', 'privacy-checker' ); ?>
	</p>
	<pre class="pc-inspector-formula"><code>overall = round( sum(percent * weight) / sum(weight) )
        = round( <?php echo (int) $weighted_sum; ?> / <?php echo (int) $total_weight; ?> )
        = <?php echo (int) $computed_overall; ?></code></pre>

	<p>
		<?php esc_html_e( 'Categories with weight 0 (connection quality, local network) appear in the table above but do not contribute to the weighted average. They are surfaced for visibility only, not for scoring.', 'privacy-checker' ); ?>
	</p>

	<h2><?php esc_html_e( 'Recommendations', 'privacy-checker' ); ?></h2>
	<?php if ( ! empty( $report['recommendations'] ) ) : ?>
		<ul class="pc-inspector-recs">
			<?php foreach ( (array) $report['recommendations'] as $rec ) : ?>
				<?php
				$priority = (string) ( $rec['priority'] ?? 'low' );
				$message  = (string) ( $rec['message']  ?? '' );
				?>
				<li class="pc-inspector-rec pc-inspector-rec--<?php echo esc_attr( $priority ); ?>">
					<span class="pc-inspector-rec__priority"><?php echo esc_html( strtoupper( $priority ) ); ?></span>
					<span class="pc-inspector-rec__msg"><?php echo esc_html( $message ); ?></span>
				</li>
			<?php endforeach; ?>
		</ul>
	<?php else : ?>
		<p><?php esc_html_e( 'No recommendations generated.', 'privacy-checker' ); ?></p>
	<?php endif; ?>

	<p class="pc-inspector-footer">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . AdminDashboard::SETTINGS_SLUG ) ); ?>" class="button">
			<?php esc_html_e( 'Open Settings', 'privacy-checker' ); ?>
		</a>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . AdminDashboard::DASHBOARD_SLUG ) ); ?>" class="button">
			<?php esc_html_e( 'Back to Dashboard', 'privacy-checker' ); ?>
		</a>
	</p>
</div>
