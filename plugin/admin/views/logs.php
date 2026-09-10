<?php
/**
 * Phase 28: Logs & Backup admin view.
 *
 * Renders the filter bar, KPI tiles, table of recent events, export
 * buttons, and the restore form. Reads filters from $_GET so the URL
 * itself is shareable / bookmarkable.
 *
 * @package PrivacyChecker\Admin\Views
 */

declare( strict_types=1 );

use PrivacyChecker\EventLog;
use PrivacyChecker\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$enabled = EventLog::enabled();

/* ---------- Read filters from $_GET ---------- */
$filter_event = isset( $_GET['filter_event'] ) ? sanitize_key( wp_unslash( (string) $_GET['filter_event'] ) ) : '';
$filter_level = isset( $_GET['filter_level'] ) ? sanitize_key( wp_unslash( (string) $_GET['filter_level'] ) ) : '';
$filter_days  = isset( $_GET['filter_days'] )  ? max( 1, min( 365, (int) $_GET['filter_days'] ) ) : 30;
$filter_search = isset( $_GET['filter_search'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['filter_search'] ) ) : '';

$filters = array();
if ( '' !== $filter_event )  { $filters['event']  = $filter_event; }
if ( '' !== $filter_level )  { $filters['level']  = $filter_level; }
if ( $filter_days > 0 )       { $filters['days']   = $filter_days; }
if ( '' !== $filter_search )  { $filters['search'] = $filter_search; }

$counts_by_event = EventLog::counts_by_event( max( 1, $filter_days ) );
$total_logs      = array_sum( $counts_by_event );
$rows            = $enabled ? EventLog::recent( 200, $filters ) : array();
$daily_counts    = $enabled ? EventLog::counts_by_day( max( 1, min( 90, $filter_days ) ) ) : array();

/* ---------- Notices (after non-GET actions) ---------- */
$pc_msg       = isset( $_GET['pc_msg'] ) ? sanitize_key( wp_unslash( (string) $_GET['pc_msg'] ) ) : '';
$logs_written = isset( $_GET['logs_written'] ) ? (int) $_GET['logs_written'] : 0;
$restore_diff = array();
if ( 'restore_dry' === $pc_msg && ! empty( $_GET['diff'] ) ) {
	$restored_diff_json = sanitize_text_field( rawurldecode( (string) $_GET['diff'] ) );
	$decoded = json_decode( $restored_diff_json, true );
	if ( is_array( $decoded ) ) {
		$restore_diff = $decoded;
	}
}
?>
<div class="wrap pc-logs">
	<h1><?php esc_html_e( 'Logs & Backup', 'privacy-checker' ); ?></h1>

	<?php if ( ! $enabled ) : ?>
		<div class="notice notice-warning inline">
			<p>
				<strong><?php esc_html_e( 'Event log is disabled.', 'privacy-checker' ); ?></strong>
				<?php esc_html_e( 'Enable it under Settings → Privacy & Logging to start recording events.', 'privacy-checker' ); ?>
			</p>
		</div>
	<?php endif; ?>

	<?php if ( 'restore_dry' === $pc_msg ) : ?>
		<div class="notice notice-info inline">
			<p><strong><?php esc_html_e( 'Restore preview', 'privacy-checker' ); ?></strong> —
				<?php
				printf(
					/* translators: 1: new logs, 2: existing logs */
					esc_html__( '%1$d new logs would be added, %2$d already present.', 'privacy-checker' ),
					(int) ( $restore_diff['logs_new'] ?? 0 ),
					(int) ( $restore_diff['logs_existing'] ?? 0 )
				);
				?>
			</p>
			<p>
				<?php
				printf(
					/* translators: 1: changed, 2: added, 3: removed */
					esc_html__( 'Settings: %1$d changed, %2$d added, %3$d removed.', 'privacy-checker' ),
					(int) ( $restore_diff['settings_keys_changed'] ?? 0 ),
					(int) ( $restore_diff['settings_added'] ?? 0 ),
					(int) ( $restore_diff['settings_removed'] ?? 0 )
				);
				?>
			</p>
			<p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data" style="display:inline">
					<input type="hidden" name="action" value="pc_logs_restore" />
					<input type="hidden" name="mode" value="apply" />
					<?php wp_nonce_field( 'pc_logs_restore' ); ?>
					<button type="submit" class="button button-primary" <?php disabled( ( $restore_diff['logs_new'] ?? 0 ) <= 0 && ( $restore_diff['settings_keys_changed'] ?? 0 ) <= 0 ); ?>>
						<?php esc_html_e( 'Apply restore', 'privacy-checker' ); ?>
					</button>
				</form>
				<span class="description"><?php esc_html_e( 'Confirm to merge the backup into this install. Existing rows are preserved (INSERT IGNORE).', 'privacy-checker' ); ?></span>
			</p>
		</div>
	<?php elseif ( 'restore_applied' === $pc_msg ) : ?>
		<div class="notice notice-success inline">
			<p>
				<?php
				printf(
					/* translators: %d: rows inserted */
					esc_html__( 'Restore applied: %d new log rows inserted.', 'privacy-checker' ),
					$logs_written
				);
				?>
			</p>
		</div>
	<?php elseif ( 'log_cleared' === $pc_msg ) : ?>
		<div class="notice notice-success inline"><p><?php esc_html_e( 'Event log cleared.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'restore_no_file' === $pc_msg ) : ?>
		<div class="notice notice-error inline"><p><?php esc_html_e( 'No file uploaded.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'restore_empty' === $pc_msg || 'restore_bad_json' === $pc_msg ) : ?>
		<div class="notice notice-error inline"><p><?php esc_html_e( 'Backup file is empty or unreadable.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'restore_wrong_type' === $pc_msg ) : ?>
		<div class="notice notice-error inline"><p><?php esc_html_e( 'Backup file is not a Privacy Checker backup.', 'privacy-checker' ); ?></p></div>
	<?php endif; ?>

	<!-- KPI tiles -->
	<section class="pc-logs__kpis">
		<?php
		$kpi_labels = array(
			'scan'    => __( 'Scans', 'privacy-checker' ),
			'share'   => __( 'Shares', 'privacy-checker' ),
			'export'  => __( 'Exports', 'privacy-checker' ),
			'restore' => __( 'Restores', 'privacy-checker' ),
			'admin'   => __( 'Admin actions', 'privacy-checker' ),
			'error'   => __( 'Errors', 'privacy-checker' ),
		);
		foreach ( EventLog::CATEGORIES as $cat ) :
			$count = (int) ( $counts_by_event[ $cat ] ?? 0 );
			?>
			<div class="pc-logs__kpi" data-pcv2-tone="<?php echo 'error' === $cat ? 'danger' : 'neutral'; ?>">
				<span class="pc-logs__kpi-label"><?php echo esc_html( $kpi_labels[ $cat ] ?? ucfirst( $cat ) ); ?></span>
				<span class="pc-logs__kpi-value mono"><?php echo esc_html( number_format_i18n( $count ) ); ?></span>
				<span class="pc-logs__kpi-sub"><?php
					/* translators: %d: days */
					printf( esc_html__( 'last %d days', 'privacy-checker' ), (int) $filter_days );
				?></span>
			</div>
		<?php endforeach; ?>
	</section>

	<!-- Filter bar -->
	<form method="get" class="pc-logs__filters">
		<input type="hidden" name="page" value="<?php echo esc_attr( AdminLogs::SLUG ); ?>" />
		<label>
			<?php esc_html_e( 'Category', 'privacy-checker' ); ?>
			<select name="filter_event">
				<option value=""><?php esc_html_e( 'All', 'privacy-checker' ); ?></option>
				<?php foreach ( EventLog::CATEGORIES as $cat ) : ?>
					<option value="<?php echo esc_attr( $cat ); ?>" <?php selected( $filter_event, $cat ); ?>>
						<?php echo esc_html( $kpi_labels[ $cat ] ?? ucfirst( $cat ) ); ?>
					</option>
				<?php endforeach; ?>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Level', 'privacy-checker' ); ?>
			<select name="filter_level">
				<option value=""><?php esc_html_e( 'All', 'privacy-checker' ); ?></option>
				<option value="info"    <?php selected( $filter_level, 'info' ); ?>><?php esc_html_e( 'Info', 'privacy-checker' ); ?></option>
				<option value="warning" <?php selected( $filter_level, 'warning' ); ?>><?php esc_html_e( 'Warning', 'privacy-checker' ); ?></option>
				<option value="error"   <?php selected( $filter_level, 'error' ); ?>><?php esc_html_e( 'Error', 'privacy-checker' ); ?></option>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Window', 'privacy-checker' ); ?>
			<select name="filter_days">
				<?php foreach ( array( 1, 7, 30, 90, 365 ) as $d ) : ?>
					<option value="<?php echo esc_attr( (string) $d ); ?>" <?php selected( $filter_days, $d ); ?>>
						<?php
						/* translators: %d: days */
						printf( esc_html__( '%d days', 'privacy-checker' ), $d );
						?>
					</option>
				<?php endforeach; ?>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Search', 'privacy-checker' ); ?>
			<input type="search" name="filter_search" value="<?php echo esc_attr( $filter_search ); ?>" placeholder="<?php esc_attr_e( 'message contains…', 'privacy-checker' ); ?>" />
		</label>
		<button type="submit" class="button button-primary"><?php esc_html_e( 'Apply', 'privacy-checker' ); ?></button>
		<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=' . AdminLogs::SLUG ) ); ?>"><?php esc_html_e( 'Reset', 'privacy-checker' ); ?></a>
	</form>

	<!-- Action bar -->
	<section class="pc-logs__actions">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
			<input type="hidden" name="action" value="pc_logs_export" />
			<input type="hidden" name="mode" value="logs" />
			<input type="hidden" name="format" value="json" />
			<?php
			foreach ( $filters as $k => $v ) {
				printf( '<input type="hidden" name="%s" value="%s" />', esc_attr( 'filter_' . $k ), esc_attr( (string) $v ) );
			}
			wp_nonce_field( 'pc_logs_export' );
			?>
			<button type="submit" class="button"><?php esc_html_e( 'Export JSON', 'privacy-checker' ); ?></button>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
			<input type="hidden" name="action" value="pc_logs_export" />
			<input type="hidden" name="mode" value="logs" />
			<input type="hidden" name="format" value="csv" />
			<?php
			foreach ( $filters as $k => $v ) {
				printf( '<input type="hidden" name="%s" value="%s" />', esc_attr( 'filter_' . $k ), esc_attr( (string) $v ) );
			}
			wp_nonce_field( 'pc_logs_export' );
			?>
			<button type="submit" class="button"><?php esc_html_e( 'Export CSV', 'privacy-checker' ); ?></button>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
			<input type="hidden" name="action" value="pc_logs_export" />
			<input type="hidden" name="mode" value="backup" />
			<?php wp_nonce_field( 'pc_logs_export' ); ?>
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Backup everything', 'privacy-checker' ); ?></button>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('<?php echo esc_attr__( 'Clear all events from the log?', 'privacy-checker' ); ?>');">
			<input type="hidden" name="action" value="pc_logs_clear" />
			<?php wp_nonce_field( 'pc_logs_clear' ); ?>
			<button type="submit" class="button"><?php esc_html_e( 'Clear log', 'privacy-checker' ); ?></button>
		</form>
	</section>

	<!-- Restore form -->
	<section class="pc-logs__restore">
		<h2><?php esc_html_e( 'Restore from backup', 'privacy-checker' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Upload a backup file produced by "Backup everything". Dry-run shows the diff without writing anything; apply merges logs (INSERT IGNORE) and replaces settings.', 'privacy-checker' ); ?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
			<input type="hidden" name="action" value="pc_logs_restore" />
			<input type="hidden" name="mode" value="dry" />
			<?php wp_nonce_field( 'pc_logs_restore' ); ?>
			<input type="file" name="backup" accept="application/json,.json" required />
			<button type="submit" class="button"><?php esc_html_e( 'Preview diff', 'privacy-checker' ); ?></button>
		</form>
	</section>

	<!-- Table -->
	<section class="pc-logs__table-wrap">
		<h2>
			<?php
			printf(
				/* translators: 1: row count, 2: days */
				esc_html__( 'Recent events (%1$d shown · last %2$d days)', 'privacy-checker' ),
				count( $rows ),
				(int) $filter_days
			);
			?>
		</h2>
		<table class="widefat striped pc-logs__table">
			<thead>
				<tr>
					<th class="pc-col-time"><?php esc_html_e( 'Time (UTC)', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Category', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Level', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Source', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Message', 'privacy-checker' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $rows ) ) : ?>
					<tr><td colspan="5" style="text-align:center; padding:24px; color:#666">
						<?php esc_html_e( 'No events match the current filters.', 'privacy-checker' ); ?>
					</td></tr>
				<?php else : ?>
					<?php foreach ( $rows as $r ) :
						$ctx = is_string( $r['context'] ?? null ) ? $r['context'] : '';
						?>
						<tr>
							<td class="pc-col-time mono"><?php echo esc_html( (string) ( $r['created_at'] ?? '' ) ); ?></td>
							<td><span class="pc-cat-badge pc-cat-<?php echo esc_attr( (string) ( $r['event'] ?? 'misc' ) ); ?>"><?php echo esc_html( (string) ( $r['event'] ?? 'misc' ) ); ?></span></td>
							<td><span class="pc-level pc-level-<?php echo esc_attr( (string) ( $r['level'] ?? 'info' ) ); ?>"><?php echo esc_html( (string) ( $r['level'] ?? 'info' ) ); ?></span></td>
							<td class="mono"><?php echo esc_html( (string) ( $r['source'] ?? '' ) ); ?></td>
							<td>
								<span title="<?php echo esc_attr( $ctx ); ?>"><?php echo esc_html( (string) ( $r['message'] ?? '' ) ); ?></span>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>
	</section>
</div>
