<?php
/**
 * Admin subpage: Event Log + backup/restore.
 *
 * Phase 28: lets operators
 *   • View a filterable table of every event recorded to the
 *     `pc_event_log` table.
 *   • Export the visible rows (or a full backup snapshot that includes
 *     `pc_settings`) as JSON / CSV.
 *   • Restore from a backup JSON (dry-run or apply).
 *   • Clear the event log (existing handler, exposed here too).
 *
 * @package PrivacyChecker\Admin
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\EventLog;
use PrivacyChecker\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminLogs {

	public const SLUG = 'privacy-checker-logs';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
		add_action( 'admin_post_pc_logs_export', array( $this, 'handle_export' ) );
		add_action( 'admin_post_pc_logs_restore', array( $this, 'handle_restore' ) );
		add_action( 'admin_post_pc_logs_clear', array( $this, 'handle_clear' ) );
	}

	public function register_menu(): void {
		add_submenu_page(
			AdminDashboard::DASHBOARD_SLUG,
			__( 'Logs & Backup', 'privacy-checker' ),
			__( 'Logs & Backup', 'privacy-checker' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render_page' )
		);
	}

	public function enqueue( string $hook ): void {
		if ( false === strpos( $hook, self::SLUG ) ) {
			return;
		}
		wp_enqueue_style(
			'pc-admin-logs',
			PRIVACY_CHECKER_URL . 'admin/assets/admin-logs.css',
			array(),
			PRIVACY_CHECKER_VERSION
		);
	}

	/* ---------- Handlers ---------- */

	/**
	 * Export handler — supports three modes selected by `$_POST['mode']`:
	 *
	 *   - `logs`       → JSON or CSV of the currently filtered event rows.
	 *   - `backup`     → JSON snapshot of {settings, logs} — the restore
	 *                    point that captures everything an admin would
	 *                    need to recreate this install elsewhere.
	 *   - `csv`        → Force CSV instead of JSON (only valid for `logs`).
	 *
	 * Authentication: `manage_options` + WP nonce `pc_logs_export`.
	 */
	public function handle_export(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_logs_export' );

		$mode = sanitize_key( $_POST['mode'] ?? 'logs' );
		$fmt  = sanitize_key( $_POST['format'] ?? 'json' );
		$filters = self::read_filters_from_post();

		$rows = EventLog::enabled()
			? EventLog::recent( 5000, $filters )
			: array();

		if ( 'backup' === $mode ) {
			$payload = array(
				'type'           => 'privacy-checker-backup',
				'version'        => PRIVACY_CHECKER_VERSION,
				'exported_at'    => gmdate( 'c' ),
				'settings'       => get_option( 'pc_settings', array() ),
				'logs'           => $rows,
				'log_row_count'  => count( $rows ),
			);
			$filename = sprintf( 'privacy-checker-backup-%s.json', gmdate( 'Ymd-His' ) );
			self::stream_json_download( $payload, $filename );
			return;
		}

		// Default: logs-only export.
		if ( 'csv' === $fmt ) {
			$filename = sprintf( 'privacy-checker-logs-%s.csv', gmdate( 'Ymd-His' ) );
			self::stream_csv_download( $rows, $filename );
			return;
		}
		$payload = array(
			'type'        => 'privacy-checker-logs',
			'version'     => PRIVACY_CHECKER_VERSION,
			'exported_at' => gmdate( 'c' ),
			'filters'     => $filters,
			'rows'        => $rows,
		);
		$filename = sprintf( 'privacy-checker-logs-%s.json', gmdate( 'Ymd-His' ) );
		self::stream_json_download( $payload, $filename );
	}

	/**
	 * Restore handler — accepts a JSON upload. Two modes:
	 *
	 *   - `dry`  → echo a diff (counts of new/existing logs, settings
	 *              key deltas) and exit without writing anything.
	 *   - `apply` → merge logs (INSERT IGNORE on the
	 *              `created_at|level|source|message` triple) and
	 *              replace `pc_settings`.
	 *
	 * Authentication: `manage_options` + WP nonce `pc_logs_restore`.
	 */
	public function handle_restore(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_logs_restore' );

		$mode = sanitize_key( $_POST['mode'] ?? 'dry' );
		$file = $_FILES['backup'] ?? null;
		if ( ! is_array( $file ) || ! empty( $file['error'] ) ) {
			$this->redirect_err( 'restore_no_file' );
		}
		$contents = file_get_contents( (string) $file['tmp_name'] );
		if ( false === $contents || '' === $contents ) {
			$this->redirect_err( 'restore_empty' );
		}
		$payload = json_decode( $contents, true );
		if ( ! is_array( $payload ) ) {
			$this->redirect_err( 'restore_bad_json' );
		}
		$type = $payload['type'] ?? '';
		if ( 'privacy-checker-backup' !== $type ) {
			$this->redirect_err( 'restore_wrong_type' );
		}
		$logs     = is_array( $payload['logs'] ?? null ) ? $payload['logs'] : array();
		$settings = is_array( $payload['settings'] ?? null ) ? $payload['settings'] : null;

		$diff = self::compute_restore_diff( $logs, $settings );

		if ( 'dry' === $mode ) {
			$redirect = add_query_arg(
				array(
					'page'   => self::SLUG,
					'pc_msg' => 'restore_dry',
					'diff'   => rawurlencode( wp_json_encode( $diff ) ),
				),
				admin_url( 'admin.php' )
			);
			wp_safe_redirect( $redirect );
			exit;
		}

		// apply
		$settings_written = false;
		if ( null !== $settings ) {
			update_option( 'pc_settings', $settings );
			$settings_written = true;
		}
		$logs_written = EventLog::enabled() ? self::restore_logs( $logs ) : 0;
		EventLog::record_if_enabled(
			'restore',
			'info',
			'logs-restore',
			sprintf( 'restored: settings=%s, logs=%d', $settings_written ? 'yes' : 'no', $logs_written ),
			array(
				'settings_written'  => $settings_written,
				'logs_written'      => $logs_written,
				'rows_provided'     => count( $logs ),
			)
		);
		wp_safe_redirect( add_query_arg(
			array(
				'page'         => self::SLUG,
				'pc_msg'       => 'restore_applied',
				'logs_written' => $logs_written,
			),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	public function handle_clear(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_logs_clear' );
		EventLog::clear();
		EventLog::record_if_enabled( 'admin', 'info', 'log-clear', 'event log cleared via Logs page', array() );
		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'pc_msg' => 'log_cleared' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ---------- Helpers ---------- */

	/**
	 * @return array{event?:string,level?:string,days?:int,search?:string}
	 */
	public static function read_filters_from_post(): array {
		$filters = array();
		if ( ! empty( $_POST['filter_event'] ) ) {
			$filters['event'] = sanitize_key( wp_unslash( (string) $_POST['filter_event'] ) );
		}
		if ( ! empty( $_POST['filter_level'] ) ) {
			$filters['level'] = sanitize_key( wp_unslash( (string) $_POST['filter_level'] ) );
		}
		if ( ! empty( $_POST['filter_days'] ) ) {
			$filters['days'] = max( 1, min( 365, (int) $_POST['filter_days'] ) );
		}
		if ( ! empty( $_POST['filter_search'] ) ) {
			$filters['search'] = sanitize_text_field( wp_unslash( (string) $_POST['filter_search'] ) );
		}
		return $filters;
	}

	private static function stream_json_download( array $payload, string $filename ): void {
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		// Pretty-print for human readability when the file is opened in a
		// text editor; gzcompress if gzencode is available (it almost
		// always is, but the `function_exists` guard keeps PHP 7.0 hosts
		// happy).
		$body = wp_json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		if ( function_exists( 'gzencode' ) ) {
			header( 'Content-Encoding: gzip' );
			$body = gzencode( (string) $body );
		}
		echo $body; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped — JSON body.
		exit;
	}

	/**
	 * @param array<int,array<string,mixed>> $rows
	 */
	private static function stream_csv_download( array $rows, string $filename ): void {
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
		$out = fopen( 'php://output', 'w' );
		if ( false === $out ) {
			exit;
		}
		fputcsv( $out, array( 'id', 'created_at', 'level', 'source', 'event', 'context', 'message' ) );
		foreach ( $rows as $r ) {
			fputcsv( $out, array(
				$r['id']         ?? '',
				$r['created_at'] ?? '',
				$r['level']      ?? '',
				$r['source']     ?? '',
				$r['event']      ?? '',
				is_string( $r['context'] ?? null ) ? $r['context'] : '',
				$r['message']    ?? '',
			) );
		}
		fclose( $out );
		exit;
	}

	/**
	 * @param array<int,array<string,mixed>> $incoming_logs
	 * @param array<string,mixed>|null       $incoming_settings
	 * @return array{logs_total:int,logs_new:int,logs_existing:int,settings_keys_changed:int,settings_added:int,settings_removed:int}
	 */
	private static function compute_restore_diff( array $incoming_logs, ?array $incoming_settings ): array {
		global $wpdb;
		$table = EventLog::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		$existing_keys = array();
		if ( $exists === $table ) {
			// Hash each existing row on (created_at, level, source, message)
			// to dedupe. The set is bounded by retention so it's small.
			$rows = $wpdb->get_results( "SELECT created_at, level, source, message FROM {$table}", ARRAY_A );
			if ( is_array( $rows ) ) {
				foreach ( $rows as $r ) {
					$existing_keys[] = md5( (string) $r['created_at'] . '|' . (string) $r['level'] . '|' . (string) $r['source'] . '|' . (string) $r['message'] );
				}
			}
		}
		$existing_set = array_flip( $existing_keys );
		$new = 0;
		foreach ( $incoming_logs as $r ) {
			$h = md5( (string) ( $r['created_at'] ?? '' ) . '|' . (string) ( $r['level'] ?? '' ) . '|' . (string) ( $r['source'] ?? '' ) . '|' . (string) ( $r['message'] ?? '' ) );
			if ( ! isset( $existing_set[ $h ] ) ) {
				$new++;
			}
		}

		$settings_diff = array(
			'keys_changed' => 0,
			'added'        => 0,
			'removed'      => 0,
		);
		if ( is_array( $incoming_settings ) ) {
			$current = (array) get_option( 'pc_settings', array() );
			$all_keys = array_unique( array_merge( array_keys( $current ), array_keys( $incoming_settings ) ) );
			foreach ( $all_keys as $k ) {
				$in = $incoming_settings[ $k ] ?? null;
				$cu = $current[ $k ] ?? null;
				if ( null === $cu && null !== $in ) {
					$settings_diff['added']++;
				} elseif ( null !== $cu && null === $in ) {
					$settings_diff['removed']++;
				} elseif ( $in !== $cu ) {
					$settings_diff['keys_changed']++;
				}
			}
		}

		return array(
			'logs_total'           => count( $incoming_logs ),
			'logs_new'             => $new,
			'logs_existing'        => count( $incoming_logs ) - $new,
			'settings_keys_changed'=> $settings_diff['keys_changed'],
			'settings_added'       => $settings_diff['added'],
			'settings_removed'     => $settings_diff['removed'],
		);
	}

	/**
	 * @param array<int,array<string,mixed>> $rows
	 * @return int Count of rows actually inserted.
	 */
	private static function restore_logs( array $rows ): int {
		global $wpdb;
		$table = EventLog::table();
		EventLog::ensure_table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return 0;
		}
		$inserted = 0;
		foreach ( $rows as $r ) {
			$created = (string) ( $r['created_at'] ?? gmdate( 'Y-m-d H:i:s' ) );
			$level   = sanitize_key( (string) ( $r['level'] ?? 'info' ) );
			$source  = sanitize_key( (string) ( $r['source'] ?? '' ) );
			$event   = sanitize_key( (string) ( $r['event'] ?? 'misc' ) );
			$ctx     = isset( $r['context'] ) && is_array( $r['context'] )
				? wp_json_encode( $r['context'] )
				: ( is_string( $r['context'] ?? null ) ? $r['context'] : null );
			$message = wp_kses_post( (string) ( $r['message'] ?? '' ) );

			$ok = $wpdb->query( $wpdb->prepare(
				"INSERT IGNORE INTO {$table}
				 (created_at, level, source, event, context, message)
				 SELECT %s, %s, %s, %s, %s, %s FROM DUAL
				 WHERE NOT EXISTS (
				   SELECT 1 FROM {$table}
				   WHERE created_at = %s AND level = %s AND source = %s AND message = %s
				 )",
				$created, $level, $source, $event, $ctx, $message,
				$created, $level, $source, $message
			) );
			// `INSERT IGNORE` returns 0 when the row was a duplicate OR
			// when the SELECT-NOT-EXISTS guard suppressed it. Either way
			// we used a slot — count by checking affected_rows.
			if ( false !== $ok && $wpdb->insert_id ) {
				$inserted++;
			} elseif ( $ok > 0 ) {
				// PHP returns rowCount() from PDO; for wpdb::query() it's
				// the number of rows affected.
				$inserted += (int) $ok;
			}
		}
		return $inserted;
	}

	private function redirect_err( string $code ): void {
		wp_safe_redirect( add_query_arg(
			array( 'page' => self::SLUG, 'pc_msg' => $code ),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	/* ---------- Render ---------- */

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
		}
		require_once PRIVACY_CHECKER_DIR . 'admin/views/logs.php';
	}
}
