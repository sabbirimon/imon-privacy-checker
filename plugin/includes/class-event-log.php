<?php
/**
 * Event log — small, opt-in append-only table for admin diagnostics.
 *
 * Created lazily via dbDelta when an admin enables the setting. The default
 * install never creates the table. Retention is enforced daily by the
 * existing privacy/retention cron.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class EventLog {

	/**
	 * Whether the admin wants us to record events at all.
	 */
	public static function enabled(): bool {
		return (bool) Plugin::instance()->setting( 'event_log_enabled', false );
	}

	/**
	 * Name of the table (without prefix).
	 */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'pc_event_log';
	}

	/**
	 * Create the table via dbDelta if it doesn't exist. Idempotent.
	 */
	public static function ensure_table(): void {
		global $wpdb;
		$table   = self::table();
		$exists  = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists === $table ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();
		$sql = "CREATE TABLE {$table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			level VARCHAR(16) NOT NULL DEFAULT 'info',
			source VARCHAR(64) NOT NULL DEFAULT '',
			message TEXT NOT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY source (source)
		) {$charset_collate};";
		dbDelta( $sql );
	}

	/**
	 * Record a single event. No-op when logging is disabled.
	 *
	 * @param string $level   info|warning|error
	 * @param string $source  free-form subsystem tag (scan, ip-fallback, maxmind, ...)
	 * @param string $message
	 */
	public static function record( string $level, string $source, string $message ): void {
		if ( ! self::enabled() ) {
			return;
		}
		self::ensure_table();
		global $wpdb;
		$wpdb->insert(
			self::table(),
			array(
				'level'      => sanitize_key( $level ),
				'source'     => sanitize_key( $source ),
				'message'    => wp_kses_post( $message ),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( int $limit = 50 ): array {
		self::ensure_table();
		global $wpdb;
		$limit  = max( 1, min( 500, $limit ) );
		$table  = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return array();
		}
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, created_at, level, source, message FROM {$table} ORDER BY id DESC LIMIT %d",
				$limit
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Truncate the log. Returns true on success.
	 */
	public static function clear(): bool {
		global $wpdb;
		$table  = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return true;
		}
		return (bool) $wpdb->query( "TRUNCATE TABLE {$table}" );
	}

	/**
	 * Aggregate count per day for the chart.
	 *
	 * @return array<string, int>
	 */
	public static function counts_by_day( int $days = 7 ): array {
		self::ensure_table();
		global $wpdb;
		$days  = max( 1, min( 90, $days ) );
		$table = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return array();
		}
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(created_at) AS d, COUNT(*) AS c
				 FROM {$table}
				 WHERE created_at >= %s
				 GROUP BY DATE(created_at)
				 ORDER BY d ASC",
				gmdate( 'Y-m-d 00:00:00', time() - ( $days * DAY_IN_SECONDS ) )
			),
			ARRAY_A
		);
		$out = array();
		if ( is_array( $rows ) ) {
			foreach ( $rows as $r ) {
				$out[ (string) $r['d'] ] = (int) $r['c'];
			}
		}
		return $out;
	}
}