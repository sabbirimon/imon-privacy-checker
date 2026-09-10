<?php
/**
 * Event log — small, opt-in append-only table for admin diagnostics.
 *
 * Created lazily via dbDelta when an admin enables the setting. The default
 * install never creates the table. Retention is enforced daily by the
 * existing privacy/retention cron.
 *
 * Phase 28: extended with an `event` category column and a `context` JSON
 * column. Per-category recording can be toggled via
 * `Plugin::setting('logs.<category>_enabled', true)` — use
 * `record_if_enabled()` at every call site so the toggle is enforced in
 * one place.
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
	 * Known event categories. Anything outside this list still gets
	 * recorded, but it won't show up under a category-specific toggle
	 * (it's recorded whenever the master switch is on).
	 */
	public const CATEGORIES = array( 'scan', 'share', 'export', 'restore', 'admin', 'error' );

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
	 *
	 * Also performs an idempotent ALTER TABLE to add the Phase 28
	 * `event` and `context` columns. The codebase uses
	 * `SHOW COLUMNS LIKE` to detect missing columns before issuing
	 * the migration, matching the pattern used elsewhere.
	 */
	public static function ensure_table(): void {
		global $wpdb;
		$table   = self::table();
		$exists  = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();
		if ( $exists !== $table ) {
			$sql = "CREATE TABLE {$table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				level VARCHAR(16) NOT NULL DEFAULT 'info',
				source VARCHAR(64) NOT NULL DEFAULT '',
				event VARCHAR(64) NOT NULL DEFAULT 'misc',
				context LONGTEXT NULL,
				message TEXT NOT NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY source (source),
				KEY event (event),
				KEY created_event (created_at, event)
			) {$charset_collate};";
			dbDelta( $sql );
			return;
		}
		// Phase 28 migration: add `event` and `context` to existing installs.
		$col = $wpdb->get_results( "SHOW COLUMNS FROM {$table} LIKE 'event'" );
		if ( empty( $col ) ) {
			$wpdb->query( "ALTER TABLE {$table}
				ADD COLUMN event VARCHAR(64) NOT NULL DEFAULT 'misc' AFTER source,
				ADD COLUMN context LONGTEXT NULL AFTER event,
				ADD INDEX event (event),
				ADD INDEX created_event (created_at, event)" );
		}
	}

	/**
	 * Record a single event. No-op when the master logging switch is off.
	 *
	 * Back-compat signature: the older 3-argument form
	 * `record($level, $source, $message)` still works — `$event` defaults
	 * to 'misc' and `$context` defaults to [].
	 *
	 * @param string             $level   info|warning|error
	 * @param string             $source  free-form subsystem tag (scan, ip-fallback, maxmind, ...)
	 * @param string             $message
	 * @param string             $event   category: scan|share|export|restore|admin|error|misc
	 * @param array<string,mixed> $context Optional structured data (JSON-encoded into the row)
	 */
	public static function record( string $level, string $source, string $message, string $event = 'misc', array $context = array() ): void {
		if ( ! self::enabled() ) {
			return;
		}
		self::ensure_table();
		global $wpdb;
		$context_json = empty( $context ) ? null : wp_json_encode( $context );
		$wpdb->insert(
			self::table(),
			array(
				'level'      => sanitize_key( $level ),
				'source'     => sanitize_key( $source ),
				'event'      => sanitize_key( $event ),
				'context'    => $context_json,
				'message'    => wp_kses_post( $message ),
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Convenience wrapper — checks the per-category toggle, then
	 * forwards to `record()`. Every call site in the plugin should
	 * use this so the admin can disable individual event categories
	 * without touching code.
	 *
	 * @param string             $category scan|share|export|restore|admin|error
	 * @param string             $level
	 * @param string             $source
	 * @param string             $message
	 * @param array<string,mixed> $context
	 * @return bool true when the event was recorded, false when gated off
	 */
	public static function record_if_enabled( string $category, string $level, string $source, string $message, array $context = array() ): bool {
		if ( ! self::enabled() ) {
			return false;
		}
		// Per-category toggle. Defaults to true so admins who never
		// opened the settings page still get the full audit trail.
		$toggle_key = 'logs.' . $category . '_enabled';
		if ( ! (bool) Plugin::instance()->setting( $toggle_key, true ) ) {
			return false;
		}
		self::record( $level, $source, $message, $category, $context );
		return true;
	}

	/**
	 * @param array<string,mixed> $filters Optional: ['event' => 'scan', 'level' => 'error', 'search' => '...', 'days' => 7]
	 * @return array<int, array<string, mixed>>
	 */
	public static function recent( int $limit = 50, array $filters = array() ): array {
		self::ensure_table();
		global $wpdb;
		$limit  = max( 1, min( 500, $limit ) );
		$table  = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return array();
		}
		$where = array( '1=1' );
		$args  = array();
		if ( ! empty( $filters['event'] ) ) {
			$where[] = 'event = %s';
			$args[]  = sanitize_key( $filters['event'] );
		}
		if ( ! empty( $filters['level'] ) ) {
			$where[] = 'level = %s';
			$args[]  = sanitize_key( $filters['level'] );
		}
		if ( ! empty( $filters['days'] ) ) {
			$where[] = 'created_at >= %s';
			$args[]  = gmdate( 'Y-m-d 00:00:00', time() - ( (int) $filters['days'] * DAY_IN_SECONDS ) );
		}
		if ( ! empty( $filters['search'] ) ) {
			$like    = '%' . $wpdb->esc_like( (string) $filters['search'] ) . '%';
			$where[] = 'message LIKE %s';
			$args[]  = $like;
		}
		$args[] = $limit;
		$sql    = "SELECT id, created_at, level, source, event, context, message FROM {$table} WHERE " . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d';
		$rows   = $wpdb->get_results( $wpdb->prepare( $sql, $args ), ARRAY_A );
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Per-category count for the last N days. Drives the KPI tiles
	 * in the logs admin view.
	 *
	 * @return array<string, int>  keyed by category name
	 */
	public static function counts_by_event( int $days = 30 ): array {
		self::ensure_table();
		global $wpdb;
		$days  = max( 1, min( 365, $days ) );
		$table = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return array_fill_keys( self::CATEGORIES, 0 );
		}
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event, COUNT(*) AS c FROM {$table}
				 WHERE created_at >= %s
				 GROUP BY event",
				gmdate( 'Y-m-d 00:00:00', time() - ( $days * DAY_IN_SECONDS ) )
			),
			ARRAY_A
		);
		$out = array_fill_keys( self::CATEGORIES, 0 );
		if ( is_array( $rows ) ) {
			foreach ( $rows as $r ) {
				$out[ (string) $r['event'] ] = (int) $r['c'];
			}
		}
		return $out;
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
	 * Retention sweep — delete rows older than `$days`. Also enforce
	 * the row cap (`max_rows`) by trimming the oldest rows beyond the
	 * cap, regardless of age. Whichever cap is hit first wins.
	 *
	 * @return array{deleted_by_age:int, deleted_by_cap:int}
	 */
	public static function purge( int $days, int $max_rows = 50000 ): array {
		global $wpdb;
		$table  = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists !== $table ) {
			return array( 'deleted_by_age' => 0, 'deleted_by_cap' => 0 );
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$age_deleted = (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) );

		$cap_deleted = 0;
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		if ( $count > $max_rows ) {
			$overflow = $count - $max_rows;
			$cap_deleted = (int) $wpdb->query( $wpdb->prepare(
				"DELETE FROM {$table} ORDER BY id ASC LIMIT %d",
				$overflow
			) );
		}
		return array( 'deleted_by_age' => $age_deleted, 'deleted_by_cap' => $cap_deleted );
	}

	/**
	 * WP-Cron entry point — invoked daily by `pc_log_purge`.
	 *
	 * Reads the retention policy from settings, runs `purge()`, and
	 * records an `admin` event with the result so the admin can see
	 * when the last sweep ran and how many rows it removed. Failures
	 * are caught + logged via `error` category — never thrown, since
	 * WP-Cron silently drops uncaught exceptions.
	 *
	 * @return array{deleted_by_age:int, deleted_by_cap:int}|null
	 */
	public static function run_daily_purge(): ?array {
		if ( ! self::enabled() ) {
			return null;
		}
		try {
			$retention = (int) Plugin::instance()->setting( 'logs.retention_days', 90 );
			$max_rows  = (int) Plugin::instance()->setting( 'logs.max_rows', 50000 );
			$result    = self::purge( $retention, $max_rows );
			self::record_if_enabled(
				'admin',
				'info',
				'log-purge',
				sprintf(
					'daily purge: %d by age, %d by cap (retention=%dd, cap=%d)',
					$result['deleted_by_age'],
					$result['deleted_by_cap'],
					$retention,
					$max_rows
				),
				$result
			);
			return $result;
		} catch ( \Throwable $e ) {
			self::record_if_enabled(
				'error',
				'error',
				'log-purge',
				sprintf( 'purge failed: %s', $e->getMessage() ),
				array( 'exception' => get_class( $e ) )
			);
			return null;
		}
	}

	/**
	 * Aggregate count per day for the chart. Preserved from the
	 * pre-Phase-28 implementation; used by the existing dashboard.
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