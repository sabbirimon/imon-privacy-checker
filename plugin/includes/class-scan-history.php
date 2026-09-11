<?php
/**
 * Per-visitor smart scan history DB — Phase 32.
 *
 * Stores one row per scan keyed by an anonymous visitor token
 * (a UUIDv4 generated in the browser, kept in localStorage). The row
 * holds *only* the metadata useful for "did my IP change today?",
 * "what country am I in today?", and aggregate trend dashboards —
 * never the full scan report, never browser fingerprint data, never
 * anything that could re-identify a person across sites.
 *
 * Daily-dedupe via UNIQUE(visitor_id, scan_date) — one row per visitor
 * per calendar day, with the row updated when the same visitor rescans
 * later the same day (keeping the latest snapshot, not appending).
 * This keeps the table small (100 visitors × 90 days = 9 000 rows max
 * per the default admin cap) while still giving "today / 7 days / 30
 * days" views enough resolution to be useful.
 *
 * Retention sweep is folded into the existing pc_log_purge cron so we
 * don't multiply timers; the rows-per-visitor cap + time window are
 * configurable from Settings → Privacy & Logging.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScanHistory {

	/**
	 * Storage fields. Each maps to a JSON column so the schema can grow
	 * without an ALTER every time we want to log a new metric.
	 */
	public const FIELDS = array(
		'ipv4', 'ipv6',
		'country', 'country_code', 'region', 'city', 'postal', 'timezone',
		'latitude', 'longitude',
		'isp', 'org', 'asn',
		'connection_type', 'connection_effective',
		'connection_downlink_mbps', 'connection_rtt_ms',
		'dns_resolver', 'dns_leak_count', 'webrtc_leak_count',
		'score', 'grade',
		'ua_family', 'os_family',
	);

	/**
	 * Master toggle — admin can disable the entire feature without
	 * dropping the table (rows are simply not recorded).
	 */
	public static function enabled(): bool {
		return (bool) Plugin::instance()->setting( 'scan_history_enabled', true );
	}

	/**
	 * Time-based retention in days. Default 90.
	 */
	public static function retention_days(): int {
		return max( 1, min( 3650, (int) Plugin::instance()->setting( 'scan_history_retention_days', 90 ) ) );
	}

	/**
	 * Total-row cap. Once exceeded, the oldest rows beyond the cap
	 * are dropped on the next sweep — whichever bound (time or count)
	 * is reached first wins.
	 */
	public static function max_rows(): int {
		return max( 100, min( 1000000, (int) Plugin::instance()->setting( 'scan_history_max_rows', 10000 ) ) );
	}

	/**
	 * Full table name including WP prefix.
	 */
	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'pc_scan_history';
	}

	/**
	 * Idempotent table creation via dbDelta. Mirrors the pattern in
	 * EventLog::ensure_table() and ApiTokens::ensure_table().
	 */
	public static function ensure_table(): void {
		global $wpdb;
		$table = self::table();

		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists === $table ) {
			return;
		}
		if ( isset( $wpdb->tables ) && is_array( $wpdb->tables ) && ! array_key_exists( $table, $wpdb->tables ) ) {
			$wpdb->tables[ $table ] = array();
		}
		if ( ! defined( 'WP_INSTALLING' ) || ! WP_INSTALLING ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			$charset_collate = $wpdb->get_charset_collate();
			$sql = "CREATE TABLE {$table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				visitor_id CHAR(36) NOT NULL,
				scan_date DATE NOT NULL,
				scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				scan_count SMALLINT UNSIGNED NOT NULL DEFAULT 1,
				ipv4 VARCHAR(45) NULL DEFAULT NULL,
				ipv6 VARCHAR(45) NULL DEFAULT NULL,
				country VARCHAR(64) NULL DEFAULT NULL,
				country_code CHAR(2) NULL DEFAULT NULL,
				region VARCHAR(128) NULL DEFAULT NULL,
				city VARCHAR(128) NULL DEFAULT NULL,
				postal VARCHAR(32) NULL DEFAULT NULL,
				timezone VARCHAR(64) NULL DEFAULT NULL,
				latitude DECIMAL(9,6) NULL DEFAULT NULL,
				longitude DECIMAL(9,6) NULL DEFAULT NULL,
				isp VARCHAR(190) NULL DEFAULT NULL,
				org VARCHAR(190) NULL DEFAULT NULL,
				asn VARCHAR(32) NULL DEFAULT NULL,
				connection_type VARCHAR(32) NULL DEFAULT NULL,
				connection_effective VARCHAR(16) NULL DEFAULT NULL,
				connection_downlink_mbps DECIMAL(8,2) NULL DEFAULT NULL,
				connection_rtt_ms INT UNSIGNED NULL DEFAULT NULL,
				dns_resolver VARCHAR(190) NULL DEFAULT NULL,
				dns_leak_count TINYINT UNSIGNED NULL DEFAULT NULL,
				webrtc_leak_count TINYINT UNSIGNED NULL DEFAULT NULL,
				score TINYINT UNSIGNED NULL DEFAULT NULL,
				grade VARCHAR(4) NULL DEFAULT NULL,
				ua_family VARCHAR(32) NULL DEFAULT NULL,
				os_family VARCHAR(32) NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY uniq_visitor_day (visitor_id, scan_date),
				KEY idx_scanned_at (scanned_at),
				KEY idx_visitor (visitor_id),
				KEY idx_country (country_code),
				KEY idx_asn (asn)
			) {$charset_collate};";
			dbDelta( $sql );
		}
	}

	/**
	 * Record (or upsert) a single scan for a visitor. Returns the row id.
	 *
	 * Safe to call on every scan. If a row already exists for
	 * (visitor_id, today), the existing row is updated and scan_count
	 * is incremented. If the visitor is unknown, the upsert is a no-op
	 * (the API only accepts the visitor_id from the same browser that
	 * submitted the scan, so spoofing is bounded).
	 *
	 * @param string $visitor_id  UUIDv4 string from the visitor's browser.
	 * @param array<string,mixed> $payload  Scan report metadata.
	 * @return int|null  Inserted/updated row id, or null when disabled.
	 */
	public static function record( string $visitor_id, array $payload ): ?int {
		if ( ! self::enabled() ) {
			return null;
		}
		$visitor_id = trim( $visitor_id );
		if ( ! self::is_valid_visitor_id( $visitor_id ) ) {
			return null;
		}
		self::ensure_table();
		global $wpdb;

		$row = self::extract_row( $payload );
		if ( null === $row ) {
			return null;
		}
		$row['visitor_id']  = $visitor_id;
		$row['scan_date']   = gmdate( 'Y-m-d' );
		$row['scanned_at']  = gmdate( 'Y-m-d H:i:s' );

		// Insert; on duplicate (visitor_id, scan_date) update everything
		// and bump scan_count.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->prefix}pc_scan_history
					(visitor_id, scan_date, scanned_at, scan_count,
					 ipv4, ipv6, country, country_code, region, city, postal, timezone,
					 latitude, longitude, isp, org, asn,
					 connection_type, connection_effective,
					 connection_downlink_mbps, connection_rtt_ms,
					 dns_resolver, dns_leak_count, webrtc_leak_count,
					 score, grade, ua_family, os_family)
				 VALUES
					(%s, %s, %s, 1, %s,%s,%s,%s,%s,%s,%s,%s, %s,%s, %s,%s,%s, %s,%s, %s,%s, %s,%s,%s, %s,%s,%s,%s)
				 ON DUPLICATE KEY UPDATE
					scanned_at = VALUES(scanned_at),
					scan_count = scan_count + 1,
					ipv4 = VALUES(ipv4),
					ipv6 = VALUES(ipv6),
					country = VALUES(country),
					country_code = VALUES(country_code),
					region = VALUES(region),
					city = VALUES(city),
					postal = VALUES(postal),
					timezone = VALUES(timezone),
					latitude = VALUES(latitude),
					longitude = VALUES(longitude),
					isp = VALUES(isp),
					org = VALUES(org),
					asn = VALUES(asn),
					connection_type = VALUES(connection_type),
					connection_effective = VALUES(connection_effective),
					connection_downlink_mbps = VALUES(connection_downlink_mbps),
					connection_rtt_ms = VALUES(connection_rtt_ms),
					dns_resolver = VALUES(dns_resolver),
					dns_leak_count = VALUES(dns_leak_count),
					webrtc_leak_count = VALUES(webrtc_leak_count),
					score = VALUES(score),
					grade = VALUES(grade),
					ua_family = VALUES(ua_family),
					os_family = VALUES(os_family)",
				array(
					$row['visitor_id'], $row['scan_date'], $row['scanned_at'],
					$row['ipv4'], $row['ipv6'], $row['country'], $row['country_code'],
					$row['region'], $row['city'], $row['postal'], $row['timezone'],
					$row['latitude'], $row['longitude'], $row['isp'], $row['org'], $row['asn'],
					$row['connection_type'], $row['connection_effective'],
					$row['connection_downlink_mbps'], $row['connection_rtt_ms'],
					$row['dns_resolver'], $row['dns_leak_count'], $row['webrtc_leak_count'],
					$row['score'], $row['grade'], $row['ua_family'], $row['os_family'],
				)
			)
		);
		return (int) $wpdb->insert_id ?: null;
	}

	/**
	 * Pull a visitor's history. Returns rows newest-first.
	 *
	 * @return array<int, array<string,mixed>>
	 */
	public static function for_visitor( string $visitor_id, int $limit = 90 ): array {
		if ( ! self::is_valid_visitor_id( $visitor_id ) ) {
			return array();
		}
		self::ensure_table();
		global $wpdb;
		$limit  = max( 1, min( 365, $limit ) );
		$table  = self::table();
		$rows   = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table}
				 WHERE visitor_id = %s
				 ORDER BY scan_date DESC
				 LIMIT %d",
				$visitor_id,
				$limit
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Aggregate counts for the admin trend dashboard. Returns a
	 * structure keyed by day / country / ASN / connection type / grade.
	 *
	 * @return array{by_day: array<int,array{date:string,scans:int,visitors:int}>, by_country: array<int,array{code:string,name:string,scans:int,visitors:int}>, by_asn: array<int,array{asn:string,isp:string,scans:int,visitors:int}>, by_connection: array<int,array{type:string,scans:int}>, by_grade: array<string,int>, totals: array<string,int>}
	 */
	public static function aggregates( int $days = 30 ): array {
		self::ensure_table();
		global $wpdb;
		$days  = max( 1, min( 365, $days ) );
		$table = self::table();
		$since = gmdate( 'Y-m-d', strtotime( "-{$days} days" ) );

		$out = array(
			'by_day'        => array(),
			'by_country'    => array(),
			'by_asn'        => array(),
			'by_connection' => array(),
			'by_grade'      => array(),
			'totals'        => array(
				'scans'    => 0,
				'visitors' => 0,
				'rows'     => 0,
			),
		);

		// Totals.
		$totals = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT
					COALESCE(SUM(scan_count), 0) AS scans,
					COUNT(DISTINCT visitor_id)   AS visitors,
					COUNT(*)                     AS rows
				 FROM {$table} WHERE scan_date >= %s",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $totals ) ) {
			$out['totals'] = array(
				'scans'    => (int) $totals['scans'],
				'visitors' => (int) $totals['visitors'],
				'rows'     => (int) $totals['rows'],
			);
		}

		// Per-day scans + visitors.
		$day_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT scan_date,
					COALESCE(SUM(scan_count), 0) AS scans,
					COUNT(DISTINCT visitor_id)   AS visitors
				 FROM {$table} WHERE scan_date >= %s
				 GROUP BY scan_date ORDER BY scan_date ASC",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $day_rows ) ) {
			foreach ( $day_rows as $r ) {
				$out['by_day'][] = array(
					'date'     => (string) $r['scan_date'],
					'scans'    => (int) $r['scans'],
					'visitors' => (int) $r['visitors'],
				);
			}
		}

		// By country.
		$country_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT country_code, country,
					COALESCE(SUM(scan_count), 0) AS scans,
					COUNT(DISTINCT visitor_id)   AS visitors
				 FROM {$table} WHERE scan_date >= %s AND country_code IS NOT NULL
				 GROUP BY country_code, country
				 ORDER BY scans DESC LIMIT 20",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $country_rows ) ) {
			foreach ( $country_rows as $r ) {
				$out['by_country'][] = array(
					'code'     => (string) $r['country_code'],
					'name'     => (string) $r['country'],
					'scans'    => (int) $r['scans'],
					'visitors' => (int) $r['visitors'],
				);
			}
		}

		// By ASN.
		$asn_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT asn, isp,
					COALESCE(SUM(scan_count), 0) AS scans,
					COUNT(DISTINCT visitor_id)   AS visitors
				 FROM {$table} WHERE scan_date >= %s AND asn IS NOT NULL AND asn <> ''
				 GROUP BY asn, isp ORDER BY scans DESC LIMIT 20",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $asn_rows ) ) {
			foreach ( $asn_rows as $r ) {
				$out['by_asn'][] = array(
					'asn'      => (string) $r['asn'],
					'isp'      => (string) $r['isp'],
					'scans'    => (int) $r['scans'],
					'visitors' => (int) $r['visitors'],
				);
			}
		}

		// By connection type.
		$conn_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT connection_type,
					COALESCE(SUM(scan_count), 0) AS scans
				 FROM {$table} WHERE scan_date >= %s AND connection_type IS NOT NULL AND connection_type <> ''
				 GROUP BY connection_type ORDER BY scans DESC LIMIT 20",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $conn_rows ) ) {
			foreach ( $conn_rows as $r ) {
				$out['by_connection'][] = array(
					'type'  => (string) $r['connection_type'],
					'scans' => (int) $r['scans'],
				);
			}
		}

		// By grade.
		$grade_rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT grade, COALESCE(SUM(scan_count), 0) AS scans
				 FROM {$table} WHERE scan_date >= %s AND grade IS NOT NULL AND grade <> ''
				 GROUP BY grade",
				$since
			),
			ARRAY_A
		);
		if ( is_array( $grade_rows ) ) {
			foreach ( $grade_rows as $r ) {
				$out['by_grade'][ (string) $r['grade'] ] = (int) $r['scans'];
			}
		}

		return $out;
	}

	/**
	 * Forget all rows for a single visitor (the "Forget me" button).
	 * Returns the number of rows deleted.
	 */
	public static function forget_visitor( string $visitor_id ): int {
		if ( ! self::is_valid_visitor_id( $visitor_id ) ) {
			return 0;
		}
		self::ensure_table();
		global $wpdb;
		$table = self::table();
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE visitor_id = %s",
				$visitor_id
			)
		);
		return (int) $wpdb->rows_affected;
	}

	/**
	 * Retention sweep — runs daily from the pc_log_purge cron. Removes
	 * rows older than the retention window and trims the table to the
	 * max_rows cap (whichever is reached first wins).
	 */
	public static function run_daily_purge(): int {
		if ( ! self::enabled() ) {
			return 0;
		}
		self::ensure_table();
		global $wpdb;
		$table   = self::table();
		$days    = self::retention_days();
		$cap     = self::max_rows();
		$cutoff  = gmdate( 'Y-m-d', strtotime( "-{$days} days" ) );

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE scan_date < %s",
				$cutoff
			)
		);
		$deleted = (int) $wpdb->rows_affected;

		// Row-cap enforcement: keep the newest N rows.
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		if ( $total > $cap ) {
			$over = $total - $cap;
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table} ORDER BY scan_date ASC, id ASC LIMIT %d",
					$over
				)
			);
			$deleted += (int) $wpdb->rows_affected;
		}
		if ( $deleted > 0 ) {
			EventLog::record_if_enabled( 'admin', 'info', 'scan_history', sprintf( 'purged %d history rows', $deleted ) );
		}
		return $deleted;
	}

	/**
	 * Pull a flat array of column values out of the scan report, with
	 * sane defaults + light sanitisation. Returns null if the report
	 * is too sparse to be worth storing.
	 *
	 * @param array<string,mixed> $payload
	 * @return array<string,mixed>|null
	 */
	private static function extract_row( array $payload ): ?array {
		$req_ip = isset( $payload['request_ip'] ) && is_array( $payload['request_ip'] ) ? $payload['request_ip'] : array();
		$geo    = isset( $payload['geo'] ) && is_array( $payload['geo'] ) ? $payload['geo'] : array();
		$conn   = isset( $payload['connection'] ) && is_array( $payload['connection'] ) ? $payload['connection'] : array();
		$report = isset( $payload['privacy_report'] ) && is_array( $payload['privacy_report'] ) ? $payload['privacy_report'] : array();
		$fpr    = isset( $payload['fingerprint'] ) && is_array( $payload['fingerprint'] ) ? $payload['fingerprint'] : array();

		// Reject rows with no IP at all — would indicate a server error.
		if ( empty( $req_ip['ipv4'] ) && empty( $req_ip['ipv6'] ) ) {
			return null;
		}

		$row = array();
		$row['ipv4']   = isset( $req_ip['ipv4'] )   ? substr( (string) $req_ip['ipv4'], 0, 45 ) : null;
		$row['ipv6']   = isset( $req_ip['ipv6'] )   ? substr( (string) $req_ip['ipv6'], 0, 45 ) : null;
		$row['country']      = isset( $geo['country_name'] ) ? substr( (string) $geo['country_name'], 0, 64 ) : null;
		$row['country_code'] = isset( $geo['country_code'] ) ? strtoupper( substr( (string) $geo['country_code'], 0, 2 ) ) : null;
		$row['region']       = isset( $geo['region'] )  ? substr( (string) $geo['region'], 0, 128 ) : null;
		$row['city']         = isset( $geo['city'] )    ? substr( (string) $geo['city'], 0, 128 ) : null;
		$row['postal']       = isset( $geo['postal'] )  ? substr( (string) $geo['postal'], 0, 32 ) : null;
		$row['timezone']     = isset( $geo['timezone'] ) ? substr( (string) $geo['timezone'], 0, 64 ) : null;
		$row['latitude']     = isset( $geo['latitude'] )  && is_numeric( $geo['latitude'] )  ? (float) $geo['latitude']  : null;
		$row['longitude']    = isset( $geo['longitude'] ) && is_numeric( $geo['longitude'] ) ? (float) $geo['longitude'] : null;
		$row['isp']          = isset( $geo['isp'] ) ? substr( (string) $geo['isp'], 0, 190 ) : null;
		$row['org']          = isset( $geo['org'] ) ? substr( (string) $geo['org'], 0, 190 ) : null;
		$row['asn']          = isset( $geo['asn'] ) ? substr( (string) $geo['asn'], 0, 32 ) : null;
		$row['connection_type']       = isset( $conn['type'] ) ? substr( strtolower( (string) $conn['type'] ), 0, 32 ) : null;
		$row['connection_effective']  = isset( $conn['effectiveType'] ) ? substr( strtolower( (string) $conn['effectiveType'] ), 0, 16 ) : null;
		$row['connection_downlink_mbps'] = isset( $conn['downlink'] ) && is_numeric( $conn['downlink'] ) ? (float) $conn['downlink'] : null;
		$row['connection_rtt_ms']     = isset( $conn['rtt'] ) && is_numeric( $conn['rtt'] ) ? (int) round( $conn['rtt'] ) : null;
		$row['dns_resolver']   = isset( $payload['dns_resolver'] ) ? substr( (string) $payload['dns_resolver'], 0, 190 ) : null;
		$row['dns_leak_count'] = isset( $payload['dns_leak_count'] ) && is_numeric( $payload['dns_leak_count'] ) ? (int) $payload['dns_leak_count'] : null;
		$row['webrtc_leak_count'] = isset( $payload['webrtc_leak_count'] ) && is_numeric( $payload['webrtc_leak_count'] ) ? (int) $payload['webrtc_leak_count'] : null;
		$row['score']          = isset( $report['overall'] ) && is_numeric( $report['overall'] ) ? max( 0, min( 100, (int) round( $report['overall'] ) ) ) : null;
		$row['grade']          = isset( $report['grade'] ) ? substr( (string) $report['grade'], 0, 4 ) : null;
		$row['ua_family']      = isset( $fpr['ua_family'] ) ? substr( (string) $fpr['ua_family'], 0, 32 ) : null;
		$row['os_family']      = isset( $fpr['os_family'] ) ? substr( (string) $fpr['os_family'], 0, 32 ) : null;

		return $row;
	}

	/**
	 * UUIDv4 sanity check — the visitor_id is generated client-side as
	 * crypto.randomUUID() and must look like one before we accept it.
	 */
	public static function is_valid_visitor_id( string $visitor_id ): bool {
		return (bool) preg_match( '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/', $visitor_id );
	}
}
