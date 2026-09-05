<?php
/**
 * External services catalog.
 *
 * Stores optional integrations with third-party sites / services that the
 * operator wants to subscribe to. Each row carries a vendor key, a friendly
 * label, an endpoint URL, and an API key or token that is stored opaque on
 * disk (never echoed back to the browser, even to admins).
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ServicesCatalog {

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'pc_services';
	}

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
				vendor VARCHAR(64) NOT NULL DEFAULT '',
				label VARCHAR(190) NOT NULL DEFAULT '',
				endpoint VARCHAR(255) NOT NULL DEFAULT '',
				api_key_hash CHAR(64) NOT NULL DEFAULT '',
				enabled TINYINT(1) NOT NULL DEFAULT 1,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				KEY vendor (vendor),
				KEY enabled (enabled)
			) {$charset_collate};";
			dbDelta( $sql );
		}
	}

	public static function add( string $vendor, string $label, string $endpoint, string $api_key, bool $enabled ): int {
		self::ensure_table();
		global $wpdb;
		$vendor   = sanitize_key( $vendor );
		$label    = sanitize_text_field( $label );
		$endpoint = esc_url_raw( $endpoint );
		$enabled  = $enabled ? 1 : 0;
		$wpdb->insert(
			self::table(),
			array(
				'vendor'      => $vendor,
				'label'       => $label,
				'endpoint'    => $endpoint,
				'api_key_hash'=> '' === $api_key ? '' : hash( 'sha256', $api_key ),
				'enabled'     => $enabled,
				'created_at'  => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s' )
		);
		return (int) $wpdb->insert_id;
	}

	public static function save( int $id, string $label, string $endpoint, ?string $api_key, bool $enabled ): bool {
		self::ensure_table();
		global $wpdb;
		$data = array(
			'label'      => sanitize_text_field( $label ),
			'endpoint'   => esc_url_raw( $endpoint ),
			'enabled'    => $enabled ? 1 : 0,
			'updated_at' => gmdate( 'Y-m-d H:i:s' ),
		);
		$formats = array( '%s', '%s', '%d', '%s' );
		if ( null !== $api_key ) {
			$data['api_key_hash'] = '' === $api_key ? '' : hash( 'sha256', $api_key );
			$formats[] = '%s';
		}
		$updated = $wpdb->update( self::table(), $data, array( 'id' => $id ), $formats, array( '%d' ) );
		return false !== $updated;
	}

	public static function delete( int $id ): bool {
		self::ensure_table();
		global $wpdb;
		$deleted = $wpdb->delete( self::table(), array( 'id' => $id ), array( '%d' ) );
		return false !== $deleted && (int) $deleted > 0;
	}

	public static function list_all(): array {
		self::ensure_table();
		global $wpdb;
		$rows = $wpdb->get_results(
			"SELECT id, vendor, label, endpoint, api_key_hash, enabled, created_at, updated_at FROM " . self::table() . " ORDER BY id ASC LIMIT 200",
			'ARRAY_A'
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		foreach ( $rows as &$row ) {
			$row['id']       = (int) $row['id'];
			$row['enabled']  = ! empty( $row['enabled'] );
			$row['has_key']  = ! empty( $row['api_key_hash'] );
			// Never expose the hashed value to callers.
			unset( $row['api_key_hash'] );
		}
		return $rows;
	}

	/**
	 * Find a service entry by vendor key.
	 *
	 * @return array<string,mixed>|null
	 */
	public static function find_by_vendor( string $vendor ): ?array {
		self::ensure_table();
		global $wpdb;
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, vendor, label, endpoint, enabled FROM " . self::table() . " WHERE vendor = %s AND enabled = 1 ORDER BY id ASC LIMIT 1",
				sanitize_key( $vendor )
			),
			'ARRAY_A'
		);
		if ( ! is_array( $row ) ) {
			return null;
		}
		return $row;
	}
}
