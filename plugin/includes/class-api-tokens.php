<?php
/**
 * Enterprise API tokens.
 *
 * Issues opaque API tokens to non-UI clients (bots, AI agents, integration
 * services) so they can call the privacy REST endpoints without a WordPress
 * login cookie. Each token is stored as a SHA-256 hash; the plaintext is
 * returned exactly once at creation.
 *
 * Tokens are scoped (e.g. `scan:read`, `lookup:read`) and rate-limited
 * independently of the per-IP buckets so a single tenant cannot starve
 * other visitors.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * API token CRUD + verification.
 */
final class ApiTokens {

	public const PREFIX = 'pc_live_';

	public static function table(): string {
		global $wpdb;
		return $wpdb->prefix . 'pc_api_tokens';
	}

	public static function ensure_table(): void {
		global $wpdb;
		$table = self::table();
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( $exists === $table ) {
			return;
		}
		// Test-friendly hook so the in-memory wpdb stub can prep an empty row set
		// without needing a real dbDelta. WP installs get the CREATE TABLE.
		if ( isset( $wpdb->tables ) && is_array( $wpdb->tables ) && ! array_key_exists( $table, $wpdb->tables ) ) {
			$wpdb->tables[ $table ] = array();
		}
		if ( ! defined( 'WP_INSTALLING' ) || ! WP_INSTALLING ) {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			$charset_collate = $wpdb->get_charset_collate();
			$sql = "CREATE TABLE {$table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				label VARCHAR(190) NOT NULL DEFAULT '',
				token_hash CHAR(64) NOT NULL,
				token_prefix VARCHAR(16) NOT NULL DEFAULT '',
				scopes TEXT NOT NULL,
				rate_limit_per_minute INT UNSIGNED NOT NULL DEFAULT 120,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				created_by BIGINT UNSIGNED NOT NULL DEFAULT 0,
				last_used_at DATETIME NULL DEFAULT NULL,
				last_used_ip VARBINARY(16) NULL DEFAULT NULL,
				revoked_at DATETIME NULL DEFAULT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY token_hash (token_hash),
				KEY revoked_at (revoked_at)
			) {$charset_collate};";
			dbDelta( $sql );
		}
	}

	public static function enabled(): bool {
		return (bool) Plugin::instance()->setting( 'api_tokens_enabled', true );
	}

	/**
	 * Issue a new token. Returns the plaintext token exactly once.
	 *
	 * @param string $label Human-readable name shown in the admin list.
	 * @param string[] $scopes Optional list of scope strings (e.g. ['scan:read', 'lookup:read']).
	 * @param int $rate_limit_per_minute Per-token rate cap.
	 * @param int $user_id WP user id that issued the token.
	 * @return array<string, mixed>  { token, label, prefix, scopes, rate_limit, id }
	 */
	public static function issue( string $label, array $scopes, int $rate_limit_per_minute, int $user_id ): array {
		self::ensure_table();
		global $wpdb;

		$plaintext = self::PREFIX . bin2hex( random_bytes( 24 ) );
		$hash      = hash( 'sha256', $plaintext );
		$prefix    = substr( $plaintext, 0, strlen( self::PREFIX ) + 8 );
		$scopes_in = array_values( array_filter( array_map( 'strval', $scopes ) ) );

		$wpdb->insert(
			self::table(),
			array(
				'label'                 => sanitize_text_field( $label ),
				'token_hash'            => $hash,
				'token_prefix'          => $prefix,
				'scopes'                => wp_json_encode( $scopes_in ),
				'rate_limit_per_minute' => max( 1, min( 100000, $rate_limit_per_minute ) ),
				'created_at'            => gmdate( 'Y-m-d H:i:s' ),
				'created_by'            => (int) $user_id,
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);

		$id = (int) $wpdb->insert_id;

		return array(
			'token'      => $plaintext,
			'id'         => $id,
			'label'      => sanitize_text_field( $label ),
			'prefix'     => $prefix,
			'scopes'     => $scopes_in,
			'rate_limit' => max( 1, min( 100000, $rate_limit_per_minute ) ),
		);
	}

	/**
	 * Verify a plaintext token (received via Authorization: Bearer). Returns the row array
	 * on success, null on any failure. Never throws.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function verify( string $plaintext ): ?array {
		if ( '' === $plaintext || strpos( $plaintext, self::PREFIX ) !== 0 ) {
			return null;
		}
		if ( ! self::enabled() ) {
			return null;
		}
		self::ensure_table();
		global $wpdb;

		$hash = hash( 'sha256', $plaintext );
		$row  = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT id, label, token_prefix, scopes, rate_limit_per_minute, revoked_at FROM " . self::table() . " WHERE token_hash = %s LIMIT 1",
				$hash
			),
			'ARRAY_A'
		);
		if ( ! is_array( $row ) ) {
			return null;
		}
		if ( ! empty( $row['revoked_at'] ) && '0000-00-00 00:00:00' !== $row['revoked_at'] ) {
			return null;
		}
		$row['scopes'] = json_decode( (string) ( $row['scopes'] ?? '[]' ), true );
		if ( ! is_array( $row['scopes'] ) ) {
			$row['scopes'] = array();
		}
		$row['rate_limit_per_minute'] = (int) ( $row['rate_limit_per_minute'] ?? 120 );
		return $row;
	}

	public static function touch_used( int $id, ?string $ip ): void {
		self::ensure_table();
		global $wpdb;
		$packed = null;
		if ( null !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			$packed = @inet_pton( $ip );
		}
		$wpdb->update(
			self::table(),
			array(
				'last_used_at' => gmdate( 'Y-m-d H:i:s' ),
				'last_used_ip' => $packed,
			),
			array( 'id' => $id ),
			array( '%s', '%s' ),
			array( '%d' )
		);
	}

	public static function revoke( int $id ): bool {
		self::ensure_table();
		global $wpdb;
		$updated = $wpdb->update(
			self::table(),
			array( 'revoked_at' => gmdate( 'Y-m-d H:i:s' ) ),
			array( 'id' => $id ),
			array( '%s' ),
			array( '%d' )
		);
		return false !== $updated;
	}

	public static function list_all(): array {
		self::ensure_table();
		global $wpdb;
		$rows = $wpdb->get_results(
			"SELECT id, label, token_prefix, scopes, rate_limit_per_minute, created_at, created_by, last_used_at, revoked_at FROM " . self::table() . " ORDER BY id DESC LIMIT 200",
			'ARRAY_A'
		);
		if ( ! is_array( $rows ) ) {
			return array();
		}
		foreach ( $rows as &$row ) {
			$row['scopes']  = json_decode( (string) ( $row['scopes'] ?? '[]' ), true );
			$row['scopes']  = is_array( $row['scopes'] ) ? $row['scopes'] : array();
			$row['revoked'] = ! empty( $row['revoked_at'] ) && '0000-00-00 00:00:00' !== $row['revoked_at'];
		}
		return $rows;
	}

	/**
	 * Default scope set covering the public endpoints.
	 *
	 * @return string[]
	 */
	public static function default_scopes(): array {
		return array( 'scan:read', 'lookup:read', 'dns:read', 'ping:read', 'port:read' );
	}

	/**
	 * All scopes the admin UI can offer when creating a token.
	 *
	 * @return array<string, string>
	 */
	public static function all_scopes(): array {
		return array(
			'scan:read'    => __( 'Run privacy scans (/scan)', 'privacy-checker' ),
			'lookup:read'  => __( 'IP intelligence lookups (/lookup/ip)', 'privacy-checker' ),
			'dns:read'     => __( 'DNS leak tests (/scan/dns-test/*)', 'privacy-checker' ),
			'ping:read'    => __( 'Ping / latency probes (/scan/ping)', 'privacy-checker' ),
			'port:read'    => __( 'Port scan (self) (/scan/port)', 'privacy-checker' ),
			'admin:write'  => __( 'Admin write operations (revoke tokens, flush cache)', 'privacy-checker' ),
		);
	}

	/**
	 * Decide whether a token row has a given scope.
	 *
	 * @param array<string, mixed> $token_row
	 */
	public static function has_scope( array $token_row, string $scope ): bool {
		$scopes = $token_row['scopes'] ?? array();
		if ( ! is_array( $scopes ) ) {
			return false;
		}
		if ( in_array( 'admin:write', $scopes, true ) ) {
			return true;
		}
		return in_array( $scope, $scopes, true );
	}

	/**
	 * Extract a Bearer token from a WP_REST_Request, or null.
	 */
	public static function extract_bearer( \WP_REST_Request $request ): ?string {
		$auth = $request->get_header( 'authorization' );
		if ( ! is_string( $auth ) || '' === $auth ) {
			// Try `_token` query arg fallback for limited clients.
			$token = $request->get_param( '_token' );
			if ( is_string( $token ) && '' !== $token ) {
				return $token;
			}
			return null;
		}
		if ( stripos( $auth, 'bearer ' ) === 0 ) {
			$token = trim( substr( $auth, 7 ) );
			return '' !== $token ? $token : null;
		}
		return null;
	}
}
