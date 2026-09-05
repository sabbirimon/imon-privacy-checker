<?php
/**
 * GeoIP database inventory + upload helpers.
 *
 * Persists uploaded BIN/MMDB/ZIP/CSV files under wp-content/uploads/privacy-checker-geoip/
 * and exposes the inventory for the admin panel. ZIP files are extracted in
 * place so individual providers can find their .bin / .mmdb files without the
 * upload leaving a wrapper archive.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use WP_Error;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class GeoIpDatabase {

	private const SUBDIR = 'privacy-checker-geoip';

	/**
	 * Maximum upload size in bytes (250 MB by default).
	 */
	public static function max_upload_bytes(): int {
		return 250 * 1024 * 1024;
	}

	public static function upload_dir(): string {
		$uploads = wp_upload_dir();
		$base    = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
		if ( '' === $base ) {
			return '';
		}
		$dir = rtrim( $base, '/' ) . '/' . self::SUBDIR;
		$dir = (string) ( function_exists( 'apply_filters' ) ? apply_filters( 'pc_geoip_upload_dir', $dir ) : $dir );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		return $dir;
	}

	/**
	 * Store an uploaded file. Returns the resulting filename on success, WP_Error on failure.
	 *
	 * @param array<string, mixed> $file     The $_FILES['database'] entry.
	 * @param string               $category country|city|asn|cidr|proxy|misc
	 * @return string|WP_Error
	 */
	public static function store_upload( array $file, string $category ) {
		if ( empty( $file['tmp_name'] ) || ! is_uploaded_file( $file['tmp_name'] ) ) {
			return new WP_Error( 'pc_no_tmp', 'No uploaded file.' );
		}
		if ( ! empty( $file['error'] ) ) {
			return new WP_Error( 'pc_upload_err', 'Upload failed: ' . (string) $file['error'] );
		}
		$size = (int) ( $file['size'] ?? 0 );
		if ( $size <= 0 ) {
			return new WP_Error( 'pc_empty', 'Uploaded file is empty.' );
		}
		if ( $size > self::max_upload_bytes() ) {
			return new WP_Error( 'pc_too_big', 'File exceeds the upload size limit.' );
		}
		$orig = sanitize_file_name( (string) ( $file['name'] ?? '' ) );
		if ( '' === $orig ) {
			return new WP_Error( 'pc_bad_name', 'Invalid filename.' );
		}
		$ext = strtolower( pathinfo( $orig, PATHINFO_EXTENSION ) );
		$allowed_ext = array( 'bin', 'mmdb', 'zip', 'csv', 'dat', 'gz' );
		if ( ! in_array( $ext, $allowed_ext, true ) ) {
			return new WP_Error( 'pc_bad_ext', 'Unsupported file type: ' . $ext );
		}
		$dir = self::upload_dir();
		if ( '' === $dir ) {
			return new WP_Error( 'pc_no_dir', 'Upload directory unavailable.' );
		}

		// Tag the filename with the chosen category so the inventory list can
		// group records without a separate database table.
		$base = pathinfo( $orig, PATHINFO_FILENAME );
		$tagged = sanitize_file_name( $category . '__' . $base ) . '.' . $ext;
		$dest = $dir . '/' . $tagged;
		if ( ! move_uploaded_file( $file['tmp_name'], $dest ) ) {
			return new WP_Error( 'pc_move_failed', 'Could not move uploaded file.' );
		}
		@chmod( $dest, 0644 );

		// Auto-extract zips.
		if ( 'zip' === $ext && class_exists( '\\ZipArchive' ) ) {
			$za = new \ZipArchive();
			if ( true === $za->open( $dest ) ) {
				$za->extractTo( $dir );
				$za->close();
			}
		}

		self::clear_cache();
		return $tagged;
	}

	public static function delete( string $name ): bool {
		$dir = self::upload_dir();
		$path = $dir . '/' . sanitize_file_name( $name );
		if ( ! is_file( $path ) ) {
			return false;
		}
		@unlink( $path );
		self::clear_cache();
		return true;
	}

	public static function categories(): array {
		return array( 'geoip', 'country', 'city', 'asn', 'geoproxy', 'proxy', 'datacenter', 'mobile', 'cidr', 'reputation', 'tor', 'vpn', 'misc' );
	}

	public static function list_with_meta(): array {
		$dir = self::upload_dir();
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return array();
		}
		$cache_key = 'pc_db_inventory_v1';
		$cached = Cache::get( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$out = array();
		foreach ( (array) scandir( $dir ) as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( ! is_file( $path ) ) {
				continue;
			}
			$ext  = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
			$category = 'misc';
			$base = pathinfo( $name, PATHINFO_FILENAME );
			$prefix = strtolower( strtok( $base, '__' ) );
			if ( in_array( $prefix, self::categories(), true ) ) {
				$category = $prefix;
			}
			$out[] = array(
				'name'     => $name,
				'category' => $category,
				'format'   => strtoupper( $ext ),
				'size'     => (int) filesize( $path ),
				'modified' => gmdate( 'Y-m-d H:i', (int) filemtime( $path ) ),
				'path'     => $path,
			);
		}
		usort( $out, function ( $a, $b ) {
			return strcmp( $a['category'] . $a['name'], $b['category'] . $b['name'] );
		} );
		Cache::set( $cache_key, $out, 5 * MINUTE_IN_SECONDS );
		return $out;
	}

	/**
	 * Discover a database file for a given vendor + category. Search order:
	 *   1. Explicit `pc_geoip_dir_{vendor}` setting if a directory override is set.
	 *   2. The uploads/privacy-checker-geoip folder, files matching vendor/category.
	 *   3. The bundled /GeoIP Database/ folder.
	 */
	public static function locate( string $vendor, string $category = '' ): ?string {
		$dir = self::upload_dir();
		if ( '' === $dir ) {
			return null;
		}
		$candidates = array();
		// Tag-based matching.
		foreach ( array( $vendor, $category ) as $needle ) {
			if ( '' === $needle ) {
				continue;
			}
			foreach ( self::list_with_meta() as $row ) {
				if ( 0 === strpos( strtolower( $row['name'] ), strtolower( $needle ) . '__' ) ) {
					$candidates[] = $row['path'];
				}
			}
		}
		if ( ! empty( $candidates ) ) {
			return $candidates[0];
		}
		// Bundle fallback.
		$project_dir = dirname( dirname( dirname( dirname( __DIR__ ) ) ) ) . '/GeoIP Database';
		if ( is_dir( $project_dir ) ) {
			foreach ( (array) scandir( $project_dir ) as $name ) {
				$lname = strtolower( $name );
				if ( false !== strpos( $lname, strtolower( $vendor ) ) ) {
					$path = $project_dir . '/' . $name;
					if ( is_file( $path ) ) {
						return $path;
					}
				}
			}
		}
		return null;
	}

	public static function clear_cache(): void {
		Cache::delete( 'pc_db_inventory_v1' );
	}
}
