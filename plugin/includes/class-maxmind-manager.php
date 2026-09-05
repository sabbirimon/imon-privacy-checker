<?php
/**
 * MaxMind database download / refresh manager.
 *
 * Downloads GeoLite2 archives from the official MaxMind URLs (or from
 * user-supplied URLs), extracts the .mmdb files into
 * wp-content/uploads/maxmind/, and keeps them fresh via wp-cron.
 *
 * The manager is intentionally lenient:
 *   - a missing license key is non-fatal; admin sees a notice and nothing
 *     happens;
 *   - a single failed download does not abort the whole batch;
 *   - archive entries with path-traversal sequences are rejected before
 *     extraction;
 *   - the directory the manager writes to is the same one MaxmindProvider
 *     reads from.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class MaxmindManager {

	/**
	 * Canonical MaxMind download URLs the plugin always considers as defaults.
	 * Admins can add additional URLs via the admin UI; these are stable.
	 *
	 * @return string[]
	 */
	public static function official_urls(): array {
		$edition_id = (string) Plugin::instance()->setting( 'maxmind_license_key', '' );
		$edition_id = trim( $edition_id );

		$urls = array(
			'https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz',
			'https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz',
			'https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz',
		);

		// When a license key is configured MaxMind requires it as a query
		// parameter. Without a key the downloads will return HTTP 401 but
		// the manager surfaces that as an error rather than failing the
		// whole batch.
		if ( '' !== $edition_id ) {
			$urls = array_map(
				static function ( string $u ) use ( $edition_id ): string {
					return $u . ( str_contains( $u, '?' ) ? '&' : '?' ) . 'license_key=' . rawurlencode( $edition_id );
				},
				$urls
			);
		}

		return $urls;
	}

	/**
	 * URLs the admin has added in the settings page.
	 *
	 * @return string[]
	 */
	public static function user_urls(): array {
		$raw = Plugin::instance()->setting( 'maxmind_custom_urls', array() );
		if ( ! is_array( $raw ) ) {
			return array();
		}
		return array_values(
			array_filter(
				array_map(
					static function ( $u ): string {
						$u = is_string( $u ) ? trim( $u ) : '';
						return $u;
					},
					$raw
				),
				static fn( string $u ): bool => '' !== $u && (
					str_starts_with( $u, 'https://download.maxmind.com/' ) ||
					str_starts_with( $u, 'https://example.com/' )
				)
			)
		);
	}

	/**
	 * Current state of the local MaxMind cache.
	 *
	 * @return array{
	 *   dir: string,
	 *   exists: bool,
	 *   license_key_set: bool,
	 *   last_update: int,
	 *   files: array<string, array{size:int, mtime:int}>
	 * }
	 */
	public static function get_status(): array {
		$dir   = self::db_dir();
		$files = array();
		if ( is_dir( $dir ) ) {
			foreach ( array( 'GeoLite2-City.mmdb', 'GeoLite2-ASN.mmdb', 'GeoLite2-Country.mmdb', 'GeoLite2-Anonymous-IP.mmdb' ) as $basename ) {
				$path = $dir . '/' . $basename;
				if ( is_file( $path ) ) {
					$files[ $basename ] = array(
						'size'  => (int) filesize( $path ),
						'mtime' => (int) filemtime( $path ),
					);
				}
			}
		}
		return array(
			'dir'             => $dir,
			'exists'          => is_dir( $dir ),
			'license_key_set' => '' !== trim( (string) Plugin::instance()->setting( 'maxmind_license_key', '' ) ),
			'last_update'     => (int) Plugin::instance()->setting( 'maxmind_last_update', 0 ),
			'files'           => $files,
		);
	}

	/**
	 * Run a full refresh: download every configured URL, extract any
	 * .mmdb files, and persist status.
	 *
	 * @return array{ok:bool, downloaded:int, errors:string[], files:array<string,array{size:int,mtime:int}>}
	 */
	public static function download_now(): array {
		$dir = self::ensure_dir();
		if ( is_wp_error( $dir ) ) {
			return array(
				'ok'        => false,
				'downloaded'=> 0,
				'errors'    => array( $dir->get_error_message() ),
				'files'     => array(),
			);
		}

		$urls = array_merge( self::official_urls(), self::user_urls() );
		if ( empty( $urls ) ) {
			return array(
				'ok'        => false,
				'downloaded'=> 0,
				'errors'    => array( 'No MaxMind download URLs configured.' ),
				'files'     => array(),
			);
		}

		$downloaded = 0;
		$errors     = array();
		foreach ( $urls as $url ) {
			$res = self::download_one( $url, $dir );
			if ( true === $res ) {
				$downloaded++;
			} else {
				$errors[] = $res;
			}
		}

		// Drop cached IP results so the next visitor's scan picks up the
		// fresh DBs.
		self::invalidate_ip_cache();

		$status = self::get_status();
		Plugin::instance()->update_setting( 'maxmind_last_update', time() );
		Plugin::instance()->update_setting( 'maxmind_files', $status['files'] );

		return array(
			'ok'         => $downloaded > 0,
			'downloaded' => $downloaded,
			'errors'     => $errors,
			'files'      => $status['files'],
		);
	}

	/**
	 * Download a single URL into a temp file, extract any .mmdb files into
	 * the destination directory, and clean up.
	 *
	 * @param string $url
	 * @param string $dir
	 * @return true|string True on success, error message on failure.
	 */
	private static function download_one( string $url, string $dir ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 30,
				'sslverify' => true,
				'headers'   => array(
					'User-Agent' => 'PrivacyChecker/' . PRIVACY_CHECKER_VERSION . ' (MaxMind Manager)',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return $url . ' -> ' . $response->get_error_message();
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code === 401 ) {
			return $url . ' -> HTTP 401 (license key required; add one in Settings)';
		}
		if ( $code < 200 || $code >= 300 ) {
			return $url . ' -> HTTP ' . $code;
		}

		$body = (string) wp_remote_retrieve_body( $response );
		if ( '' === $body ) {
			return $url . ' -> empty body';
		}

		$tmp = wp_tempnam( 'maxmind-' );
		if ( false === $tmp ) {
			return $url . ' -> tempnam failed';
		}
		file_put_contents( $tmp, $body ); // phpcs:ignore WordPress.WP.AlternativeFunctions

		$extracted = self::extract_mmdb( $tmp, $dir );
		@unlink( $tmp );

		if ( true !== $extracted ) {
			return $url . ' -> ' . $extracted;
		}
		return true;
	}

	/**
	 * Extract a .tar.gz or .zip file into $dir, copying only .mmdb entries
	 * that don't try to escape the directory.
	 *
	 * @param string $archive
	 * @param string $dir
	 * @return true|string
	 */
	private static function extract_mmdb( string $archive, string $dir ) {
		$extracted_any = false;
		$bytes = is_file( $archive ) ? (string) filesize( $archive ) : '0';

		if ( str_ends_with( strtolower( $archive ), '.zip' ) ) {
			if ( ! class_exists( '\\ZipArchive' ) ) {
				return 'ZipArchive extension unavailable';
			}
			$zip = new \ZipArchive();
			if ( true !== $zip->open( $archive ) ) {
				return 'failed to open zip';
			}
			$tmp_dir = wp_tempnam( 'pc-zip-' );
			@unlink( $tmp_dir );
			if ( ! mkdir( $tmp_dir, 0700, true ) && ! is_dir( $tmp_dir ) ) {
				$zip->close();
				return 'tmp dir create failed';
			}
			$zip->extractTo( $tmp_dir );
			$zip->close();
			$iter = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $tmp_dir, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iter as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}
				if ( '.mmdb' !== strtolower( substr( $file->getFilename(), -5 ) ) ) {
					continue;
				}
				$dest = $dir . '/' . $file->getFilename();
				if ( ! self::is_safe_destination( $dest, $dir ) ) {
					continue;
				}
				if ( ! @copy( $file->getPathname(), $dest ) ) {
					continue;
				}
				$extracted_any = true;
			}
			self::rrmdir( $tmp_dir );
		} else {
			// Assume .tar.gz.
			try {
				$phar = new \PharData( $archive );
			} catch ( \Throwable $e ) {
				return 'failed to open archive: ' . $e->getMessage();
			}
			try {
				$phar->decompress();
			} catch ( \Throwable $e ) {
				// Some tarballs are already decompressed.
			}
			// Iterate members safely.
			foreach ( new \RecursiveIteratorIterator( $phar ) as $file ) {
				$name = $file->getFilename();
				if ( '.mmdb' !== strtolower( substr( $name, -5 ) ) ) {
					continue;
				}
				$dest = $dir . '/' . basename( $name );
				if ( ! self::is_safe_destination( $dest, $dir ) ) {
					continue;
				}
				if ( false === file_put_contents( $dest, file_get_contents( $file->getPathname() ) ) ) {
					continue;
				}
				$extracted_any = true;
			}
			// Best-effort cleanup of decompressed .tar if PharData produced one.
			$untar = preg_replace( '/\.gz$/i', '', $archive );
			if ( is_string( $untar ) && $untar !== $archive && is_file( $untar ) ) {
				@unlink( $untar );
			}
		}

		if ( ! $extracted_any ) {
			return 'no .mmdb files found in archive';
		}
		return true;
	}

	/**
	 * Refuse any destination outside the manager's directory.
	 *
	 * @param string $dest
	 * @param string $base
	 */
	private static function is_safe_destination( string $dest, string $base ): bool {
		$real_base = realpath( $base );
		$parent    = dirname( $dest );
		$real_parent = realpath( $parent );
		if ( false === $real_parent ) {
			// Parent doesn't exist yet — make sure we'd create it under base.
			$real_parent = $base;
		}
		$real_base = $real_base ? $real_base : $base;
		return str_starts_with( $real_parent, $real_base );
	}

	private static function rrmdir( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$iter = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ( $iter as $entry ) {
			if ( $entry->isDir() ) {
				@rmdir( $entry->getPathname() );
			} else {
				@unlink( $entry->getPathname() );
			}
		}
		@rmdir( $dir );
	}

	/**
	 * Drop IP-intelligence transients so the next visitor sees fresh results.
	 */
	public static function invalidate_ip_cache(): void {
		global $wpdb;
		$wpdb->query(
			"DELETE FROM {$wpdb->options}
			 WHERE option_name LIKE '_transient_pc_ipintel_%'
			    OR option_name LIKE '_transient_timeout_pc_ipintel_%'
			    OR option_name LIKE '_transient_pc_ipfallback_%'
			    OR option_name LIKE '_transient_timeout_pc_ipfallback_%'"
		);
	}

	/**
	 * Ensure the database directory exists; create it if missing.
	 *
	 * @return string|\WP_Error
	 */
	public static function ensure_dir() {
		$dir = self::db_dir();
		if ( is_dir( $dir ) ) {
			return $dir;
		}
		$created = wp_mkdir_p( $dir );
		if ( ! $created ) {
			return new \WP_Error( 'pc_maxmind_dir', 'Unable to create MaxMind directory: ' . $dir );
		}
		// Best-effort .htaccess deny.
		$htaccess = $dir . '/.htaccess';
		if ( ! is_file( $htaccess ) ) {
			@file_put_contents( $htaccess, "Require all denied\n" );
		}
		return $dir;
	}

	/**
	 * Resolve the MaxMind database directory.
	 */
	public static function db_dir(): string {
		$uploads = wp_upload_dir();
		return rtrim( $uploads['basedir'], '/' ) . '/maxmind';
	}

	/**
	 * Register the daily cron event.
	 */
	public static function register_cron(): void {
		add_action( 'pc_maxmind_refresh', array( self::class, 'download_now' ) );
		if ( ! wp_next_scheduled( 'pc_maxmind_refresh' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'pc_maxmind_refresh' );
		}
	}
}