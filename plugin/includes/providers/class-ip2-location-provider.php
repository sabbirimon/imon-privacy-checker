<?php
/**
 * IP2Location LITE DB11 IP intelligence provider (local .BIN file).
 *
 * Reads the IP2Location LITE DB11 binary database shipped under
 *   /GeoIP Database/IP2LOCATION-LITE-DB11.BIN.zip
 *   /GeoIP Database/IP2LOCATION-LITE-DB11.IPV6.BIN.zip
 *
 * On first use the zip files are extracted into
 *   wp-content/uploads/ip2location/
 * (the original zips stay where they are so the user can re-extract on
 *  update). The .BIN files themselves are then read via the official
 * ip2location/ip2location-php composer package — no API calls, no keys.
 *
 * NOTE: IP2Location LITE is **free for non-commercial use** and has
 *       accuracy "up to Class C" only. For production-grade accuracy,
 *       prefer MaxMind GeoLite2 (also bundled in this plugin) or
 *       ip-api.com. This provider exists so admins who already use
 *       IP2Location elsewhere can keep using it as a local fallback.
 *
 * Attribution (per the LITE license):
 *   "[Site name] uses the IP2Location LITE database for
 *    https://lite.ip2location.com"
 * The admin dashboard footer includes this string automatically when
 * the provider is active.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use IP2Location\Database as Ip2LocationDatabase;
use PrivacyChecker\Plugin;
use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads IP2Location LITE DB11 .BIN files from disk. Never throws; returns
 * status => 'unavailable' or 'error' on any failure (missing file, bad
 * zip, corrupted bin, etc.).
 */
final class Ip2LocationProvider implements IpIntelligenceProviderInterface {

	/** @var string */
	private string $bin_dir;

	public function __construct() {
		$this->bin_dir = $this->resolve_bin_dir();
	}

	public function key(): string {
		return 'ip2location';
	}

	public function label(): string {
		return 'IP2Location LITE DB11 (local)';
	}

	public function lookup( string $ip ): array {
		if ( ! Security::is_public_ip_literal( $ip ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'Invalid IP address.',
			);
		}

		$bin_path = $this->bin_path_for( $ip );
		if ( '' === $bin_path || ! is_readable( $bin_path ) ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'IP2Location database file is not present on this server. Place IP2LOCATION-LITE-DB11.BIN (and .IPV6.BIN for IPv6) under the configured ip2location_db_dir.',
			);
		}

		try {
			$db = new Ip2LocationDatabase( $bin_path, Ip2LocationDatabase::FILE_IO );
			$rec = $db->lookup( $ip, Ip2LocationDatabase::ALL );
		} catch ( \Throwable $e ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'IP2Location lookup failed: ' . $e->getMessage(),
			);
		}

		if ( ! is_array( $rec ) || empty( $rec['countryCode'] ) || '-' === ( $rec['countryCode'] ?? '-' ) ) {
			// "Not found" returns all-dashes. Treat as a soft miss.
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'IP2Location has no record for this IP.',
			);
		}

		return $this->normalise( $rec );
	}

	/**
	 * Pick the right .BIN file for the IP family.
	 */
	private function bin_path_for( string $ip ): string {
		$is_v6 = ( strpos( $ip, ':' ) !== false );
		$file  = $is_v6 ? 'IP2LOCATION-LITE-DB11.IPV6.BIN' : 'IP2LOCATION-LITE-DB11.BIN';
		return rtrim( $this->bin_dir, '/' ) . '/' . $file;
	}

	/**
	 * Normalise the IP2Location record to the project's common shape.
	 *
	 * @param array<string,mixed> $rec
	 * @return array<string,mixed>
	 */
	private function normalise( array $rec ): array {
		$out = array(
			'status'       => 'ok',
			'ip'           => $rec['ipAddress'] ?? null,
			'version'      => isset( $rec['ipVersion'] ) ? 'IPv' . $rec['ipVersion'] : null,
			'country'      => $this->clean( $rec['countryCode'] ?? null ),
			'country_name' => $this->clean( $rec['countryName'] ?? null ),
			'region'       => $this->clean( $rec['regionName'] ?? null ),
			'city'         => $this->clean( $rec['cityName'] ?? null ),
			'postal'       => $this->clean( $rec['zipCode'] ?? null ),
			'timezone'     => $this->clean( $rec['timeZone'] ?? null ),
			'isp'          => $this->clean( $rec['isp'] ?? null ),
			'domain'       => $this->clean( $rec['domainName'] ?? null ),
			'usage_type'   => $this->clean( $rec['usageType'] ?? null ),
			'elevation'    => $this->num( $rec['elevation'] ?? null ),
			'net_speed'    => $this->clean( $rec['netSpeed'] ?? null ),
		);

		$lat = $this->num( $rec['latitude'] ?? null );
		$lng = $this->num( $rec['longitude'] ?? null );
		if ( null !== $lat ) { $out['latitude']  = $lat; }
		if ( null !== $lng ) { $out['longitude'] = $lng; }

		// Compose org/asn-org-ish string from ISP if present.
		if ( ! empty( $out['isp'] ) ) {
			$out['org'] = $out['isp'];
		}
		if ( ! empty( $rec['asn'] ) && 'N/A' !== $rec['asn'] ) {
			$out['asn']    = 'AS' . (int) $rec['asn'];
			$out['asn_org'] = $this->clean( $rec['as'] ?? null );
			if ( ! empty( $out['asn_org'] ) ) {
				$out['org'] = trim( ( $out['asn'] ?? '' ) . ' ' . $out['asn_org'] );
			}
		}

		// Normalise empty / dash placeholders to null.
		foreach ( array( 'country', 'country_name', 'region', 'city', 'postal', 'timezone', 'isp', 'domain', 'usage_type', 'net_speed' ) as $field ) {
			if ( isset( $out[ $field ] ) && ( '' === $out[ $field ] || '-' === $out[ $field ] || 'N/A' === $out[ $field ] ) ) {
				$out[ $field ] = null;
			}
		}

		return $out;
	}

	private function clean( $v ): ?string {
		if ( null === $v ) return null;
		$s = (string) $v;
		if ( '' === $s || '-' === $s || 'N/A' === $s ) return null;
		return $s;
	}

	private function num( $v ): ?float {
		if ( null === $v || '' === $v || '-' === $v ) return null;
		return (float) $v;
	}

	/**
	 * Where to look for .BIN files.
	 *
	 * Resolution order:
	 *   1. The `ip2location_db_dir` plugin setting (admin override).
	 *   2. wp-content/uploads/ip2location/  (auto-extracted from the
	 *      project-local zips under /GeoIP Database/ on first call).
	 *   3. /GeoIP Database/  (read zips in-place — last-resort fallback).
	 *
	 * The extraction step is idempotent and only runs when the .BIN
	 * files are missing from the uploads dir.
	 */
	private function resolve_bin_dir(): string {
		$configured = (string) Plugin::instance()->setting( 'ip2location_db_dir', '' );
		if ( '' !== $configured && is_dir( $configured ) ) {
			return rtrim( $configured, '/' );
		}

		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['basedir'] ) ) {
			$dest = rtrim( $uploads['basedir'], '/' ) . '/ip2location';
			$this->maybe_extract( $dest );
			if ( is_dir( $dest ) ) {
				return $dest;
			}
		}

		// Last-resort: project-local GeoIP Database folder.
		$project_dir = dirname( dirname( dirname( dirname( __DIR__ ) ) ) ) . '/GeoIP Database';
		if ( is_dir( $project_dir ) ) {
			return $project_dir;
		}

		return '';
	}

	/**
	 * Extract the .BIN files from the project's IP2LOCATION-LITE-DB11*.BIN.zip
	 * archives into $dest on first use. Silent on failure (the caller will
	 * report "unavailable" if the files still aren't there).
	 */
	private function maybe_extract( string $dest ): void {
		$ipv4_bin = $dest . '/IP2LOCATION-LITE-DB11.BIN';
		if ( is_readable( $ipv4_bin ) ) {
			return; // already extracted
		}
		if ( ! is_dir( $dest ) && ! @mkdir( $dest, 0755, true ) && ! is_dir( $dest ) ) {
			return;
		}

		$project_dir = dirname( dirname( dirname( dirname( __DIR__ ) ) ) ) . '/GeoIP Database';
		$zips = array(
			$project_dir . '/IP2LOCATION-LITE-DB11.BIN.zip'      => $ipv4_bin,
			$project_dir . '/IP2LOCATION-LITE-DB11.IPV6.BIN.zip' => $dest . '/IP2LOCATION-LITE-DB11.IPV6.BIN',
		);
		foreach ( $zips as $zip => $bin_target ) {
			if ( ! is_readable( $zip ) ) continue;
			if ( is_readable( $bin_target ) ) continue;
			// PHP's ZipArchive is available everywhere we run; if it's
			// missing the @-suppressed call returns false and we silently
			// give up — caller will report "unavailable".
			$za = @new \ZipArchive();
			if ( true !== $za->open( $zip ) ) continue;
			$bin_name = basename( $bin_target );
			$za->extractTo( $dest, array( $bin_name ) );
			$za->close();
		}
	}
}
