<?php
/**
 * MaxMind GeoLite2 IP intelligence provider (local .mmdb).
 *
 * Reads mmdb files placed under wp-content/uploads/maxmind/. The plugin ships
 * with three databases (City, ASN, Country) but can also pick up additional
 * files dropped in the same directory (e.g. GeoLite2-Anonymous-IP.mmdb).
 *
 * Database licensing: GeoLite2 data is provided by MaxMind under CC BY-SA 4.0.
 * Attribution is shown in the admin dashboard footer.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use MaxMind\Db\Reader;
use PrivacyChecker\Plugin;
use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads MaxMind .mmdb files from disk. Never throws; returns
 * status => 'unavailable' or 'error' on any failure.
 */
final class MaxmindProvider implements IpIntelligenceProviderInterface {

	/** @var string */
	private string $db_dir;

	public function __construct() {
		$this->db_dir = $this->resolve_db_dir();
	}

	public function key(): string {
		return 'maxmind';
	}

	public function label(): string {
		return 'MaxMind GeoLite2 (local)';
	}

	public function lookup( string $ip ): array {
		if ( ! Security::is_public_ip_literal( $ip ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'Invalid IP address.',
			);
		}

		$city_path   = $this->db_dir . '/GeoLite2-City.mmdb';
		$asn_path    = $this->db_dir . '/GeoLite2-ASN.mmdb';
		$country_path = $this->db_dir . '/GeoLite2-Country.mmdb';

		if ( ! is_readable( $city_path ) && ! is_readable( $country_path ) ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'MaxMind database files are not present on this server.',
			);
		}

		$result = array(
			'status' => 'ok',
			'ip'     => $ip,
		);

		$city = null;
		try {
			if ( is_readable( $city_path ) ) {
				$reader = new Reader( $city_path );
				$city   = $reader->get( $ip );
				$reader->close();
			}
		} catch ( \Throwable $e ) {
			$result['status'] = 'error';
			$result['error']  = 'GeoLite2-City read failed: ' . $e->getMessage();
		}

		$country = null;
		try {
			if ( is_readable( $country_path ) ) {
				$reader  = new Reader( $country_path );
				$country = $reader->get( $ip );
				$reader->close();
			}
		} catch ( \Throwable $e ) {
			// Country DB is a fallback only; ignore errors.
		}

		if ( is_array( $city ) ) {
			$result['continent']   = $city['continent']['code'] ?? null;
			$result['country']     = $city['country']['iso_code'] ?? null;
			$result['country_name'] = $city['country']['names']['en'] ?? null;
			$result['region']      = $city['subdivisions'][0]['names']['en'] ?? null;
			$result['region_code'] = $city['subdivisions'][0]['iso_code'] ?? null;
			$result['city']        = $city['city']['names']['en'] ?? null;
			$result['postal']      = $city['postal']['code'] ?? null;
			$result['latitude']    = isset( $city['location']['latitude'] ) ? (float) $city['location']['latitude'] : null;
			$result['longitude']   = isset( $city['location']['longitude'] ) ? (float) $city['location']['longitude'] : null;
			$result['timezone']    = $city['location']['time_zone'] ?? null;
			if ( ! empty( $city['traits']['user_type'] ) ) {
				$result['user_type'] = (string) $city['traits']['user_type'];
			}
		}

		if ( is_array( $country ) && empty( $result['country'] ) ) {
			$result['country']      = $country['country']['iso_code'] ?? null;
			$result['country_name'] = $country['country']['names']['en'] ?? null;
			$result['continent']    = $country['continent']['code'] ?? null;
		}

		try {
			if ( is_readable( $asn_path ) ) {
				$reader = new Reader( $asn_path );
				$asn    = $reader->get( $ip );
				$reader->close();
				if ( is_array( $asn ) ) {
					$result['asn']    = isset( $asn['autonomous_system_number'] ) ? 'AS' . (int) $asn['autonomous_system_number'] : null;
					$result['asn_org'] = $asn['autonomous_system_organization'] ?? null;
					if ( $result['asn'] && $result['asn_org'] ) {
						$result['org'] = $result['asn'] . ' ' . $result['asn_org'];
					}
				}
			}
		} catch ( \Throwable $e ) {
			// ASN DB optional; ignore.
		}

		// Privacy DB is optional but useful for VPN/Tor/hosting hints.
		$privacy_path = $this->db_dir . '/GeoLite2-Anonymous-IP.mmdb';
		try {
			if ( is_readable( $privacy_path ) ) {
				$reader = new Reader( $privacy_path );
				$priv   = $reader->get( $ip );
				$reader->close();
				if ( is_array( $priv ) ) {
					$result['privacy'] = array(
						'is_anonymous'    => (bool) ( $priv['is_anonymous'] ?? false ),
						'is_anonymous_vpn'=> (bool) ( $priv['is_anonymous_vpn'] ?? false ),
						'is_hosting'      => (bool) ( $priv['is_hosting'] ?? false ),
						'is_public_proxy'=> (bool) ( $priv['is_public_proxy'] ?? false ),
						'is_residential_proxy' => (bool) ( $priv['is_residential_proxy'] ?? false ),
						'is_tor_exit_node'=> (bool) ( $priv['is_tor_exit_node'] ?? false ),
					);
				}
			}
		} catch ( \Throwable $e ) {
			// ignore.
		}

		// Normalise empty strings to null so the UI shows "Unable to determine".
		foreach ( array( 'country', 'country_name', 'region', 'city', 'asn', 'asn_org', 'org', 'timezone', 'postal' ) as $field ) {
			if ( isset( $result[ $field ] ) && '' === $result[ $field ] ) {
				$result[ $field ] = null;
			}
		}

		return $result;
	}

	/**
	 * Where to look for .mmdb files.
	 *
	 * Admins can override the directory via the `maxmind_db_dir` setting.
	 */
	private function resolve_db_dir(): string {
		$configured = (string) Plugin::instance()->setting( 'maxmind_db_dir', '' );
		if ( '' !== $configured && is_dir( $configured ) ) {
			return rtrim( $configured, '/' );
		}
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['basedir'] ) ) {
			return rtrim( $uploads['basedir'], '/' ) . '/maxmind';
		}
		// Fallback (should not normally hit).
		return WP_CONTENT_DIR . '/uploads/maxmind';
	}
}