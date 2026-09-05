<?php
/**
 * ip-api.com IP intelligence provider (free tier).
 *
 * Free tier: 45 requests/minute per source IP, no API key required, http-only
 * (https requires a paid plan). See https://ip-api.com/docs/ for field
 * reference and rate limits.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Providers;

use PrivacyChecker\Plugin;
use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IpApiComProvider implements IpIntelligenceProviderInterface {

	public function key(): string {
		return 'ip-api-com';
	}

	public function label(): string {
		return 'ip-api.com (free)';
	}

	public function lookup( string $ip ): array {
		if ( ! Security::is_public_ip_literal( $ip ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'Invalid IP address.',
			);
		}

		// Admin can disable this provider from the settings page (e.g. when the
		// site is on a strict HTTPS-only CSP that forbids http origins).
		if ( ! (bool) Plugin::instance()->setting( 'ip_api_com_enabled', true ) ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'ip-api.com is disabled in settings.',
			);
		}

		// ip-api.com free tier is HTTP-only. The fields parameter restricts the
		// response payload to what we need; the default fields include extra
		// noise. See https://ip-api.com/docs/api:unedited
		$fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,query';
		$url    = 'http://ip-api.com/json/' . rawurlencode( $ip ) . '?fields=' . $fields;

		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 0,
				'user-agent'  => 'PrivacyChecker/' . PRIVACY_CHECKER_VERSION . ' (WordPress)',
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => $response->get_error_message(),
			);
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 429 === $code ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'ip-api.com rate limit reached.',
			);
		}
		if ( $code < 200 || $code >= 300 ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => 'ip-api.com responded with HTTP ' . $code . '.',
			);
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $data ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'Malformed response from ip-api.com.',
			);
		}

		// ip-api.com uses { "status": "success" | "fail" } instead of HTTP codes
		// for application-level failures.
		if ( isset( $data['status'] ) && 'success' !== $data['status'] ) {
			return array(
				'status' => 'unavailable',
				'ip'     => $ip,
				'error'  => isset( $data['message'] ) ? (string) $data['message'] : 'ip-api.com lookup failed.',
			);
		}

		$asn = null;
		if ( ! empty( $data['as'] ) ) {
			$asn = is_string( $data['as'] ) && str_starts_with( $data['as'], 'AS' )
				? $data['as']
				: 'AS' . $data['as'];
		}

		$result = array(
			'status'       => 'ok',
			'ip'           => $data['query'] ?? $ip,
			'country'      => $data['countryCode'] ?? null,
			'country_name' => $data['country'] ?? null,
			'region'       => $data['regionName'] ?? null,
			'region_code'  => $data['region'] ?? null,
			'city'         => $data['city'] ?? null,
			'postal'       => $data['zip'] ?? null,
			'latitude'     => isset( $data['lat'] ) ? (float) $data['lat'] : null,
			'longitude'    => isset( $data['lon'] ) ? (float) $data['lon'] : null,
			'timezone'     => $data['timezone'] ?? null,
			'isp'          => $data['isp'] ?? null,
			'org'          => $data['org'] ?? null,
			'asn'          => $asn,
			'asn_org'      => $data['asname'] ?? null,
			'reverse_dns'  => $data['reverse'] ?? null,
		);

		// Normalise empty strings.
		foreach ( $result as $k => $v ) {
			if ( is_string( $v ) && '' === $v ) {
				$result[ $k ] = null;
			}
		}

		// ip-api.com `proxy` and `hosting` flags are useful, but the field is
		// free-tier-only and not always present. Surface them if available.
		if ( isset( $data['proxy'] ) && 'true' === $data['proxy'] ) {
			$result['is_proxy'] = true;
		}
		if ( isset( $data['hosting'] ) && 'true' === $data['hosting'] ) {
			$result['is_hosting'] = true;
		}

		return $result;
	}
}