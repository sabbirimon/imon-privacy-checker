<?php
/**
 * IP intelligence fallback chain.
 *
 * Iterates through the configured provider chain and returns the first
 * provider that produced a useful `status => 'ok'` response. Each step is
 * wrapped in try/catch so a broken provider can never crash the scan.
 *
 * The final result is cached per-IP (transient-backed). Per-provider
 * intermediate failures are NOT cached, so a transient outage of one
 * provider self-heals on the next request without admin intervention.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Providers\IpapiProvider;
use PrivacyChecker\Providers\IpApiComProvider;
use PrivacyChecker\Providers\IpinfoProvider;
use PrivacyChecker\Providers\Ip2LocationProvider;
use PrivacyChecker\Providers\MaxmindProvider;
use PrivacyChecker\Providers\MockIpProvider;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IpFallback {

	/**
	 * Default chain order. MaxMind first (highest accuracy, free + offline),
	 * then ip-api.com (free, no key, second-most accurate for general lookups),
	 * then the existing ipinfo / ipapi providers, then mock as the safety net.
	 *
	 * @return string[]
	 */
	public static function default_chain(): array {
		// 'mock' is intentionally NOT included — production visitors
		// must always get real geolocation data, never mock/placeholder
		// values. Tests use build_provider('mock') directly.
		//
		// Local-first: maxmind (if .mmdb present) → ip2location (if
		// .BIN present) → ip-api.com → ipinfo → ipapi.
		return array( 'maxmind', 'ip2location', 'ip-api-com', 'ipinfo', 'ipapi' );
	}

	/**
	 * Resolve a single IP through the configured chain.
	 *
	 * @param string $ip IPv4 or IPv6 literal.
	 * @return array<string,mixed>
	 */
	public static function lookup( string $ip ): array {
		if ( ! Security::is_public_ip_literal( $ip ) ) {
			return array(
				'status' => 'error',
				'ip'     => $ip,
				'error'  => 'Non-public IP literals are not looked up.',
				'chain'  => array(),
			);
		}

		$cache_key = 'ipfallback_' . strtolower( $ip );
		$cached    = Cache::get( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$chain_keys = self::read_chain();
		$tried      = array();

		foreach ( $chain_keys as $key ) {
			$provider = self::build_provider( $key );
			if ( null === $provider ) {
				$tried[] = array(
					'key'    => $key,
					'status' => 'skipped',
					'note'   => 'Provider not configured or unavailable.',
				);
				continue;
			}

			$result = null;
			try {
				$result = $provider->lookup( $ip );
			} catch ( \Throwable $e ) {
				$tried[] = array(
					'key'    => $key,
					'label'  => $provider->label(),
					'status' => 'error',
					'error'  => $e->getMessage(),
				);
				continue;
			}

			if ( ! is_array( $result ) ) {
				$tried[] = array(
					'key'    => $key,
					'label'  => $provider->label(),
					'status' => 'error',
					'error'  => 'Provider returned non-array.',
				);
				continue;
			}

			$tried[] = array(
				'key'    => $key,
				'label'  => $provider->label(),
				'status' => $result['status'] ?? 'unknown',
				'error'  => $result['error']  ?? null,
			);

			if ( self::is_acceptable( $result ) ) {
				$result['provider_key']    = $key;
				$result['provider_label']  = $provider->label();
				$result['source']          = $key;
				$result['source_label']    = $provider->label();
				$result['chain']           = $tried;
				Cache::set( $cache_key, $result );
				return $result;
			}
		}

		// No provider in the chain returned acceptable data.
		$fallback = array(
			'status'  => 'unavailable',
			'ip'      => $ip,
			'error'   => 'No IP intelligence provider returned a usable response.',
			'chain'   => $tried,
		);
		// Cache the negative result too, but briefly, so a thundering herd of
		// visitors from the same upstream (e.g. an ISP NAT) doesn't hammer the
		// fallback chain every minute.
		Cache::set( $cache_key, $fallback, 60 );
		return $fallback;
	}

	/**
	 * Whether a result has enough signal to be useful to the UI.
	 *
	 * @param array<string,mixed> $result
	 */
	private static function is_acceptable( array $result ): bool {
		if ( ( $result['status'] ?? null ) !== 'ok' ) {
			return false;
		}
		// Accept if we got any geo or ASN signal.
		$signal_fields = array( 'country', 'country_name', 'asn', 'org', 'isp' );
		foreach ( $signal_fields as $f ) {
			if ( ! empty( $result[ $f ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read the configured chain from settings.
	 *
	 * @return string[]
	 */
	public static function read_chain(): array {
		$configured = Plugin::instance()->setting( 'provider_chain_ip', null );
		if ( is_array( $configured ) && ! empty( $configured ) ) {
			return array_values( array_filter( array_map( 'strval', $configured ) ) );
		}
		return self::default_chain();
	}

	/**
	 * Construct a provider by key, returning null when its precondition fails.
	 *
	 * @return IpIntelligenceProviderInterface|null
	 */
	private static function build_provider( string $key ): ?IpIntelligenceProviderInterface {
		switch ( $key ) {
			case 'maxmind':
				$provider = new MaxmindProvider();
				if ( ! $provider instanceof IpIntelligenceProviderInterface ) {
					return null;
				}
				return $provider;

			case 'ip2location':
				return new Ip2LocationProvider();

			case 'ip-api-com':
				return new IpApiComProvider();

			case 'ipinfo':
				return new IpinfoProvider();

			case 'ipapi':
				return new IpapiProvider();

			case 'mock':
				return new MockIpProvider();

			default:
				return null;
		}
	}

	/**
	 * Reset cache for a single IP. Useful from the admin dashboard.
	 */
	public static function flush_ip( string $ip ): bool {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		Cache::delete( 'ipfallback_' . strtolower( $ip ) );
		Cache::delete( 'ipintel_' . strtolower( $ip ) );
		return true;
	}

	/**
	 * Return the WP server's own public IP — used by the port-scan / ping
	 * features so visitors can probe their own host without admin
	 * configuration. Cached for 6 hours so we don't hit the upstream chain
	 * on every scan.
	 *
	 * Detection order:
	 *   1. Cached value (`pc_server_self_ip`).
	 *   2. `$_SERVER['SERVER_ADDR']` if it's a public literal.
	 *   3. The configured provider chain, asked for a sentinel IP, then we
	 *      take the resolver IP that answered. (Fallback only — requires
	 *      outbound network.)
	 *   4. `null` if all paths fail.
	 *
	 * @return string|null Public IPv4/IPv6 literal, or null.
	 */
	public static function server_self_ip(): ?string {
		$cached = Cache::get( 'server_self_ip' );
		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}

		$detected = null;

		// SERVER_ADDR is the easiest path on most shared hosts.
		$server_addr = isset( $_SERVER['SERVER_ADDR'] ) ? (string) $_SERVER['SERVER_ADDR'] : '';
		if ( '' !== $server_addr && Security::is_public_ip_literal( $server_addr ) ) {
			$detected = $server_addr;
		}

		// Fall back to the configured chain. We ask it to resolve
		// `127.0.0.1` (which every provider rejects as non-public); the
		// provider's outbound TCP connection still leaves a trace in the
		// `answer_ip` field of `IpIntelligence::lookup()` responses for
		// lookups performed against that provider's own infrastructure.
		// We don't depend on that — we just use `IpIntelligence` to confirm
		// outbound works. The actual self-IP comes from SERVER_ADDR above.
		// If SERVER_ADDR was empty/private, we try a single gethostbyname
		// of the WP home host as a last resort.
		if ( null === $detected ) {
			$home_host = (string) ( wp_parse_url( home_url(), PHP_URL_HOST ) ?: '' );
			if ( '' !== $home_host && ! filter_var( $home_host, FILTER_VALIDATE_IP ) ) {
				$resolved = @gethostbyname( $home_host );
				if ( $resolved !== $home_host && Security::is_public_ip_literal( $resolved ) ) {
					$detected = $resolved;
				}
			}
		}

		if ( null !== $detected ) {
			Cache::set( 'server_self_ip', $detected, 6 * HOUR_IN_SECONDS );
		}
		return $detected;
	}
}