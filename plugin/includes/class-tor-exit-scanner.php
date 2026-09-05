<?php
/**
 * Tor / VPN / proxy exit-list scanner.
 *
 * Reads uploaded exit-list files (plain IP list, CSV with IP + extra columns,
 * or IP2Location-style BIN/MMDB via the configured providers) and answers
 * "is this visitor IP a known Tor exit / VPN / proxy / datacenter / mobile?"
 *
 * Files are looked up by category tag:
 *   • tor     — Tor exit-node list (https://check.torproject.org/exit-addresses,
 *               dan.me.uk / torstatus, etc.).
 *   • vpn     — Commercial VPN provider IP ranges.
 *   • proxy   — Open proxies (any kind).
 *   • datacenter — Hosting/cloud IP ranges.
 *   • mobile  — Mobile carrier ranges.
 *   • reputation — IP reputation / blacklists.
 *
 * Lookups are O(N) in the file's line count because exit lists are not big
 * enough to warrant a tree and we want zero external dependencies. The file
 * is cached via Cache::remember() for 5 minutes per IP.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class TorExitScanner {

	/**
	 * Maximum bytes of an exit-list file to actually scan in one request.
	 * Tor exit list is ~1-2 MB; we cap at 32 MB to keep request latency bounded.
	 */
	private const MAX_FILE_BYTES = 32 * 1024 * 1024;

	/**
	 * Categories of lists this scanner understands.
	 *
	 * @return string[]
	 */
	public static function supported_categories(): array {
		return array( 'tor', 'vpn', 'proxy', 'datacenter', 'mobile', 'reputation' );
	}

	/**
	 * Look up an IP in every uploaded exit-list / proxy list whose category is
	 * one of the supported ones. Returns a per-category verdict, with Tor
	 * flagged explicitly. The first match in each category wins.
	 *
	 * @param string $ip IPv4 or IPv6 literal.
	 * @return array<string, array<string, mixed>>
	 */
	public static function lookup( string $ip ): array {
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return array();
		}
		$cache_key = 'pc_tor_lookup_' . hash( 'xxh3', $ip );
		$cached    = Cache::get( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$rows     = GeoIpDatabase::list_with_meta();
		$verdicts = array();

		foreach ( self::supported_categories() as $cat ) {
			$hit = null;
			foreach ( $rows as $row ) {
				if ( $row['category'] !== $cat ) {
					continue;
				}
				$path = isset( $row['path'] ) ? (string) $row['path'] : '';
				if ( '' === $path || ! is_readable( $path ) ) {
					continue;
				}
				$match = self::scan_file( $path, $ip );
				if ( $match ) {
					$hit = array(
						'category' => $cat,
						'matched'  => true,
						'source'   => $row['name'],
						'format'   => $row['format'],
						'match'    => $match,
					);
					break;
				}
			}
			$verdicts[ $cat ] = $hit ?: array(
				'category' => $cat,
				'matched'  => false,
			);
		}

		Cache::set( $cache_key, $verdicts, 5 * MINUTE_IN_SECONDS );
		return $verdicts;
	}

	/**
	 * Convenience: return a single Tor verdict for an IP.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function is_tor_exit( string $ip ): ?array {
		$all = self::lookup( $ip );
		return $all['tor'] ?? null;
	}

	/**
	 * Scan a single file for the IP. Returns the matching line (trimmed) or
	 * null on no match. Supports:
	 *   • plain-IP lists (one IPv4/IPv6 literal per line, # comments ok)
	 *   • CSV / Tor exit-addresses / dan.me.uk style lists with an IP column
	 *   • IP2Location / MaxMind binary DBs (delegated to the providers)
	 *
	 * @return string|null
	 */
	private static function scan_file( string $path, string $ip ): ?string {
		$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );

		// Binary DBs: delegate to the configured provider if it understands
		// the format. This keeps the scanner from having to parse the DB
		// directly.
		if ( 'bin' === $ext || 'mmdb' === $ext ) {
			$result = self::lookup_via_provider( $path, $ip );
			return null !== $result ? wp_json_encode( $result ) : null;
		}

		// Plain text / CSV lists.
		if ( filesize( $path ) > self::MAX_FILE_BYTES ) {
			return null;
		}
		$fh = @fopen( $path, 'r' );
		if ( ! $fh ) {
			return null;
		}
		$matched = null;
		$needle  = strtolower( $ip );
		while ( ! feof( $fh ) ) {
			$line = fgets( $fh );
			if ( false === $line ) {
				break;
			}
			$line = trim( $line );
			if ( '' === $line || '#' === substr( $line, 0, 1 ) ) {
				continue;
			}
			// Strip CSV to the IP column when present.
			$candidate = $line;
			if ( false !== strpos( $line, ',' ) ) {
				$parts = str_getcsv( $line, ',', '"', '\\' );
				// Prefer columns that look like IPs.
				foreach ( $parts as $p ) {
					$p = trim( $p );
					if ( filter_var( $p, FILTER_VALIDATE_IP ) ) {
						$candidate = $p;
						break;
					}
				}
			} else {
				// Whitespace-separated list (e.g. dan.me.uk torstatus).
				$parts = preg_split( '/\s+/', $line );
				foreach ( $parts as $p ) {
					if ( filter_var( $p, FILTER_VALIDATE_IP ) ) {
						$candidate = $p;
						break;
					}
				}
			}
			if ( strtolower( $candidate ) === $needle ) {
				$matched = $line;
				break;
			}
		}
		fclose( $fh );
		return $matched;
	}

	/**
	 * Look up an IP in a binary DB by asking the configured IP-intelligence
	 * provider. Returns whatever shape the provider yields (typically
	 * {country, isp, proxy, ...}).
	 *
	 * @return array<string, mixed>|null
	 */
	private static function lookup_via_provider( string $path, string $ip ): ?array {
		try {
			$plugin = Plugin::instance();
			$provider = $plugin->provider(
				\PrivacyChecker\Provider\IpIntelligenceProviderInterface::class,
				(string) $plugin->setting( 'ip_provider', 'mock' )
			);
			$result = $provider->lookup( $ip );
			return is_array( $result ) ? $result : null;
		} catch ( \Throwable $e ) {
			return null;
		}
	}
}
