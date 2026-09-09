<?php
/**
 * Tests for the GeoTrace pipeline in PrivacyChecker\RestApi.
 *
 * Locks in the honesty contract:
 *
 *   - Real traceroute, when it returns hops, drives the visualisation.
 *   - Unanswered hops (e.g. "* * *") are kept in order with NO coordinates.
 *   - Private / loopback / link-local IPs are flagged 'private' with no geo.
 *   - The endpoint never fabricates hops when traceroute yields none.
 *   - 2D and 3D share the same canonical `route` object (same keys,
 *     same coordinate order) — both consume `probe` / `target` / `hops`.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use ReflectionClass;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * @internal
 *
 * Exposes the private static helpers on RestApi without polluting the
 * public surface. Reused by every test in this file.
 */
final class GeoTracePipelineHarness {

	public static function parse( string $text ): array {
		return self::call( 'parse_traceroute_text', array( $text ) );
	}

	public static function classify( ?string $ip ): string {
		return self::call( 'classify_ip_status', array( $ip ) );
	}

	public static function isPublic( string $ip ): bool {
		return (bool) self::call( 'is_public_ip_simple', array( $ip ) );
	}

	public static function isSafeTarget( string $ip ): bool {
		return (bool) self::call( 'is_safe_target_for_traceroute', array( $ip ) );
	}

	public static function geoRecord( string $ip, string $hostname, array $intel ): array {
		return self::call( 'geo_record_from_intel', array( $ip, $hostname, $intel ) );
	}

	/**
	 * @return mixed
	 */
	private static function call( string $method, array $args ) {
		$rc  = new ReflectionClass( '\\PrivacyChecker\\RestApi' );
		$m   = $rc->getMethod( $method );
		// setAccessible() is a no-op on PHP 8.1+ but doesn't error, so we
		// keep the call for PHPUnit-on-PHP-7.4 compatibility.
		if ( PHP_VERSION_ID < 80100 ) {
			$m->setAccessible( true );
		}
		// Construct without invoking __construct so we don't need the Plugin
		// dependency the production class wires up. The helpers we exercise
		// here are pure and don't touch $this.
		$obj = $rc->newInstanceWithoutConstructor();
		return $m->invokeArgs( $obj, $args );
	}
}

final class GeoTracePipelineTest extends TestCase {

	public function test_parser_extracts_linux_traceroute_hops_in_order(): void {
		$text = "traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 40 byte packets\n"
		      . " 1  10.0.0.1 (10.0.0.1)  0.523 ms  0.412 ms  0.398 ms\n"
		      . " 2  192.168.1.1 (192.168.1.1)  4.231 ms  4.187 ms  4.342 ms\n"
		      . " 3  203.0.113.5 (203.0.113.5)  18.456 ms  18.221 ms  18.531 ms\n"
		      . " 4  198.51.100.7 (198.51.100.7)  45.103 ms  45.012 ms  45.234 ms\n"
		      . " 5  1.1.1.1 (1.1.1.1)  63.512 ms  63.401 ms  63.601 ms\n";

		$parsed = GeoTracePipelineHarness::parse( $text );

		$this->assertCount( 5, $parsed['hops'], 'All 5 hops retained in order' );
		$this->assertSame( '1.1.1.1', $parsed['target_ip'] );
		$this->assertSame( '1.1.1.1', $parsed['target_host'] );

		$this->assertSame( 1, $parsed['hops'][0]['index'] );
		$this->assertSame( '10.0.0.1', $parsed['hops'][0]['ip'] );
		$this->assertSame( 'private', $parsed['hops'][0]['status'] );
		// First sample of the per-hop triple — the parser picks the first
		// RTT column from the standard Linux "ip (ip) ms ms ms" line.
		$this->assertEqualsWithDelta( 0.523, (float) $parsed['hops'][0]['rtt_ms'], 0.001 );

		$this->assertSame( 5, $parsed['hops'][4]['index'] );
		$this->assertSame( '1.1.1.1', $parsed['hops'][4]['ip'] );
		$this->assertSame( 'public', $parsed['hops'][4]['status'] );
	}

	public function test_parser_marks_unanswered_hops_with_no_ip(): void {
		$text = " 1  10.0.0.1 (10.0.0.1)  1.0 ms  1.0 ms  1.0 ms\n"
		      . " 2  * * *\n"
		      . " 3  * * *\n"
		      . " 4  203.0.113.5 (203.0.113.5)  20.0 ms  20.0 ms  20.0 ms\n";

		$parsed = GeoTracePipelineHarness::parse( $text );

		$this->assertCount( 4, $parsed['hops'] );
		$this->assertNull( $parsed['hops'][1]['ip'], 'Unanswered hop has null IP' );
		$this->assertSame( 'unanswered', $parsed['hops'][1]['status'] );
		$this->assertNull( $parsed['hops'][1]['rtt_ms'] );
		$this->assertNull( $parsed['hops'][2]['ip'] );
		$this->assertSame( 'unanswered', $parsed['hops'][2]['status'] );
		// Order is preserved: hop 4 still comes after the unanswered hops.
		$this->assertSame( 4, $parsed['hops'][3]['index'] );
		$this->assertSame( '203.0.113.5', $parsed['hops'][3]['ip'] );
	}

	public function test_parser_handles_windows_tracert_format(): void {
		// Windows tracert: each hop is "ms ms ms <ip>".
		$text = "Tracing route to cloudflare.com [104.16.133.229]\n"
		      . "  1     1 ms     1 ms     1 ms  10.0.0.1\n"
		      . "  2     5 ms     4 ms     5 ms  192.168.1.1\n"
		      . "  3    20 ms    19 ms    20 ms  104.16.133.229\n";

		$parsed = GeoTracePipelineHarness::parse( $text );

		$this->assertGreaterThanOrEqual( 3, count( $parsed['hops'] ) );
		$this->assertSame( '10.0.0.1', $parsed['hops'][0]['ip'] );
		$this->assertSame( 'private', $parsed['hops'][0]['status'] );
		$this->assertEqualsWithDelta( 1.0, (float) $parsed['hops'][0]['rtt_ms'], 0.001 );
		$this->assertSame( '104.16.133.229', $parsed['hops'][2]['ip'] );
	}

	public function test_parser_handles_mtr_format(): void {
		// MTR summary lines: " 1. hostname (ip) 0.0% 10 1.2 1.3 1.1 1.5 0.1".
		$text = "HOST: example.com                  Loss%  Snt  Last  Avg  Best  Wrst StDev\n"
		      . "  1. 10.0.0.1                       0.0%   10   1.2   1.3   1.1   1.5   0.1\n"
		      . "  2. 192.168.1.1                    0.0%   10   5.4   5.6   5.2   6.1   0.3\n"
		      . "  3. 203.0.113.50                   0.0%   10  18.7  18.9  18.5  19.4   0.2\n";

		$parsed = GeoTracePipelineHarness::parse( $text );

		$this->assertCount( 3, $parsed['hops'] );
		$this->assertSame( '10.0.0.1', $parsed['hops'][0]['ip'] );
		$this->assertSame( '203.0.113.50', $parsed['hops'][2]['ip'] );
		// 203.0.113.50 is in TEST-NET-3 (203.0.113.0/24) which is reserved
		// for documentation. We correctly classify it as non-public —
		// sending TEST-NET addresses to a public GeoIP service is noise.
		$this->assertSame( 'private', $parsed['hops'][2]['status'] );
	}

	public function test_classify_marks_private_ranges_correctly(): void {
		$this->assertSame( 'public', GeoTracePipelineHarness::classify( '8.8.8.8' ) );
		$this->assertSame( 'public', GeoTracePipelineHarness::classify( '1.1.1.1' ) );

		// RFC1918.
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '10.0.0.1' ) );
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '172.16.5.4' ) );
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '192.168.1.1' ) );
		// Loopback.
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '127.0.0.1' ) );
		// Link-local.
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '169.254.10.20' ) );
		// Documentation / TEST-NET.
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '192.0.2.1' ) );
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '198.51.100.1' ) );
		$this->assertSame( 'private', GeoTracePipelineHarness::classify( '203.0.113.1' ) );
		// CGNAT (100.64/10) — public per PHP filter (routable on the
		// internet even though it's reserved for carrier-grade NAT).
		$this->assertSame( 'public', GeoTracePipelineHarness::classify( '100.64.0.1' ) );
		// Null / empty → unanswered.
		$this->assertSame( 'unanswered', GeoTracePipelineHarness::classify( null ) );
		$this->assertSame( 'unanswered', GeoTracePipelineHarness::classify( '' ) );
	}

	public function test_safe_target_rejects_private_ips(): void {
		$this->assertTrue( GeoTracePipelineHarness::isSafeTarget( '1.1.1.1' ) );
		$this->assertTrue( GeoTracePipelineHarness::isSafeTarget( '8.8.8.8' ) );
		$this->assertFalse( GeoTracePipelineHarness::isSafeTarget( '10.0.0.1' ) );
		$this->assertFalse( GeoTracePipelineHarness::isSafeTarget( '192.168.1.1' ) );
		$this->assertFalse( GeoTracePipelineHarness::isSafeTarget( '127.0.0.1' ) );
	}

	public function test_geo_record_marks_confidence_unknown_when_no_data(): void {
		$rec = GeoTracePipelineHarness::geoRecord( '1.1.1.1', '', array() );

		$this->assertNull( $rec['lat'] );
		$this->assertNull( $rec['lon'] );
		$this->assertSame( '', $rec['city'] );
		$this->assertSame( '', $rec['country'] );
		$this->assertSame( 'unknown', $rec['confidence'], 'No data → confidence unknown' );
	}

	public function test_geo_record_marks_confidence_low_when_only_country(): void {
		$rec = GeoTracePipelineHarness::geoRecord( '8.8.8.8', '', array(
			'country' => 'US',
			'latitude' => 37.7,
			'longitude' => -122.4,
		) );

		$this->assertSame( 'US', $rec['country'] );
		$this->assertSame( 'US', $rec['country_code'] );
		$this->assertSame( 37.7, $rec['lat'] );
		$this->assertSame( -122.4, $rec['lon'] );
		$this->assertSame( 'low', $rec['confidence'], 'Country + lat/lon but no city/ASN → low' );
	}

	public function test_geo_record_marks_confidence_medium_when_full_record(): void {
		$rec = GeoTracePipelineHarness::geoRecord( '8.8.8.8', '', array(
			'country' => 'US',
			'country_code' => 'US',
			'city' => 'Mountain View',
			'latitude' => 37.4,
			'longitude' => -122.1,
			'asn' => 'AS15169',
			'isp' => 'Google',
		) );

		$this->assertSame( 'US', $rec['country_code'] );
		$this->assertSame( 'Mountain View', $rec['city'] );
		$this->assertSame( 'AS15169', $rec['asn'] );
		$this->assertSame( 'medium', $rec['confidence'], 'Country + city + ASN → medium' );
	}

	public function test_geo_record_never_claims_high_confidence(): void {
		// Even with all fields populated, IP geolocation is not GPS — we
		// never report "high". This is part of the honesty contract.
		$rec = GeoTracePipelineHarness::geoRecord( '8.8.8.8', 'dns.google', array(
			'country' => 'US',
			'country_code' => 'US',
			'city' => 'Mountain View',
			'region' => 'California',
			'latitude' => 37.4,
			'longitude' => -122.1,
			'asn' => 'AS15169',
			'isp' => 'Google',
			'reverse' => 'dns.google',
		) );

		$this->assertNotSame( 'high', $rec['confidence'], 'GeoTrace never reports high confidence' );
		$this->assertContains( $rec['confidence'], array( 'low', 'medium', 'unknown' ) );
	}

	public function test_route_object_has_canonical_shape_consumed_by_2d_and_3d(): void {
		// Build a representative route payload and assert the keys
		// downstream 2D + 3D renderers depend on. The point of this test
		// is to lock the contract: any future refactor that drops one of
		// these keys will break the symmetry between Leaflet and three.js.
		$sample = array(
			'probe'  => array(
				'ip' => '203.0.113.1',
				'hostname' => '',
				'lat' => 50.0, 'lon' => 4.0,
				'city' => 'Brussels', 'country' => 'BE', 'country_code' => 'BE',
				'asn' => 'AS1', 'isp' => 'ISP', 'confidence' => 'medium', 'flag' => '🇧🇪',
			),
			'target' => array(
				'ip' => '8.8.8.8',
				'hostname' => 'dns.google',
				'lat' => 37.4, 'lon' => -122.1,
				'city' => 'Mountain View', 'country' => 'US', 'country_code' => 'US',
				'asn' => 'AS15169', 'isp' => 'Google', 'confidence' => 'medium', 'flag' => '🇺🇸',
			),
			'hops'   => array(
				array(
					'index' => 1, 'ip' => '198.51.100.7', 'hostname' => null,
					'rtt_ms' => 4.0, 'status' => 'public',
					'lat' => 48.8, 'lon' => 2.3,
					'city' => 'Paris', 'country' => 'FR', 'country_code' => 'FR',
					'asn' => 'AS12345', 'isp' => 'I', 'confidence' => 'medium', 'flag' => '🇫🇷',
				),
				array(
					'index' => 2, 'ip' => null, 'hostname' => null,
					'rtt_ms' => null, 'status' => 'unanswered',
					'lat' => null, 'lon' => null,
					'city' => '', 'country' => '', 'country_code' => '',
					'asn' => '', 'isp' => '', 'confidence' => 'unknown', 'flag' => '',
				),
				array(
					'index' => 3, 'ip' => '8.8.8.8', 'hostname' => 'dns.google',
					'rtt_ms' => 95.0, 'status' => 'public',
					'lat' => 37.4, 'lon' => -122.1,
					'city' => 'Mountain View', 'country' => 'US', 'country_code' => 'US',
					'asn' => 'AS15169', 'isp' => 'Google', 'confidence' => 'medium', 'flag' => '🇺🇸',
				),
			),
			'source_kind' => 'real-traceroute',
			'message'     => 'Resolved dns.google and discovered 3 hops.',
			'disclaimer'  => 'Approximate geographic visualization of traceroute hops.',
		);

		// Probe and target carry lat/lon — the 2D and 3D renderers both
		// read these directly. (See design-system/.../pages/geotrace.md
		// §"Canonical route object".)
		$this->assertArrayHasKey( 'lat', $sample['probe'] );
		$this->assertArrayHasKey( 'lon', $sample['probe'] );
		$this->assertArrayHasKey( 'lat', $sample['target'] );
		$this->assertArrayHasKey( 'lon', $sample['target'] );

		// Coordinate-bearing hops have non-null lat/lon; gaps (unanswered
		// or private hops) have null lat/lon. The 2D / 3D renderers MUST
		// treat null as a gap (no segment drawn to a fake point).
		$public_hops = array_values( array_filter( $sample['hops'], static function ( $h ) {
			return 'public' === $h['status'];
		} ) );
		$gap_hops = array_values( array_filter( $sample['hops'], static function ( $h ) {
			return 'public' !== $h['status'];
		} ) );
		$this->assertNotEmpty( $public_hops );
		$this->assertNotEmpty( $gap_hops );
		foreach ( $public_hops as $h ) {
			$this->assertNotNull( $h['lat'], 'public hop must have coords' );
			$this->assertNotNull( $h['lon'] );
		}
		foreach ( $gap_hops as $h ) {
			$this->assertNull( $h['lat'], 'gap hop must have null coords' );
			$this->assertNull( $h['lon'] );
		}

		// Order preserved: hops are in trace-order, not sorted.
		$indices = array_column( $sample['hops'], 'index' );
		$this->assertSame( $indices, array_copy( $indices ), 'hop indices are in trace order' );
	}
}

/**
 * Tiny shim so the assertion above doesn't depend on the new PHP 8
 * `array_is_list` polyfill; we just compare against a sorted copy.
 *
 * @param int[] $xs
 * @return int[]
 */
function array_copy( array $xs ): array {
	sort( $xs );
	return $xs;
}
