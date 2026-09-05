<?php
/**
 * Tests for PrivacyChecker\BrowserVersions — small static lookup that
 * classifies a browser family + major version as current / outdated /
 * very_outdated. Coverage limited to Chrome/Firefox/Safari/Edge.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\BrowserVersions;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class BrowserVersionsTest extends TestCase {

	public function test_chrome_at_or_above_current_is_current(): void {
		$r = BrowserVersions::check( 'Chrome', 145 );
		$this->assertSame( 'current', $r['status'] );
		$this->assertSame( 'Chrome',  $r['browser'] );
		$this->assertSame( 145,       $r['version'] );
		$this->assertStringContainsString( 'no update', $r['message'] );
	}

	public function test_chrome_between_thresholds_is_outdated(): void {
		// current=130, outdated_cutoff=100 → 120 should be outdated.
		$r = BrowserVersions::check( 'Chrome', 120 );
		$this->assertSame( 'outdated', $r['status'] );
		$this->assertStringContainsString( 'update when convenient', $r['message'] );
	}

	public function test_chrome_below_outdated_cutoff_is_very_outdated(): void {
		$r = BrowserVersions::check( 'Chrome', 95 );
		$this->assertSame( 'very_outdated', $r['status'] );
		$this->assertStringContainsString( 'known security issues', $r['message'] );
	}

	public function test_firefox_at_current_is_current(): void {
		$r = BrowserVersions::check( 'Firefox', 130 );
		$this->assertSame( 'current', $r['status'] );
	}

	public function test_firefox_below_cutoff_is_very_outdated(): void {
		$r = BrowserVersions::check( 'Firefox', 88 );
		$this->assertSame( 'very_outdated', $r['status'] );
	}

	public function test_safari_at_current_is_current(): void {
		$r = BrowserVersions::check( 'Safari', 17 );
		$this->assertSame( 'current', $r['status'] );
	}

	public function test_safari_below_14_is_very_outdated(): void {
		$r = BrowserVersions::check( 'Safari', 13 );
		$this->assertSame( 'very_outdated', $r['status'] );
	}

	public function test_edge_uses_chrome_thresholds(): void {
		// Edge shares Chrome's cycle.
		$r = BrowserVersions::check( 'Edge', 120 );
		$this->assertSame( 'outdated', $r['status'] );

		$r = BrowserVersions::check( 'Edge', 145 );
		$this->assertSame( 'current', $r['status'] );
	}

	public function test_unknown_family_returns_unknown_family_status(): void {
		$r = BrowserVersions::check( 'Opera', 100 );
		$this->assertSame( 'unknown_family', $r['status'] );
		$this->assertSame( 'Opera', $r['browser'] );
		$this->assertSame( 100,      $r['version'] );
		$this->assertStringContainsString( 'No version guidance', $r['message'] );
	}

	public function test_empty_browser_name_is_unknown_family(): void {
		$r = BrowserVersions::check( '', 100 );
		$this->assertSame( 'unknown_family', $r['status'] );
	}

	public function test_null_version_returns_unknown_version_for_known_family(): void {
		$r = BrowserVersions::check( 'Chrome', null );
		$this->assertSame( 'unknown_version', $r['status'] );
		$this->assertSame( 'Chrome', $r['browser'] );
		$this->assertNull(         $r['version'] );
	}

	public function test_zero_version_returns_unknown_version(): void {
		$r = BrowserVersions::check( 'Firefox', 0 );
		$this->assertSame( 'unknown_version', $r['status'] );
	}

	public function test_negative_version_returns_unknown_version(): void {
		$r = BrowserVersions::check( 'Edge', -5 );
		$this->assertSame( 'unknown_version', $r['status'] );
	}

	public function test_result_always_contains_required_keys(): void {
		// Defensive shape check — never surface a partial structure.
		$r = BrowserVersions::check( 'Chrome', 145 );
		$this->assertArrayHasKey( 'status',  $r );
		$this->assertArrayHasKey( 'browser', $r );
		$this->assertArrayHasKey( 'version', $r );
		$this->assertArrayHasKey( 'message', $r );
		$this->assertNotEmpty( $r['message'] );
	}

	/**
	 * Phase 8: the public thresholds() getter exposes the threshold table
	 * so the admin "Scoring Parameters" reference card can render from
	 * this single source of truth.
	 */
	public function test_thresholds_getter_returns_expected_four_families(): void {
		$t = BrowserVersions::thresholds();

		$this->assertArrayHasKey( 'Chrome',  $t );
		$this->assertArrayHasKey( 'Firefox', $t );
		$this->assertArrayHasKey( 'Safari',  $t );
		$this->assertArrayHasKey( 'Edge',    $t );

		// Shape per family.
		foreach ( $t as $family => $row ) {
			$this->assertArrayHasKey( 'current',         $row, "$family missing current" );
			$this->assertArrayHasKey( 'outdated_cutoff', $row, "$family missing outdated_cutoff" );
			$this->assertIsInt( $row['current'] );
			$this->assertIsInt( $row['outdated_cutoff'] );
			$this->assertGreaterThan( $row['outdated_cutoff'], $row['current'] );
		}

		// Pin the specific values that the reference card renders.
		$this->assertSame( 130, $t['Chrome']['current'] );
		$this->assertSame( 100, $t['Chrome']['outdated_cutoff'] );
		$this->assertSame( 125, $t['Firefox']['current'] );
		$this->assertSame( 17,  $t['Safari']['current'] );
		$this->assertSame( 14,  $t['Safari']['outdated_cutoff'] );
		$this->assertSame( 130, $t['Edge']['current'] );
	}
}
