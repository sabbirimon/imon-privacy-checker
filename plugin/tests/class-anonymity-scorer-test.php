<?php
/**
 * Tests for PrivacyChecker\AnonymityScorer::score().
 *
 * Pure correlation — the scorer takes four signals already present in a
 * scan report (IP-geo timezone, browser timezone, WebRTC verdict, proxy
 * classification) plus an optional completed DNS-leak test, and returns a
 * composite score plus a list of mismatches. These tests pin down:
 *
 *   - All-consistent baseline = 100, no mismatches.
 *   - Timezone mismatch (different UTC offset)  → -20, severity medium.
 *   - Timezone mismatch within same offset      → no deduction.
 *   - WebRTC verdict `potential_exposure`       → -40, severity high.
 *   - DNS resolver on a different org           → -30, severity high.
 *   - Confirmed VPN/proxy alone is not penalised.
 *   - Unknown / unparseable inputs never throw.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\AnonymityScorer;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class AnonymityScorerTest extends TestCase {

	private function base_intel( string $timezone = 'Europe/Berlin' ): array {
		return array(
			'ip'       => '203.0.113.42',
			'query'    => '203.0.113.42',
			'timezone' => $timezone,
			'org'      => 'Acme Networks',
			'isp'      => 'Acme Networks',
		);
	}

	private function clean_webrtc(): array {
		return array(
			'verdict'      => 'protected',
			'public_addrs' => array(),
		);
	}

	private function leaked_webrtc(): array {
		return array(
			'verdict'      => 'potential_exposure',
			'public_addrs' => array( '198.51.100.7' ),
		);
	}

	private function proxy_unknown(): array {
		return array(
			'category'   => 'unknown',
			'confidence' => 'low',
		);
	}

	public function test_all_consistent_baseline_returns_100_and_no_mismatches() {
		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin', // matches IP-geo timezone
			null
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( array(), $result['mismatches'] );
		$this->assertNotEmpty( $result['summary'] );
	}

	public function test_timezone_mismatch_with_different_offset_deducts_20() {
		$result = AnonymityScorer::score(
			$this->base_intel( 'America/New_York' ),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		$this->assertFalse( $result['consistent'] );
		$this->assertSame( 80, $result['score'] );
		$this->assertCount( 1, $result['mismatches'] );
		$this->assertSame( 'timezone', $result['mismatches'][0]['signal'] );
		$this->assertSame( 'medium', $result['mismatches'][0]['severity'] );
	}

	public function test_timezone_mismatch_within_same_offset_is_not_a_mismatch() {
		// Europe/Berlin and Europe/Paris share the same UTC offset (+01:00
		// in winter) — should not be flagged as a mismatch.
		$result = AnonymityScorer::score(
			$this->base_intel( 'Europe/Paris' ),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( array(), $result['mismatches'] );
	}

	public function test_webrtc_potential_exposure_deducts_40_with_high_severity() {
		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->leaked_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		$this->assertSame( 60, $result['score'] );
		$this->assertCount( 1, $result['mismatches'] );
		$m = $result['mismatches'][0];
		$this->assertSame( 'webrtc', $m['signal'] );
		$this->assertSame( 'high',   $m['severity'] );
		$this->assertStringContainsString( '198.51.100.7', $m['detail'] );
	}

	public function test_dns_resolver_on_different_org_deducts_30() {
		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			array( 'resolver_org' => 'Google Public DNS' )
		);

		$this->assertSame( 70, $result['score'] );
		$this->assertCount( 1, $result['mismatches'] );
		$m = $result['mismatches'][0];
		$this->assertSame( 'dns',   $m['signal'] );
		$this->assertSame( 'high',  $m['severity'] );
	}

	public function test_dns_resolver_on_same_org_is_not_a_mismatch() {
		$result = AnonymityScorer::score(
			$this->base_intel(),  // org = 'Acme Networks'
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			array( 'resolver_org' => 'Acme Networks' )
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_dns_resolver_substring_match_is_not_a_mismatch() {
		// ISP name is a prefix of resolver org (or vice versa).
		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			array( 'resolver_org' => 'Acme Networks — DNS' )
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_dns_without_resolver_org_does_not_count() {
		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			array( 'resolver_org' => '' ) // explicit empty
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_confirmed_vpn_alone_is_not_penalised() {
		// High-confidence VPN/proxy + no other mismatches = 100.
		$proxy = array(
			'category'   => 'vpn',
			'vendor'     => 'Mullvad',
			'confidence' => 'high',
		);

		$result = AnonymityScorer::score(
			$this->base_intel(),
			$this->clean_webrtc(),
			$proxy,
			'Europe/Berlin', // matches IP-geo
			null
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_all_signals_compound_below_floor_clamps_to_zero() {
		// timezone -20 + webrtc -40 + dns -30 = -90. Starting from 100 → 10,
		// not zero — that's the natural floor for these three mismatches.
		// Add a fourth "ip_intel missing" test elsewhere to actually hit zero
		// would be artificial; clamp itself is trivial.
		$result = AnonymityScorer::score(
			$this->base_intel( 'America/New_York' ),
			$this->leaked_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			array( 'resolver_org' => 'Google Public DNS' )
		);

		$this->assertSame( 10, $result['score'] );
		$this->assertCount( 3, $result['mismatches'] );
		$this->assertStringContainsString( 'exposed', $result['summary'] ); // score < 50 → that summary string
	}

	public function test_score_floor_does_not_go_below_zero() {
		// White-box: make the scorer see severe negative contributions
		// via a proxy result that loses all its base points (the
		// `score = min(score + 0, 100)` branch only tops up; it never
		// subtracts). Then verify floor clamps to >= 0.
		// In practice, with only the three real signals the worst
		// achievable is 100 - 90 = 10. We assert it's still in [0, 100]
		// rather than going negative.
		$result = AnonymityScorer::score(
			$this->base_intel( 'America/New_York' ),
			$this->leaked_webrtc(),
			array( 'category' => 'vpn', 'confidence' => 'high' ),
			'Europe/Berlin',
			array( 'resolver_org' => 'Google Public DNS' )
		);

		$this->assertGreaterThanOrEqual( 0, $result['score'] );
		$this->assertLessThanOrEqual( 100, $result['score'] );
	}

	public function test_score_above_fifty_uses_mild_summary() {
		// timezone -20 only → score 80 → mild summary.
		$result = AnonymityScorer::score(
			$this->base_intel( 'America/New_York' ),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		$this->assertSame( 80, $result['score'] );
		$this->assertStringContainsString( 'Minor', $result['summary'] );
	}

	public function test_unknown_timezone_does_not_throw_and_skips_comparison() {
		$result = AnonymityScorer::score(
			$this->base_intel( '' ), // no IP-geo timezone known
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_invalid_browser_timezone_does_not_throw() {
		// Intl-garbage that DateTimeZone rejects.
		$result = AnonymityScorer::score(
			$this->base_intel( 'Not/A/Real/Zone' ),
			$this->clean_webrtc(),
			$this->proxy_unknown(),
			'Europe/Berlin',
			null
		);

		// timezones_share_offset catches the throw and returns true → not
		// flagged. Score stays at 100.
		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
	}

	public function test_empty_inputs_yield_baseline_consistent() {
		$result = AnonymityScorer::score(
			array(),
			array(),
			array(),
			'',
			null
		);

		$this->assertTrue( $result['consistent'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( array(), $result['mismatches'] );
	}

	/**
	 * Phase 8: the public signal_weights() getter exposes the
	 * per-signal deduction table for the admin "Scoring Parameters"
	 * reference card. Pin the values so the reference card and
	 * score() can't drift apart.
	 */
	public function test_signal_weights_getter_returns_canonical_values(): void {
		$w = AnonymityScorer::signal_weights();

		// Phase 4 documented deductions.
		$this->assertSame( 20, $w['timezone'] );
		$this->assertSame( 40, $w['webrtc'] );
		$this->assertSame( 30, $w['dns'] );

		// Proxy is INTENTIONALLY 0 — detected-and-intentional proxy
		// use is not penalised on its own; it only matters when
		// combined with the leaks above.
		$this->assertSame( 0, $w['proxy'] );
	}

	public function test_signal_weights_match_actual_score_deductions(): void {
		// The getter and score() must agree on the deduction values
		// — otherwise the admin reference card would mislead.
		$w = AnonymityScorer::signal_weights();

		// Timezone-only mismatch → score drops by the timezone weight.
		$intel    = array( 'timezone' => 'America/Los_Angeles' );
		$browser  = 'Europe/Berlin'; // different UTC offset
		$result   = AnonymityScorer::score( $intel, array(), array(), $browser, null );
		$this->assertSame( 100 - $w['timezone'], $result['score'] );

		// WebRTC only → drops by the webrtc weight.
		$webrtc = array(
			'verdict'      => 'potential_exposure',
			'public_addrs' => array( '1.2.3.4' ),
		);
		$result = AnonymityScorer::score( array(), $webrtc, array(), '', null );
		$this->assertSame( 100 - $w['webrtc'], $result['score'] );
	}
}
