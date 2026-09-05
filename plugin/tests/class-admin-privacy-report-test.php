<?php
/**
 * Tests for PrivacyChecker\Admin\AdminPrivacyReport.
 *
 * Phase 8.1: the inspector's render() path depends on WordPress admin
 * globals (add_submenu_page, current_user_can, etc.) that the test
 * suite doesn't boot. We instead exercise the data layer — the
 * `build_self_scan()` static method — which is the only piece of
 * logic that's worth pinning down. The render() view is a thin
 * templated wrapper around PrivacyReport::build() output.
 *
 * build_self_scan() is pure PHP over $_SERVER and the WP settings
 * table; both are stub-controlled via WpState, so the tests are
 * hermetic.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Admin\AdminPrivacyReport;
use PrivacyChecker\PrivacyReport;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class AdminPrivacyReportTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		$_SERVER['REMOTE_ADDR']         = '203.0.113.42';
		$_SERVER['HTTP_USER_AGENT']     = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0';
		$_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,en;q=0.9';
		$_SERVER['HTTP_HOST']           = 'example.test';
	}

	public function test_build_self_scan_returns_expected_top_level_shape(): void {
		$scan = AdminPrivacyReport::build_self_scan();

		$this->assertArrayHasKey( 'generated_at', $scan );
		$this->assertArrayHasKey( 'request_ip',   $scan );
		$this->assertArrayHasKey( 'connection',   $scan );
		$this->assertArrayHasKey( 'reputation',   $scan );
		$this->assertArrayHasKey( 'user_agent',   $scan );
		$this->assertArrayHasKey( 'fingerprint',  $scan );
		$this->assertArrayHasKey( 'webrtc',       $scan );
		$this->assertArrayHasKey( 'dns_test',     $scan );

		// Browser-side categories that the inspector cannot collect
		// must be present but empty/unknown — same fail-closed
		// pattern the visitor flow uses.
		$this->assertArrayHasKey( 'connection_quality', $scan );
		$this->assertArrayHasKey( 'local_network',      $scan );
		$this->assertSame( array(), $scan['connection_quality'] );
		$this->assertSame( array(), $scan['local_network'] );
	}

	public function test_build_self_scan_reads_admin_request_ip(): void {
		$scan = AdminPrivacyReport::build_self_scan();
		$this->assertSame( '203.0.113.42', $scan['request_ip']['ipv4'] );
	}

	public function test_build_self_scan_fingerprint_is_unknown_when_no_client_signals(): void {
		$scan = AdminPrivacyReport::build_self_scan();
		// Without browser-side signals we cannot fingerprint the visitor —
		// the inspector reports unknown rather than fabricating data.
		$this->assertSame( 'unknown', $scan['fingerprint']['level'] );
	}

	public function test_build_self_scan_webrtc_has_no_public_ips_when_no_client_signals(): void {
		$scan = AdminPrivacyReport::build_self_scan();
		// Webrtc::summarize() with empty input returns a verdict but
		// must not surface any leaked public IPs.
		$this->assertArrayHasKey( 'public_addrs', $scan['webrtc'] );
		$this->assertSame( array(), $scan['webrtc']['public_addrs'] );
		$this->assertArrayHasKey( 'verdict', $scan['webrtc'] );
		// Verdict is 'not_supported' when no client data was supplied —
		// the WebRTC API wasn't even probed, so there's nothing to leak.
		$this->assertSame( 'not_supported', $scan['webrtc']['verdict'] );
	}

	public function test_build_self_scan_security_posture_contains_tls_and_browser(): void {
		$scan = AdminPrivacyReport::build_self_scan();
		$this->assertArrayHasKey( 'tls',     $scan['security_posture'] );
		$this->assertArrayHasKey( 'browser', $scan['security_posture'] );

		// The UA is Chrome 130 → should classify as current.
		$this->assertSame( 'current', $scan['security_posture']['browser']['status'] );
		$this->assertSame( 'Chrome',  $scan['security_posture']['browser']['browser'] );
	}

	public function test_build_self_scan_user_agent_is_parsed(): void {
		$scan = AdminPrivacyReport::build_self_scan();
		$this->assertSame( 'Chrome', $scan['user_agent']['browser'] );
		$this->assertSame( 'Linux',  $scan['user_agent']['os'] );
	}

	public function test_build_self_scan_runs_through_privacy_report_build(): void {
		// The end-to-end sanity check: feeding build_self_scan() into
		// PrivacyReport::build() must produce a valid report with all
		// 12 categories. Catches regressions in the payload shape.
		$scan   = AdminPrivacyReport::build_self_scan();
		$report = PrivacyReport::build( $scan );

		$this->assertIsInt( $report['overall'] );
		$this->assertContains( $report['grade'], array( 'A', 'B', 'C', 'D', 'E', 'F' ) );
		$this->assertContains( $report['confidence'], array( 'high', 'medium', 'low' ) );

		$expected = array(
			'ip', 'reputation', 'dns', 'webrtc', 'fingerprint',
			'user_agent', 'ipv6', 'consistency', 'security_posture',
			'proxy', 'connection_quality', 'local_network',
		);
		foreach ( $expected as $key ) {
			$this->assertArrayHasKey( $key, $report['categories'], "missing $key in inspector report" );
		}
	}

	public function test_build_self_scan_arithmetic_panel_matches_overall(): void {
		// The inspector's transparency panel renders the formula
		// (sum of percent*weight) / sum(weight) = overall. Verify the
		// math by recomputing it here against the same PrivacyReport
		// output and asserting the result equals $report['overall'].
		$scan   = AdminPrivacyReport::build_self_scan();
		$report = PrivacyReport::build( $scan );

		$weighted_sum = 0;
		$total_weight = 0;
		foreach ( $report['categories'] as $key => $row ) {
			$w = (int) ( $row['weight'] ?? 0 );
			if ( $w <= 0 ) {
				continue;
			}
			$weighted_sum += (int) ( $row['percent'] ?? 0 ) * $w;
			$total_weight += $w;
		}
		$computed = $total_weight > 0
			? (int) round( $weighted_sum / $total_weight )
			: 0;

		$this->assertSame(
			(int) $report['overall'],
			$computed,
			'inspector transparency panel arithmetic does not match reported overall'
		);
	}

	public function test_men_slug_constant_is_distinct_from_dashboard_and_settings(): void {
		// Defensive: prevents a future refactor from accidentally
		// collapsing the Privacy Report submenu onto Dashboard or
		// Settings, which would shadow either page.
		$this->assertNotSame( 'privacy-checker',             AdminPrivacyReport::MENU_SLUG );
		$this->assertNotSame( 'privacy-checker-settings',    AdminPrivacyReport::MENU_SLUG );
	}
}
