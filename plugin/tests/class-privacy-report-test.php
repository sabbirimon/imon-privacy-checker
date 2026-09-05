<?php
/**
 * Tests for PrivacyChecker\PrivacyReport::build().
 *
 * Builds a synthetic scan payload (the same shape the orchestrator
 * produces) and asserts that the report shape, grade buckets, and
 * category rows all conform to the documented contract.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\PrivacyReport;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class PrivacyReportTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	/**
	 * Construct a "good" synthetic scan — Google Cloud datacenter egress,
	 * clean reputation, minimal fingerprint, no WebRTC leak.
	 */
	private function good_scan(): array {
		return array(
			'request_ip'  => array(
				'ipv4'    => '8.8.8.8',
				'ipv6'    => '',
				'is_mock' => false,
			),
			'connection'  => array(
				'ipv4'   => '8.8.8.8',
				'ipv6'   => '',
				'source' => 'REMOTE_ADDR',
				'intel'  => array(
					'status'  => 'ok',
					'country' => 'US',
					'asn'     => 'AS15169',
					'org'     => 'Google LLC',
					'timezone' => 'America/Los_Angeles',
				),
				'proxy'  => array(
					'category'   => 'datacenter',
					'vendor'     => 'Google Cloud',
					'label'      => 'Datacenter IP (Google Cloud)',
					'confidence' => 'high',
					'reasons'    => array(),
					'score'      => 55,
				),
				'anonymity' => array(
					'consistent' => true,
					'score'      => 100,
					'mismatches' => array(),
					'summary'    => 'No inconsistencies detected.',
				),
			),
			'reputation'  => array( 'status' => 'clean' ),
			'user_agent'  => array(
				'ua'              => 'Mozilla/5.0',
				'browser'         => 'Firefox',
				'browser_version' => '120.0',
				'os'              => 'Linux',
				'os_version'      => '5.15',
				'device'          => 'Desktop',
				'bot'             => false,
			),
			'fingerprint' => array(
				'level'     => 'low',
				'bits'      => 4.5,
				'timezone'  => 'America/Los_Angeles',
			),
			'webrtc'      => array(
				'verdict'     => 'protected',
				'public_ips'  => array(),
			),
			'security_posture' => array(
				'tls'     => array(
					'status'   => 'modern',
					'protocol' => 'TLSv1.3',
					'cipher'   => 'TLS_AES_128_GCM_SHA256',
					'note'     => 'Current.',
				),
				'browser' => array(
					'status'  => 'current',
					'browser' => 'Firefox',
					'version' => 120,
					'message' => 'No update required.',
				),
			),
			'dns_test'    => array(
				'configured' => false,
				'note'       => '',
			),
		);
	}

	public function test_build_good_scan_returns_expected_shape(): void {
		$report = PrivacyReport::build( $this->good_scan() );

		// Top-level shape.
		$this->assertIsInt( $report['overall'] );
		$this->assertGreaterThanOrEqual( 0, $report['overall'] );
		$this->assertLessThanOrEqual( 100, $report['overall'] );

		$this->assertContains( $report['grade'], array( 'A', 'B', 'C', 'D', 'E', 'F' ) );
		$this->assertContains( $report['confidence'], array( 'high', 'medium', 'low' ) );
		$this->assertNotEmpty( $report['headline'] );
		$this->assertIsString( $report['headline'] );
	}

	public function test_build_good_scan_categories_have_required_keys(): void {
		$report = PrivacyReport::build( $this->good_scan() );

		$this->assertArrayHasKey( 'categories', $report );
		$this->assertArrayHasKey( 'ip', $report['categories'] );
		$this->assertArrayHasKey( 'reputation', $report['categories'] );
		$this->assertArrayHasKey( 'dns', $report['categories'] );
		$this->assertArrayHasKey( 'webrtc', $report['categories'] );
		$this->assertArrayHasKey( 'fingerprint', $report['categories'] );
		$this->assertArrayHasKey( 'user_agent', $report['categories'] );
		$this->assertArrayHasKey( 'ipv6', $report['categories'] );
		$this->assertArrayHasKey( 'consistency', $report['categories'] );
		$this->assertArrayHasKey( 'proxy', $report['categories'] );

		foreach ( $report['categories'] as $key => $row ) {
			$this->assertArrayHasKey( 'percent', $row, "category $key missing percent" );
			$this->assertArrayHasKey( 'status', $row, "category $key missing status" );
			$this->assertArrayHasKey( 'weight', $row, "category $key missing weight" );
			$this->assertArrayHasKey( 'message', $row, "category $key missing message" );

			$this->assertIsInt( $row['percent'] );
			$this->assertGreaterThanOrEqual( 0, $row['percent'] );
			$this->assertLessThanOrEqual( 100, $row['percent'] );

			$this->assertContains( $row['status'], array( 'good', 'warning', 'bad' ) );
			$this->assertIsInt( $row['weight'] );
			// weight 0 = surface-only (Phase 6 categories). Other categories
			// must have at least weight 1.
			$this->assertGreaterThanOrEqual( 0, $row['weight'] );
			$this->assertIsString( $row['message'] );
		}
	}

	public function test_build_good_scan_proxy_field_is_echoed(): void {
		$report = PrivacyReport::build( $this->good_scan() );
		$this->assertIsArray( $report['proxy'] );
		$this->assertSame( 'datacenter', $report['proxy']['category'] );
		$this->assertSame( 'Google Cloud', $report['proxy']['vendor'] );
	}

	public function test_build_good_scan_recommendations_have_shape(): void {
		$report = PrivacyReport::build( $this->good_scan() );
		$this->assertIsArray( $report['recommendations'] );
		$this->assertNotEmpty( $report['recommendations'] );

		foreach ( $report['recommendations'] as $rec ) {
			$this->assertArrayHasKey( 'key', $rec );
			$this->assertArrayHasKey( 'priority', $rec );
			$this->assertArrayHasKey( 'message', $rec );
			$this->assertContains( $rec['priority'], array( 'high', 'medium', 'low' ) );
			$this->assertIsString( $rec['message'] );
		}
	}

	public function test_build_bad_scan_scores_low_and_grades_d_or_below(): void {
		$bad = array(
			'request_ip'  => array(
				'ipv4'    => '8.8.8.8',
				'ipv6'    => '',
				'is_mock' => false,
			),
			'connection'  => array(
				'ipv4'  => '8.8.8.8',
				'intel' => array(
					'status'   => 'error',
					'timezone' => 'Europe/Berlin',
				),
				'proxy' => array(
					'category'   => 'unknown',
					'vendor'     => '',
					'label'      => 'Unknown',
					'confidence' => 'low',
					'reasons'    => array(),
					'score'      => 0,
				),
				'anonymity' => array(
					'consistent' => false,
					'score'      => 20,
					'mismatches' => array(
						array(
							'signal'   => 'webrtc',
							'detail'   => 'Public IP leaked via WebRTC',
							'severity' => 'high',
						),
						array(
							'signal'   => 'dns',
							'detail'   => 'DNS resolver on different org',
							'severity' => 'high',
						),
					),
					'summary'    => 'Multiple signals disagree with each other.',
				),
			),
			'security_posture' => array(
				'tls'     => array(
					'status'   => 'outdated',
					'protocol' => 'TLSv1.0',
					'cipher'   => 'RC4-SHA',
					'note'     => 'Outdated.',
				),
				'browser' => array(
					'status'  => 'very_outdated',
					'browser' => 'Chrome',
					'version' => 70,
					'message' => 'Known security issues.',
				),
			),
			'reputation'  => array( 'status' => 'listed' ),
			'user_agent'  => array(
				'ua'       => 'curl/7.88',
				'bot'      => true,
				'bot_name' => 'curl',
			),
			'fingerprint' => array(
				'level'    => 'high',
				'bits'     => 18.5,
				'timezone' => 'Europe/Berlin',
			),
			'webrtc'      => array(
				'verdict'    => 'potential_exposure',
				'public_ips' => array( '1.2.3.4' ),
			),
			'dns_test'    => array(
				'configured'  => true,
				'consistent'  => false,
				'leak_score'  => 0.9,
				'status'      => 'ok',
			),
		);

		$report = PrivacyReport::build( $bad );

		$this->assertLessThan( 50, $report['overall'] );
		$this->assertContains( $report['grade'], array( 'D', 'E', 'F' ) );
	}

	public function test_categories_include_phase_6_security_posture_and_surface_only(): void {
		$report = PrivacyReport::build( $this->good_scan() );

		$this->assertArrayHasKey( 'security_posture',    $report['categories'] );
		$this->assertArrayHasKey( 'connection_quality',  $report['categories'] );
		$this->assertArrayHasKey( 'local_network',       $report['categories'] );
	}

	public function test_consistency_uses_anonymity_scorer_output(): void {
		$scan = $this->good_scan();
		// 100 / consistent / no mismatches → 'good' category.
		$scan['connection']['anonymity'] = array(
			'consistent' => true,
			'score'      => 100,
			'mismatches' => array(),
			'summary'    => 'No inconsistencies.',
		);
		$report = PrivacyReport::build( $scan );
		$this->assertSame( 'good', $report['categories']['consistency']['status'] );
		$this->assertSame( 100,  $report['categories']['consistency']['percent'] );

		// Score 30 with mismatches → 'bad' category.
		$scan['connection']['anonymity'] = array(
			'consistent' => false,
			'score'      => 30,
			'mismatches' => array(
				array( 'signal' => 'webrtc', 'detail' => 'leak', 'severity' => 'high' ),
			),
			'summary'    => 'Multiple signals disagree.',
		);
		$report = PrivacyReport::build( $scan );
		$this->assertSame( 'bad', $report['categories']['consistency']['status'] );
		$this->assertSame( 30,  $report['categories']['consistency']['percent'] );
	}

	public function test_consistency_missing_anonymity_data_returns_unknown(): void {
		$scan = $this->good_scan();
		unset( $scan['connection']['anonymity'] );
		$report = PrivacyReport::build( $scan );
		$this->assertSame( 'unknown', $report['categories']['consistency']['status_source'] );
	}

	public function test_security_posture_modern_tls_and_current_browser_is_good(): void {
		$report = PrivacyReport::build( $this->good_scan() );
		$sp      = $report['categories']['security_posture'];
		$this->assertSame( 'good',    $sp['status'] );
		$this->assertSame( 100,       $sp['percent'] );
		$this->assertSame( 3,         $sp['weight'] );
	}

	public function test_security_posture_outdated_tls_and_very_outdated_browser_is_bad(): void {
		$scan = $this->good_scan();
		$scan['security_posture'] = array(
			'tls'     => array(
				'status'   => 'outdated',
				'protocol' => 'TLSv1.0',
				'cipher'   => 'RC4-SHA',
				'note'     => 'Outdated.',
			),
			'browser' => array(
				'status'  => 'very_outdated',
				'browser' => 'Chrome',
				'version' => 70,
				'message' => 'Known issues.',
			),
		);
		$report = PrivacyReport::build( $scan );
		$sp      = $report['categories']['security_posture'];
		$this->assertSame( 'bad', $sp['status'] );
		// Average of 25 (outdated TLS) + 25 (very_outdated browser) = 25.
		$this->assertSame( 25,    $sp['percent'] );
	}

	public function test_surface_only_categories_have_weight_zero(): void {
		$scan = $this->good_scan();
		$scan['connection_quality'] = array(
			'latency' => array( 'avg_ms' => 42.0, 'min_ms' => 38.0, 'max_ms' => 50.0, 'jitter_ms' => 12.0 ),
		);
		$scan['local_network'] = array(
			'reachable'    => array(),
			'probed'       => array(),
			'total_probes' => 0,
		);
		$report = PrivacyReport::build( $scan );

		$this->assertSame( 0, $report['categories']['connection_quality']['weight'] );
		$this->assertSame( 0, $report['categories']['local_network']['weight'] );
	}

	public function test_surface_only_categories_do_not_drag_overall(): void {
		// Two scans that differ ONLY in the surface-only categories must
		// produce identical overall scores — proves the weight-0 skip.
		$base    = $this->good_scan();
		$chatty  = $this->good_scan();
		$base['connection_quality']   = array( 'latency' => array( 'avg_ms' => 30.0, 'jitter_ms' => 5.0 ) );
		$base['local_network']        = array( 'reachable' => array(), 'probed' => array(), 'total_probes' => 0 );
		$chatty['connection_quality'] = array( 'latency' => array( 'avg_ms' => 999.0, 'jitter_ms' => 800.0 ) );
		$chatty['local_network']      = array(
			'reachable'    => array( '192.168.0.1:80', '192.168.0.1:443', '10.0.0.1:80', '10.0.0.1:443' ),
			'probed'       => array(),
			'total_probes' => 15,
		);

		$base_report   = PrivacyReport::build( $base );
		$chatty_report = PrivacyReport::build( $chatty );

		$this->assertSame( $base_report['overall'], $chatty_report['overall'] );
	}

	public function test_consistency_has_highest_weight(): void {
		// Per IMON-BUILD-GUIDE.md Phase 6: anonymity consistency is the
		// highest-weighted signal. Pin it so a future refactor doesn't
		// accidentally drop it.
		$report = PrivacyReport::build( $this->good_scan() );
		$weights = array();
		foreach ( $report['categories'] as $key => $row ) {
			$weights[ $key ] = $row['weight'];
		}
		$this->assertSame( 4, $weights['consistency'] );

		// Surface-only must NOT beat any weighted category.
		$this->assertGreaterThanOrEqual(
			max( 0, max( array_diff( $weights, array( 0 ) ) ) ?: 0 ),
			$weights['consistency']
		);
	}

	public function test_connection_quality_with_client_payload_promotes_to_measured(): void {
		// Phase 7 wiring: when the client POSTs a valid connection_quality
		// payload (from connectionQualityProbe + navigatorConnectionSnapshot),
		// the orchestrator threads it onto $scan['connection_quality'] and
		// the privacy-report category source is 'measured' (not 'unknown'),
		// with a status that reflects the actual readings.
		$scan = $this->good_scan();
		$scan['connection_quality'] = array(
			'latency' => array(
				'avg_ms'    => 42.0,
				'min_ms'    => 38.0,
				'max_ms'    => 50.0,
				'jitter_ms' => 12.0,
				'count'     => 3,
			),
			'network' => array(
				'available'      => true,
				'downlink_mbps'  => 50.0,
				'effective_type' => '4g',
				'rtt_ms'         => 80,
			),
		);

		$report = PrivacyReport::build( $scan );
		$cq      = $report['categories']['connection_quality'];

		$this->assertSame( 'measured', $cq['status_source'] );
		// 42 ms avg + 12 ms jitter → good band.
		$this->assertSame( 'good',     $cq['status'] );
		$this->assertSame( 0,          $cq['weight'] );
		// Payload is passed through to the row's details so the UI
		// can render the same numbers it shows in connectionQualityCard().
		$this->assertSame( 42.0,       $cq['details']['latency']['avg_ms'] );
		$this->assertSame( '4g',       $cq['details']['network']['effective_type'] );
	}

	public function test_connection_quality_high_jitter_promotes_to_warning(): void {
		$scan = $this->good_scan();
		$scan['connection_quality'] = array(
			'latency' => array(
				'avg_ms'    => 300.0,
				'min_ms'    => 100.0,
				'max_ms'    => 600.0,
				'jitter_ms' => 500.0,
				'count'     => 3,
			),
		);

		$report = PrivacyReport::build( $scan );
		$cq      = $report['categories']['connection_quality'];

		$this->assertSame( 'measured', $cq['status_source'] );
		// 300 ms / 500 ms jitter → falls into the >250/jitter>80 warning band.
		$this->assertSame( 'warning',  $cq['status'] );
	}

	public function test_connection_quality_missing_payload_remains_unknown(): void {
		// When the client doesn't supply a connection_quality payload
		// (older builds, JS disabled, probe rejected), the category
		// source stays 'unknown' and the weight-0 exclusion holds.
		$report = PrivacyReport::build( $this->good_scan() );
		$cq      = $report['categories']['connection_quality'];

		$this->assertSame( 'unknown', $cq['status_source'] );
		$this->assertSame( 0,         $cq['weight'] );
	}
}
