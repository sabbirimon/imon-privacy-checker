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
				),
				'proxy'  => array(
					'category'   => 'datacenter',
					'vendor'     => 'Google Cloud',
					'label'      => 'Datacenter IP (Google Cloud)',
					'confidence' => 'high',
					'reasons'    => array(),
					'score'      => 55,
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
			'fingerprint' => array( 'level' => 'low', 'bits' => 4.5 ),
			'webrtc'      => array(
				'verdict'     => 'protected',
				'public_ips'  => array(),
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
			$this->assertGreaterThanOrEqual( 1, $row['weight'] );
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
				'intel' => array( 'status' => 'error' ),
				'proxy' => array(
					'category'   => 'unknown',
					'vendor'     => '',
					'label'      => 'Unknown',
					'confidence' => 'low',
					'reasons'    => array(),
					'score'      => 0,
				),
			),
			'reputation'  => array( 'status' => 'listed' ),
			'user_agent'  => array(
				'ua'       => 'curl/7.88',
				'bot'      => true,
				'bot_name' => 'curl',
			),
			'fingerprint' => array( 'level' => 'high', 'bits' => 18.5 ),
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
}
