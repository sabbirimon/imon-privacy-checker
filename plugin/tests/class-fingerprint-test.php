<?php
/**
 * Tests for PrivacyChecker\Fingerprint (UA parser + visibility estimator).
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Fingerprint;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class FingerprintTest extends TestCase {

	public function test_parse_chrome_on_windows(): void {
		$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
		$r  = Fingerprint::parse_user_agent( $ua );
		$this->assertSame( 'Chrome', $r['browser'] );
		$this->assertSame( 'Windows', $r['os'] );
		$this->assertSame( 'Desktop', $r['device'] );
		$this->assertSame( 'WebKit', $r['engine'] );
		$this->assertFalse( $r['is_bot'] );
	}

	public function test_parse_firefox_on_linux(): void {
		$ua = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0';
		$r  = Fingerprint::parse_user_agent( $ua );
		$this->assertSame( 'Firefox', $r['browser'] );
		$this->assertSame( 'Linux', $r['os'] );
		$this->assertSame( 'Gecko', $r['engine'] );
		$this->assertSame( 'Desktop', $r['device'] );
	}

	public function test_parse_safari_on_iphone(): void {
		$ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1';
		$r  = Fingerprint::parse_user_agent( $ua );
		$this->assertSame( 'Safari', $r['browser'] );
		$this->assertSame( 'iOS', $r['os'] );
		$this->assertSame( 'Mobile', $r['device'] );
	}

	public function test_parse_edge(): void {
		$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0';
		$r  = Fingerprint::parse_user_agent( $ua );
		$this->assertSame( 'Edge', $r['browser'] );
	}

	public function test_parse_bot(): void {
		$ua = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
		$r  = Fingerprint::parse_user_agent( $ua );
		$this->assertTrue( $r['is_bot'] );
		$this->assertSame( 'Bot', $r['device'] );
	}

	public function test_parse_empty_ua(): void {
		$r = Fingerprint::parse_user_agent( '' );
		$this->assertSame( '', $r['raw'] );
		$this->assertNull( $r['browser'] );
		$this->assertFalse( $r['is_bot'] );
	}

	public function test_estimate_visibility_with_no_signals(): void {
		$v = Fingerprint::estimate_visibility( array() );
		$this->assertSame( 0, $v['exposure_score'] );
		$this->assertSame( 'low', $v['level'] );
	}

	public function test_estimate_visibility_with_all_signals_is_high(): void {
		$signals = array(
			'user_agent'           => 'Mozilla/5.0',
			'screen_resolution'    => '1920x1080',
			'color_depth'          => 24,
			'pixel_ratio'          => 1,
			'timezone'             => 'UTC',
			'language'             => 'en',
			'languages'            => array( 'en', 'fr' ),
			'platform'             => 'Linux',
			'hardware_concurrency' => 8,
			'device_memory'        => 8,
			'touch_support'        => true,
			'cookies'              => true,
			'do_not_track'         => '1',
			'webgl'                => 'hash',
			'canvas'               => 'hash',
			'audio'                => 'hash',
			'fonts'                => 'hash',
		);
		$v = Fingerprint::estimate_visibility( $signals );
		$this->assertSame( 100, $v['exposure_score'] );
		$this->assertSame( 'high', $v['level'] );
	}

	public function test_estimate_visibility_threshold_boundaries(): void {
		$signals = array(
			'user_agent'        => 'x',
			'screen_resolution' => '1x1',
			'timezone'          => 'UTC',
			'language'          => 'en',
		);
		$v = Fingerprint::estimate_visibility( $signals );
		$this->assertGreaterThanOrEqual( 0, $v['exposure_score'] );
		$this->assertLessThanOrEqual( 100, $v['exposure_score'] );
		$this->assertContains( $v['level'], array( 'low', 'moderate', 'high' ) );
	}
}