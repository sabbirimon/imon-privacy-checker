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
		// As of Phase 3 the score is the average of the boolean-flag score
		// and the entropy-estimator score, so all flags + all Phase 3
		// signals lands around 70-80 (high band). We assert the LEVEL
		// rather than an exact integer because the entropy bits can shift
		// slightly if a future card adds another +1 signal.
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
			'canvas_hash'          => 'deadbeef',
			'audio_hash'           => 'feedface',
			'webgl_renderer'       => 'ANGLE (Intel, Intel(R) UHD Graphics 620, OpenGL 4.5)',
			'webgl_vendor'         => 'Google Inc. (Intel)',
			'font_list'            => array( 'Arial', 'Comic Sans MS', 'Tahoma', 'Verdana', 'Georgia', 'Helvetica', 'Calibri', 'Segoe UI', 'Lato', 'Oswald' ),
		);
		$v = Fingerprint::estimate_visibility( $signals );
		$this->assertGreaterThanOrEqual( 50, $v['exposure_score'] );
		$this->assertSame( 'high', $v['level'] );
		// Entropy breakdown is now present in the response.
		$this->assertArrayHasKey( 'entropy', $v );
		$this->assertGreaterThan( 0, $v['entropy']['bits'] );
		// No masking → masked_signals is empty.
		$this->assertSame( array(), $v['masked_signals'] );
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

	public function test_estimate_visibility_with_masked_webgl_includes_masked_signals(): void {
		$signals = array(
			'user_agent'     => 'Mozilla/5.0',
			'timezone'       => 'UTC',
			'language'       => 'en',
			'webgl_renderer' => 'masked-by-browser',
			'webgl_vendor'   => 'masked-by-browser',
		);
		$v = Fingerprint::estimate_visibility( $signals );
		$this->assertContains( 'webgl_renderer', $v['masked_signals'] );
		$this->assertContains( 'webgl_vendor',   $v['masked_signals'] );
	}

	// ---- entropy_estimate() -----------------------------------------------

	public function test_entropy_estimate_with_empty_signals_is_zero(): void {
		$e = Fingerprint::entropy_estimate( array() );
		$this->assertSame( 0, $e['bits'] );
		$this->assertSame( 0, $e['score'] );
		$this->assertNotEmpty( $e['uniqueness_estimate'] );
	}

	public function test_entropy_estimate_canvas_only(): void {
		$e = Fingerprint::entropy_estimate( array( 'canvas_hash' => 'deadbeef' ) );
		$this->assertSame( 15, $e['bits'] );
		$this->assertSame( 15, $e['score'] );
		$this->assertSame( 15, $e['breakdown']['canvas_hash'] );
		$this->assertSame( 0,  $e['breakdown']['audio_hash'] );
	}

	public function test_entropy_estimate_canvas_plus_audio(): void {
		$e = Fingerprint::entropy_estimate( array(
			'canvas_hash' => 'deadbeef',
			'audio_hash'  => 'feedface',
		) );
		$this->assertSame( 30, $e['bits'] );
	}

	public function test_entropy_estimate_masked_webgl_rewards_anti_fp(): void {
		// Unmasked WebGL renderer: +6 bits. Masked: scored as anti-fp
		// signal, but bits floor at 0 (we don't go negative — masked
		// browssers get credit in the UI via `masked_signals`, not by
		// dragging the numerical score under 0).
		$unmasked = Fingerprint::entropy_estimate( array( 'webgl_renderer' => 'ANGLE (Intel UHD Graphics 620)' ) );
		$masked   = Fingerprint::entropy_estimate( array( 'webgl_renderer' => 'masked-by-browser' ) );
		$this->assertSame( 6, $unmasked['bits'] );
		$this->assertSame( 0, $masked['bits'] ); // clamped at 0
		$this->assertContains( 'webgl_renderer', $masked['masked_signals'] );
	}

	public function test_entropy_estimate_fonts_beyond_baseline(): void {
		// Baseline is 8 fonts = 0 bits. 9th font onwards = 1 bit each.
		$baseline = Fingerprint::entropy_estimate( array( 'font_list' => array( 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' ) ) );
		$nine     = Fingerprint::entropy_estimate( array( 'font_list' => array( 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I' ) ) );
		$twelve   = Fingerprint::entropy_estimate( array( 'font_list' => array_fill( 0, 12, 'X' ) ) );
		$this->assertSame( 0, $baseline['bits'] );
		$this->assertSame( 1, $nine['bits'] );
		$this->assertSame( 4, $twelve['bits'] );
		$this->assertSame( 12, $twelve['breakdown']['font_list']['installed'] );
	}

	public function test_entropy_estimate_timezone_and_language(): void {
		$e = Fingerprint::entropy_estimate( array(
			'timezone' => 'Europe/Berlin',
			'language' => 'en-US',
		) );
		$this->assertSame( 8, $e['bits'] ); // 4 + 4
	}

	public function test_entropy_estimate_languages_array(): void {
		$one    = Fingerprint::entropy_estimate( array( 'languages' => array( 'en' ) ) );
		$many   = Fingerprint::entropy_estimate( array( 'languages' => array( 'en', 'fr', 'de' ) ) );
		$none   = Fingerprint::entropy_estimate( array( 'languages' => array() ) );
		$this->assertSame( 2, $one['bits'] );
		$this->assertSame( 2, $many['bits'] ); // single +2 regardless of count
		$this->assertSame( 0, $none['bits'] );
	}

	public function test_entropy_estimate_caps_at_100_bits(): void {
		$signals = array(
			'canvas_hash'    => 'x',
			'audio_hash'     => 'x',
			'webgl_renderer' => 'ANGLE (Intel)',
			'timezone'       => 'UTC',
			'language'       => 'en',
			'languages'      => array( 'en' ),
			'font_list'      => array_fill( 0, 200, 'X' ),
		);
		$e = Fingerprint::entropy_estimate( $signals );
		$this->assertLessThanOrEqual( 100, $e['bits'] );
		$this->assertLessThanOrEqual( 100, $e['score'] );
	}

	public function test_entropy_estimate_returns_human_readable_uniqueness_string(): void {
		$e = Fingerprint::entropy_estimate( array(
			'canvas_hash' => 'deadbeef',
			'audio_hash'  => 'feedface',
		) );
		$this->assertNotEmpty( $e['uniqueness_estimate'] );
		$this->assertMatchesRegularExpression( '/1 in \d+/', $e['uniqueness_estimate'] );
	}

	public function test_entropy_estimate_uniqueness_is_capped_at_10_million(): void {
		// Construct a theoretical 80+ bit signal set; the human string
		// shouldn't report "1 in 2^80 visitors" because that's nonsense
		// in the context of web traffic.
		$signals = array(
			'canvas_hash'    => str_repeat( 'a', 8 ),
			'audio_hash'     => str_repeat( 'b', 8 ),
			'webgl_renderer' => str_repeat( 'c', 32 ),
			'timezone'       => 'UTC',
			'language'       => 'en',
			'languages'      => array( 'en', 'fr' ),
			'font_list'      => array_fill( 0, 200, 'X' ),
		);
		$e = Fingerprint::entropy_estimate( $signals );
		preg_match( '/1 in (\d[\d,]*)/', $e['uniqueness_estimate'], $m );
		$n = (int) str_replace( ',', '', $m[1] );
		$this->assertLessThanOrEqual( 10000000, $n );
	}
}