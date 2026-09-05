<?php
/**
 * Tests for PrivacyChecker\RateLimiter.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Plugin;
use PrivacyChecker\RateLimiter;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class RateLimiterTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		// Seed a salt so the identifier is deterministic per test bucket.
		\WpState::$options['pc_settings'] = array( 'secret_salt' => 'test-salt' );
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
	}

	protected function tear_down(): void {
		unset( $_SERVER['REMOTE_ADDR'] );
		parent::tear_down();
	}

	public function test_first_request_in_bucket_is_allowed(): void {
		$result = RateLimiter::check( 'scan', 5 );
		$this->assertTrue( $result['allowed'] );
		$this->assertSame( 4, $result['remaining'] );
		$this->assertSame( 0, $result['retry_after'] );
	}

	public function test_limit_is_enforced_after_max_hits(): void {
		$limit = 3;
		for ( $i = 0; $i < $limit; $i++ ) {
			$r = RateLimiter::check( 'lookup', $limit );
			$this->assertTrue( $r['allowed'], "Request $i should be allowed" );
		}
		$blocked = RateLimiter::check( 'lookup', $limit );
		$this->assertFalse( $blocked['allowed'] );
		$this->assertSame( 0, $blocked['remaining'] );
		$this->assertGreaterThan( 0, $blocked['retry_after'] );
	}

	public function test_different_buckets_are_independent(): void {
		// Fill the scan bucket.
		for ( $i = 0; $i < 2; $i++ ) {
			RateLimiter::check( 'scan', 2 );
		}
		$blocked = RateLimiter::check( 'scan', 2 );
		$this->assertFalse( $blocked['allowed'] );

		// The lookup bucket is untouched.
		$allowed = RateLimiter::check( 'lookup', 2 );
		$this->assertTrue( $allowed['allowed'] );
	}

	public function test_identifier_does_not_leak_raw_ip(): void {
		// Two different salts → two different identifier prefixes.
		\WpState::$options['pc_settings'] = array( 'secret_salt' => 'salt-a' );
		RateLimiter::check( 'audit', 100 );

		// Inspect transient key prefix to confirm hashed form.
		$keys = array_keys( \WpState::$transients );
		$hit  = null;
		foreach ( $keys as $k ) {
			if ( strpos( $k, 'pc_rl_audit_' ) === 0 ) {
				$hit = $k;
				break;
			}
		}
		$this->assertNotNull( $hit );
		// Identifier is hex 24 chars; ensure the raw IP is NOT in the key.
		$this->assertStringNotContainsString( '203.0.113.10', $hit );
		$this->assertMatchesRegularExpression( '/[a-f0-9]{24}\z/', $hit, 'Identifier should be 24-hex' );
	}
}