<?php
/**
 * Tests for PrivacyChecker\IpFallback — chain traversal + graceful failures.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Cache;
use PrivacyChecker\IpFallback;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class IpFallbackTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	protected function tear_down(): void {
		Cache::delete( 'ipfallback_1.1.1.1' );
		parent::tear_down();
	}

	public function test_default_chain_starts_with_maxmind_then_local_then_ipapi(): void {
		$chain = IpFallback::default_chain();
		$this->assertSame( 'maxmind', $chain[0] );
		$this->assertSame( 'ipapi', end( $chain ) );
		$this->assertContains( 'ip2location', $chain );
		$this->assertContains( 'ip-api-com', $chain );
	}

	public function test_lookup_rejects_non_public_ip(): void {
		$result = IpFallback::lookup( '10.0.0.5' );
		$this->assertSame( 'error', $result['status'] );
		$this->assertStringContainsString( 'Non-public', (string) $result['error'] );
	}

	public function test_lookup_rejects_malformed_ip(): void {
		$result = IpFallback::lookup( 'not-an-ip' );
		$this->assertSame( 'error', $result['status'] );
	}

	public function test_lookup_with_only_mock_in_chain_returns_ok(): void {
		\WpState::$options['pc_settings'] = array(
			'provider_chain_ip' => array( 'mock' ),
		);
		Cache::delete( 'ipfallback_1.1.1.1' );
		$result = IpFallback::lookup( '1.1.1.1' );
		$this->assertSame( 'ok', $result['status'] );
		$this->assertSame( 'mock', $result['provider_key'] );
		$this->assertNotEmpty( $result['chain'] );
		$this->assertSame( 'mock', $result['chain'][0]['key'] );
	}

	public function test_chain_trace_includes_each_attempted_step(): void {
		\WpState::$options['pc_settings'] = array(
			'provider_chain_ip' => array( 'mock' ),
		);
		Cache::delete( 'ipfallback_8.8.8.8' );
		$result = IpFallback::lookup( '8.8.8.8' );
		$this->assertArrayHasKey( 'chain', $result );
		$this->assertCount( 1, $result['chain'] );
		$this->assertSame( 'mock', $result['chain'][0]['key'] );
	}

	public function test_successful_lookup_is_cached(): void {
		\WpState::$options['pc_settings'] = array(
			'provider_chain_ip' => array( 'mock' ),
		);
		Cache::delete( 'ipfallback_1.1.1.1' );
		IpFallback::lookup( '1.1.1.1' );
		$cached = Cache::get( 'ipfallback_1.1.1.1' );
		$this->assertIsArray( $cached );
		$this->assertSame( 'ok', $cached['status'] );
	}

	public function test_flush_ip_invalidates_cache(): void {
		\WpState::$options['pc_settings'] = array(
			'provider_chain_ip' => array( 'mock' ),
		);
		IpFallback::lookup( '1.1.1.1' );
		$this->assertTrue( IpFallback::flush_ip( '1.1.1.1' ) );
		$this->assertNull( Cache::get( 'ipfallback_1.1.1.1' ) );
	}

	public function test_flush_ip_rejects_malformed(): void {
		$this->assertFalse( IpFallback::flush_ip( 'not-an-ip' ) );
	}
}