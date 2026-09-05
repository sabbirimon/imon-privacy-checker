<?php
/**
 * Tests for PrivacyChecker\NetworkProbe (host:port split, IP allowlist,
 * public/private IP gating) plus the related Security helpers.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Cache;
use PrivacyChecker\IpFallback;
use PrivacyChecker\NetworkProbe;
use PrivacyChecker\Security;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class NetworkProbeTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	// ---------------------------------------------------------------------
	// Security::split_hostport()
	// ---------------------------------------------------------------------

	public function test_split_hostport_handles_host_and_port(): void {
		[ $host, $port ] = Security::split_hostport( 'cloudflare.com:443' );
		$this->assertSame( 'cloudflare.com', $host );
		$this->assertSame( 443, $port );
	}

	public function test_split_hostport_handles_ipv6_with_brackets_and_port(): void {
		[ $host, $port ] = Security::split_hostport( '[2001:db8::1]:8080' );
		$this->assertSame( '2001:db8::1', $host );
		$this->assertSame( 8080, $port );
	}

	public function test_split_hostport_handles_ipv6_with_brackets_no_port(): void {
		[ $host, $port ] = Security::split_hostport( '[2001:db8::1]' );
		$this->assertSame( '2001:db8::1', $host );
		$this->assertNull( $port );
	}

	public function test_split_hostport_handles_hostname_only(): void {
		[ $host, $port ] = Security::split_hostport( 'example.com' );
		$this->assertSame( 'example.com', $host );
		$this->assertNull( $port );
	}

	public function test_split_hostport_handles_empty_input(): void {
		[ $host, $port ] = Security::split_hostport( '' );
		$this->assertSame( '', $host );
		$this->assertNull( $port );
	}

	public function test_split_hostport_rejects_unbracketed_ipv6(): void {
		// Multiple colons in input with no brackets → entire string is treated
		// as the host and no port is detected.
		[ $host, $port ] = Security::split_hostport( '2001:db8::1' );
		$this->assertSame( '2001:db8::1', $host );
		$this->assertNull( $port );
	}

	public function test_split_hostport_rejects_port_out_of_range(): void {
		[ $host, $port ] = Security::split_hostport( 'cloudflare.com:99999' );
		// Out-of-range port should fall back to the whole string as host.
		$this->assertSame( 'cloudflare.com:99999', $host );
		$this->assertNull( $port );
	}

	// ---------------------------------------------------------------------
	// Security::is_public_ip_literal()
	// ---------------------------------------------------------------------

	public function test_is_public_ip_literal_accepts_public_ipv4(): void {
		$this->assertTrue( Security::is_public_ip_literal( '8.8.8.8' ) );
	}

	public function test_is_public_ip_literal_rejects_loopback(): void {
		$this->assertFalse( Security::is_public_ip_literal( '127.0.0.1' ) );
	}

	public function test_is_public_ip_literal_rejects_rfc1918(): void {
		$this->assertFalse( Security::is_public_ip_literal( '10.0.0.1' ) );
	}

	public function test_is_public_ip_literal_rejects_link_local_aws_metadata(): void {
		$this->assertFalse( Security::is_public_ip_literal( '169.254.169.254' ) );
	}

	public function test_is_public_ip_literal_rejects_rfc1918_192_168(): void {
		$this->assertFalse( Security::is_public_ip_literal( '192.168.1.1' ) );
	}

	public function test_is_public_ip_literal_rejects_ipv6_loopback(): void {
		$this->assertFalse( Security::is_public_ip_literal( '::1' ) );
	}

	public function test_is_public_ip_literal_rejects_ipv6_documentation_prefix(): void {
		$this->assertFalse( Security::is_public_ip_literal( '2001:db8::1' ) );
	}

	public function test_is_public_ip_literal_accepts_public_ipv6(): void {
		$this->assertTrue( Security::is_public_ip_literal( '2606:4700:4700::1111' ) );
	}

	public function test_is_public_ip_literal_rejects_malformed_input(): void {
		$this->assertFalse( Security::is_public_ip_literal( 'not-an-ip' ) );
	}

	// ---------------------------------------------------------------------
	// NetworkProbe::default_* accessors
	// ---------------------------------------------------------------------

	public function test_default_dns_resolvers_contains_expected_keys(): void {
		$resolvers = NetworkProbe::default_dns_resolvers();
		$this->assertArrayHasKey( 'cloudflare', $resolvers );
		$this->assertArrayHasKey( 'google', $resolvers );
		$this->assertArrayHasKey( 'quad9', $resolvers );
	}

	public function test_default_dns_resolvers_use_https(): void {
		$resolvers = NetworkProbe::default_dns_resolvers();
		foreach ( $resolvers as $url ) {
			$this->assertStringStartsWith( 'https://', $url );
		}
	}

	public function test_default_ping_targets_is_non_empty(): void {
		$targets = NetworkProbe::default_ping_targets();
		$this->assertNotEmpty( $targets );
		$this->assertIsArray( $targets );
	}

	public function test_default_port_scan_ports_is_non_empty(): void {
		$ports = NetworkProbe::default_port_scan_ports();
		$this->assertNotEmpty( $ports );
		$this->assertIsArray( $ports );
		foreach ( $ports as $p ) {
			$this->assertIsInt( $p );
		}
	}

	// ---------------------------------------------------------------------
	// NetworkProbe::check_target_allowed()
	// ---------------------------------------------------------------------

	/**
	 * Seed the cached self-IP so NetworkProbe's "self-only" mode accepts
	 * a probe that targets the WP server's own public address.
	 */
	private function seed_self_ip( string $ip ): void {
		Cache::set( 'server_self_ip', $ip, 6 * HOUR_IN_SECONDS );
	}

	public function test_check_target_allowed_accepts_self_ip_when_allowlist_empty(): void {
		$this->seed_self_ip( '8.8.8.8' );
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '8.8.8.8', 443 );
		$this->assertTrue( $allowed );
		$this->assertNull( $reason );
	}

	public function test_check_target_allowed_denies_private_ip(): void {
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '127.0.0.1', 443 );
		$this->assertFalse( $allowed );
		$this->assertNotNull( $reason );
	}

	public function test_check_target_allowed_denies_aws_metadata(): void {
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '169.254.169.254', 80 );
		$this->assertFalse( $allowed );
		$this->assertNotNull( $reason );
	}

	public function test_check_target_allowed_denies_hardcoded_denylisted_port(): void {
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '8.8.8.8', 22 );
		$this->assertFalse( $allowed );
		$this->assertStringContainsString( 'denylist', (string) $reason );
	}

	public function test_check_target_allowed_denies_port_out_of_range(): void {
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '8.8.8.8', 99999 );
		$this->assertFalse( $allowed );
		$this->assertStringContainsString( '1 and 65535', (string) $reason );
	}

	public function test_check_target_allowed_denies_localhost(): void {
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( 'localhost', 80 );
		$this->assertFalse( $allowed );
		$this->assertNotNull( $reason );
	}

	public function test_check_target_allowed_denies_ip_not_on_allowlist(): void {
		// Seed an allowlist that does NOT include 8.8.8.8.
		\WpState::$options['pc_settings'] = array(
			'port_scan_allowlist' => array( '1.1.1.1' ),
		);
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '8.8.8.8', 443 );
		$this->assertFalse( $allowed );
		$this->assertStringContainsString( 'allowlist', (string) $reason );
	}

	public function test_check_target_allowed_accepts_ip_on_allowlist(): void {
		\WpState::$options['pc_settings'] = array(
			'port_scan_allowlist' => array( '1.1.1.1' ),
		);
		[ $allowed, $reason ] = NetworkProbe::check_target_allowed( '1.1.1.1', 443 );
		$this->assertTrue( $allowed );
		$this->assertNull( $reason );
	}
}
