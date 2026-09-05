<?php
/**
 * Tests for PrivacyChecker\Security (SSRF guard, IP validation, redirects).
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Security;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class SecurityTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	public function test_is_public_ip_literal_accepts_public_ipv4(): void {
		$this->assertTrue( Security::is_public_ip_literal( '1.1.1.1' ) );
		$this->assertTrue( Security::is_public_ip_literal( '8.8.8.8' ) );
		$this->assertTrue( Security::is_public_ip_literal( '93.184.216.34' ) );
	}

	public function test_is_public_ip_literal_rejects_private_ipv4(): void {
		$this->assertFalse( Security::is_public_ip_literal( '10.0.0.1' ) );
		$this->assertFalse( Security::is_public_ip_literal( '172.16.0.1' ) );
		$this->assertFalse( Security::is_public_ip_literal( '192.168.1.1' ) );
		$this->assertFalse( Security::is_public_ip_literal( '127.0.0.1' ) );
		$this->assertFalse( Security::is_public_ip_literal( '169.254.169.254' ) );
		$this->assertFalse( Security::is_public_ip_literal( '0.0.0.0' ) );
		$this->assertFalse( Security::is_public_ip_literal( '255.255.255.255' ) );
	}

	public function test_is_public_ip_literal_rejects_ipv6_reserved(): void {
		$this->assertFalse( Security::is_public_ip_literal( '::1' ) );
		$this->assertFalse( Security::is_public_ip_literal( 'fc00::1' ) );
		$this->assertFalse( Security::is_public_ip_literal( 'fe80::1' ) );
		$this->assertFalse( Security::is_public_ip_literal( 'fd00:ec2::254' ) );
	}

	public function test_is_public_ip_literal_rejects_malformed(): void {
		$this->assertFalse( Security::is_public_ip_literal( '' ) );
		$this->assertFalse( Security::is_public_ip_literal( 'not-an-ip' ) );
		$this->assertFalse( Security::is_public_ip_literal( '999.999.999.999' ) );
	}

	public function test_validate_remote_url_blocks_localhost(): void {
		$result = Security::validate_remote_url( 'http://localhost/' );
		$this->assertFalse( $result['valid'] );
		$this->assertStringContainsString( 'Localhost', (string) $result['error'] );
	}

	public function test_validate_remote_url_blocks_private_ip_literal(): void {
		$result = Security::validate_remote_url( 'http://10.0.0.5/' );
		$this->assertFalse( $result['valid'] );

		$result127 = Security::validate_remote_url( 'http://127.0.0.1/' );
		$this->assertFalse( $result127['valid'] );

		$resultAws = Security::validate_remote_url( 'http://169.254.169.254/latest/meta-data' );
		$this->assertFalse( $resultAws['valid'] );
	}

	public function test_validate_remote_url_blocks_disallowed_scheme(): void {
		$result = Security::validate_remote_url( 'file:///etc/passwd' );
		$this->assertFalse( $result['valid'] );

		$result2 = Security::validate_remote_url( 'ftp://example.com/' );
		$this->assertFalse( $result2['valid'] );
	}

	public function test_validate_remote_url_rejects_empty(): void {
		$result = Security::validate_remote_url( '' );
		$this->assertFalse( $result['valid'] );
		$this->assertSame( 'URL is required.', $result['error'] );
	}

	public function test_is_safe_redirect_target_defers_to_validate(): void {
		$this->assertFalse( Security::is_safe_redirect_target( 'http://localhost/' ) );
		$this->assertFalse( Security::is_safe_redirect_target( 'http://10.0.0.1/' ) );
		// The hostname may not resolve in the test environment; either "valid"
		// or "could not be resolved" is acceptable. Just ensure no crash.
		Security::is_safe_redirect_target( 'https://example.test/' );
		$this->assertTrue( true );
	}
}