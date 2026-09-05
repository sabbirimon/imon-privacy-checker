<?php
/**
 * Tests for PrivacyChecker\TlsInfo — TLS protocol + cipher reporting for
 * the current request. Pure data lookup; the class never makes a
 * network call.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\TlsInfo;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class TlsInfoTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		// Reset $_SERVER every test — TlsInfo reads from it directly.
		$_SERVER = array();
	}

	public function test_returns_unknown_when_no_protocol_key_present(): void {
		unset( $_SERVER['SSL_PROTOCOL'], $_SERVER['HTTPS_TLS_VERSION'], $_SERVER['TLS_VERSION'] );
		unset( $_SERVER['SSL_CIPHER'],   $_SERVER['HTTPS_TLS_CIPHER'],   $_SERVER['TLS_CIPHER'] );

		$r = TlsInfo::current_request_info();

		$this->assertSame( 'unknown', $r['status'] );
		$this->assertSame( '',         $r['protocol'] );
		$this->assertSame( '',         $r['cipher'] );
		$this->assertNotEmpty(        $r['note'] );
	}

	public function test_returns_modern_for_tls_v1_3(): void {
		$_SERVER['SSL_PROTOCOL'] = 'TLSv1.3';
		$_SERVER['SSL_CIPHER']   = 'TLS_AES_128_GCM_SHA256';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'modern',                $r['status'] );
		$this->assertSame( 'TLSv1.3',               $r['protocol'] );
		$this->assertSame( 'TLS_AES_128_GCM_SHA256', $r['cipher'] );
		$this->assertStringContainsString( 'current', $r['note'] );
	}

	public function test_returns_modern_for_tls_v1_3_via_nginx_key(): void {
		unset( $_SERVER['SSL_PROTOCOL'] );
		$_SERVER['HTTPS_TLS_VERSION'] = 'TLSv1.3';
		$_SERVER['HTTPS_TLS_CIPHER']  = 'TLS_CHACHA20_POLY1305_SHA256';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'modern', $r['status'] );
		$this->assertSame( 'TLSv1.3', $r['protocol'] );
		$this->assertSame( 'TLS_CHACHA20_POLY1305_SHA256', $r['cipher'] );
	}

	public function test_returns_acceptable_for_tls_v1_2(): void {
		$_SERVER['SSL_PROTOCOL'] = 'TLSv1.2';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'acceptable', $r['status'] );
		$this->assertStringContainsString( 'acceptable', $r['note'] );
	}

	public function test_returns_outdated_for_tls_v1_0(): void {
		$_SERVER['SSL_PROTOCOL'] = 'TLSv1.0';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'outdated', $r['status'] );
		$this->assertStringContainsString( 'outdated', $r['note'] );
	}

	public function test_returns_outdated_for_sslv3(): void {
		$_SERVER['SSL_PROTOCOL'] = 'SSLv3';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'outdated', $r['status'] );
	}

	public function test_cipher_present_without_protocol_still_unknown(): void {
		unset( $_SERVER['SSL_PROTOCOL'] );
		$_SERVER['SSL_CIPHER'] = 'something';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'unknown', $r['status'] );
		// Cipher alone shouldn't be lost — useful for the UI even if
		// the protocol can't be classified.
		$this->assertSame( 'something', $r['cipher'] );
	}

	public function test_unknown_protocol_string_yields_unknown_not_outdated(): void {
		// Some servers report protocol under a non-standard label.
		// Don't false-alarm; treat as unknown.
		$_SERVER['SSL_PROTOCOL'] = 'CUSTOM_FUTURE_TLS';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'unknown', $r['status'] );
		$this->assertSame( 'CUSTOM_FUTURE_TLS', $r['protocol'] );
	}

	public function test_empty_string_in_protocol_key_treated_as_unknown(): void {
		$_SERVER['SSL_PROTOCOL'] = '   ';
		$r = TlsInfo::current_request_info();
		$this->assertSame( 'unknown', $r['status'] );
	}

	public function test_classify_protocol_static_method(): void {
		$this->assertSame( 'modern',     TlsInfo::classify_protocol( 'TLSv1.3' ) );
		$this->assertSame( 'acceptable', TlsInfo::classify_protocol( 'TLSv1.2' ) );
		$this->assertSame( 'outdated',   TlsInfo::classify_protocol( 'TLSv1.1' ) );
		$this->assertSame( 'outdated',   TlsInfo::classify_protocol( 'TLSv1.0' ) );
		$this->assertSame( 'outdated',   TlsInfo::classify_protocol( 'SSLv3' ) );
		$this->assertSame( 'outdated',   TlsInfo::classify_protocol( 'SSLv2' ) );
		$this->assertSame( 'unknown',    TlsInfo::classify_protocol( '' ) );
		$this->assertSame( 'unknown',    TlsInfo::classify_protocol( 'no-prefix' ) );
	}
}
