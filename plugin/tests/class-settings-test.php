<?php
/**
 * Tests for PrivacyChecker\Settings — sanitization + allowed chain keys.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Settings;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class SettingsTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
	}

	public function test_allowed_chain_keys_contain_required_providers(): void {
		$keys = Settings::allowed_chain_keys();
		$this->assertContains( 'maxmind', $keys );
		$this->assertContains( 'ip-api-com', $keys );
		$this->assertContains( 'ipinfo', $keys );
		$this->assertContains( 'ipapi', $keys );
		$this->assertContains( 'mock', $keys );
	}

	public function test_provider_options_lists_ip_providers(): void {
		$opts = Settings::provider_options();
		$this->assertArrayHasKey( 'ip_provider', $opts );
		$this->assertContains( 'maxmind', $opts['ip_provider'] );
		$this->assertContains( 'ip-api-com', $opts['ip_provider'] );
	}

	public function test_sanitize_accepts_valid_chain_array(): void {
		$current = array();
		$input   = array(
			'provider_chain_ip' => array( 'maxmind', 'ip-api-com', 'mock' ),
		);
		$out     = Settings::sanitize( array_merge( $current, $input ) );
		$this->assertSame( array( 'maxmind', 'ip-api-com', 'mock' ), $out['provider_chain_ip'] );
	}

	public function test_sanitize_accepts_chain_as_csv_string(): void {
		$out = Settings::sanitize( array( 'provider_chain_ip' => 'mock,ip-api-com,maxmind' ) );
		$this->assertSame( array( 'mock', 'ip-api-com', 'maxmind' ), $out['provider_chain_ip'] );
	}

	public function test_sanitize_drops_unknown_chain_keys(): void {
		$out = Settings::sanitize( array( 'provider_chain_ip' => array( 'maxmind', 'evil-provider', 'mock' ) ) );
		$this->assertSame( array( 'maxmind', 'mock' ), $out['provider_chain_ip'] );
	}

	public function test_sanitize_falls_back_when_chain_empty(): void {
		$out = Settings::sanitize( array( 'provider_chain_ip' => array() ) );
		$this->assertNotEmpty( $out['provider_chain_ip'] );
	}

	public function test_sanitize_clamps_rate_limits(): void {
		$out = Settings::sanitize( array( 'rate_limit_scan' => 999999 ) );
		$this->assertSame( 10000, $out['rate_limit_scan'] );

		$out = Settings::sanitize( array( 'rate_limit_scan' => -5 ) );
		$this->assertSame( 1, $out['rate_limit_scan'] );
	}

	public function test_sanitize_clamps_cache_ttl_to_one_day(): void {
		$out = Settings::sanitize( array( 'cache_ttl' => 99999999 ) );
		$this->assertSame( DAY_IN_SECONDS, $out['cache_ttl'] );
	}

	public function test_sanitize_strips_non_https_custom_urls(): void {
		$out = Settings::sanitize( array(
			'maxmind_custom_urls' => array(
				'https://download.maxmind.com/example.tar.gz',
				'http://insecure.example.com/x.tar.gz',
				'ftp://also.invalid/y.tar.gz',
				'',
			),
		) );
		$this->assertCount( 1, $out['maxmind_custom_urls'] );
		$this->assertStringStartsWith( 'https://', $out['maxmind_custom_urls'][0] );
	}

	public function test_sanitize_accepts_newline_separated_custom_urls(): void {
		$out = Settings::sanitize( array(
			'maxmind_custom_urls' => "https://a.example.com/x.tar.gz\nhttps://b.example.com/y.tar.gz\n",
		) );
		$this->assertCount( 2, $out['maxmind_custom_urls'] );
	}

	public function test_sanitize_persists_existing_license_key_when_input_blank(): void {
		\WpState::$options['pc_settings'] = array( 'maxmind_license_key' => 'kept-secret' );
		$out = Settings::sanitize( array( 'maxmind_license_key' => '' ) );
		$this->assertSame( 'kept-secret', $out['maxmind_license_key'] );
	}

	public function test_sanitize_seeds_secret_salt_when_missing(): void {
		$out = Settings::sanitize( array() );
		$this->assertNotEmpty( $out['secret_salt'] );
		$this->assertGreaterThanOrEqual( 32, strlen( $out['secret_salt'] ) );
	}
}