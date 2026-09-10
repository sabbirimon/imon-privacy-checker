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

	public function test_sanitize_normalises_logs_block_defaults(): void {
		$out = Settings::sanitize( array(
			'logs' => array(
				'scan_enabled'    => '1',
				'share_enabled'   => '',
				'export_enabled'  => '1',
				'restore_enabled' => '0',
				'error_enabled'   => '1',
				'admin_enabled'   => '0',
				'retention_days'  => 7,
				'max_rows'        => 1000,
			),
		) );
		$this->assertTrue( $out['logs']['scan_enabled'] );
		$this->assertFalse( $out['logs']['share_enabled'] );
		$this->assertTrue( $out['logs']['export_enabled'] );
		$this->assertFalse( $out['logs']['restore_enabled'] );
		$this->assertSame( 7, $out['logs']['retention_days'] );
		$this->assertSame( 1000, $out['logs']['max_rows'] );
	}

	public function test_sanitize_clamps_logs_retention_days_to_minimum(): void {
		$out = Settings::sanitize( array( 'logs' => array( 'retention_days' => -10 ) ) );
		$this->assertSame( 1, $out['logs']['retention_days'] );
	}

	public function test_sanitize_clamps_logs_retention_days_to_maximum(): void {
		$out = Settings::sanitize( array( 'logs' => array( 'retention_days' => 9999999 ) ) );
		$this->assertSame( 3650, $out['logs']['retention_days'] );
	}

	public function test_sanitize_clamps_logs_max_rows_to_floor(): void {
		$out = Settings::sanitize( array( 'logs' => array( 'max_rows' => 50 ) ) );
		$this->assertSame( 1000, $out['logs']['max_rows'] );
	}

	public function test_sanitize_clamps_logs_max_rows_to_ceiling(): void {
		$out = Settings::sanitize( array( 'logs' => array( 'max_rows' => 9999999 ) ) );
		$this->assertSame( 1000000, $out['logs']['max_rows'] );
	}

	public function test_sanitize_logs_block_defaults_when_input_missing(): void {
		// Fresh install without any logs.* keys: the per-category toggles
		// default to false at sanitize time (a brand-new settings page
		// submission that never opened the Logging section), but the
		// retention/max_rows caps fall back to the documented defaults.
		$out = Settings::sanitize( array() );
		$this->assertArrayHasKey( 'logs', $out );
		$this->assertSame( 90, $out['logs']['retention_days'] );
		$this->assertSame( 50000, $out['logs']['max_rows'] );
	}

	public function test_sanitize_logs_block_inherits_existing_values(): void {
		// An admin who enabled some categories previously should keep
		// them after submitting a settings page that didn't touch the
		// Logging section.
		\WpState::$options['pc_settings'] = array(
			'logs' => array(
				'scan_enabled'    => true,
				'share_enabled'   => false,
				'export_enabled'  => true,
				'restore_enabled' => true,
				'error_enabled'   => true,
				'admin_enabled'   => true,
				'retention_days'  => 60,
				'max_rows'        => 25000,
			),
		);
		$out = Settings::sanitize( array() );
		// When the admin didn't open the Logging section, all toggles
		// revert to "not enabled" — but the retention caps are preserved
		// from the existing option. Document this so it's intentional.
		$this->assertSame( 60, $out['logs']['retention_days'] );
		$this->assertSame( 25000, $out['logs']['max_rows'] );
	}
}