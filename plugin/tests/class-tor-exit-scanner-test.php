<?php
/**
 * Tests for the Tor / VPN / proxy exit-list scanner.
 *
 * Exercises the scanner's IP-matching against in-memory fake list files.
 * The scanner reads files from the upload dir (pc_uploads() helper), so
 * the test stubs `GeoIpDatabase::list_with_meta()` via the wpdb_stub layer.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\GeoIpDatabase;
use PrivacyChecker\TorExitScanner;
use PHPUnit\Framework\TestCase;
use WpState;

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/**
 * @covers \PrivacyChecker\TorExitScanner
 */
final class TorExitScannerTest extends TestCase {

	/** @var string */
	private string $tmpdir;

	protected function setUp(): void {
		parent::setUp();
		// Reset wp state from previous tests.
		WpState::reset();
		$this->tmpdir = sys_get_temp_dir() . '/pc-tortest-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->tmpdir, 0755, true );
		// Point the upload dir at our temp folder via a filter.
		add_filter( 'pc_geoip_upload_dir', function () { return $this->tmpdir; } );
	}

	protected function tearDown(): void {
		WpState::reset();
		if ( is_dir( $this->tmpdir ) ) {
			foreach ( (array) scandir( $this->tmpdir ) as $f ) {
				if ( '.' !== $f && '..' !== $f ) {
					@unlink( $this->tmpdir . '/' . $f );
				}
			}
			@rmdir( $this->tmpdir );
		}
		parent::tearDown();
	}

	private function write_list( string $category, string $filename, string $body ): void {
		file_put_contents( $this->tmpdir . '/' . $category . '__' . $filename, $body );
	}

	public function test_lookup_returns_tor_match_when_ip_in_tor_list(): void {
		$this->write_list( 'tor', 'exits.txt', "198.51.100.7\n203.0.113.42\n# comment line\n" );
		$result = TorExitScanner::lookup( '203.0.113.42' );
		$this->assertTrue( $result['tor']['matched'] );
		$this->assertSame( 'tor', $result['tor']['category'] );
		$this->assertStringContainsString( '203.0.113.42', (string) $result['tor']['match'] );
		$this->assertFalse( $result['vpn']['matched'] );
	}

	public function test_lookup_skips_comment_lines(): void {
		$this->write_list( 'tor', 'exits.txt', "# this is a comment\n198.51.100.7\n" );
		// The comment line must not match an IP literal; the only real IP in
		// the file is 198.51.100.7 so a query for an unrelated IP returns
		// matched=false.
		$result = TorExitScanner::lookup( '8.8.8.8' );
		$this->assertFalse( $result['tor']['matched'] );
		// And querying the real IP does match.
		$result2 = TorExitScanner::lookup( '198.51.100.7' );
		$this->assertTrue( $result2['tor']['matched'] );
	}

	public function test_lookup_handles_csv_list(): void {
		$this->write_list( 'vpn', 'providers.csv',
			"Provider,IP,Country\nMullvad,198.51.100.7,SE\nPIA,203.0.113.42,US\n" );
		$result = TorExitScanner::lookup( '198.51.100.7' );
		$this->assertTrue( $result['vpn']['matched'] );
	}

	public function test_lookup_handles_whitespace_separated(): void {
		$this->write_list( 'proxy', 'open.txt', "open proxy list\n198.51.100.7  foo bar\n203.0.113.42 baz\n" );
		$result = TorExitScanner::lookup( '203.0.113.42' );
		$this->assertTrue( $result['proxy']['matched'] );
	}

	public function test_lookup_returns_no_match_when_ip_absent(): void {
		$this->write_list( 'tor', 'exits.txt', "198.51.100.7\n" );
		$result = TorExitScanner::lookup( '8.8.8.8' );
		$this->assertFalse( $result['tor']['matched'] );
	}

	public function test_lookup_rejects_invalid_ip(): void {
		$this->assertSame( array(), TorExitScanner::lookup( 'not-an-ip' ) );
	}

	public function test_is_tor_exit_convenience(): void {
		$this->write_list( 'tor', 'exits.txt', "198.51.100.7\n" );
		$hit = TorExitScanner::is_tor_exit( '198.51.100.7' );
		$this->assertNotNull( $hit );
		$this->assertTrue( $hit['matched'] );
		$miss = TorExitScanner::is_tor_exit( '1.1.1.1' );
		$this->assertNotNull( $miss );
		$this->assertFalse( $miss['matched'] );
	}

	public function test_supported_categories_contains_tor(): void {
		$cats = TorExitScanner::supported_categories();
		$this->assertContains( 'tor', $cats );
		$this->assertContains( 'vpn', $cats );
		$this->assertContains( 'proxy', $cats );
	}
}
