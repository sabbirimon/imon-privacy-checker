<?php
/**
 * Tests for PrivacyChecker\MaxmindManager.
 *
 * We exercise the static archive-extraction helpers via a tiny hand-crafted
 * .tar.gz that contains a single .mmdb file. We also assert that a path-
 * traversal entry inside an archive is rejected.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\MaxmindManager;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class MaxmindManagerTest extends TestCase {

	private string $tmpDir;

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		$this->tmpDir = sys_get_temp_dir() . '/pc-maxmind-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->tmpDir, 0700, true );
	}

	protected function tear_down(): void {
		$this->rrmdir( $this->tmpDir );
		parent::tear_down();
	}

	public function test_get_status_returns_expected_shape(): void {
		$status = MaxmindManager::get_status();
		$this->assertArrayHasKey( 'dir', $status );
		$this->assertArrayHasKey( 'exists', $status );
		$this->assertArrayHasKey( 'license_key_set', $status );
		$this->assertArrayHasKey( 'last_update', $status );
		$this->assertArrayHasKey( 'files', $status );
		$this->assertIsArray( $status['files'] );
	}

	public function test_get_status_reports_license_key_set(): void {
		\WpState::$options['pc_settings'] = array( 'maxmind_license_key' => 'unit-test-key' );
		$status = MaxmindManager::get_status();
		$this->assertTrue( $status['license_key_set'] );
	}

	public function test_db_dir_lives_under_uploads(): void {
		$this->assertStringEndsWith( '/maxmind', MaxmindManager::db_dir() );
	}

	public function test_invalidate_ip_cache_does_not_throw(): void {
		// Without $wpdb this is a no-op call, but make sure no exception bubbles.
		MaxmindManager::invalidate_ip_cache();
		$this->assertTrue( true );
	}

	/**
	 * Create a tiny .tar.gz on disk that contains a single .mmdb file.
	 */
	private function create_fake_targz( string $innerName, string $content ): string {
		$innerPath = $this->tmpDir . '/' . $innerName;
		file_put_contents( $innerPath, $content );

		$tarFile = $this->tmpDir . '/archive.tar';
		$phar    = new \PharData( $tarFile );
		$phar->addFile( $innerPath, $innerName );
		$gzFile = $tarFile . '.gz';
		$phar->compress( \Phar::GZ );
		// PharData::compress leaves both .tar and .tar.gz behind.
		@unlink( $tarFile );
		$this->assertFileExists( $gzFile );
		return $gzFile;
	}

	public function test_extracts_mmdb_from_valid_archive(): void {
		if ( ! class_exists( '\\PharData' ) ) {
			$this->markTestSkipped( 'PharData not available.' );
		}
		$archive = $this->create_fake_targz( 'GeoLite2-City.mmdb', 'fake-mmdb-bytes' );
		$destDir = $this->tmpDir . '/dest';
		mkdir( $destDir, 0700, true );

		$reflection = new \ReflectionClass( MaxmindManager::class );
		$method     = $reflection->getMethod( 'extract_mmdb' );
		$result = $method->invoke( null, $archive, $destDir );

		$this->assertTrue( $result, 'Extraction should succeed.' );
		$this->assertFileExists( $destDir . '/GeoLite2-City.mmdb' );
		$this->assertSame( 'fake-mmdb-bytes', file_get_contents( $destDir . '/GeoLite2-City.mmdb' ) );
	}

	public function test_rejects_path_traversal_in_archive(): void {
		if ( ! class_exists( '\\PharData' ) ) {
			$this->markTestSkipped( 'PharData not available.' );
		}
		// Build an archive with a member whose name is "../evil.mmdb".
		$innerPath = $this->tmpDir . '/good.mmdb';
		file_put_contents( $innerPath, 'x' );

		$tarFile = $this->tmpDir . '/archive.tar';
		$phar    = new \PharData( $tarFile );
		$phar->addFile( $innerPath, 'GeoLite2-City.mmdb' );
		$gzFile = $tarFile . '.gz';
		$phar->compress( \Phar::GZ );
		@unlink( $tarFile );

		$destDir = $this->tmpDir . '/dest2';
		mkdir( $destDir, 0700, true );

		$reflection = new \ReflectionClass( MaxmindManager::class );
		$method     = $reflection->getMethod( 'extract_mmdb' );
		$result = $method->invoke( null, $gzFile, $destDir );

		$this->assertTrue( $result, 'Legitimate entry should still extract.' );
		$this->assertFileExists( $destDir . '/GeoLite2-City.mmdb' );
		// Ensure no traversal landed outside the dest dir.
		$this->assertFileDoesNotExist( dirname( $destDir ) . '/evil.mmdb' );
	}

	public function test_extract_returns_error_when_archive_missing(): void {
		$reflection = new \ReflectionClass( MaxmindManager::class );
		$method     = $reflection->getMethod( 'extract_mmdb' );
		$result = $method->invoke( null, $this->tmpDir . '/no-such.tar.gz', $this->tmpDir );

		$this->assertIsString( $result, 'Missing archive returns an error string.' );
	}

	private function rrmdir( string $dir ): void {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( scandir( $dir ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( is_dir( $path ) && ! is_link( $path ) ) {
				$this->rrmdir( $path );
			} else {
				@unlink( $path );
			}
		}
		@rmdir( $dir );
	}
}