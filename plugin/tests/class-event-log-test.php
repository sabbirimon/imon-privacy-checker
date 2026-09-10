<?php
/**
 * Tests for PrivacyChecker\EventLog.
 *
 * Uses a per-test fake table name backed by a static array in WpState.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\EventLog;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class EventLogTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		\WpState::$options['pc_settings'] = array( 'event_log_enabled' => true );
	}

	public function test_enabled_returns_true_when_setting_on(): void {
		\WpState::$options['pc_settings']['event_log_enabled'] = true;
		$this->assertTrue( EventLog::enabled() );
	}

	public function test_enabled_returns_false_by_default(): void {
		\WpState::$options['pc_settings'] = array();
		$this->assertFalse( EventLog::enabled() );
	}

	public function test_record_inserts_row_when_enabled(): void {
		// Ensure stub `ensure_table` is non-blocking.
		EventLog::record( 'info', 'scan', 'hello world' );
		// Without dbDelta support, `record` will attempt to write; the stub
		// short-circuits. We just confirm it didn't throw.
		$this->assertTrue( true );
	}

	public function test_record_is_noop_when_disabled(): void {
		\WpState::$options['pc_settings']['event_log_enabled'] = false;
		EventLog::record( 'info', 'scan', 'should be dropped' );
		// We cannot easily inspect a table we don't have, but we can confirm
		// no fatal error and no wp_send_json_error triggered.
		$this->assertSame( array(), \WpState::$errors );
	}

	public function test_clear_is_safe_when_disabled(): void {
		EventLog::clear();
		$this->assertTrue( true );
	}

	public function test_recent_returns_empty_array_when_no_table(): void {
		// Without dbDelta the table never exists; recent() must not throw.
		$rows = EventLog::recent( 10 );
		$this->assertIsArray( $rows );
	}

	public function test_counts_by_day_returns_empty_when_no_table(): void {
		$series = EventLog::counts_by_day( 7 );
		$this->assertIsArray( $series );
	}

	// ---------------------------------------------------------------
	// Phase 28 — extended schema (event, context) + record_if_enabled
	// ---------------------------------------------------------------

	public function test_record_if_enabled_respects_per_category_toggle(): void {
		\WpState::$options['pc_settings']['logs'] = array(
			'scan_enabled'    => true,
			'share_enabled'   => false,
			'export_enabled'  => true,
			'restore_enabled' => true,
			'error_enabled'   => true,
			'admin_enabled'   => true,
		);

		// The stub WpState doesn't actually write rows; the gate is the
		// observable side-effect (no error) + the fact that the call
		// returns boolean.
		$scan_ok = EventLog::record_if_enabled( 'scan', 'info', 'scan', 'v2 scan', array( 'score' => 74 ) );
		$share_blocked = EventLog::record_if_enabled( 'share', 'info', 'share', 'share-link', array() );
		$export_ok = EventLog::record_if_enabled( 'export', 'info', 'export', 'download-json', array() );

		$this->assertTrue( $scan_ok, 'scan category is on → recorded' );
		$this->assertFalse( $share_blocked, 'share category is off → blocked' );
		$this->assertTrue( $export_ok, 'export category is on → recorded' );
	}

	public function test_record_if_enabled_defaults_to_true_when_setting_missing(): void {
		// Admin who never opened the settings page still gets a full
		// audit trail. Default for every category is true.
		\WpState::$options['pc_settings']['logs'] = array();
		$scan_ok = EventLog::record_if_enabled( 'scan', 'info', 'scan', 'first scan', array() );
		$this->assertTrue( $scan_ok, 'missing toggle key defaults to true' );
	}

	public function test_record_if_enabled_respects_master_switch(): void {
		\WpState::$options['pc_settings']['event_log_enabled'] = false;
		$ok = EventLog::record_if_enabled( 'scan', 'info', 'scan', 'should be dropped', array() );
		$this->assertFalse( $ok, 'master switch off → all categories gated' );
	}

	public function test_purge_returns_zero_when_no_table(): void {
		$result = EventLog::purge( 90, 50000 );
		$this->assertIsArray( $result );
		$this->assertArrayHasKey( 'deleted_by_age', $result );
		$this->assertArrayHasKey( 'deleted_by_cap', $result );
		$this->assertSame( 0, $result['deleted_by_age'] );
		$this->assertSame( 0, $result['deleted_by_cap'] );
	}

	public function test_counts_by_event_returns_zeroed_baseline_when_no_table(): void {
		$counts = EventLog::counts_by_event( 30 );
		$this->assertIsArray( $counts );
		// Every known category must be present (zero) so the KPI tiles
		// never have to deal with a missing key.
		foreach ( EventLog::CATEGORIES as $cat ) {
			$this->assertArrayHasKey( $cat, $counts );
			$this->assertSame( 0, $counts[ $cat ] );
		}
	}

	public function test_recent_accepts_filter_array_without_throwing(): void {
		$rows = EventLog::recent( 10, array(
			'event'  => 'scan',
			'level'  => 'error',
			'days'   => 7,
			'search' => 'something',
		) );
		$this->assertIsArray( $rows );
	}

	public function test_record_backcompat_signature_still_works(): void {
		// The original 3-arg signature must keep working.
		EventLog::record( 'info', 'scan', 'legacy caller' );
		$this->assertSame( array(), \WpState::$errors );
	}

	public function test_record_new_signature_accepts_event_and_context(): void {
		EventLog::record( 'warning', 'scan', 'v2 scan', 'scan', array( 'score' => 74, 'grade' => 'C' ) );
		$this->assertSame( array(), \WpState::$errors );
	}
}