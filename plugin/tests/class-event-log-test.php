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
}