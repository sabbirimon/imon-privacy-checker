<?php
/**
 * Tests for PrivacyChecker\ApiTokens.
 *
 * Uses the WordPress stub harness to avoid touching a real DB. The token CRUD
 * methods hit $wpdb, so we register a tiny in-memory shim via the
 * WpState helper used by the rest of the suite.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PHPUnit\Framework\TestCase;
use PrivacyChecker\ApiTokens;
use WpState;

/**
 * @coversDefaultClass \PrivacyChecker\ApiTokens
 */
final class ApiTokensTest extends TestCase {

	protected function set_up(): void {
		parent::set_up();
		WpState::reset();
		// Pre-populate the secret salt used by the API token hashing.
		WpState::$options['pc_settings'] = array(
			'secret_salt'        => 'unit-test-salt',
			'api_tokens_enabled' => true,
		);
	}

	public function test_issue_returns_prefixed_token(): void {
		$issued = ApiTokens::issue( 'bot-1', array( 'scan:read' ), 60, 42 );
		$this->assertStringStartsWith( ApiTokens::PREFIX, $issued['token'] );
		$this->assertSame( 60, $issued['rate_limit'] );
		$this->assertSame( 'bot-1', $issued['label'] );
		$this->assertContains( 'scan:read', $issued['scopes'] );
	}

	public function test_verify_round_trip(): void {
		$issued = ApiTokens::issue( 'bot-2', array( 'lookup:read' ), 30, 1 );
		$row = ApiTokens::verify( $issued['token'] );
		$this->assertIsArray( $row );
		$this->assertSame( 'bot-2', $row['label'] );
		$this->assertContains( 'lookup:read', $row['scopes'] );
		$this->assertSame( 30, (int) $row['rate_limit_per_minute'] );
	}

	public function test_verify_rejects_unknown_token(): void {
		$row = ApiTokens::verify( ApiTokens::PREFIX . 'deadbeef' );
		$this->assertNull( $row );
	}

	public function test_verify_rejects_empty_or_wrong_prefix(): void {
		$this->assertNull( ApiTokens::verify( '' ) );
		$this->assertNull( ApiTokens::verify( 'wrong_prefix_xxx' ) );
	}

	public function test_has_scope_with_admin_write_grants_all(): void {
		$issued = ApiTokens::issue( 'admin-bot', array( 'admin:write' ), 60, 1 );
		$row = ApiTokens::verify( $issued['token'] );
		$this->assertTrue( ApiTokens::has_scope( $row, 'scan:read' ) );
		$this->assertTrue( ApiTokens::has_scope( $row, 'lookup:read' ) );
		$this->assertTrue( ApiTokens::has_scope( $row, 'dns:read' ) );
	}

	public function test_revoke_invalidates_token(): void {
		$issued = ApiTokens::issue( 'bot-3', array( 'scan:read' ), 30, 1 );
		$this->assertNotNull( ApiTokens::verify( $issued['token'] ) );
		ApiTokens::revoke( (int) $issued['id'] );
		$this->assertNull( ApiTokens::verify( $issued['token'] ) );
	}

	public function test_verify_respects_disabled_flag(): void {
		$issued = ApiTokens::issue( 'bot-4', array( 'scan:read' ), 30, 1 );
		WpState::$options['pc_settings']['api_tokens_enabled'] = false;
		$this->assertNull( ApiTokens::verify( $issued['token'] ) );
	}

	public function test_extract_bearer_reads_header(): void {
		$req = new \WP_REST_Request();
		$req->set_header( 'authorization', 'Bearer pc_live_xyz' );
		$this->assertSame( 'pc_live_xyz', ApiTokens::extract_bearer( $req ) );

		$req2 = new \WP_REST_Request();
		$req2->set_header( 'authorization', 'bearer pc_live_abc' );
		$this->assertSame( 'pc_live_abc', ApiTokens::extract_bearer( $req2 ) );

		$req3 = new \WP_REST_Request();
		$this->assertNull( ApiTokens::extract_bearer( $req3 ) );
	}
}
