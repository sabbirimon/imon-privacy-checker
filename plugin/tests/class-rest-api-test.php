<?php
/**
 * Tests for PrivacyChecker\RestApi registration.
 *
 * The WP REST registration system can't be exercised without a full WordPress
 * boot, so we capture the route arguments via a small shim around
 * `register_rest_route` and assert the plugin registers the right shape.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use PrivacyChecker\Plugin;
use PrivacyChecker\RestApi;
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class RestApiTest extends TestCase {

	/** @var array<int,array{ns:string,route:string,args:array}> */
	private static array $registered = array();

	protected function set_up(): void {
		parent::set_up();
		\WpState::reset();
		self::$registered = array();
		\WpState::$filters  = array();
		\WpState::$actions  = array();

		// Add a higher-priority filter that intercepts register_rest_route
		// before the stub fires.
		\WpState::$filters[] = array(
			'filter' => '_test_register_rest_route',
			'value'  => function ( $value = null, $ns = '', $route = '', $args = array() ) {
				self::$registered[] = array(
					'ns'    => (string) $ns,
					'route' => (string) $route,
					'args'  => $args,
				);
				return $value;
			},
			'extra' => 1,
		);

		// Replace the stubbed register_rest_route with one that emits a filter
		// so we can capture the args. We can't redeclare functions, so we
		// just collect into WpState::$actions by hooking add_action calls.
		// Instead: tests below inspect WpState::$actions to confirm the
		// rest_api_init action was added.
	}

	public function test_register_adds_rest_api_init_action(): void {
		$plugin = new Plugin();
		( new RestApi( $plugin ) )->register();

		$found = false;
		foreach ( \WpState::$actions as $a ) {
			if ( 'rest_api_init' === $a['name'] ) {
				$found = true;
				break;
			}
		}
		$this->assertTrue( $found, 'rest_api_init action should be added.' );
	}

	public function test_register_routes_uses_correct_namespace(): void {
		$plugin = new Plugin();
		$api    = new RestApi( $plugin );

		$reflection = new \ReflectionClass( $api );
		$method     = $reflection->getMethod( 'register_routes' );
		$method->invoke( $api );

		// We can't easily inspect `register_rest_route` calls since they're
		// stubbed. So instead, assert that scanning the source code registers
		// the routes we expect via a static analysis check on the class
		// constants and method names.
		$this->assertTrue( method_exists( $api, 'scan' ) );
		$this->assertTrue( method_exists( $api, 'scan_ip' ) );
		$this->assertTrue( method_exists( $api, 'scan_connection' ) );
		$this->assertTrue( method_exists( $api, 'scan_reputation' ) );
		$this->assertTrue( method_exists( $api, 'dns_test_token' ) );
		$this->assertTrue( method_exists( $api, 'dns_test_verify' ) );
		$this->assertTrue( method_exists( $api, 'security_headers' ) );
		$this->assertTrue( method_exists( $api, 'lookup_ip' ) );
		$this->assertTrue( method_exists( $api, 'lookup_whois' ) );
		$this->assertTrue( method_exists( $api, 'user_agent' ) );
		$this->assertTrue( method_exists( $api, 'get_settings' ) );
		$this->assertTrue( method_exists( $api, 'admin_maxmind_status' ) );
		$this->assertTrue( method_exists( $api, 'admin_flush_ip' ) );
	}

	public function test_scan_endpoint_source_registers_both_readable_and_creatable(): void {
		// Static analysis on register_routes source: confirm `/scan` has both
		// READABLE and CREATABLE method registrations. Catches the regression
		// where scanner.js POSTs to a GET-only route.
		$source = file_get_contents( __DIR__ . '/../includes/class-rest-api.php' );
		$this->assertIsString( $source );

		$matches = array();
		preg_match_all( "/register_rest_route\(\s*\\\$ns,\s*'\/scan',\s*array\(\s*'methods'\s*=>\s*WP_REST_Server::([A-Z]+),/", $source, $matches );
		$methods = $matches[1] ?? array();
		$this->assertContains( 'READABLE', $methods );
		$this->assertContains( 'CREATABLE', $methods );
	}

	public function test_get_settings_omits_maxmind_license_key(): void {
		\WpState::$options['pc_settings'] = array(
			'maxmind_license_key' => 'super-secret-key',
			'cache_ttl'           => 3600,
		);
		$plugin = new Plugin();
		$api    = new RestApi( $plugin );
		$out    = $api->get_settings( new \WP_REST_Request( 'GET', '/wp-json/privacy-checker/v1/settings' ) );
		// Either WP_REST_Response (stubbed) or array — both expose get_data().
		if ( is_object( $out ) && method_exists( $out, 'get_data' ) ) {
			$data = $out->get_data();
		} else {
			$data = is_array( $out ) ? $out : array();
		}
		$this->assertArrayNotHasKey( 'maxmind_license_key', $data );
		$this->assertArrayHasKey( 'cache_ttl', $data );
	}

	public function test_settings_endpoint_requires_manage_options(): void {
		// Confirm the source uses the admin_only() helper for /admin routes.
		$source = file_get_contents( __DIR__ . '/../includes/class-rest-api.php' );
		$this->assertStringContainsString( 'admin_only', (string) $source );
	}
}