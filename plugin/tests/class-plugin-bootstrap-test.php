<?php
/**
 * Tests for the IMON Privacy Checker plugin bootstrap file.
 *
 * Regression guard for the symlinked-plugin URL bug (Phase 14.5): the
 * local dev WP install resolves `__FILE__` through the symlink to the
 * real filesystem path, so `plugin_dir_url( __FILE__ )` was baking
 * `/Users/code/.../Browser Checker/plugin/public/assets/` into every
 * asset URL and silently breaking the dashboard. The fix anchors
 * `PRIVACY_CHECKER_URL` to `content_url( 'plugins/privacy-checker/' )`,
 * which is symlink-safe.
 *
 * These tests fail the moment anyone reverts that fix.
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

namespace PrivacyChecker\Tests;

use Yoast\PHPUnitPolyfills\TestCases\TestCase;

final class PluginBootstrapTest extends TestCase {

	/**
	 * Boots plugin/privacy-checker.php in an isolated PHP process and
	 * reads back the resulting PRIVACY_CHECKER_URL constant. The child
	 * process gets a stubbed WP environment that mirrors wp-stubs.php
	 * but DOES NOT pre-define PRIVACY_CHECKER_URL — so the value we
	 * observe is whatever the plugin bootstrap itself defined.
	 *
	 * Using a child process (rather than re-running the file in the
	 * current test runner) keeps the bootstrap hermetic: a future
	 * regression that, say, runs register_activation_hook() during
	 * load would explode here instead of silently mutating global test
	 * state.
	 *
	 * @return string The PRIVACY_CHECKER_URL constant defined by the
	 *                plugin bootstrap in a clean PHP process.
	 */
	private function boot_plugin_isolated(): string {
		$plugin_file = dirname( __DIR__ ) . '/privacy-checker.php';

		if ( ! is_readable( $plugin_file ) ) {
			$this->markTestSkipped( 'Plugin bootstrap file not readable: ' . $plugin_file );
		}

		$script = <<<'PHP'
<?php
declare( strict_types = 1 );

// Mirrors plugin/tests/wp-stubs.php but does NOT pre-define
// PRIVACY_CHECKER_URL — that's what we're testing the plugin bootstrap for.
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! function_exists( 'plugin_dir_path' ) ) {
    function plugin_dir_path( string $file ): string {
        return dirname( $file ) . '/';
    }
}
if ( ! function_exists( 'plugin_dir_url' ) ) {
    function plugin_dir_url( string $file ): string {
        // Simulates the buggy path: plugin_dir_url(__FILE__) follows
        // the symlink and bakes the absolute filesystem path in.
        // The bootstrap must NOT call this for PRIVACY_CHECKER_URL.
        return 'https://example.test/wp-content/plugins/Users/code/Documents/';
    }
}
if ( ! function_exists( 'content_url' ) ) {
    function content_url( string $path = '' ): string {
        return 'https://example.test/wp-content/' . ltrim( $path, '/' );
    }
}
if ( ! function_exists( 'register_activation_hook' ) ) {
    function register_activation_hook( string $file, callable $callback ): void {}
}
if ( ! function_exists( 'register_deactivation_hook' ) ) {
    function register_deactivation_hook( string $file, callable $callback ): void {}
}
if ( ! function_exists( 'add_action' ) ) {
    function add_action( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
        return true;
    }
}

// ABSPATH guard inside the plugin: define it for the require.
require $argv[1];

echo PRIVACY_CHECKER_URL;
PHP;

		$tmp = tempnam( sys_get_temp_dir(), 'pc-bs-');
		if ( $tmp === false ) {
			$this->markTestSkipped( 'Could not create tempnam for isolated bootstrap test.' );
		}
		// tempnam creates an empty file; append our script with a PHP open tag.
		// We use a unique .php suffix so the linter / opcache doesn't complain.
		$script_file = $tmp . '.php';
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- intentional cleanup of the tempnam blank file.
		@unlink( $tmp );
		if ( file_put_contents( $script_file, $script ) === false ) {
			$this->markTestSkipped( 'Could not write isolated bootstrap script.' );
		}

		// PHP_BINARY is the same interpreter that's running PHPUnit. -d
		// flags disable opcache so re-running the bootstrap file in a
		// future test doesn't hit a stale cached result.
		$cmd = escapeshellcmd( PHP_BINARY )
			. ' -d opcache.enable_cli=0 -d opcache.enable=0'
			. ' ' . escapeshellarg( $script_file )
			. ' ' . escapeshellarg( $plugin_file )
			. ' 2>&1';

		$output = [];
		$rc     = 0;
		// phpcs:ignore WordPress.PHP.NoSilencedErrors -- best-effort isolated run.
		$lines  = @exec( $cmd, $output, $rc );
		// phpcs:ignore WordPress.PHP.NoSilencedErrors
		@unlink( $script_file );

		if ( $rc !== 0 || $lines === null ) {
			$this->fail(
				sprintf(
					"Isolated plugin bootstrap failed (rc=%d):\n%s",
					$rc,
					implode( "\n", $output )
				)
			);
		}

		// Trim any trailing whitespace / newlines from the printed URL.
		return rtrim( (string) $lines, "\r\n" );
	}

	/**
	 * Locks in the symlinked-plugin URL fix: PRIVACY_CHECKER_URL must
	 * end in `/wp-content/plugins/privacy-checker/` regardless of
	 * whether the install is a real directory or a symlink.
	 */
	public function test_url_constant_uses_plugin_slug_not_filesystem_path(): void {
		$url = $this->boot_plugin_isolated();

		$this->assertSame(
			'https://example.test/wp-content/plugins/privacy-checker/',
			$url,
			'PRIVACY_CHECKER_URL must resolve to /wp-content/plugins/privacy-checker/ ' .
			'(symlink-safe). See commit 6eed8bd.'
		);
	}

	/**
	 * The buggy implementation was `plugin_dir_url( __FILE__ )` which
	 * returns the absolute filesystem path on symlinked installs. Read
	 * the source file and assert it does NOT use that exact pattern for
	 * the PRIVACY_CHECKER_URL constant.
	 *
	 * Belt-and-braces companion to the runtime test above: even if a
	 * future refactor rewires the constant to a different helper, this
	 * source-level guard fires before the runtime test ever runs.
	 */
	public function test_source_does_not_use_plugin_dir_url_for_constant(): void {
		$plugin_file = dirname( __DIR__ ) . '/privacy-checker.php';
		$source      = file_get_contents( $plugin_file );
		$this->assertNotFalse( $source, 'Could not read plugin bootstrap file.' );

		// The PRIVACY_CHECKER_URL define block. Tolerate whitespace and
		// comments around the helper call.
		$this->assertMatchesRegularExpression(
			'/define\(\s*[\'"]PRIVACY_CHECKER_URL[\'"]\s*,\s*content_url\s*\(\s*[\'"]plugins\/privacy-checker\/[\'"]\s*\)\s*\)\s*;/',
			$source,
			'PRIVACY_CHECKER_URL must be defined via content_url(\'plugins/privacy-checker/\').'
		);
		$this->assertDoesNotMatchRegularExpression(
			'/define\(\s*[\'"]PRIVACY_CHECKER_URL[\'"]\s*,\s*plugin_dir_url\s*\(/',
			$source,
			'PRIVACY_CHECKER_URL must NOT use plugin_dir_url() — that helper ' .
			'follows symlinks and bakes the absolute filesystem path into the URL.'
		);
	}

	/**
	 * Smoke check: PRIVACY_CHECKER_FILE and PRIVACY_CHECKER_DIR stay
	 * filesystem-relative (plugin_dir_path is symlink-safe and we
	 * genuinely want the real disk path for vendor autoload etc.).
	 * Phase 14.5 only touched the URL constant — this guards against
	 * an over-eager future refactor that flips the DIR constant too.
	 */
	public function test_dir_constant_still_uses_plugin_dir_path(): void {
		$plugin_file = dirname( __DIR__ ) . '/privacy-checker.php';
		$source      = file_get_contents( $plugin_file );
		$this->assertNotFalse( $source );

		$this->assertMatchesRegularExpression(
			'/define\(\s*[\'"]PRIVACY_CHECKER_DIR[\'"]\s*,\s*plugin_dir_path\s*\(\s*__FILE__\s*\)\s*\)\s*;/',
			$source,
			'PRIVACY_CHECKER_DIR must continue to use plugin_dir_path(__FILE__) — ' .
			'vendor autoload etc. need the real on-disk path.'
		);
	}
}
