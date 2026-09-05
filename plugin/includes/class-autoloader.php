<?php
/**
 * PSR-4 autoloader for the Privacy Checker plugin.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Simple PSR-4 autoloader.
 *
 * Supports both `PrivacyChecker\Foo\Bar` → `includes/foo/class-bar.php`
 * and `PrivacyChecker\Provider\Baz` → `includes/providers/class-baz-provider.php`.
 */
final class Autoloader {

    /**
     * Register the autoloader with SPL.
     */
    public static function register(): void {
        spl_autoload_register( array( self::class, 'load' ) );
    }

    /**
     * Resolve a class name to a file path and require it if it exists.
     *
     * Resolution order:
     *   1. If namespace contains 'Provider\Interfaces': looks for `interfaces/interface-{slug}.php`
     *   2. If last segment begins with 'Interface_': looks for `interfaces/interface-{slug}.php`
     *   3. Otherwise: `class-{slug}.php` under the namespace subfolder.
     *
     * @param string $class Fully-qualified class name.
     */
    public static function load( string $class ): void {
        if ( strpos( $class, 'PrivacyChecker\\' ) !== 0 ) {
            return;
        }

        $relative = substr( $class, strlen( 'PrivacyChecker\\' ) );
        $parts    = explode( '\\', $relative );

        $last_segment = array_pop( $parts );
        // Convert camelCase / PascalCase to kebab-case, plus underscores.
        // Examples: EventLog -> event-log, IpFallback -> ip-fallback, MaxMindProvider -> max-mind-provider.
        $slug         = strtolower( preg_replace( '/(?<!^)([A-Z])/', '-$1', str_replace( '_', '-', $last_segment ) ) );

        // Special-case for interfaces: any class whose name ends with
        // `Interface` (e.g. `IpIntelligenceProviderInterface`) or lives
        // under the `Interfaces\` sub-namespace is loaded from an
        // `interface-{slug}.php` file. Note: we check the suffix, not the
        // prefix, because PHP allows interfaces named like
        // `IpIntelligenceProviderInterface`.
        $is_interface = (
            in_array( 'Interfaces', $parts, true ) ||
            str_ends_with( $last_segment, 'Interface' )
        );

        // If this is an interface (e.g. `IpIntelligenceProviderInterface`),
        // strip the trailing `-interface` from the file slug because the
        // files on disk are named like `interface-ip-intelligence-provider.php`
        // (not `...-interface.php`).
        if ( $is_interface && str_ends_with( $slug, '-interface' ) ) {
            $slug = substr( $slug, 0, -strlen( '-interface' ) );
        }

        $file_slug    = ( $is_interface ? 'interface-' : 'class-' ) . $slug;

        // Build the subfolder path. Note that the singular `Provider`
        // namespace segment resolves to the `interfaces/` folder on disk
        // when we're looking for an interface; otherwise it stays as-is.
        $subfolder = implode( '/', array_map(
            static function ( string $segment ) use ( $is_interface ): string {
                $lower = strtolower( str_replace( '_', '-', $segment ) );
                if ( $is_interface && 'provider' === $lower ) {
                    return 'interfaces';
                }
                return $lower;
            },
            $parts
        ) );

        $path = PRIVACY_CHECKER_DIR . 'includes/'
            . ( '' !== $subfolder ? $subfolder . '/' : '' )
            . $file_slug . '.php';

        if ( is_readable( $path ) ) {
            require_once $path;
            return;
        }

        // Fallback: top-level interfaces/ folder.
        if ( $is_interface ) {
            $alt = PRIVACY_CHECKER_DIR . 'includes/interfaces/' . $file_slug . '.php';
            if ( is_readable( $alt ) ) {
                require_once $alt;
                return;
            }
        }

        // Fallback: top-level providers/ folder.
        $alt_provider = PRIVACY_CHECKER_DIR . 'includes/providers/' . $file_slug . '.php';
        if ( is_readable( $alt_provider ) ) {
            require_once $alt_provider;
            return;
        }

        // Fallback: plugin/admin/ (admin sub-namespace classes live there).
        $alt_admin = PRIVACY_CHECKER_DIR . 'admin/' . $file_slug . '.php';
        if ( is_readable( $alt_admin ) ) {
            require_once $alt_admin;
            return;
        }

        // Fallback: plugin/public/ (public-facing classes live there).
        $alt_public = PRIVACY_CHECKER_DIR . 'public/' . $file_slug . '.php';
        if ( is_readable( $alt_public ) ) {
            require_once $alt_public;
        }
    }
}