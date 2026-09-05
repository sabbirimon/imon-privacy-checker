<?php
/**
 * IANA root zone database.
 *
 * Source file: "All tld list/All tld list and detatis .txt"
 * Upstream:    https://www.iana.org/domains/root/db
 *
 * The bundled snapshot (plugin/data/iana-root-db.json) covers ~1,425
 * ccTLDs, gTLDs, and sponsored-restricted TLDs from the IANA root zone.
 * IDN entries (Arabic, Chinese, Cyrillic, etc.) are intentionally omitted
 * to keep the file small -- for non-ASCII TLDs the IANA RDAP bootstrap
 * and IANA WHOIS referral service remain authoritative.
 *
 * The JSON file is loaded lazily on first access and cached in process
 * memory. Admins can rebuild it from Settings -> WHOIS -> "Refresh
 * from IANA".
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Static snapshot of the IANA root zone database.
 *
 * Used by the WHOIS provider to enrich fallback responses with the
 * official IANA-registered type and TLD manager, and exposed via a
 * helper class for the rest of the plugin (admin diagnostics, REST
 * endpoints that need to know which TLDs the plugin supports).
 */
final class TldRegistry {

    /**
     * Path to the bundled JSON snapshot.
     */
    private const DATA_FILE = __DIR__ . '/../data/iana-root-db.json';

    /** Public IANA source for a complete root-zone listing. */
    private const IANA_ROOT_URL = 'https://www.iana.org/domains/root/db';

    /** Minimum interval between automatic refresh attempts. */
    private const AUTO_REFRESH_INTERVAL = DAY_IN_SECONDS;

    /**
     * Trigger an opt-in refresh from IANA's root-zone index.
     *
     * Refreshes are throttled to once per day and only run when the admin
     * explicitly enables `tld_registry_auto_update`. The bundled snapshot is
     * retained whenever the remote response cannot be fetched or parsed.
     *
     * @return array{status:string,count?:int,error?:string,source?:string}
     */
    public static function maybe_auto_refresh(): array {
        $settings = (array) get_option( 'pc_settings', array() );
        if ( empty( $settings['tld_registry_auto_update'] ) ) {
            return array( 'status' => 'disabled' );
        }
        $last = (int) get_option( 'pc_tld_registry_last_refresh', 0 );
        if ( $last > ( time() - self::AUTO_REFRESH_INTERVAL ) ) {
            return array( 'status' => 'throttled' );
        }
        update_option( 'pc_tld_registry_last_refresh', time(), false );
        return self::refresh_from_iana();
    }

    /** Refresh the local snapshot from IANA's root-zone index. */
    public static function refresh_from_iana(): array {
        $response = wp_remote_get( self::IANA_ROOT_URL, array(
            'timeout' => 15,
            'headers' => array( 'Accept' => 'text/html' ),
        ) );
        if ( is_wp_error( $response ) ) {
            return array( 'status' => 'error', 'error' => $response->get_error_message() );
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        $html = (string) wp_remote_retrieve_body( $response );
        if ( $code < 200 || $code >= 300 || '' === $html ) {
            return array( 'status' => 'error', 'error' => 'IANA returned HTTP ' . $code . '.' );
        }
        $rows = self::parse_root_index( $html );
        if ( count( $rows ) < 100 ) {
            return array( 'status' => 'error', 'error' => 'IANA response did not contain a complete TLD listing.' );
        }
        $json = wp_json_encode( $rows );
        if ( ! is_string( $json ) || false === file_put_contents( self::DATA_FILE, $json, LOCK_EX ) ) {
            return array( 'status' => 'error', 'error' => 'Could not write the local TLD snapshot.' );
        }
        self::flush_cache();
        update_option( 'pc_tld_registry_last_count', count( $rows ), false );
        return array( 'status' => 'ok', 'count' => count( $rows ), 'source' => self::IANA_ROOT_URL );
    }

    /** Parse TLD/type/manager rows from the IANA root database HTML. */
    private static function parse_root_index( string $html ): array {
        $out = array();
        if ( ! class_exists( 'DOMDocument' ) ) {
            return $out;
        }
        $dom = new \DOMDocument();
        $previous = libxml_use_internal_errors( true );
        $dom->loadHTML( $html );
        libxml_clear_errors();
        libxml_use_internal_errors( $previous );
        $xpath = new \DOMXPath( $dom );
        foreach ( $xpath->query( '//table//tr' ) as $row ) {
            $cells = array();
            foreach ( $xpath->query( './th|./td', $row ) as $cell ) {
                $cells[] = trim( preg_replace( '/\\s+/', ' ', $cell->textContent ) );
            }
            if ( count( $cells ) < 3 || 0 === strcasecmp( $cells[0], 'Domain' ) ) {
                continue;
            }
            $tld = strtolower( ltrim( $cells[0], '.' ) );
            if ( preg_match( '/^[a-z0-9-]+$/', $tld ) ) {
                $out[ $tld ] = array( $cells[1] => $cells[2] );
            }
        }
        ksort( $out );
        return $out;
    }

    /**
     * In-memory cache of the loaded TLD map.
     *
     * @var array<string,array<string,string>>|null
     */
    private static ?array $cache = null;

    /**
     * Load the snapshot from disk, then return the cached map.
     *
     * @return array<string,array<string,string>>
     */
    private static function load(): array {
        if ( null !== self::$cache ) {
            return self::$cache;
        }
        $path = self::DATA_FILE;
        if ( ! is_readable( $path ) ) {
            self::$cache = array();
            return self::$cache;
        }
        $raw = file_get_contents( $path );
        if ( false === $raw || '' === $raw ) {
            self::$cache = array();
            return self::$cache;
        }
        $decoded = json_decode( $raw, true );
        self::$cache = is_array( $decoded ) ? $decoded : array();
        return self::$cache;
    }

    /**
     * Reset the in-process cache. Used by tests and by the
     * "Refresh from IANA" admin action.
     */
    public static function flush_cache(): void {
        self::$cache = null;
    }

    /**
     * IANA-registered type for $tld (e.g. "country-code", "generic").
     */
    public static function type_of( string $tld ): ?string {
        $tld = strtolower( ltrim( $tld, '.' ) );
        $map = self::load();
        if ( ! isset( $map[ $tld ] ) ) {
            return null;
        }
        $entry = $map[ $tld ];
        return is_array( $entry ) ? ( array_key_first( $entry ) ?: null ) : null;
    }

    /**
     * IANA-registered manager for $tld.
     */
    public static function manager_of( string $tld ): ?string {
        $tld = strtolower( ltrim( $tld, '.' ) );
        $map = self::load();
        if ( ! isset( $map[ $tld ] ) ) {
            return null;
        }
        $entry = $map[ $tld ];
        if ( ! is_array( $entry ) || empty( $entry ) ) {
            return null;
        }
        return reset( $entry ) ?: null;
    }

    /**
     * Whether $tld is in the bundled snapshot.
     */
    public static function knows( string $tld ): bool {
        return isset( self::load()[ strtolower( ltrim( $tld, '.' ) ) ] );
    }

    /**
     * Total number of TLDs in the snapshot.
     */
    public static function count(): int {
        return count( self::load() );
    }

    /**
     * Count TLDs grouped by type.
     *
     * @return array<string,int>
     */
    public static function count_by_type(): array {
        $out = array(
            'country-code'        => 0,
            'generic'             => 0,
            'generic-restricted'  => 0,
            'sponsored'           => 0,
            'infrastructure'      => 0,
            'test'                => 0,
        );
        foreach ( self::load() as $entry ) {
            if ( ! is_array( $entry ) || empty( $entry ) ) {
                continue;
            }
            $type = array_key_first( $entry );
            if ( isset( $out[ $type ] ) ) {
                $out[ $type ]++;
            }
        }
        return $out;
    }

    /**
     * Rebuild the JSON snapshot from the user's TSV file. The admin
     * tool calls this from Settings -> WHOIS -> "Refresh from IANA".
     *
     * Returns the number of TLDs written.
     */
    public static function rebuild_from_file( string $tsv_path ): int {
        if ( ! is_readable( $tsv_path ) ) {
            return 0;
        }
        $out = array();
        $fh  = fopen( $tsv_path, 'r' );
        if ( ! $fh ) {
            return 0;
        }
        // Skip header line.
        fgets( $fh );
        while ( ( $line = fgets( $fh ) ) !== false ) {
            $parts = explode( "\t", rtrim( $line, "\n\r" ) );
            if ( count( $parts ) < 3 ) {
                continue;
            }
            $tld_raw = ltrim( $parts[0], '.' );
            // ASCII-only filter.
            if ( '' === $tld_raw || ! preg_match( '/^[A-Za-z0-9-]+$/', $tld_raw ) ) {
                continue;
            }
            $out[ strtolower( $tld_raw ) ] = array( $parts[1] => $parts[2] );
        }
        fclose( $fh );
        ksort( $out );
        $json = wp_json_encode( $out );
        if ( ! is_string( $json ) ) {
            return 0;
        }
        file_put_contents( self::DATA_FILE, $json );
        self::flush_cache();
        return count( $out );
    }
}
