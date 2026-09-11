<?php
/**
 * Settings registry / sanitizer.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Centralized settings definitions used by both admin UI and REST.
 */
final class Settings {

    public const OPTION_KEY = 'pc_settings';

    /**
     * Allowed values for provider-type options.
     *
     * @return array<string,string[]>
     */
    public static function provider_options(): array {
        return array(
            'ip_provider'         => array( 'maxmind', 'ip-api-com', 'ipinfo', 'ipapi', 'mock' ),
            'reputation_provider' => array( 'spamhaus', 'iphub', 'mock' ),
            'whois_provider'      => array( 'rdap', 'mock' ),
            'dns_provider'        => array( 'none', 'doh-fanout', 'token+doh' ),
        );
    }

    /**
     * Provider keys allowed in the IP fallback chain.
     *
     * @return string[]
     */
    public static function allowed_chain_keys(): array {
        return array( 'maxmind', 'ip-api-com', 'ipinfo', 'ipapi', 'mock' );
    }

    /**
     * Sanitize a settings array coming from an admin form.
     *
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function sanitize( array $input ): array {
        $current = (array) get_option( self::OPTION_KEY, array() );
        $output  = $current;

        $output['ip_provider']         = self::sanitize_choice( $input['ip_provider']         ?? null, array( 'maxmind', 'ip-api-com', 'ipinfo', 'ipapi', 'mock' ), $current['ip_provider']         ?? 'mock' );
        $output['reputation_provider'] = self::sanitize_choice( $input['reputation_provider'] ?? null, array( 'spamhaus', 'iphub', 'mock' ), $current['reputation_provider'] ?? 'mock' );
        $output['whois_provider']      = self::sanitize_choice( $input['whois_provider']      ?? null, array( 'rdap', 'mock' ), $current['whois_provider']      ?? 'mock' );
        $output['dns_provider']        = self::sanitize_choice( $input['dns_provider']        ?? null, array( 'none', 'doh-fanout', 'token+doh' ), $current['dns_provider']        ?? 'doh-fanout' );

        $output['dns_test_enabled']    = ! empty( $input['dns_test_enabled'] );
        $output['tld_registry_auto_update'] = array_key_exists( 'tld_registry_auto_update', $input )
            ? ! empty( $input['tld_registry_auto_update'] )
            : (bool) ( $current['tld_registry_auto_update'] ?? false );
        $output['logging_enabled']     = ! empty( $input['logging_enabled'] );
        $output['log_retention_days']  = max( 0, min( 365, (int) ( $input['log_retention_days'] ?? 0 ) ) );
        $output['dev_mode']            = ! empty( $input['dev_mode'] );
        $output['api_tokens_enabled']  = array_key_exists( 'api_tokens_enabled', $input ) ? ! empty( $input['api_tokens_enabled'] ) : (bool) ( $current['api_tokens_enabled'] ?? true );
        $output['share_enabled']       = array_key_exists( 'share_enabled', $input ) ? ! empty( $input['share_enabled'] ) : (bool) ( $current['share_enabled'] ?? false );
        $output['share_ttl_seconds']   = max( 60, min( 30 * DAY_IN_SECONDS, (int) ( $input['share_ttl_seconds'] ?? ( $current['share_ttl_seconds'] ?? 7 * DAY_IN_SECONDS ) ) ) );

        $output['rate_limit_scan']     = max( 1, min( 10000, (int) ( $input['rate_limit_scan'] ?? 60 ) ) );
        $output['rate_limit_lookup']   = max( 1, min( 10000, (int) ( $input['rate_limit_lookup'] ?? 30 ) ) );
        $output['rate_limit_security'] = max( 1, min( 10000, (int) ( $input['rate_limit_security'] ?? 10 ) ) );
        $output['cache_ttl']           = max( 60, min( DAY_IN_SECONDS, (int) ( $input['cache_ttl'] ?? 3600 ) ) );

        $output['ip_api_key']         = sanitize_text_field( (string) ( $input['ip_api_key'] ?? '' ) );
        $output['reputation_api_key'] = sanitize_text_field( (string) ( $input['reputation_api_key'] ?? '' ) );
        $output['whois_api_key']      = sanitize_text_field( (string) ( $input['whois_api_key'] ?? '' ) );

        // Provider chain (order matters). Each entry must be one of the
        // allowed provider keys; unknown entries are dropped.
        $raw_chain = $input['provider_chain_ip'] ?? null;
        if ( is_string( $raw_chain ) ) {
            // Accept either "a,b,c" or "a\nb\nc" from a textarea/hidden input.
            $raw_chain = preg_split( '/[\s,]+/', $raw_chain, -1, PREG_SPLIT_NO_EMPTY );
        }
        if ( is_array( $raw_chain ) ) {
            $clean = array();
            foreach ( $raw_chain as $k ) {
               	$k = sanitize_key( (string) $k );
                if ( in_array( $k, self::allowed_chain_keys(), true ) && ! in_array( $k, $clean, true ) ) {
                    $clean[] = $k;
                }
            }
            $output['provider_chain_ip'] = ! empty( $clean ) ? $clean : array( 'mock' );
        } elseif ( ! isset( $output['provider_chain_ip'] ) || ! is_array( $output['provider_chain_ip'] ) ) {
            $output['provider_chain_ip'] = array( 'maxmind', 'ip-api-com', 'ipinfo', 'ipapi', 'mock' );
        }

        // MaxMind license key: empty input preserves the existing key. This matches
        // the password-field UX where a blank submission means "no change".
        $submitted_key = $input['maxmind_license_key'] ?? null;
        if ( null !== $submitted_key && '' !== (string) $submitted_key ) {
            $output['maxmind_license_key'] = sanitize_text_field( (string) $submitted_key );
        } elseif ( isset( $current['maxmind_license_key'] ) ) {
            $output['maxmind_license_key'] = (string) $current['maxmind_license_key'];
        } else {
            $output['maxmind_license_key'] = '';
        }
        $raw_urls                      = $input['maxmind_custom_urls'] ?? null;
        if ( is_string( $raw_urls ) ) {
            // Textarea posts a newline-separated string. Convert to array.
            $raw_urls = preg_split( '/\r?\n/', $raw_urls );
        }
        if ( is_array( $raw_urls ) ) {
            $clean_urls = array();
            foreach ( $raw_urls as $u ) {
                $u = esc_url_raw( (string) $u );
                // Accept any HTTPS URL; users may mirror MaxMind or run their own.
                if ( '' !== $u && str_starts_with( $u, 'https://' ) ) {
                    $clean_urls[] = $u;
                }
            }
            $output['maxmind_custom_urls'] = $clean_urls;
        }
        $output['ip_api_com_enabled']   = ! empty( $input['ip_api_com_enabled'] );
        $output['event_log_enabled']    = ! empty( $input['event_log_enabled'] );
        $output['dashboard_chart_days'] = max( 1, min( 90, (int) ( $input['dashboard_chart_days'] ?? 7 ) ) );
        $output['maxmind_last_update']  = isset( $output['maxmind_last_update'] ) ? (int) $output['maxmind_last_update'] : (int) ( $current['maxmind_last_update'] ?? 0 );
        $output['maxmind_files']        = isset( $output['maxmind_files'] ) && is_array( $output['maxmind_files'] ) ? $output['maxmind_files'] : ( is_array( $current['maxmind_files'] ?? null ) ? $current['maxmind_files'] : array() );

        // DNS leak test (Phase 8).
        $output['dns_test_hostname_base'] = sanitize_text_field( (string) ( $input['dns_test_hostname_base'] ?? ( $current['dns_test_hostname_base'] ?? 'cloudflare.com' ) ) );
        $output['dns_query_timeout_sec']  = max( 1, min( 10, (int) ( $input['dns_query_timeout_sec'] ?? 3 ) ) );

        // Resolver fallback chain: free → online → paid → local. Order is the
        // priority used by the DoH fan-out probe when the primary fails.
        $raw_dns_chain = $input['dns_provider_chain'] ?? null;
        if ( is_string( $raw_dns_chain ) ) {
            $raw_dns_chain = preg_split( '/[\s,]+/', $raw_dns_chain, -1, PREG_SPLIT_NO_EMPTY );
        }
        if ( is_array( $raw_dns_chain ) ) {
            $clean_dns_chain = array();
            $allowed_dns     = array( 'free', 'online', 'paid', 'local' );
            foreach ( $raw_dns_chain as $c ) {
                $c = sanitize_key( (string) $c );
                if ( in_array( $c, $allowed_dns, true ) && ! in_array( $c, $clean_dns_chain, true ) ) {
                    $clean_dns_chain[] = $c;
                }
            }
            $output['dns_provider_chain'] = ! empty( $clean_dns_chain ) ? $clean_dns_chain : array( 'free', 'online', 'paid', 'local' );
        } elseif ( ! isset( $output['dns_provider_chain'] ) || ! is_array( $output['dns_provider_chain'] ) ) {
            $output['dns_provider_chain'] = array( 'free', 'online', 'paid', 'local' );
        }

        // Paid-resolver credentials (only used when chain reaches the "paid" tier).
        $paid_endpoint_raw = $input['dns_paid_endpoint'] ?? ( $current['dns_paid_endpoint'] ?? '' );
        $paid_endpoint     = esc_url_raw( (string) $paid_endpoint_raw );
        if ( '' !== $paid_endpoint && ! str_starts_with( $paid_endpoint, 'https://' ) ) {
            $paid_endpoint = '';
        }
        $output['dns_paid_endpoint'] = $paid_endpoint;
        $paid_submitted              = $input['dns_paid_api_key'] ?? null;
        if ( null !== $paid_submitted && '' !== (string) $paid_submitted ) {
            $output['dns_paid_api_key'] = sanitize_text_field( (string) $paid_submitted );
        } elseif ( isset( $current['dns_paid_api_key'] ) ) {
            $output['dns_paid_api_key'] = (string) $current['dns_paid_api_key'];
        } else {
            $output['dns_paid_api_key'] = '';
        }

        // Local DNS resolver list (only used when chain reaches the "local" tier).
        $raw_local = $input['dns_local_resolvers'] ?? null;
        if ( is_string( $raw_local ) ) {
            $raw_local = preg_split( '/[\s,]+/', $raw_local, -1, PREG_SPLIT_NO_EMPTY );
        }
        if ( is_array( $raw_local ) ) {
            $clean_local = array();
            foreach ( $raw_local as $entry ) {
                $entry = preg_replace( '/[^0-9.]/', '', (string) $entry );
                if ( '' !== $entry && filter_var( $entry, FILTER_VALIDATE_IP ) ) {
                    $clean_local[] = $entry;
                }
            }
            $output['dns_local_resolvers'] = array_values( array_unique( $clean_local ) );
        } elseif ( ! isset( $output['dns_local_resolvers'] ) ) {
            $output['dns_local_resolvers'] = array();
        }
        $raw_resolvers = $input['dns_resolvers'] ?? null;
        if ( is_string( $raw_resolvers ) ) {
            // JSON-encoded map of name=>URL (admin form posts as JSON).
            $decoded = json_decode( $raw_resolvers, true );
            if ( is_array( $decoded ) ) {
                $raw_resolvers = $decoded;
            }
        }
        if ( is_array( $raw_resolvers ) ) {
            $clean_resolvers = array();
            foreach ( $raw_resolvers as $name => $url ) {
                $name = sanitize_key( (string) $name );
                $url  = esc_url_raw( (string) $url );
                if ( '' !== $name && '' !== $url && str_starts_with( $url, 'https://' ) ) {
                    $clean_resolvers[ $name ] = $url;
                }
            }
            $output['dns_resolvers'] = ! empty( $clean_resolvers ) ? $clean_resolvers : NetworkProbe::default_dns_resolvers();
        } elseif ( ! isset( $output['dns_resolvers'] ) || ! is_array( $output['dns_resolvers'] ) ) {
            $output['dns_resolvers'] = NetworkProbe::default_dns_resolvers();
        }

        // Ping / latency.
        $raw_targets = $input['ping_targets'] ?? null;
        if ( is_string( $raw_targets ) ) {
            $raw_targets = preg_split( '/\r?\n/', $raw_targets );
        }
        if ( is_array( $raw_targets ) ) {
            $clean_targets = array();
            foreach ( $raw_targets as $t ) {
                $t = trim( (string) $t );
                if ( '' !== $t ) {
                    $clean_targets[] = $t;
                }
            }
            $output['ping_targets'] = ! empty( $clean_targets ) ? $clean_targets : NetworkProbe::default_ping_targets();
        } elseif ( ! isset( $output['ping_targets'] ) || ! is_array( $output['ping_targets'] ) ) {
            $output['ping_targets'] = NetworkProbe::default_ping_targets();
        }
        $output['ping_timeout_sec'] = max( 0.5, min( 5.0, (float) ( $input['ping_timeout_sec'] ?? 1.5 ) ) );

        // Port scan.
        $raw_allow = $input['port_scan_allowlist'] ?? null;
        if ( is_string( $raw_allow ) ) {
            $raw_allow = preg_split( '/\r?\n/', $raw_allow );
        }
        if ( is_array( $raw_allow ) ) {
            $clean_allow = array();
            foreach ( $raw_allow as $entry ) {
                $entry = trim( (string) $entry );
                if ( '' !== $entry ) {
                    $clean_allow[] = $entry;
                }
            }
            $output['port_scan_allowlist'] = $clean_allow;
        } elseif ( ! isset( $output['port_scan_allowlist'] ) ) {
            $output['port_scan_allowlist'] = array();
        }
        $raw_ports = $input['port_scan_default_ports'] ?? null;
        if ( is_string( $raw_ports ) ) {
            $raw_ports = preg_split( '/[\s,]+/', $raw_ports, -1, PREG_SPLIT_NO_EMPTY );
        }
        if ( is_array( $raw_ports ) ) {
            $clean_ports = array();
            foreach ( $raw_ports as $p ) {
                $p = (int) $p;
                if ( $p >= 1 && $p <= 65535 ) {
                    $clean_ports[] = $p;
                }
            }
            $output['port_scan_default_ports'] = ! empty( $clean_ports ) ? array_values( array_unique( $clean_ports ) ) : NetworkProbe::default_port_scan_ports();
        } elseif ( ! isset( $output['port_scan_default_ports'] ) || ! is_array( $output['port_scan_default_ports'] ) ) {
            $output['port_scan_default_ports'] = NetworkProbe::default_port_scan_ports();
        }
        $output['port_scan_timeout_sec'] = max( 0.2, min( 5.0, (float) ( $input['port_scan_timeout_sec'] ?? 1.0 ) ) );

        // Per-bucket rate limits for the new probes.
        $output['rate_limit_dns_probe']        = max( 1, min( 60,  (int) ( $input['rate_limit_dns_probe']        ?? 5  ) ) );
        $output['rate_limit_ping']             = max( 5, min( 300, (int) ( $input['rate_limit_ping']             ?? 30 ) ) );
        $output['rate_limit_port_scan']        = max( 1, min( 60,  (int) ( $input['rate_limit_port_scan']        ?? 10 ) ) );
        // Connection echo has its own bucket (separate from `ping`, which is
        // the TCP-connect endpoint) so the 3 trips per report never starve
        // the legitimate /scan/ping traffic.
        $output['rate_limit_connection_echo']  = max( 10, min( 600, (int) ( $input['rate_limit_connection_echo']  ?? 60 ) ) );

        // Secret salt: never accept over the wire; only ever rotate via separate endpoint.
        if ( empty( $output['secret_salt'] ) ) {
            $output['secret_salt'] = wp_generate_password( 32, false );
        }

        // Phase 28: per-category event-log toggles + retention policy.
        // Each checkbox defaults to true (mirroring the activation default)
        // so an admin who never opened the Settings page still gets the
        // full audit trail. Retention caps at 3650 days (~10y) and the
        // row cap at 1M to keep `purge()` bounded.
        $logs_in = is_array( $input['logs'] ?? null ) ? (array) $input['logs'] : array();
        $logs_current = is_array( $current['logs'] ?? null ) ? (array) $current['logs'] : array();
        $output['logs'] = array(
            'scan_enabled'    => ! empty( $logs_in['scan_enabled'] ),
            'share_enabled'   => ! empty( $logs_in['share_enabled'] ),
            'export_enabled'  => ! empty( $logs_in['export_enabled'] ),
            'restore_enabled' => ! empty( $logs_in['restore_enabled'] ),
            'error_enabled'   => ! empty( $logs_in['error_enabled'] ),
            'admin_enabled'   => ! empty( $logs_in['admin_enabled'] ),
            'retention_days'  => max( 1, min( 3650, (int) ( $logs_in['retention_days'] ?? ( $logs_current['retention_days'] ?? 90 ) ) ) ),
            'max_rows'        => max( 1000, min( 1000000, (int) ( $logs_in['max_rows'] ?? ( $logs_current['max_rows'] ?? 50000 ) ) ) ),
        );

        // Phase 37: map tile-source picker. Default OSM (no key, no
        // ToS issues). For paid providers (Google, Baidu, Apple, Yandex
        // Maps SDK), admins paste their API key here. The JS reads
        // pc_settings.map.tile_source + .api_keys via the
        // PC_SCAN.map localize object and swaps the Leaflet tile URL
        // accordingly. Unknown choices silently fall back to OSM so a
        // typo can't break the dashboard.
        $map_in      = is_array( $input['map'] ?? null ) ? (array) $input['map'] : array();
        $map_current = is_array( $current['map'] ?? null ) ? (array) $current['map'] : array();
        $allowed_sources = array(
            'osm', 'cartodb_voyager', 'cartodb_dark', 'stamen_toner',
            'opentopomap', 'esri_worldimagery', 'google_roadmap',
            'google_satellite', 'yandex_map', 'baidu_map', 'apple_map',
        );
        $source = sanitize_key( (string) ( $map_in['tile_source'] ?? ( $map_current['tile_source'] ?? 'osm' ) ) );
        if ( ! in_array( $source, $allowed_sources, true ) ) {
            $source = 'osm';
        }
        $output['map'] = array(
            'tile_source'  => $source,
            'google_key'   => sanitize_text_field( (string) ( $map_in['google_key'] ?? ( $map_current['google_key'] ?? '' ) ) ),
            'yandex_key'   => sanitize_text_field( (string) ( $map_in['yandex_key'] ?? ( $map_current['yandex_key'] ?? '' ) ) ),
            'baidu_key'    => sanitize_text_field( (string) ( $map_in['baidu_key']  ?? ( $map_current['baidu_key']  ?? '' ) ) ),
            'apple_team_id'=> sanitize_text_field( (string) ( $map_in['apple_team_id'] ?? ( $map_current['apple_team_id'] ?? '' ) ) ),
            'apple_key_id' => sanitize_text_field( (string) ( $map_in['apple_key_id']  ?? ( $map_current['apple_key_id']  ?? '' ) ) ),
            'apple_key'    => sanitize_text_field( (string) ( $map_in['apple_key']     ?? ( $map_current['apple_key']     ?? '' ) ) ),
        );

        return $output;
    }

    /**
     * Sanitize a value against an allowed list.
     */
    private static function sanitize_choice( $value, array $allowed, string $fallback ): string {
        $value = is_string( $value ) ? $value : '';
        return in_array( $value, $allowed, true ) ? $value : $fallback;
    }
}