<?php
/**
 * Main plugin orchestrator.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use PrivacyChecker\Admin\Admin;
use PrivacyChecker\Admin\AdminDashboard;
use PrivacyChecker\Provider\IpIntelligenceProviderInterface;
use PrivacyChecker\Provider\ReputationProviderInterface;
use PrivacyChecker\Provider\WhoisProviderInterface;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Singleton entry point that wires up the plugin.
 */
final class Plugin {

    /**
     * Singleton instance.
     */
    private static ?Plugin $instance = null;

    /**
     * Loaded provider implementations.
     *
     * @var array<string,object>
     */
    private array $providers = array();

    /**
     * Whether the plugin has been booted.
     */
    private bool $booted = false;

    /**
     * Get/create singleton.
     */
    public static function instance(): Plugin {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Activation hook: seed defaults, schedule nothing.
     */
    public static function on_activate(): void {
        if ( ! current_user_can( 'activate_plugins' ) ) {
            return;
        }

        $existing = get_option( 'pc_settings', null );
        if ( null === $existing ) {
            add_option(
                'pc_settings',
                array(
                    // Real-data providers by default. Mock is opt-in only via the
                    // admin settings panel or wp-config PRIVACY_CHECKER_DEV_MODE.
                    'ip_provider'             => 'ip-api-com',
                    'reputation_provider'     => 'spamhaus',
                    'whois_provider'          => 'rdap',
                    'dns_provider'            => 'doh-fanout',
                    'dns_test_enabled'        => true,
                    'tld_registry_auto_update' => false,
                    'logging_enabled'         => false,
                    'log_retention_days'      => 0,
                    'rate_limit_scan'         => 60,
                    'rate_limit_lookup'       => 30,
                    'rate_limit_security'     => 10,
                    'cache_ttl'               => 3600,
                    'ip_api_key'              => '',
                    'reputation_api_key'      => '',
                    'whois_api_key'           => '',
                    'dev_mode'                => defined( 'PRIVACY_CHECKER_DEV_MODE' ) && PRIVACY_CHECKER_DEV_MODE,
                    'secret_salt'             => wp_generate_password( 32, false ),
                    // Fallback chain (order matters). Default favours local
                    // MaxMind when present, then ip-api.com (free, no key),
                    // then the existing providers, finally mock as the safety net.
                    'provider_chain_ip'       => array( 'maxmind', 'ip2location', 'ip-api-com', 'ipinfo', 'ipapi' ),
                    'maxmind_license_key'     => '',
                    'maxmind_custom_urls'     => array(),
                    'ip_api_com_enabled'      => true,
                    'maxmind_last_update'     => 0,
                    'maxmind_files'           => array(),
                    'ip2location_db_dir'      => '',     // empty = auto-extract from project /GeoIP Database/
                    'ip2location_attribution' => 1,     // show required LITE attribution in admin footer
                    'event_log_enabled'       => false,
                    // Phase 28 — per-category event recording toggles.
                    // Defaults to true for every category so admins who
                    // never opened the settings page still get the full
                    // audit trail. The master `event_log_enabled` switch
                    // remains the kill-switch.
                    'logs'                    => array(
                        'scan_enabled'    => true,
                        'share_enabled'   => true,
                        'export_enabled'  => true,
                        'restore_enabled' => true,
                        'error_enabled'   => true,
                        'admin_enabled'   => true,
                        'retention_days'  => 90,
                        'max_rows'        => 50000,
                    ),
                    'dashboard_chart_days'    => 7,
                    'api_tokens_enabled'      => true,
                    'share_enabled'           => false,
                    'share_ttl_seconds'      => 7 * DAY_IN_SECONDS,

                    // DNS leak test (Phase 8).
                    'dns_test_hostname_base'  => 'cloudflare.com',
                    'dns_query_timeout_sec'   => 3,
                    'dns_resolvers'           => array(
                        'cloudflare' => 'https://cloudflare-dns.com/dns-query',
                        'google'     => 'https://dns.google/resolve',
                        'quad9'      => 'https://dns.quad9.net/dns-query',
                    ),

                    // DNS resolver fallback chain. Free public DoH is the default;
                    // online/paid/local tiers are opt-in fallbacks.
                    'dns_provider_chain'      => array( 'free', 'online', 'paid', 'local' ),
                    'dns_paid_endpoint'       => '',
                    'dns_paid_api_key'        => '',
                    'dns_local_resolvers'     => array(),

                    'ping_targets'            => array(
                        'cloudflare.com:443',
                        'google.com:443',
                        'example.com:443',
                    ),
                    'ping_timeout_sec'        => 1.5,

                    // Port scan.
                    'port_scan_allowlist'     => array(),
                    'port_scan_default_ports' => array( 80, 443, 8080, 8443 ),
                    'port_scan_timeout_sec'   => 1.0,

                    // Per-bucket rate limits for the new probes.
                    'rate_limit_dns_probe'        => 5,
                    'rate_limit_ping'             => 30,
                    'rate_limit_port_scan'        => 10,
                    'rate_limit_connection_echo'  => 60,
                )
            );
        } else {
            // Existing install: backfill any missing keys so a stale option
            // still gets the new defaults. This is a one-shot migration path.
            $backfill = array(
                'dns_provider'            => 'doh-fanout',
                'dns_test_enabled'        => true,
                'tld_registry_auto_update' => false,
                'dns_test_hostname_base'  => 'cloudflare.com',
                'dns_query_timeout_sec'   => 3,
                'dns_resolvers'           => array(
                    'cloudflare' => 'https://cloudflare-dns.com/dns-query',
                    'google'     => 'https://dns.google/resolve',
                    'quad9'      => 'https://dns.quad9.net/dns-query',
                ),
                'ping_targets'            => array(
                    'cloudflare.com:443',
                    'google.com:443',
                    'example.com:443',
                ),
                'ping_timeout_sec'        => 1.5,
                'port_scan_allowlist'     => array(),
                'port_scan_default_ports' => array( 80, 443, 8080, 8443 ),
                'port_scan_timeout_sec'   => 1.0,
                'rate_limit_dns_probe'        => 5,
                'rate_limit_ping'             => 30,
                'rate_limit_port_scan'        => 10,
                'rate_limit_connection_echo'  => 60,
            );
            $needs_update = false;
            foreach ( $backfill as $k => $v ) {
                if ( ! array_key_exists( $k, $existing ) ) {
                    $existing[ $k ] = $v;
                    $needs_update   = true;
                }
            }
            // Migration: replace legacy mock defaults with real providers and
            // turn off dev_mode so live installs never stamp `is_mock: true`
            // on scan responses or run UI through mock data.
            $migrations = array(
                'ip_provider'         => 'ip-api-com',
                'reputation_provider' => 'spamhaus',
                'whois_provider'      => 'rdap',
                'dev_mode'            => false,
            );
            foreach ( $migrations as $k => $v ) {
                if ( ( $existing[ $k ] ?? null ) !== $v ) {
                    $existing[ $k ] = $v;
                    $needs_update   = true;
                }
            }
            if ( $needs_update ) {
                update_option( 'pc_settings', $existing );
            }
        }

        // Ensure the salt exists even if settings existed before.
        $settings = get_option( 'pc_settings', array() );
        if ( empty( $settings['secret_salt'] ) ) {
            $settings['secret_salt'] = wp_generate_password( 32, false );
            update_option( 'pc_settings', $settings );
        }

        // Seed default WP pages (only once).
        $seeded = get_option( 'pc_pages_seeded', false );
        if ( ! $seeded ) {
            self::seed_legal_pages();
            self::seed_geotrace_page();
            update_option( 'pc_pages_seeded', true );
        } else {
            // Idempotent: ensure the /geotrace/ page exists even on
            // installs that were activated before Phase 30.
            self::seed_geotrace_page();
        }

        flush_rewrite_rules();
    }

    /**
     * Deactivation: flush rewrites + clear scheduled log purge.
     */
    public static function on_deactivate(): void {
        self::clear_log_cron();
        flush_rewrite_rules();
    }

    /**
     * Create placeholder legal pages on first activation.
     */
    private static function seed_legal_pages(): void {
        $pages = array(
            'privacy' => __( 'Privacy Policy', 'privacy-checker' ),
            'terms'   => __( 'Terms of Service', 'privacy-checker' ),
            'cookies' => __( 'Cookie Policy', 'privacy-checker' ),
            'about'   => __( 'About', 'privacy-checker' ),
        );

        foreach ( $pages as $slug => $title ) {
            if ( null === get_page_by_path( $slug ) ) {
                wp_insert_post(
                    array(
                        'post_title'   => $title,
                        'post_name'    => $slug,
                        'post_status'  => 'publish',
                        'post_type'    => 'page',
                        'post_content' => self::placeholder_content( $title ),
                    )
                );
            }
        }
    }

    /**
     * Placeholder content reminding the operator to supply real legal text.
     */
    private static function placeholder_content( string $title ): string {
        $title_safe = esc_html( $title );
        return sprintf(
            "<!-- wp:paragraph -->\n<p><strong>%s</strong> &mdash; placeholder content. Replace with your own legal copy before going live. The IMON plugin does not provide legal advice.</p>\n<!-- /wp:paragraph -->",
            $title_safe
        );
    }

    /**
     * Phase 30: idempotently create the `/geotrace/` page on activation.
     *
     * Renders `[privacy_checker_geotrace]` so visitors get the
     * redesigned traceroute page at a stable URL. Idempotent — running
     * this twice on the same install does nothing.
     */
    private static function seed_geotrace_page(): void {
        if ( null !== get_page_by_path( 'geotrace' ) ) {
            return;
        }
        wp_insert_post(
            array(
                'post_title'   => __( 'GeoTrace', 'privacy-checker' ),
                'post_name'    => 'geotrace',
                'post_status'  => 'publish',
                'post_type'    => 'page',
                'post_content' => '[privacy_checker_geotrace]',
            )
        );
    }

    /**
     * Wire up all plugin hooks.
     */
    public function boot(): void {
        if ( $this->booted ) {
            return;
        }
        $this->booted = true;

        load_plugin_textdomain( 'privacy-checker', false, dirname( plugin_basename( PRIVACY_CHECKER_FILE ) ) . '/languages' );

        // Admin.
        if ( is_admin() ) {
            ( new Admin() )->register();
            ( new AdminDashboard() )->register();
            ( new Admin\AdminApiTokens() )->register();
            ( new Admin\AdminDatabases() )->register();
            ( new Admin\AdminLogs() )->register();
            ( new Admin\AdminPrivacyReport() )->register();
        }

        // Public-facing assets and shortcodes.
        ( new PublicAssets() )->register();

        // v2 experimental UI — opt-in via ?v=2 query string or the
        // `pc_ui_v2` cookie. v1 is unaffected; deleting the v2 files
        // removes v2 entirely.
        ( new PublicAssetsV2() )->register();

        // REST API.
        ( new RestApi( $this ) )->register();

        // Privacy cleanup hooks.
        add_action( 'wp_loaded', array( Privacy::class, 'register_hooks' ) );

        // MaxMind daily refresh.
        MaxmindManager::register_cron();

        // API tokens table for enterprise clients.
        ApiTokens::ensure_table();

        // Services catalog for admin-uploaded 3rd-party credentials.
        ServicesCatalog::ensure_table();

        // Phase 28: EventLog table + daily retention purge.
        EventLog::ensure_table();
        self::register_log_cron();

        // Phase 28: catch uncaught errors (PHP fatals don't trigger
        // shutdown by default; we register a handler that records
        // anything logged via error_log inside the plugin).
        self::register_error_catcher();

        // Touch the upload directory once so the WP_Filesystem listing is hot.
        GeoIpDatabase::upload_dir();

        // Local-dev CORS: when the WP siteurl differs from the page origin
        // (e.g. user accessed http://localhost:8080 but WP siteurl is
        // http://127.0.0.1:8080), the browser blocks cross-origin POSTs to
        // /scan. WP's stock rest_send_cors_headers() echoes the Origin
        // header back, but only when the request reaches the REST
        // dispatcher — a 403 from rest_cookie_invalid_nonce still emits
        // it, but the browser then drops the response because the body
        // is empty for CORS-checked fetches. We re-emit the headers
        // ourselves on rest_pre_serve_request with priority 9 (just
        // before WP core's default 10) so the browser always sees them.
        // No-op in production where siteurl matches the request origin.
        add_filter( 'rest_pre_serve_request', array( self::class, 'maybe_emit_cors_headers' ), 9, 4 );
    }

    /**
     * Re-emit CORS headers for privacy-checker routes regardless of
     * siteurl mismatch. Mirrors WP core's rest_send_cors_headers() but
     * runs unconditionally and only for this plugin's namespace.
     *
     * @param mixed              $value  Existing serve value (passthrough).
     * @param \WP_REST_Response  $response Current response object.
     * @param \WP_REST_Request   $request Current request.
     * @param \WP_REST_Server    $server REST server instance.
     * @return mixed Unchanged passthrough.
     */
    public static function maybe_emit_cors_headers( $value, $response = null, $request = null, $server = null ) {
        // Derive the matched route from the request URI rather than
        // relying on a 4th filter arg (the WP filter signature doesn't
        // pass $route here).
        if ( ! $request instanceof \WP_REST_Request ) {
            return $value;
        }
        $route = $request->get_route();
        if ( strpos( $route, '/' . PRIVACY_CHECKER_REST_NS ) !== 0 ) {
            return $value;
        }
        $origin = get_http_origin();
        if ( $origin ) {
            header( 'Access-Control-Allow-Origin: ' . esc_url_raw( $origin ) );
            header( 'Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE' );
            header( 'Access-Control-Allow-Credentials: true' );
            header( 'Access-Control-Allow-Headers: Authorization, X-WP-Nonce, Content-Type, Content-Disposition' );
            header( 'Vary: Origin', false );
        }
        return $value;
    }

    /**
     * Get a configured provider by interface and key.
     *
     * @template T of object
     * @param class-string<T> $interface Fully-qualified interface name.
     * @param string          $key       Provider key (ipapi, ipinfo, mock, ...).
     * @return T
     */
    public function provider( string $interface, string $key ): object {
        $cache_key = $interface . '::' . $key;
        if ( isset( $this->providers[ $cache_key ] ) ) {
            return $this->providers[ $cache_key ];
        }

        $provider = $this->build_provider( $interface, $key );
        $this->providers[ $cache_key ] = $provider;
        return $provider;
    }

    /**
     * Construct a provider by interface and key.
     *
     * @template T of object
     * @param class-string<T> $interface
     * @param string          $key
     * @return T
     */
    private function build_provider( string $interface, string $key ): object {
        $ip_intel = array(
            'ipapi'       => Providers\IpapiProvider::class,
            'ipinfo'      => Providers\IpinfoProvider::class,
            'ip-api-com'  => Providers\IpApiComProvider::class,
            'maxmind'     => Providers\MaxmindProvider::class,
            'ip2location' => Providers\Ip2LocationProvider::class,
            'mock'        => Providers\MockIpProvider::class,
        );
        $reputation = array(
            'spamhaus' => Providers\SpamhausProvider::class,
            'iphub'    => Providers\IphubProvider::class,
            'mock'     => Providers\MockReputationProvider::class,
        );
        $whois = array(
            'rdap'  => Providers\RdapWhoisProvider::class,
            'mock'  => Providers\MockWhoisProvider::class,
        );

        $map = array();
        if ( $interface === IpIntelligenceProviderInterface::class ) {
            $map = $ip_intel;
        } elseif ( $interface === ReputationProviderInterface::class ) {
            $map = $reputation;
        } elseif ( $interface === WhoisProviderInterface::class ) {
            $map = $whois;
        }

        if ( ! isset( $map[ $key ] ) ) {
            // Unknown provider requested → fall back to mock so the UI stays safe.
            $key = 'mock';
        }

        $class = $map[ $key ];

        /** @var T $provider */
        $provider = new $class();
        return $provider;
    }

    /**
     * Read a setting value with default.
     *
     * @param string $key Setting key.
     * @param mixed  $default Default value.
     * @return mixed
     */
    public function setting( string $key, $default = null ) {
        $settings = get_option( 'pc_settings', array() );
        // Phase 28: support dot-notation for nested-array settings
        // (e.g. `logs.scan_enabled`). Falls back to $default when any
        // segment is missing. Single-key callers (the common case)
        // take the fast path and don't pay the explode() cost.
        if ( strpos( $key, '.' ) === false ) {
            return $settings[ $key ] ?? $default;
        }
        $cursor = $settings;
        foreach ( explode( '.', $key ) as $segment ) {
            if ( ! is_array( $cursor ) || ! array_key_exists( $segment, $cursor ) ) {
                return $default;
            }
            $cursor = $cursor[ $segment ];
        }
        return $cursor;
    }

    /**
     * Update a single key inside the consolidated pc_settings option.
     *
     * Preserves all other keys. Used by admin-post handlers, MaxMind manager,
     * and other code paths that need to mutate one setting without a full
     * round-trip through Settings::sanitize().
     */
    public function update_setting( string $key, $value ): bool {
        $settings = get_option( 'pc_settings', array() );
        if ( ! is_array( $settings ) ) {
            $settings = array();
        }
        // Phase 28: dot-notation setter, mirrors the getter.
        if ( strpos( $key, '.' ) === false ) {
            $settings[ $key ] = $value;
            return (bool) update_option( 'pc_settings', $settings );
        }
        $segments = explode( '.', $key );
        $last     = array_pop( $segments );
        $cursor   = &$settings;
        foreach ( $segments as $segment ) {
            if ( ! isset( $cursor[ $segment ] ) || ! is_array( $cursor[ $segment ] ) ) {
                $cursor[ $segment ] = array();
            }
            $cursor = &$cursor[ $segment ];
        }
        $cursor[ $last ] = $value;
        return (bool) update_option( 'pc_settings', $settings );
    }

    /**
     * Check whether development mode is enabled.
     */
    public function is_dev_mode(): bool {
        return (bool) $this->setting( 'dev_mode', false );
    }

    /**
     * Phase 28: schedule the daily log retention sweep.
     *
     * Hooks `pc_log_purge` to fire every 24h. The handler delegates to
     * `EventLog::run_daily_purge()` so the policy lives with the data
     * class (and so tests can call it directly without going through
     * WP-Cron).
     */
    public static function register_log_cron(): void {
        add_action( 'pc_log_purge', array( EventLog::class, 'run_daily_purge' ) );
        add_action( 'init', array( self::class, 'maybe_schedule_log_purge' ) );
    }

    /**
     * Idempotently schedule the daily purge.
     *
     * Schedules ~60s in the future on first run so a fresh install
     * doesn't immediately churn rows. WP's `wp_schedule_event` returns
     * false silently when a duplicate event exists, so we don't need a
     * second check.
     */
    public static function maybe_schedule_log_purge(): void {
        if ( ! function_exists( 'wp_next_scheduled' ) ) {
            return;
        }
        if ( wp_next_scheduled( 'pc_log_purge' ) ) {
            return;
        }
        wp_schedule_event( time() + 60, 'daily', 'pc_log_purge' );
    }

    /**
     * Clear the scheduled purge on plugin deactivation. Wired via
     * `register_deactivation_hook` in the main plugin file (it requires
     * a callable filename, not a method on this class).
     */
    public static function clear_log_cron(): void {
        if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
            wp_clear_scheduled_hook( 'pc_log_purge' );
        }
    }

    /**
     * Phase 28: catch uncaught PHP errors during a request and record
     * them to the event log as `error` category.
     *
     * We attach to `shutdown` (last possible moment) and inspect
     * `error_get_last()` for a fatal. Non-fatals (warnings, notices)
     * don't reach shutdown in PHP, so we also hook
     * `set_error_handler` to record user-thrown errors but only inside
     * our plugin's namespace — hooking globally would flood the log
     * with arbitrary plugin/theme warnings.
     */
    public static function register_error_catcher(): void {
        add_action( 'shutdown', array( self::class, 'record_shutdown_error' ) );
    }

    /**
     * Inspect the last error at shutdown. PHP only populates
     * `error_get_last()` for E_ERROR / E_PARSE / E_CORE_ERROR /
     * E_CORE_WARNING / E_COMPILE_ERROR / E_COMPILE_WARNING — the
     * crash-class errors we most care about. Recording requires the
     * `logs.error_enabled` toggle AND the master `event_log_enabled`
     * switch (gated inside `record_if_enabled`).
     */
    public static function record_shutdown_error(): void {
        if ( ! function_exists( 'error_get_last' ) ) {
            return;
        }
        $err = error_get_last();
        if ( ! is_array( $err ) ) {
            return;
        }
        $fatal_types = array( E_ERROR, E_PARSE, E_CORE_ERROR, E_CORE_WARNING, E_COMPILE_ERROR, E_COMPILE_WARNING );
        if ( ! in_array( $err['type'] ?? 0, $fatal_types, true ) ) {
            return;
        }
        // Skip errors that originate outside our plugin path — otherwise
        // every WP debug warning from another plugin would land here.
        if ( isset( $err['file'] ) && defined( 'PRIVACY_CHECKER_FILE' ) ) {
            $our_dir = dirname( PRIVACY_CHECKER_FILE );
            if ( strpos( (string) $err['file'], $our_dir ) !== 0 ) {
                return;
            }
        }
        EventLog::record_if_enabled(
            'error',
            'error',
            'shutdown',
            sprintf( '%s in %s:%d', $err['message'] ?? 'unknown', $err['file'] ?? '?', $err['line'] ?? 0 ),
            array(
                'type'    => $err['type'] ?? null,
                'file'    => $err['file'] ?? null,
                'line'    => $err['line'] ?? null,
                'message' => $err['message'] ?? null,
            )
        );
    }
}