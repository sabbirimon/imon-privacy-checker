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
            update_option( 'pc_pages_seeded', true );
        }

        flush_rewrite_rules();
    }

    /**
     * Deactivation: flush rewrites.
     */
    public static function on_deactivate(): void {
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
            ( new Admin\AdminPrivacyReport() )->register();
        }

        // Public-facing assets and shortcodes.
        ( new PublicAssets() )->register();

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

        // Touch the upload directory once so the WP_Filesystem listing is hot.
        GeoIpDatabase::upload_dir();
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
        return $settings[ $key ] ?? $default;
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
        $settings[ $key ] = $value;
        return (bool) update_option( 'pc_settings', $settings );
    }

    /**
     * Check whether development mode is enabled.
     */
    public function is_dev_mode(): bool {
        return (bool) $this->setting( 'dev_mode', false );
    }
}