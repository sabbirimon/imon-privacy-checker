<?php
/**
 * Admin area entry point.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\Plugin;
use PrivacyChecker\Settings;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers the admin menu page and asset enqueueing.
 */
final class Admin {

    public const MENU_SLUG = 'privacy-checker';

    public function register(): void {
        // The menu itself is registered by AdminDashboard so Dashboard and
        // Settings both share the same top-level. We only register fields.
        add_action( 'admin_init', array( $this, 'register_settings' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
    }

    /**
     * Register settings + fields.
     */
    public function register_settings(): void {
        register_setting(
            'pc_settings_group',
            Settings::OPTION_KEY,
            array(
                'type'              => 'array',
                'sanitize_callback' => array( Settings::class, 'sanitize' ),
                'default'           => array(),
            )
        );

        add_settings_section( 'pc_general', __( 'General', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Provider selection, rate limits, and cache TTL.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'dev_mode', __( 'Development Mode', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'dev_mode', false );
            printf(
                '<label><input type="checkbox" name="%1$s[dev_mode]" value="1" %2$s /> %3$s</label>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Use mock providers and skip rate limiting where helpful.', 'privacy-checker' )
            );
        }, self::MENU_SLUG, 'pc_general' );

        add_settings_section( 'pc_chain', __( 'IP Provider Fallback Chain', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'The scanner walks this list top-to-bottom. The first provider that returns useful data wins; later providers are tried only when earlier ones are unavailable.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'provider_chain_ip', __( 'Chain order', 'privacy-checker' ), array( $this, 'render_chain_field' ), self::MENU_SLUG, 'pc_chain' );

        add_settings_section( 'pc_maxmind', __( 'MaxMind GeoLite2 (local)', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'When a MaxMind license key is configured and a database file is present, lookups happen entirely on this server. No third party ever sees your visitors\' IPs.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'maxmind_license_key', __( 'License key', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'maxmind_license_key', '' );
            printf(
                '<input type="password" autocomplete="off" name="%1$s[maxmind_license_key]" value="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( $value )
            );
            echo '<p class="description">' . esc_html__( 'Free license key from maxmind.com. Stored server-side only.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_maxmind' );

        add_settings_field( 'maxmind_custom_urls', __( 'Custom download URLs', 'privacy-checker' ), function () {
            $value = (array) Plugin::instance()->setting( 'maxmind_custom_urls', array() );
            if ( empty( $value ) ) {
                $value = array( '' );
            }
            echo '<p class="description">' . esc_html__( 'Optional. One URL per line. Must be HTTPS and point at a .tar.gz or .zip containing an .mmdb file.', 'privacy-checker' ) . '</p>';
            echo '<textarea name="' . esc_attr( Settings::OPTION_KEY ) . '[maxmind_custom_urls]" rows="4" class="large-text code">';
            echo esc_textarea( implode( "\n", $value ) );
            echo '</textarea>';
        }, self::MENU_SLUG, 'pc_maxmind' );

        add_settings_section( 'pc_ip_api_com', __( 'ip-api.com (free, no key)', 'privacy-checker' ), function () {
            echo '<p>' . wp_kses(
				__( 'Provides IP geolocation, ASN, ISP, and reverse DNS via a simple HTTP GET to <code>ip-api.com</code>. Free for non-commercial use, 45 req/min/IP. See <a href="https://ip-api.com/docs/" target="_blank" rel="noopener">docs</a>.', 'privacy-checker' ),
				array( 'code' => array(), 'a' => array( 'href' => array(), 'target' => array(), 'rel' => array() ) )
			) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'ip_api_com_enabled', __( 'Enable ip-api.com', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'ip_api_com_enabled', true );
            printf(
                '<label><input type="checkbox" name="%1$s[ip_api_com_enabled]" value="1" %2$s /> %3$s</label><p class="description">%4$s</p>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Use ip-api.com as part of the fallback chain', 'privacy-checker' ),
                esc_html__( 'Disable if your site is on a strict HTTPS-only CSP that forbids http origins.', 'privacy-checker' )
            );
        }, self::MENU_SLUG, 'pc_ip_api_com' );

        add_settings_section( 'pc_other_providers', __( 'Other Providers', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Reputation and WHOIS lookups. The IP intelligence chain is configured separately above.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'reputation_provider', __( 'Reputation Provider', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'reputation_provider', 'mock' );
            $this->render_select( 'reputation_provider', array(
                'spamhaus' => __( 'Spamhaus DNSBL (no key)', 'privacy-checker' ),
                'iphub'    => __( 'iphub.info (key required)', 'privacy-checker' ),
                'mock'     => __( 'Mock (Development)', 'privacy-checker' ),
            ), $value );
        }, self::MENU_SLUG, 'pc_other_providers' );

        add_settings_field( 'whois_provider', __( 'WHOIS Provider', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'whois_provider', 'mock' );
            $this->render_select( 'whois_provider', array(
                'rdap' => __( 'RDAP (IANA bootstrap)', 'privacy-checker' ),
                'mock' => __( 'Mock (Development)', 'privacy-checker' ),
            ), $value );
        }, self::MENU_SLUG, 'pc_other_providers' );

        add_settings_field( 'dns_test_enabled', __( 'DNS Leak Test', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'dns_test_enabled', false );
            $note  = __( 'DNS leak testing requires external DNS infrastructure. Leave disabled unless you have configured a provider.', 'privacy-checker' );
            printf(
                '<label><input type="checkbox" name="%1$s[dns_test_enabled]" value="1" %2$s /> %3$s</label><p class="description">%4$s</p>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Enable DNS leak testing', 'privacy-checker' ),
                esc_html( $note )
            );
        }, self::MENU_SLUG, 'pc_other_providers' );

        add_settings_section( 'pc_api', __( 'API Credentials', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Stored encrypted at rest by WordPress options API. Never sent to clients.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        $api_fields = array(
            'ip_api_key'         => __( 'IP Intelligence API Key', 'privacy-checker' ),
            'reputation_api_key' => __( 'Reputation API Key', 'privacy-checker' ),
            'whois_api_key'      => __( 'WHOIS API Key', 'privacy-checker' ),
        );
        foreach ( $api_fields as $field => $label ) {
            add_settings_field( $field, $label, function () use ( $field ) {
                $value = (string) Plugin::instance()->setting( $field, '' );
                printf(
                    '<input type="password" autocomplete="off" name="%1$s[%2$s]" value="%3$s" class="regular-text" />',
                    esc_attr( Settings::OPTION_KEY ),
                    esc_attr( $field ),
                    esc_attr( $value )
                );
            }, self::MENU_SLUG, 'pc_api' );
        }

        add_settings_section( 'pc_rate', __( 'Rate Limiting', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Per-minute request limits per hashed visitor identifier.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        $rate_fields = array(
            'rate_limit_scan'     => __( 'Scan', 'privacy-checker' ),
            'rate_limit_lookup'   => __( 'Lookup', 'privacy-checker' ),
            'rate_limit_security' => __( 'Security Headers', 'privacy-checker' ),
        );
        foreach ( $rate_fields as $field => $label ) {
            add_settings_field( $field, $label, function () use ( $field ) {
                $value = (int) Plugin::instance()->setting( $field, 60 );
                printf(
                    '<input type="number" min="1" name="%1$s[%2$s]" value="%3$d" />',
                    esc_attr( Settings::OPTION_KEY ),
                    esc_attr( $field ),
                    $value
                );
            }, self::MENU_SLUG, 'pc_rate' );
        }

        add_settings_field( 'cache_ttl', __( 'Cache TTL (seconds)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'cache_ttl', 3600 );
            printf(
                '<input type="number" min="60" max="%1$d" name="%2$s[cache_ttl]" value="%3$d" />',
                DAY_IN_SECONDS,
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_rate' );

        add_settings_section( 'pc_privacy', __( 'Privacy & Logging', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Privacy defaults: no IP addresses are stored. Enable logging only if you have a retention policy in place.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'logging_enabled', __( 'Enable Logging', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'logging_enabled', false );
            printf(
                '<label><input type="checkbox" name="%1$s[logging_enabled]" value="1" %2$s /> %3$s</label>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Allow logging of scan metadata (hashed identifiers only).', 'privacy-checker' )
            );
        }, self::MENU_SLUG, 'pc_privacy' );

        add_settings_field( 'log_retention_days', __( 'Retention (days)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'log_retention_days', 0 );
            printf(
                '<input type="number" min="0" max="365" name="%1$s[log_retention_days]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
            echo '<p class="description">' . esc_html__( '0 disables the log table. Logs are deleted daily.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_privacy' );

        add_settings_section( 'pc_dns_test', __( 'DNS Leak Test', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'Real DNS leak testing via DNS-over-HTTPS fan-out. Configure the resolvers, hostname base, and rate limit. The plugin itself ships with no live DNS infrastructure; this enables the in-plugin probe when paired with resolvers you trust.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'dns_test_enabled', __( 'Enable DNS leak test', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'dns_test_enabled', false );
            printf(
                '<label><input type="checkbox" name="%1$s[dns_test_enabled]" value="1" %2$s /> %3$s</label>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Enable DNS leak test', 'privacy-checker' )
            );
            echo '<p class="description">' . esc_html__( 'Required for the server-side DoH probe to run. When disabled the UI shows "Not configured".', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_provider', __( 'Provider', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'dns_provider', 'doh-fanout' );
            $this->render_select( 'dns_provider', array(
                'none'      => __( 'Disabled', 'privacy-checker' ),
                'doh-fanout' => __( 'DoH Fan-out (recommended)', 'privacy-checker' ),
                'token+doh' => __( 'Token probe + DoH', 'privacy-checker' ),
            ), $value );
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_test_hostname_base', __( 'Hostname to resolve (admin-owned recommended)', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'dns_test_hostname_base', 'cloudflare.com' );
            printf(
                '<input type="text" name="%1$s[dns_test_hostname_base]" value="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( $value )
            );
            echo '<p class="description">' . esc_html__( 'The DNS probe resolves this name and checks whether all resolvers agree. Use a hostname you control for production use.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_query_timeout_sec', __( 'Per-resolver timeout (seconds)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'dns_query_timeout_sec', 3 );
            printf(
                '<input type="number" min="1" max="10" name="%1$s[dns_query_timeout_sec]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_resolvers', __( 'DoH resolvers (JSON map)', 'privacy-checker' ), function () {
            $default_json = '{"cloudflare":"https://cloudflare-dns.com/dns-query","google":"https://dns.google/resolve","quad9":"https://dns.quad9.net/dns-query"}';
            $value        = Plugin::instance()->setting( 'dns_resolvers', null );
            if ( empty( $value ) ) {
                $value = $default_json;
            } elseif ( is_array( $value ) ) {
                $value = wp_json_encode( $value );
            }
            echo '<textarea name="' . esc_attr( Settings::OPTION_KEY ) . '[dns_resolvers]" rows="4" class="large-text code">';
            echo esc_textarea( (string) $value );
            echo '</textarea>';
            echo '<p class="description">' . esc_html__( 'JSON object of name => URL. Default: {"cloudflare":"https://cloudflare-dns.com/dns-query","google":"https://dns.google/resolve","quad9":"https://dns.quad9.net/dns-query"}. URLs must be HTTPS.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'rate_limit_dns_probe', __( 'Rate limit (per minute)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'rate_limit_dns_probe', 5 );
            printf(
                '<input type="number" min="1" max="60" name="%1$s[rate_limit_dns_probe]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_provider_chain', __( 'Resolver tier chain', 'privacy-checker' ), function () {
            $chain = (array) Plugin::instance()->setting( 'dns_provider_chain', array( 'free', 'online', 'paid', 'local' ) );
            $tiers = array(
                'free'   => __( 'Free public DoH (Cloudflare / Google / Quad9)', 'privacy-checker' ),
                'online' => __( 'Online public DoH (Mullvad / ControlD / NextDNS)', 'privacy-checker' ),
                'paid'   => __( 'Paid resolver (use configured endpoint)', 'privacy-checker' ),
                'local'  => __( 'Local configured resolvers (informational)', 'privacy-checker' ),
            );
            echo '<p class="description">' . esc_html__( 'Drag-friendly ordering will be added later; for now enter the tier names comma-separated, top to bottom.', 'privacy-checker' ) . '</p>';
            printf(
                '<input type="text" name="%1$s[dns_provider_chain]" value="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( implode( ',', $chain ) )
            );
            echo '<p class="description">';
            foreach ( $tiers as $key => $label ) {
                echo '<code>' . esc_html( $key ) . '</code> &mdash; ' . esc_html( $label ) . '<br/>';
            }
            echo '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_paid_endpoint', __( 'Paid resolver endpoint (optional)', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'dns_paid_endpoint', '' );
            printf(
                '<input type="text" placeholder="https://dns.example.com/dns-query" name="%1$s[dns_paid_endpoint]" value="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( $value )
            );
            echo '<p class="description">' . esc_html__( 'Used only when the chain reaches the "paid" tier. HTTPS only.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_paid_api_key', __( 'Paid resolver API key (optional)', 'privacy-checker' ), function () {
            printf(
                '<input type="password" autocomplete="off" name="%1$s[dns_paid_api_key]" value="" placeholder="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr__( 'Leave blank to keep current key', 'privacy-checker' )
            );
            $has = (string) Plugin::instance()->setting( 'dns_paid_api_key', '' );
            if ( '' !== $has ) echo '<p class="description">' . esc_html__( 'A key is currently stored.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_field( 'dns_local_resolvers', __( 'Local resolvers (one IP per line)', 'privacy-checker' ), function () {
            $value = (array) Plugin::instance()->setting( 'dns_local_resolvers', array() );
            echo '<textarea name="' . esc_attr( Settings::OPTION_KEY ) . '[dns_local_resolvers]" rows="3" class="large-text code">';
            echo esc_textarea( implode( "\n", $value ) );
            echo '</textarea>';
            echo '<p class="description">' . esc_html__( 'Used only when the chain reaches the "local" tier. Listed here for transparency; the probe will still query public DoH endpoints to gather latency data.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_dns_test' );

        add_settings_section( 'pc_ping', __( 'Ping / Latency', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'TCP-connect latency probes. No ICMP, no shell exec; the plugin opens a TCP socket to host:port and measures time-to-connect.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'ping_targets', __( 'Targets (one host:port per line)', 'privacy-checker' ), function () {
            $value = (array) Plugin::instance()->setting( 'ping_targets', array() );
            if ( empty( $value ) ) {
                $value = array(
                    'cloudflare.com:443',
                    'google.com:443',
                    'example.com:443',
                );
            }
            echo '<textarea name="' . esc_attr( Settings::OPTION_KEY ) . '[ping_targets]" rows="4" class="large-text code">';
            echo esc_textarea( implode( "\n", $value ) );
            echo '</textarea>';
            echo '<p class="description">' . esc_html__( 'These are the quick-select options shown to visitors on the Ping tool page.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_ping' );

        add_settings_field( 'ping_timeout_sec', __( 'Timeout (seconds)', 'privacy-checker' ), function () {
            $value = (float) Plugin::instance()->setting( 'ping_timeout_sec', 1.5 );
            printf(
                '<input type="number" step="0.1" min="0.5" max="5.0" name="%1$s[ping_timeout_sec]" value="%2$s" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( (string) $value )
            );
        }, self::MENU_SLUG, 'pc_ping' );

        add_settings_field( 'rate_limit_ping', __( 'Rate limit (per minute)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'rate_limit_ping', 30 );
            printf(
                '<input type="number" min="5" max="300" name="%1$s[rate_limit_ping]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_ping' );

        add_settings_field( 'rate_limit_connection_echo', __( 'Connection echo rate limit (per minute)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'rate_limit_connection_echo', 60 );
            printf(
                '<input type="number" min="10" max="600" name="%1$s[rate_limit_connection_echo]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
            echo '<p class="description">' . esc_html__( 'How many round-trip timestamps the browser may request per visitor per minute for its own latency measurement. 3 per report is typical.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_ping' );

        add_settings_section( 'pc_port_scan', __( 'Port Scan', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'TCP port probe. By default only the WordPress server\'s own public IP may be probed (self-only mode). Add entries to the allowlist to permit additional targets. SSH (22), SMTP (25), and RDP (3389) are always blocked.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'port_scan_allowlist', __( 'Allowlist (one IP, CIDR, or hostname per line)', 'privacy-checker' ), function () {
            $value = (array) Plugin::instance()->setting( 'port_scan_allowlist', array() );
            if ( empty( $value ) ) {
                $value = array( '' );
            }
            echo '<textarea name="' . esc_attr( Settings::OPTION_KEY ) . '[port_scan_allowlist]" rows="4" class="large-text code">';
            echo esc_textarea( implode( "\n", $value ) );
            echo '</textarea>';
            echo '<p class="description">' . esc_html__( 'Empty = self-only mode (probe only your own WordPress server). Add public IPs, CIDR blocks (e.g. 203.0.113.0/24), or hostnames to extend. Empty by default.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_port_scan' );

        add_settings_field( 'port_scan_default_ports', __( 'Default ports (comma- or space-separated)', 'privacy-checker' ), function () {
            $value = (string) Plugin::instance()->setting( 'port_scan_default_ports', '80, 443, 8080, 8443' );
            printf(
                '<input type="text" name="%1$s[port_scan_default_ports]" value="%2$s" class="regular-text" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( $value )
            );
            echo '<p class="description">' . esc_html__( 'Quick-select chips shown in the UI. Default: 80, 443, 8080, 8443.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_port_scan' );

        add_settings_field( 'port_scan_timeout_sec', __( 'Timeout (seconds)', 'privacy-checker' ), function () {
            $value = (float) Plugin::instance()->setting( 'port_scan_timeout_sec', 1.0 );
            printf(
                '<input type="number" step="0.1" min="0.2" max="5.0" name="%1$s[port_scan_timeout_sec]" value="%2$s" />',
                esc_attr( Settings::OPTION_KEY ),
                esc_attr( (string) $value )
            );
        }, self::MENU_SLUG, 'pc_port_scan' );

        add_settings_field( 'rate_limit_port_scan', __( 'Rate limit (per minute)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'rate_limit_port_scan', 10 );
            printf(
                '<input type="number" min="1" max="60" name="%1$s[rate_limit_port_scan]" value="%2$d" />',
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_port_scan' );

        // Enterprise API access — enabled by default.
        add_settings_section( 'pc_tld_registry', __( 'TLD Registry Database', 'privacy-checker' ), function () {
            echo '<p>' . esc_html__( 'WHOIS uses the bundled IANA root-zone snapshot for broad TLD coverage. Enable the opt-in daily refresh to fetch the latest public listing from IANA. If the fetch fails, the existing local snapshot remains in use.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'tld_registry_auto_update', __( 'Automatic IANA refresh', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'tld_registry_auto_update', false );
            printf(
                '<label><input type="checkbox" name="%1$s[tld_registry_auto_update]" value="1" %2$s /> %3$s</label><p class="description">%4$s</p>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Refresh the local TLD registry once per day from IANA.', 'privacy-checker' ),
                esc_html__( 'This is disabled by default. No visitor data is sent; only the public IANA registry page is requested.', 'privacy-checker' )
            );
        }, self::MENU_SLUG, 'pc_tld_registry' );

        add_settings_section( 'pc_api_access', __( 'Enterprise API Access', 'privacy-checker' ), function () {
            echo '<p>' . wp_kses(
                __( 'Issue opaque API tokens so external bots, AI agents, and integration services can call the privacy REST API without a WordPress login. Manage tokens from the <a href="' . esc_url( admin_url( 'admin.php?page=privacy-checker-api-tokens' ) ) . '">API Tokens</a> submenu.', 'privacy-checker' ),
                array( 'a' => array( 'href' => array() ) )
            ) . '</p>';
        }, self::MENU_SLUG );

        add_settings_field( 'api_tokens_enabled', __( 'Enable API tokens', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'api_tokens_enabled', true );
            printf(
                '<label><input type="checkbox" name="%1$s[api_tokens_enabled]" value="1" %2$s /> %3$s</label>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Allow external callers to authenticate with Bearer tokens.', 'privacy-checker' )
            );
        }, self::MENU_SLUG, 'pc_api_access' );

        add_settings_field( 'share_enabled', __( 'Enable shareable reports', 'privacy-checker' ), function () {
            $value = (bool) Plugin::instance()->setting( 'share_enabled', false );
            printf(
                '<label><input type="checkbox" name="%1$s[share_enabled]" value="1" %2$s /> %3$s</label>',
                esc_attr( Settings::OPTION_KEY ),
                checked( $value, true, false ),
                esc_html__( 'Allow visitors to publish a redacted, shareable URL containing their scan summary.', 'privacy-checker' )
            );
            echo '<p class="description">' . esc_html__( 'Sensitive identifiers (IP, reverse DNS, exact coordinates) are stripped server-side before storage.', 'privacy-checker' ) . '</p>';
        }, self::MENU_SLUG, 'pc_api_access' );

        add_settings_field( 'share_ttl_seconds', __( 'Share link TTL (seconds)', 'privacy-checker' ), function () {
            $value = (int) Plugin::instance()->setting( 'share_ttl_seconds', 7 * DAY_IN_SECONDS );
            printf(
                '<input type="number" min="60" max="%1$d" name="%2$s[share_ttl_seconds]" value="%3$d" />',
                30 * DAY_IN_SECONDS,
                esc_attr( Settings::OPTION_KEY ),
                $value
            );
        }, self::MENU_SLUG, 'pc_api_access' );
    }

    /**
     * Render the settings page.
     */
    public function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
        }

        require_once PRIVACY_CHECKER_DIR . 'admin/settings-page.php';
    }

    /**
     * Enqueue admin assets only on our page.
     */
    public function enqueue( string $hook ): void {
        if ( strpos( $hook, self::MENU_SLUG ) === false ) {
            return;
        }
        wp_enqueue_style(
            'pc-admin',
            PRIVACY_CHECKER_URL . 'admin/assets/admin.css',
            array(),
            PRIVACY_CHECKER_VERSION
        );
    }

    /**
     * Render a select dropdown.
     *
     * @param string               $name
     * @param array<string,string> $options
     * @param string               $current
     */
    private function render_select( string $name, array $options, string $current ): void {
        printf( '<select name="%1$s[%2$s]">', esc_attr( Settings::OPTION_KEY ), esc_attr( $name ) );
        foreach ( $options as $key => $label ) {
            printf(
                '<option value="%1$s" %2$s>%3$s</option>',
                esc_attr( $key ),
                selected( $current, $key, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
    }

    /**
     * Render the IP provider fallback chain as an ordered list with up/down controls.
     *
     * Saving is handled by the AdminDashboard's `pc_reorder_chain` admin-post handler,
     * so this field is a *display-only* representation of the live chain plus a
     * "Reset to recommended order" shortcut. The actual editing experience lives on
     * the Dashboard page (drag-equivalent via up/down buttons).
     */
    public function render_chain_field(): void {
        $chain     = \PrivacyChecker\IpFallback::read_chain();
        $available = Settings::provider_options();
        $default   = \PrivacyChecker\IpFallback::default_chain();

        echo '<p class="description">' . esc_html__( 'Order of providers tried at scan time. The first provider that returns useful data wins. Reorder on the Dashboard page; the chain below is read-only here.', 'privacy-checker' ) . '</p>';

        echo '<ol class="pc-chain" role="list" style="max-width:520px">';
        foreach ( $chain as $idx => $key ) {
            $label = $available[ $key ] ?? $key;
            printf(
                '<li class="pc-chain__item"><span class="pc-chain__pos">%1$d</span><span class="pc-chain__name">%2$s</span> <span class="pc-chain__key">(%3$s)</span></li>',
                (int) ( $idx + 1 ),
                esc_html( $label ),
                esc_html( $key )
            );
        }
        echo '</ol>';

        printf(
            '<p><a class="button" href="%1$s">%2$s</a></p>',
            esc_url( admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::DASHBOARD_SLUG ) ),
            esc_html__( 'Reorder on Dashboard →', 'privacy-checker' )
        );

        // Hidden field so the chain always serialises through sanitize even when unchanged.
        printf(
            '<input type="hidden" name="%1$s[provider_chain_ip]" value="%2$s" />',
            esc_attr( Settings::OPTION_KEY ),
            esc_attr( implode( ',', $chain ) )
        );

        // Expose the default chain for the Dashboard reset button as a data hint.
        printf(
            '<script type="application/json" id="pc-default-chain">%s</script>',
            wp_json_encode( $default )
        );
    }
}