<?php
/**
 * REST API registration.
 *
 * @package PrivacyChecker
 */

declare( strict_types=1 );

namespace PrivacyChecker;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Registers /wp-json/privacy-checker/v1/* routes.
 */
final class RestApi {

    private Plugin $plugin;

    public function __construct( Plugin $plugin ) {
        $this->plugin = $plugin;
    }

    /**
     * Hook into rest_api_init.
     */
    public function register(): void {
        add_action( 'rest_api_init', array( $this, 'register_routes' ) );
    }

    /**
     * Register routes.
     */
    public function register_routes(): void {
        $ns = PRIVACY_CHECKER_REST_NS;

        // Aggregated scan. Accepts both GET (no client signals) and POST (with
        // fingerprint + WebRTC payload). scanner.js uses POST to ship client
        // signals; some integrations and curl checks use GET.
        register_rest_route( $ns, '/scan', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( $ns, '/scan', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan' ),
            'permission_callback' => '__return_true',
        ) );

        // IP only.
        register_rest_route( $ns, '/scan/ip', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_ip' ),
            'permission_callback' => '__return_true',
        ) );

        // Connection / IP intel. Accepts both GET (v1 scanner) and POST
        // (v2 scanner, which sends the same body shape as /scan).
        register_rest_route( $ns, '/scan/connection', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_connection' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( $ns, '/scan/connection', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan_connection' ),
            'permission_callback' => '__return_true',
        ) );

        // Reputation. Accepts both GET (v1 scanner) and POST (v2 scanner).
        register_rest_route( $ns, '/scan/reputation', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_reputation' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( $ns, '/scan/reputation', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan_reputation' ),
            'permission_callback' => '__return_true',
        ) );

        // DNS test token issue.
        register_rest_route( $ns, '/scan/dns-test/token', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'dns_test_token' ),
            'permission_callback' => '__return_true',
        ) );

        // DNS test token verify.
        register_rest_route( $ns, '/scan/dns-test/verify', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'dns_test_verify' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'token' => array(
                    'required' => true,
                    'type'     => 'string',
                ),
            ),
        ) );

        // Security-headers probe.
        register_rest_route( $ns, '/scan/security-headers', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'security_headers' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'url' => array(
                    'required' => true,
                    'type'     => 'string',
                ),
            ),
        ) );

        // IP lookup.
        register_rest_route( $ns, '/lookup/ip', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'lookup_ip' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'ip' => array(
                    'required' => true,
                    'type'     => 'string',
                ),
            ),
        ) );

        // WHOIS.
        register_rest_route( $ns, '/lookup/whois', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'lookup_whois' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'query' => array(
                    'required' => true,
                    'type'     => 'string',
                ),
            ),
        ) );

        // User-Agent parse.
        register_rest_route( $ns, '/user-agent', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'user_agent' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'ua' => array(
                    'required' => false,
                    'type'     => 'string',
                    'default'  => '',
                ),
            ),
        ) );

        // Settings — admin only.
        register_rest_route( $ns, '/settings', array(
            'methods'             => WP_REST_Server::EDITABLE,
            'callback'            => array( $this, 'update_settings' ),
            'permission_callback' => array( $this, 'admin_only' ),
        ) );

        register_rest_route( $ns, '/settings', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'get_settings' ),
            'permission_callback' => array( $this, 'admin_only' ),
        ) );

        // Admin tool: trigger a MaxMind download right now. POST so we can
        // guard against accidental GETs and CSRF via nonce.
        register_rest_route( $ns, '/admin/maxmind/download', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'admin_maxmind_download' ),
            'permission_callback' => array( $this, 'admin_only' ),
        ) );

        // Admin tool: status of the local MaxMind cache.
        register_rest_route( $ns, '/admin/maxmind/status', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'admin_maxmind_status' ),
            'permission_callback' => array( $this, 'admin_only' ),
        ) );

        // Admin tool: flush cached IP results for the current visitor.
        register_rest_route( $ns, '/admin/cache/flush-ip', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'admin_flush_ip' ),
            'permission_callback' => array( $this, 'admin_only' ),
            'args'                => array(
                'ip' => array( 'required' => true, 'type' => 'string' ),
            ),
        ) );

        // DNS leak test run — server-side DoH fan-out.
        register_rest_route( $ns, '/scan/dns-test/run', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_dns_test_run' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'hostname' => array( 'required' => false, 'type' => 'string', 'default' => '' ),
            ),
        ) );

        // TCP-connect latency ping.
        register_rest_route( $ns, '/scan/ping', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_ping' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'target' => array( 'required' => true, 'type' => 'string' ),
            ),
        ) );

        // Connection-quality endpoint — returns a trivial {t: <server microtime>}
        // payload that the visitor's browser uses to measure end-to-end latency
        // (round-trip, jitter) with performance.now() around fetch(). No
        // upstream call, no DB read, no IP detection — just a fast response.
        // Dedicated `connection_echo` rate-limit bucket (generous — the client
        // fires this 3x per report) so it never starves the TCP-connect
        // `/scan/ping` bucket.
        register_rest_route( $ns, '/scan/connection/echo', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_connection_echo' ),
            'permission_callback' => '__return_true',
        ) );

        // TCP port probe.
        register_rest_route( $ns, '/scan/port', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan_port' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'host' => array( 'required' => true, 'type' => 'string' ),
                'port' => array( 'required' => true, 'type' => 'integer' ),
            ),
        ) );

        // Multi-port probe (admin-only; for "test my firewall" UI).
        register_rest_route( $ns, '/scan/port/batch', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan_port_batch' ),
            'permission_callback' => array( $this, 'admin_only' ),
            'args'                => array(
                'host'  => array( 'required' => true, 'type' => 'string' ),
                'ports' => array( 'required' => true, 'type' => 'array' ),
            ),
        ) );

        // Geo lookup for the geotraceroute page: resolve a typed target host
        // (e.g. "facebook.com") to IP + lat/lng and return a hop chain
        // suitable for visualisation. Hops are TCP-connect latency samples,
        // not real ICMP — the page labels them as synthesised when applicable.
        register_rest_route( $ns, '/scan/geo/lookup', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'scan_geo_lookup' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'target' => array( 'required' => false, 'type' => 'string', 'default' => '' ),
            ),
        ) );

        // Paste-traceroute fallback for the geotraceroute page. Same
        // canonical route shape as /scan/geo/lookup, built from a pasted
        // traceroute / tracert / MTR blob rather than a server-side run.
        register_rest_route( $ns, '/scan/geo/paste', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'scan_geo_paste' ),
            'permission_callback' => '__return_true',
            'args'                => array(
                'paste' => array(
                    'required'          => true,
                    'type'              => 'string',
                    'sanitize_callback' => array( $this, 'sanitize_traceroute_text' ),
                ),
            ),
        ) );

        // Enterprise API token management. Admin only — the tokens themselves
        // are what external bots/agents use to authenticate.
        register_rest_route( $ns, '/admin/api-tokens', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'admin_api_tokens_list' ),
            'permission_callback' => array( $this, 'admin_only' ),
        ) );
        register_rest_route( $ns, '/admin/api-tokens', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'admin_api_tokens_issue' ),
            'permission_callback' => array( $this, 'admin_only' ),
            'args'                => array(
                'label'    => array( 'required' => true, 'type' => 'string' ),
                'scopes'   => array( 'required' => false, 'type' => 'array', 'default' => array() ),
                'rate_limit' => array( 'required' => false, 'type' => 'integer', 'default' => 120 ),
            ),
        ) );
        register_rest_route( $ns, '/admin/api-tokens/(?P<id>\d+)', array(
            'methods'             => WP_REST_Server::DELETABLE,
            'callback'            => array( $this, 'admin_api_tokens_revoke' ),
            'permission_callback' => array( $this, 'admin_only' ),
            'args'                => array(
                'id' => array( 'required' => true, 'type' => 'integer' ),
            ),
        ) );

        // Account-level "who am I" for token callers. Useful for debugging.
        register_rest_route( $ns, '/api-tokens/whoami', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'api_tokens_whoami' ),
            'permission_callback' => array( $this, 'public_or_token' ),
        ) );

        // Privacy-preserving share endpoint. Visitors POST a redacted scan
        // summary; we issue a short share id and store the canonical record
        // for a configurable TTL. GET retrieves it without authentication.
        register_rest_route( $ns, '/share', array(
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => array( $this, 'share_create' ),
            'permission_callback' => '__return_true',
        ) );
        register_rest_route( $ns, '/share/(?P<sid>[A-Za-z0-9_-]{6,40})', array(
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => array( $this, 'share_read' ),
            'permission_callback' => '__return_true',
        ) );
    }

    public function admin_api_tokens_list( WP_REST_Request $request ) {
        return rest_ensure_response( array( 'tokens' => ApiTokens::list_all() ) );
    }

    public function admin_api_tokens_issue( WP_REST_Request $request ) {
        $label   = (string) $request->get_param( 'label' );
        $scopes  = (array)  $request->get_param( 'scopes' );
        $rl      = (int)    $request->get_param( 'rate_limit' );
        if ( '' === trim( $label ) ) {
            return new WP_Error( 'pc_bad_label', __( 'Token label is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        $issued = ApiTokens::issue( $label, $scopes, $rl, get_current_user_id() );
        // The plaintext token is returned EXACTLY ONCE.
        return rest_ensure_response( array(
            'token'      => $issued['token'],
            'label'      => $issued['label'],
            'prefix'     => $issued['prefix'],
            'scopes'     => $issued['scopes'],
            'rate_limit' => $issued['rate_limit'],
            'id'         => $issued['id'],
            'warning'    => __( 'Copy the token now. It cannot be shown again.', 'privacy-checker' ),
        ) );
    }

    public function admin_api_tokens_revoke( WP_REST_Request $request ) {
        $id = (int) $request['id'];
        if ( $id <= 0 ) {
            return new WP_Error( 'pc_bad_id', __( 'Invalid token id.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        return rest_ensure_response( array( 'revoked' => ApiTokens::revoke( $id ), 'id' => $id ) );
    }

    /**
     * "Who am I" — returns the authenticated entity for the bearer token, or
     * the current WP user id otherwise. Useful for debugging token setup.
     */
    public function api_tokens_whoami( WP_REST_Request $request ) {
        $token = $this->current_token( $request );
        if ( null !== $token ) {
            return rest_ensure_response( array(
                'authenticated_via' => 'api_token',
                'token'            => array(
                    'id'      => (int) $token['id'],
                    'label'   => $token['label'],
                    'prefix'  => $token['token_prefix'],
                    'scopes'  => $token['scopes'],
                    'rate_limit' => (int) $token['rate_limit_per_minute'],
                ),
            ) );
        }
        return rest_ensure_response( array(
            'authenticated_via' => is_user_logged_in() ? 'wp_user' : 'anonymous',
            'user'             => array( 'id' => get_current_user_id() ),
        ) );
    }

    /**
     * POST /share
     *
     * Accepts a redacted scan summary, stores it as a transient keyed on a
     * short share id, and returns the public URL. The server never receives
     * the visitor's IP — the client strips sensitive identifiers before
     * calling this endpoint.
     */
    public function share_create( WP_REST_Request $request ) {
        $body = (array) $request->get_json_params();
        if ( empty( $body ) ) {
            $body = (array) $request->get_body_params();
        }
        if ( ! isset( $body['report'] ) || ! is_array( $body['report'] ) ) {
            return new WP_Error( 'pc_share_invalid', 'Missing report payload.', array( 'status' => 400 ) );
        }
        if ( ! self::share_enabled() ) {
            return new WP_Error( 'pc_share_disabled', 'Sharing is disabled on this server.', array( 'status' => 403 ) );
        }

        $report = self::redact_share_payload( (array) $body['report'] );
        $sid    = self::generate_share_id();
        $ttl    = (int) ( get_option( 'pc_settings' )['share_ttl_seconds'] ?? 7 * DAY_IN_SECONDS );
        $ttl    = max( 60, min( 30 * DAY_IN_SECONDS, $ttl ) );

        set_transient( 'pc_share_' . $sid, array(
            'created_at' => time(),
            'expires_at' => time() + $ttl,
            'report'     => $report,
        ), $ttl );

        EventLog::record_if_enabled(
            'share',
            'info',
            'share',
            sprintf( 'share link created sid=%s ttl=%ds', $sid, $ttl ),
            array(
                'sid'              => $sid,
                'ttl'              => $ttl,
                'overall_score'    => $report['privacy_report']['overall'] ?? null,
                'grade'            => $report['privacy_report']['grade'] ?? null,
                'has_request_ip'   => ! empty( $report['request_ip'] ),
            )
        );

        return rest_ensure_response( array(
            'sid'        => $sid,
            'url'        => rest_url( trailingslashit( self::namespace_name() ) . 'share/' . $sid ),
            'expires_at' => time() + $ttl,
            'ttl'        => $ttl,
        ) );
    }

    /**
     * GET /share/<sid>
     */
    public function share_read( WP_REST_Request $request ) {
        $sid = (string) $request->get_param( 'sid' );
        if ( ! preg_match( '/^[A-Za-z0-9_-]{6,40}$/', $sid ) ) {
            return new WP_Error( 'pc_share_invalid_sid', 'Invalid share id.', array( 'status' => 400 ) );
        }
        $stored = get_transient( 'pc_share_' . $sid );
        if ( ! is_array( $stored ) ) {
            return new WP_Error( 'pc_share_expired', 'Share link expired or unknown.', array( 'status' => 404 ) );
        }
        return rest_ensure_response( array(
            'created_at' => (int) ( $stored['created_at'] ?? time() ),
            'expires_at' => (int) ( $stored['expires_at'] ?? time() ),
            'report'     => (array) ( $stored['report'] ?? array() ),
        ) );
    }

    /** Whether the share endpoint is enabled (admin opt-in). */
    public static function share_enabled(): bool {
        return (bool) ( get_option( 'pc_settings' )['share_enabled'] ?? false );
    }

    /**
     * Strip identifying fields from a share report payload.
     *
     * @param array<string,mixed> $report
     * @return array<string,mixed>
     */
    private static function redact_share_payload( array $report ): array {
        $drop_top = array( 'ip', 'source_ip', 'visitor_ip', 'remote_addr' );
        $redacted = $report;
        foreach ( $drop_top as $k ) {
            if ( array_key_exists( $k, $redacted ) ) unset( $redacted[ $k ] );
        }
        if ( isset( $redacted['connection'] ) && is_array( $redacted['connection'] ) ) {
            unset( $redacted['connection']['ip'] );
            if ( isset( $redacted['connection']['intel'] ) && is_array( $redacted['connection']['intel'] ) ) {
                unset( $redacted['connection']['intel']['ip'] );
                $redacted['connection']['intel']['latitude']  = self::round_coordinate( $redacted['connection']['intel']['latitude'] ?? null );
                $redacted['connection']['intel']['longitude'] = self::round_coordinate( $redacted['connection']['intel']['longitude'] ?? null );
            }
        }
        if ( isset( $redacted['connection']['reverse_dns'] ) ) {
            unset( $redacted['connection']['reverse_dns'] );
        }
        return $redacted;
    }

    /** Round coordinate to 1 decimal place (city-level) for shareable reports. */
    private static function round_coordinate( $value ): ?float {
        if ( ! is_numeric( $value ) ) return null;
        return round( (float) $value, 1 );
    }

    /** Generate a short, URL-safe random share id. */
    private static function generate_share_id(): string {
        try {
            $raw = random_bytes( 9 );
        } catch ( \Throwable $e ) {
            $raw = wp_generate_password( 12, false );
        }
        return rtrim( strtr( base64_encode( $raw ), '+/', '-_' ), '=' );
    }

    /**
     * Sanitize a pasted traceroute blob. Keep every printable character
     * except `<` so users can paste rich tracert output verbatim, and
     * line-clip at a generous length so an attacker can't make us store
     * 1 MB of pasted text per request.
     */
    public function sanitize_traceroute_text( string $raw ): string {
        $clean = preg_replace( '/[<>]/', '', $raw );
        // 16 KB ceiling per paste — enough for ~300 hops of typical
        // traceroute output, well below any payload size we'd ever need.
        if ( strlen( $clean ) > 16384 ) {
            $clean = substr( $clean, 0, 16384 );
        }
        return $clean;
    }

    /** Expose REST namespace name for share URL building. */
    public static function namespace_name(): string {
        return 'privacy-checker/v1';
    }


    public function admin_maxmind_status( WP_REST_Request $request ) {
        return rest_ensure_response( MaxmindManager::get_status() );
    }

    public function admin_maxmind_download( WP_REST_Request $request ) {
        return rest_ensure_response( MaxmindManager::download_now() );
    }

    public function admin_flush_ip( WP_REST_Request $request ) {
        $ip = trim( (string) $request->get_param( 'ip' ) );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return new WP_Error( 'pc_bad_ip', __( 'Invalid IP.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        IpFallback::flush_ip( $ip );
        return rest_ensure_response( array( 'flushed' => true, 'ip' => $ip ) );
    }

    /**
     * Admin-only permission check.
     */
    public function admin_only(): bool {
        return current_user_can( 'manage_options' );
    }

    /**
     * Permission check: nonce cookie, public endpoint, or valid Bearer token.
     *
     * Anything that the dashboard UI calls with the wp_rest nonce already passes
     * WP's default cookie auth. Bots/agents authenticate by sending
     * "Authorization: Bearer pc_live_...". Failures fall through to the WP
     * default permission handler so the legacy 403 path still works.
     */
    public function public_or_token( WP_REST_Request $request ): bool {
        if ( current_user_can( 'manage_options' ) ) {
            return true;
        }
        $bearer = ApiTokens::extract_bearer( $request );
        if ( null === $bearer ) {
            // Allow cookie/nonce auth too — public visitors get to scan themselves.
            return is_user_logged_in() || ApiTokens::enabled();
        }
        $row = ApiTokens::verify( $bearer );
        if ( null === $row ) {
            return false;
        }
        return true;
    }

    /**
     * Resolve the row for a token used to call the request, or null.
     *
     * @return array<string, mixed>|null
     */
    private function current_token( WP_REST_Request $request ): ?array {
        $bearer = ApiTokens::extract_bearer( $request );
        if ( null === $bearer ) {
            return null;
        }
        $row = ApiTokens::verify( $bearer );
        if ( null === $row ) {
           	return null;
        }
        // Touch usage asynchronously — don't block on the write path.
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : null;
        if ( null !== $ip ) {
            ApiTokens::touch_used( (int) $row['id'], $ip );
        }
        return $row;
    }


    /**
     * Common rate-limit helper.
     *
     * When the request carries a valid API token, the per-token bucket is
     * used and the token's individual rate limit applies — so one enterprise
     * tenant cannot starve the visitor-facing limit.
     */
    private function enforce_rate_limit( WP_REST_Request $request, string $bucket, ?int $limit = null ): true|WP_Error {
        $token = $this->current_token( $request );
        if ( null !== $token ) {
            $per_token_limit = (int) ( $token['rate_limit_per_minute'] ?? 120 );
            $result = RateLimiter::check_identifier( $bucket, 'token-' . (int) $token['id'], $per_token_limit );
            if ( ! $result['allowed'] ) {
                return new WP_Error(
                    'pc_rate_limited',
                    __( 'Token rate limit reached. Please wait a moment.', 'privacy-checker' ),
                    array( 'status' => 429, 'retry_after' => $result['retry_after'] )
                );
            }
            return true;
        }

        $limit = $limit ?? (int) Plugin::instance()->setting( 'rate_limit_scan', 60 );
        if ( defined( 'PRIVACY_CHECKER_RATE_LIMIT_SCAN' ) && 'scan' === $bucket ) {
            $limit = (int) PRIVACY_CHECKER_RATE_LIMIT_SCAN;
        }
        if ( defined( 'PRIVACY_CHECKER_RATE_LIMIT_LOOKUP' ) && 'lookup' === $bucket ) {
            $limit = (int) PRIVACY_CHECKER_RATE_LIMIT_LOOKUP;
        }
        if ( defined( 'PRIVACY_CHECKER_RATE_LIMIT_DNS_PROBE' ) && 'dns_probe' === $bucket ) {
            $limit = (int) PRIVACY_CHECKER_RATE_LIMIT_DNS_PROBE;
        }
        if ( defined( 'PRIVACY_CHECKER_RATE_LIMIT_PING' ) && 'ping' === $bucket ) {
            $limit = (int) PRIVACY_CHECKER_RATE_LIMIT_PING;
        }
        if ( defined( 'PRIVACY_CHECKER_RATE_LIMIT_PORT_SCAN' ) && 'port_scan' === $bucket ) {
            $limit = (int) PRIVACY_CHECKER_RATE_LIMIT_PORT_SCAN;
        }
        $bucket_limit = (int) Plugin::instance()->setting( 'rate_limit_' . $bucket, $limit );
        $result = RateLimiter::check( $bucket, $bucket_limit );
        if ( ! $result['allowed'] ) {
            return new WP_Error(
                'pc_rate_limited',
                __( 'Too many requests. Please wait a moment.', 'privacy-checker' ),
                array( 'status' => 429, 'retry_after' => $result['retry_after'] )
            );
        }
        return true;
    }

    /**
     * GET /scan — aggregated privacy report.
     */
    public function scan( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $client_signals = $this->collect_client_signals( $request );
        $start          = microtime( true );
        $report         = ScannerOrchestrator::scan( $client_signals );
        $duration_ms    = (int) round( ( microtime( true ) - $start ) * 1000 );

        // Phase 28: record the scan event. Only the audit trail
        // fields we want retained go in `context` — the full report
        // is too large to log on every scan and is already available
        // via the Privacy Report Inspector.
        if ( is_array( $report ) ) {
            $ip     = isset( $report['request_ip']['ipv4'] ) ? (string) $report['request_ip']['ipv4'] : 'unknown';
            $score  = isset( $report['privacy_report']['overall'] ) ? (int) $report['privacy_report']['overall'] : null;
            $grade  = isset( $report['privacy_report']['grade'] ) ? (string) $report['privacy_report']['grade'] : '';
            EventLog::record_if_enabled(
                'scan',
                'info',
                'scan',
                sprintf( 'v%d scan from %s — score=%s grade=%s', 2, $ip, $score === null ? '—' : (string) $score, $grade ?: '—' ),
                array(
                    'ip'          => $ip,
                    'score'       => $score,
                    'grade'       => $grade,
                    'duration_ms' => $duration_ms,
                    'version'     => 2,
                )
            );
        }
        return rest_ensure_response( $report );
    }

    /**
     * GET /scan/ip
     */
    public function scan_ip( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $detected = IpDetector::detect();
        $payload  = array(
            'ipv4'   => $detected['ipv4'],
            'ipv6'   => $detected['ipv6'],
            'source' => $detected['source'],
        );
        if ( $detected['ipv4'] ) {
            $payload['reverse_dns'] = IpDetector::reverse_dns( $detected['ipv4'] );
        }
        if ( $detected['ipv6'] ) {
            $payload['reverse_dns_v6'] = IpDetector::reverse_dns( $detected['ipv6'] );
        }
        return rest_ensure_response( $payload );
    }

    /**
     * GET /scan/connection
     */
    public function scan_connection( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $detected = IpDetector::detect();
        $payload  = array(
            'ipv4' => $detected['ipv4'],
            'ipv6' => $detected['ipv6'],
        );
        if ( $detected['ipv4'] ) {
            $payload['intel'] = IpFallback::lookup( $detected['ipv4'] );
        }
        return rest_ensure_response( $payload );
    }

    /**
     * GET /scan/reputation
     */
    public function scan_reputation( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $detected = IpDetector::detect();
        if ( ! $detected['ipv4'] ) {
            return new WP_Error( 'pc_no_ip', __( 'No IPv4 address available to check.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        return rest_ensure_response( Reputation::check( $detected['ipv4'] ) );
    }

    /**
     * GET /scan/dns-test/token
     */
    public function dns_test_token( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        return rest_ensure_response( DnsTest::issue_token() );
    }

    /**
     * POST /scan/dns-test/verify
     */
    public function dns_test_verify( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'scan' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $token = (string) $request->get_param( 'token' );
        return rest_ensure_response( DnsTest::verify_token( $token ) );
    }

    /**
     * GET /scan/security-headers
     */
    public function security_headers( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'security', (int) Plugin::instance()->setting( 'rate_limit_security', 10 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $url = (string) $request->get_param( 'url' );
        return rest_ensure_response( SecurityHeaders::check( $url ) );
    }

    /**
     * GET /lookup/ip
     *
     * Accepts either an IPv4 / IPv6 literal or a hostname. Hostnames
     * are resolved to a public IP first; if the resolved IP is not
     * public (loopback, private, multicast) we return a 400 with the
     * same shape IP Fallback uses, so the frontend can show a friendly
     * "non-public IP" warning instead of an opaque 500.
     */
    public function lookup_ip( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'lookup' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $input = trim( (string) $request->get_param( 'ip' ) );
        if ( '' === $input ) {
            return new WP_Error( 'pc_missing_ip', __( 'IP is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        // If it's not an IP literal, try to resolve as a hostname.
        $resolved = false;
        if ( ! filter_var( $input, FILTER_VALIDATE_IP ) ) {
            // Strip any URL scheme / path (e.g. "https://example.com/").
            $host = preg_replace( '#^https?://#i', '', $input );
            $host = preg_replace( '#/.*$#', '', $host );
            $host = trim( (string) $host );
            if ( '' === $host || ! preg_match( '/^[A-Za-z0-9.\-]+$/', $host ) ) {
                return new WP_Error(
                    'pc_bad_ip',
                    sprintf( __( '"%s" is not a valid IP address or hostname.', 'privacy-checker' ), esc_html( $input ) ),
                    array( 'status' => 400 )
                );
            }
            $ip = gethostbyname( $host );
            if ( '' === $ip || $ip === $host ) {
                return new WP_Error(
                    'pc_dns_failed',
                    sprintf( __( 'Could not resolve %s.', 'privacy-checker' ), esc_html( $host ) ),
                    array( 'status' => 404 )
                );
            }
            $resolved = true;
        } else {
            $ip = $input;
        }

        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            // Surface the same shape IP Fallback would have produced so
            // the UI can render a clean "non-public IP" message.
            return rest_ensure_response( array(
                'ip'         => $ip,
                'resolved'   => $resolved,
                'reverse_dns'=> null,
                'intel'      => array(
                    'status' => 'error',
                    'ip'     => $ip,
                    'error'  => __( 'Non-public IP literals are not looked up.', 'privacy-checker' ),
                    'chain'  => array(),
                ),
            ) );
        }

        $intel   = IpFallback::lookup( $ip );
        $reverse = IpDetector::reverse_dns( $ip );
        return rest_ensure_response( array(
            'ip'         => $ip,
            'resolved'   => $resolved,
            'reverse_dns'=> $reverse,
            'intel'      => $intel,
        ) );
    }

    /**
     * GET /lookup/whois
     */
    public function lookup_whois( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'lookup' );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $query = (string) $request->get_param( 'query' );
        return rest_ensure_response( Whois::query( $query ) );
    }

    /**
     * GET /user-agent
     */
    public function user_agent( WP_REST_Request $request ) {
        $ua = (string) $request->get_param( 'ua' );
        if ( '' === $ua ) {
            $ua = (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' );
        }
        return rest_ensure_response( Fingerprint::parse_user_agent( $ua ) );
    }

    /**
     * GET /scan/dns-test/run
     *
     * Server-side DNS-over-HTTPS fan-out. Either returns the configured
     * "not_configured" sentinel or a per-resolver result table.
     */
    public function scan_dns_test_run( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'dns_probe', (int) Plugin::instance()->setting( 'rate_limit_dns_probe', 5 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }
        $hostname = (string) $request->get_param( 'hostname' );
        return rest_ensure_response( DnsTest::run_doh_probe( '' !== $hostname ? $hostname : null ) );
    }

    /**
     * GET /scan/connection/echo
     *
     * Trivial echo endpoint for client-side latency measurement. Returns
     * `{ "t": <server microtime> }` with aggressive no-cache headers so the
     * visitor's browser can time the round-trip with `performance.now()`
     * without any upstream work, DB hit, or rate-limit pressure beyond the
     * standard `ping` bucket.
     *
     * Intentionally tiny — the latency it reports is end-to-end
     * (browser → WP server → back), which is what the visitor actually cares
     * about. We do not measure server-side; that would only measure the
     * server's view of itself.
     */
    public function scan_connection_echo( WP_REST_Request $request ): \WP_REST_Response|\WP_Error {
        $limit = $this->enforce_rate_limit( $request, 'connection_echo', (int) Plugin::instance()->setting( 'rate_limit_connection_echo', 60 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $response = new WP_REST_Response( array(
            't' => microtime( true ),
        ), 200 );

        // Aggressive no-cache — every byte must come from the server so the
        // browser-side timing includes the full network round-trip, not a
        // cached response from 30 seconds ago.
        $response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
        $response->header( 'Pragma', 'no-cache' );
        $response->header( 'Expires', '0' );

        return $response;
    }

    /**
     * GET /scan/ping?target=host:port
     *
     * TCP-connect latency. Target must pass NetworkProbe::check_target_allowed().
     */
    public function scan_ping( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'ping', (int) Plugin::instance()->setting( 'rate_limit_ping', 30 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $raw_target = (string) $request->get_param( 'target' );
        list( $host, $port ) = Security::split_hostport( $raw_target );
        if ( '' === $host ) {
            return new WP_Error(
                'pc_bad_target',
                __( 'Target must be a hostname or host:port.', 'privacy-checker' ),
                array( 'status' => 400 )
            );
        }
        if ( null === $port ) {
            $port = 443;
        }

        list( $allowed, $deny_reason ) = NetworkProbe::check_target_allowed( $host, $port );
        if ( ! $allowed ) {
            return new WP_Error( 'pc_target_denied', $deny_reason, array( 'status' => 403 ) );
        }

        $timeout = (float) Plugin::instance()->setting( 'ping_timeout_sec', 1.5 );
        return rest_ensure_response( NetworkProbe::tcp_latency( $host, $port, $timeout ) );
    }

    /**
     * POST /scan/port
     *
     * Single TCP port probe. Same allowlist path as ping.
     */
    public function scan_port( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'port_scan', (int) Plugin::instance()->setting( 'rate_limit_port_scan', 10 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $host = trim( (string) $request->get_param( 'host' ) );
        $port = (int) $request->get_param( 'port' );
        if ( '' === $host ) {
            return new WP_Error( 'pc_missing_host', __( 'Host is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        if ( $port < 1 || $port > 65535 ) {
            return new WP_Error( 'pc_bad_port', __( 'Port must be between 1 and 65535.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        list( $allowed, $deny_reason ) = NetworkProbe::check_target_allowed( $host, $port );
        if ( ! $allowed ) {
            return new WP_Error( 'pc_target_denied', $deny_reason, array( 'status' => 403 ) );
        }

        $timeout = (float) Plugin::instance()->setting( 'port_scan_timeout_sec', 1.0 );
        return rest_ensure_response( NetworkProbe::tcp_probe_port( $host, $port, $timeout ) );
    }

    /**
     * POST /scan/port/batch
     *
     * Admin-only multi-port probe. Max 16 ports per call.
     */
    public function scan_port_batch( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'port_scan', (int) Plugin::instance()->setting( 'rate_limit_port_scan', 10 ) );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $host  = trim( (string) $request->get_param( 'host' ) );
        $ports = $request->get_param( 'ports' );
        if ( '' === $host ) {
            return new WP_Error( 'pc_missing_host', __( 'Host is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        if ( ! is_array( $ports ) || empty( $ports ) ) {
            return new WP_Error( 'pc_missing_ports', __( 'Ports array is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        // Coerce to ints, dedupe, clamp to [1, 65535], cap at 16.
        $clean_ports = array();
        foreach ( $ports as $p ) {
            $ip = (int) $p;
            if ( $ip >= 1 && $ip <= 65535 ) {
                $clean_ports[] = $ip;
            }
        }
        $clean_ports = array_values( array_unique( $clean_ports ) );
        if ( empty( $clean_ports ) ) {
            return new WP_Error( 'pc_bad_ports', __( 'No valid ports supplied.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        if ( count( $clean_ports ) > 16 ) {
            $clean_ports = array_slice( $clean_ports, 0, 16 );
        }

        // Validate the host once.
        list( $allowed, $deny_reason ) = NetworkProbe::check_target_allowed( $host, 443 );
        if ( ! $allowed ) {
            return new WP_Error( 'pc_target_denied', $deny_reason, array( 'status' => 403 ) );
        }

        $timeout = (float) Plugin::instance()->setting( 'port_scan_timeout_sec', 1.0 );
        $results = array();
        foreach ( $clean_ports as $port ) {
            // Per-port denylist re-check (the allowlist host check above used a
            // dummy port for the host portion only).
            list( $port_allowed, $port_reason ) = NetworkProbe::check_target_allowed( $host, $port );
            if ( ! $port_allowed ) {
                $results[] = array(
                    'host'   => $host,
                    'port'   => $port,
                    'status' => 'denied',
                    'error'  => $port_reason,
                );
                continue;
            }
            $results[] = NetworkProbe::tcp_probe_port( $host, $port, $timeout );
        }

        return rest_ensure_response( array(
            'host'    => $host,
            'ports'   => $clean_ports,
            'results' => $results,
        ) );
    }

    /**
     * GET /scan/geo/lookup?target=facebook.com
     *
     * Honest traceroute → ordered hops → per-hop geolocation pipeline.
     *
     * Returns a canonical `route` object the frontend can render directly
     * in 2D (Leaflet) and 3D (three.js) from the same coordinate array.
     *
     * Architecture:
     *
     *   1. Resolve target hostname → public IP.
     *   2. Identify the probe (the WP server's own public IP + geo) — not
     *      the visitor's. Server-side traceroute measures the server's
     *      outbound path, NOT the visitor's physical network route.
     *   3. Run /usr/sbin/traceroute. Try ICMP first, fall back to TCP/443,
     *      fall back to "unavailable". We never fabricate hops.
     *   4. Parse the output into ordered hops with the IP the router
     *      actually presented.
     *   5. Geolocate each public hop IP via IpFallback. Skip private /
     *      reserved / unanswered hops — keep them in order but mark them
     *      with no coordinates.
     *   6. Return one canonical `route` object the 2D and 3D renderers
     *      consume from the same array.
     *
     * Returns:
     *   {
     *     probe:    {ip, hostname, lat, lng, city, country, country_code, asn, isp, confidence},
     *     target:   {hostname, ip, lat, lng, city, country, country_code, asn, isp, confidence},
     *     hops: [
     *       {
     *         index: 1,
     *         ip: '203.0.113.7',   // null for unanswered hops
     *         hostname: '...',     // null for hops without rDNS
     *         rtt_ms: 4.2,         // null for unanswered
     *         status: 'public' | 'private' | 'unanswered',
     *         city, country, country_code, lat, lon, asn, isp,
     *         confidence: 'high' | 'medium' | 'low' | 'unknown',
     *       },
     *       ...
     *     ],
     *     source_kind: 'real-traceroute' | 'unavailable',
     *     message: '...',
     *     disclaimer: 'Approximate geographic visualization of traceroute hops.',
     *   }
     */
    public function scan_geo_lookup( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'geo_lookup', 30 );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $raw_target = trim( (string) $request->get_param( 'target' ) );
        $target     = self::normalize_target( $raw_target );
        if ( '' === $target ) {
            return new WP_Error( 'pc_missing_target', __( 'Target host is required.', 'privacy-checker' ), array( 'status' => 400 ) );
        }
        // Split off any port suffix.
        list( $host, $port ) = Security::split_hostport( $target );
        if ( '' === $host ) {
            return new WP_Error( 'pc_bad_target', __( 'Target must be a hostname or host:port.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        // Resolve host → IP. Accept IPv4 / IPv6 literals too.
        if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
            $ip = $host;
        } else {
            $ip = gethostbyname( $host );
            if ( '' === $ip || $ip === $host ) {
                return new WP_Error( 'pc_dns_failed', sprintf( __( 'Could not resolve %s.', 'privacy-checker' ), esc_html( $host ) ), array( 'status' => 404 ) );
            }
        }
        if ( ! Security::is_public_ip_literal( $ip ) ) {
            return new WP_Error( 'pc_private_target', __( 'Target resolves to a non-public IP.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        // Target geo.
        $target_intel  = IpFallback::lookup( $ip );
        $target_record = self::geo_record_from_intel( $ip, $host, $target_intel );

        // Probe = the WP server's own public IP + geo. NOT the visitor's
        // IP. A server-side traceroute measures the server's outbound
        // route, not the visitor's physical network path. We label the
        // route origin as "Probe" so the UI does not mislead the user.
        $probe_ip       = IpFallback::server_self_ip();
        $probe_record   = null;
        if ( $probe_ip && Security::is_public_ip_literal( $probe_ip ) ) {
            $probe_intel = IpFallback::lookup( $probe_ip );
            $probe_record = self::geo_record_from_intel( $probe_ip, '', $probe_intel );
        }
        // Local-dev fallback: if we couldn't determine the server's own
        // public IP, mark the probe as unknown so the UI shows an honest
        // "probe location unknown" instead of pretending it's somewhere.
        if ( null === $probe_record ) {
            $probe_record = array(
                'ip'           => '',
                'hostname'     => '',
                'lat'          => null,
                'lon'          => null,
                'city'         => '',
                'country'      => '',
                'country_code' => '',
                'asn'          => '',
                'isp'          => '',
                'confidence'   => 'unknown',
                'flag'         => '',
            );
        }

        // Run the real traceroute. May yield zero hops if the binary is
        // missing, shell_exec is disabled, the network blocks probes, or
        // every hop is unanswered. We never fabricate hops in any case.
        $trace = self::run_real_traceroute( $ip, $port );

        $source_kind = empty( $trace['hops'] ) ? 'unavailable' : 'real-traceroute';
        $message     = empty( $trace['hops'] )
            ? $trace['message']
            : sprintf(
                /* translators: %d = number of hops, %s = target hostname */
                __( 'Resolved %1$s and discovered %2$d hops.', 'privacy-checker' ),
                $host,
                count( $trace['hops'] )
            );

        // Phase 28: record the live-traceroute event. Surface failures
        // (source_kind=unavailable) at warning level so the admin can
        // see them in the logs view.
        EventLog::record_if_enabled(
            'share',
            $source_kind === 'unavailable' ? 'warning' : 'info',
            'geotrace',
            sprintf(
                /* translators: 1: target host, 2: number of hops */
                __( 'Live traceroute to %1$s — %2$d hops.', 'privacy-checker' ),
                $host,
                count( $trace['hops'] )
            ),
            array(
                'source_kind' => $source_kind,
                'hop_count'   => count( $trace['hops'] ),
                'target_host' => $host,
                'method'      => $trace['method'],
            )
        );

        return rest_ensure_response( array(
            'probe'      => $probe_record,
            'target'     => $target_record,
            'hops'       => $trace['hops'],
            'method'     => $trace['method'],
            'source_kind'=> $source_kind,
            'message'    => $message,
            'disclaimer' => __( 'Approximate geographic visualization of traceroute hops. IP geolocation is not GPS — coordinates indicate the registered location of each hop IP, not its physical router.', 'privacy-checker' ),
        ) );
    }

    /**
     * POST /scan/geo/paste
     *
     * Parses a pasted traceroute output (Linux traceroute, Windows tracert,
     * or MTR) into the same canonical `route` shape returned by
     * /scan/geo/lookup. Used as the fallback when the server cannot
     * execute traceroute itself (sandboxed hosting, firewall, etc.).
     */
    public function scan_geo_paste( WP_REST_Request $request ) {
        $limit = $this->enforce_rate_limit( $request, 'geo_paste', 30 );
        if ( is_wp_error( $limit ) ) {
            return $limit;
        }

        $body = (string) $request->get_param( 'paste' );
        if ( '' === trim( $body ) ) {
            return new WP_Error( 'pc_empty_paste', __( 'Paste traceroute output first.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        $parsed = self::parse_traceroute_text( $body );
        if ( empty( $parsed['hops'] ) ) {
            return new WP_Error( 'pc_parse_failed', __( 'Could not parse that traceroute. Linux / Windows / MTR formats only.', 'privacy-checker' ), array( 'status' => 400 ) );
        }

        // Geolocate each hop IP. Private / reserved / null IPs are kept in
        // order but flagged with no coordinates.
        $hops = self::geolocate_hop_list( $parsed['hops'] );

        $probe_record = array(
            'ip'           => '',
            'hostname'     => '',
            'lat'          => null,
            'lon'          => null,
            'city'         => '',
            'country'      => '',
            'country_code' => '',
            'asn'          => '',
            'isp'          => '',
            'confidence'   => 'unknown',
            'flag'         => '',
        );
        $target_record = array(
            'ip'           => $parsed['target_ip'] ?? '',
            'hostname'     => $parsed['target_host'] ?? '',
            'lat'          => null,
            'lon'          => null,
            'city'         => '',
            'country'      => '',
            'country_code' => '',
            'asn'          => '',
            'isp'          => '',
            'confidence'   => 'unknown',
            'flag'         => '',
        );

        // Phase 28: record the paste event. No PII (paste content) in
        // context — just the count and the parsed target.
        EventLog::record_if_enabled(
            'share',
            'info',
            'geotrace',
            sprintf(
                /* translators: %d = number of hops */
                __( 'Pasted traceroute — %d hops.', 'privacy-checker' ),
                count( $hops )
            ),
            array(
                'source_kind' => 'pasted-traceroute',
                'hop_count'   => count( $hops ),
                'target_host' => (string) ( $parsed['target_host'] ?? '' ),
            )
        );

        return rest_ensure_response( array(
            'probe'       => $probe_record,
            'target'      => $target_record,
            'hops'        => $hops,
            'method'      => 'pasted',
            'source_kind' => 'pasted-traceroute',
            'message'     => sprintf(
                /* translators: %d = number of hops */
                __( 'Parsed pasted traceroute — %d hops.', 'privacy-checker' ),
                count( $hops )
            ),
            'disclaimer'  => __( 'Approximate geographic visualization of traceroute hops. IP geolocation is not GPS.', 'privacy-checker' ),
        ) );
    }

    /**
     * Run /usr/sbin/traceroute against the target IP, parse the output into
     * ordered hops, and return them WITHOUT coordinates. Geolocation is a
     * separate step (geolocate_hop_list).
     *
     * Tries ICMP first (-I), then TCP/443 (-T -p 443). On failure, returns
     * an empty hop list with a clear reason in `message`.
     *
     * @return array{hops: array<int,array{index:int,ip:?string,hostname:?string,rtt_ms:?float,status:string}>, method:string, message:string}
     */
    private static function run_real_traceroute( string $target_ip, ?int $target_port ): array {
        // Capability checks — never fall back to fabrication.
        $traceroute_bin = trim( (string) shell_exec( 'command -v traceroute 2>/dev/null' ) );
        if ( '' === $traceroute_bin ) {
            return array(
                'hops'    => array(),
                'method'  => 'none',
                'message' => __( 'Traceroute binary not available on this server. Paste your own traceroute output below to visualise it.', 'privacy-checker' ),
            );
        }
        if ( self::shell_exec_disabled() ) {
            return array(
                'hops'    => array(),
                'method'  => 'none',
                'message' => __( 'Shell execution is disabled on this server, so we cannot run traceroute. Paste your own traceroute output below to visualise it.', 'privacy-checker' ),
            );
        }
        if ( ! self::is_safe_target_for_traceroute( $target_ip ) ) {
            return array(
                'hops'    => array(),
                'method'  => 'none',
                'message' => __( 'Target is not safe to traceroute (private or reserved range).', 'privacy-checker' ),
            );
        }

        $port = $target_port ?: 443;

        // Try ICMP first (works on most networks), then TCP.
        $attempts = array(
            array( '-I', '-n', '-w', '2', '-q', '1', '-m', '20' ),
            array( '-T', '-p', (string) $port, '-n', '-w', '2', '-q', '1', '-m', '20' ),
        );

        foreach ( $attempts as $flags ) {
            $cmd = self::build_traceroute_command( $traceroute_bin, $flags, $target_ip );
            $output = self::safe_shell_exec( $cmd );
            if ( '' === $output ) {
                continue;
            }
            $hops = self::parse_traceroute_text( $output );
            // Keep the attempt if it produced ANY hop with an IP. Some
            // networks block ICMP for intermediate hops but still reply to
            // the destination — we want to show what we actually got.
            $has_public = false;
            foreach ( $hops['hops'] as $h ) {
                if ( ! empty( $h['ip'] ) && self::is_public_ip_simple( $h['ip'] ) ) {
                    $has_public = true;
                    break;
                }
            }
            if ( $has_public ) {
                return array(
                    'hops'    => $hops['hops'],
                    'method'  => ( in_array( '-I', $flags, true ) ? 'icmp' : 'tcp' ),
                    'message' => sprintf(
                        /* translators: %d = hop count */
                        __( 'Discovered %d hops.', 'privacy-checker' ),
                        count( $hops['hops'] )
                    ),
                );
            }
        }

        return array(
            'hops'    => array(),
            'method'  => 'none',
            'message' => __( 'Traceroute ran but no public hops were answered. The network is likely blocking outbound traceroute probes. Paste your own traceroute output below.', 'privacy-checker' ),
        );
    }

    /**
     * Build a traceroute shell command. The target IP is already validated
     * as public, so command injection via the IP is not possible (we pass
     * it via an arg vector through escapeshellarg). The flags list is a
     * fixed internal constant, never user input.
     */
    private static function build_traceroute_command( string $bin, array $flags, string $ip ): string {
        return escapeshellcmd( $bin )
            . ' ' . implode( ' ', array_map( 'escapeshellarg', $flags ) )
            . ' ' . escapeshellarg( $ip )
            . ' 2>&1';
    }

    /**
     * shell_exec with a hard timeout and disabled-functions check.
     * The plugin's shared-host reality means shell_exec may be disabled
     * — when it is, we fail open with an empty string and the caller
     * surfaces a "traceroute unavailable" message to the UI.
     */
    private static function safe_shell_exec( string $cmd ): string {
        if ( self::shell_exec_disabled() ) {
            return '';
        }
        // 20s ceiling — traceroute with -m 20 + -w 2 can take up to ~40s
        // in the worst case; we cap at 20 so the HTTP request stays
        // responsive on the GeoTrace page.
        $cmd = 'timeout 20 ' . $cmd;
        $out = shell_exec( $cmd );
        return is_string( $out ) ? $out : '';
    }

    private static function shell_exec_disabled(): bool {
        $disabled = (string) ini_get( 'disable_functions' );
        foreach ( preg_split( '/\s*,\s*/', $disabled ) as $fn ) {
            if ( 'shell_exec' === $fn || 'exec' === $fn ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Independent of Security::is_public_ip_literal — we want a fast,
     * dependency-free check that doesn't require the Security class
     * instance and works inside static helpers.
     *
     * PHP's FILTER_FLAG_NO_RES_RANGE misses several ranges we care about
     * (notably 169.254.0.0/16 link-local, 192.0.2.0/24 + 198.51.100.0/24 +
     * 203.0.113.0/24 TEST-NET documentation ranges, and the various
     * 6to4 / 100.64.0.0/10 CGNAT carve-outs depending on PHP version), so
     * we layer a manual byte-level check on top of the filter flag.
     */
    private static function is_public_ip_simple( string $ip ): bool {
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return false;
        }
        // Link-local 169.254.0.0/16 — not in PHP's NO_RES_RANGE consistently.
        if ( false !== strpos( $ip, ':' ) ) {
            // IPv6 — trust the filter for now; the relevant IPv6 ranges
            // (fc00::/7 unique-local, fe80::/10 link-local, ::1/128
            // loopback, ::/128 unspecified) are all covered by NO_PRIV_RANGE
            // + NO_RES_RANGE in supported PHP versions.
            return true;
        }
        // IPv4 manual carve-outs.
        $parts = explode( '.', $ip );
        if ( count( $parts ) < 4 ) {
            return false;
        }
        list( $a, $b, $c ) = array( (int) $parts[0], (int) $parts[1], (int) $parts[2] );
        if ( 169 === $a && 254 === $b ) {
            return false; // link-local 169.254.0.0/16
        }
        if ( 192 === $a &&   0 === $b && 2   === $c ) { return false; } // TEST-NET-1  192.0.2.0/24
        if ( 198 === $a &&  51 === $b && 100 === $c ) { return false; } // TEST-NET-2  198.51.100.0/24
        if ( 203 === $a &&   0 === $b && 113 === $c ) { return false; } // TEST-NET-3  203.0.113.0/24
        return true;
    }

    private static function is_safe_target_for_traceroute( string $ip ): bool {
        return self::is_public_ip_simple( $ip );
    }

    /**
     * Parse traceroute-style text (Linux traceroute, Windows tracert, MTR)
     * into an ordered hop list. Recognised formats:
     *
     *   Linux:  " 3  10.0.0.1 (10.0.0.1)  1.234 ms  1.456 ms  1.789 ms"
     *   Windows:"  3     1 ms     1 ms     1 ms  10.0.0.1"
     *   MTR:    "HOST: Loss%  Snt  Last  Avg  Best  Wrst  StDev\n  1. ...\n  2. ..."
     *
     * Returns:
     *   {
     *     hops: [{index, ip|null, hostname|null, rtt_ms|null, status}],
     *     target_ip?: string,
     *     target_host?: string,
     *   }
     *
     * @return array{hops: array<int,array{index:int,ip:?string,hostname:?string,rtt_ms:?float,status:string}>, target_ip?:string, target_host?:string}
     */
    private static function parse_traceroute_text( string $text ): array {
        $hops = array();
        $target_ip   = null;
        $target_host = null;

        // Capture target from the header line if present.
        if ( preg_match( '/^traceroute to ([^\s(]+)\s*(?:\(([^)]+)\))?/m', $text, $m ) ) {
            $target_host = $m[1];
            if ( ! empty( $m[2] ) ) {
                $target_ip = $m[2];
            }
        }

        foreach ( preg_split( '/\r?\n/', $text ) as $line ) {
            $line = trim( $line );
            if ( '' === $line ) {
                continue;
            }
            // Skip headers / blanks.
            if ( preg_match( '/^(traceroute|tracert|HOST:)/i', $line ) ) {
                continue;
            }
            // Match either "<index> ..." (Linux/Windows) OR MTR's
            // "<index>. hostname (ip) loss% snt last avg best wrst stdev".
            // MTR uses a trailing dot instead of a space after the index.
            if ( ! preg_match( '/^\s*(\d{1,3})[\s.]+(.+)$/', $line, $m ) ) {
                continue;
            }
            $index = (int) $m[1];
            $rest  = $m[2];

            $hop = array(
                'index'    => $index,
                'ip'       => null,
                'hostname' => null,
                'rtt_ms'   => null,
                'status'   => 'unanswered',
            );

            // Unanswered hop (Linux / MTR): "* * *".
            if ( preg_match( '/^[\s*]*\*[\s*]*\*?[\s*]*\*?\s*$/', $rest ) ) {
                $hops[ $index ] = $hop;
                continue;
            }
            // Linux: "<ip> (<ip>)  ms  ms  ms".
            if ( preg_match( '/([0-9a-fA-F:.]+)\s+\(([^)]+)\)(?:\s+([\d.]+)\s*ms)?/i', $rest, $ipm ) ) {
                $candidate = $ipm[2];
                if ( self::is_valid_ip_text( $candidate ) ) {
                    $hop['ip']       = $candidate;
                    $hop['hostname'] = $ipm[1] !== $candidate ? $ipm[1] : null;
                    if ( ! empty( $ipm[3] ) ) {
                        $hop['rtt_ms'] = (float) $ipm[3];
                    }
                    $hop['status'] = self::classify_ip_status( $candidate );
                    if ( null === $target_ip && self::is_public_ip_simple( $candidate ) ) {
                        $target_ip = $candidate;
                    }
                    $hops[ $index ] = $hop;
                    continue;
                }
            }
            // Windows tracert: "1 ms 1 ms 1 ms <ip>" — the IP is the last token.
            if ( preg_match( '/(\d+(?:\.\d+)?)\s*ms.*?(\d+(?:\.\d+)?)\s*ms.*?(\d+(?:\.\d+)?)\s*ms\s+([0-9a-fA-F:.]+)\s*$/i', $rest, $wm ) ) {
                $candidate = $wm[4];
                $hop['ip']     = $candidate;
                $hop['rtt_ms'] = (float) $wm[1];
                $hop['status'] = self::classify_ip_status( $candidate );
                $hops[ $index ] = $hop;
                continue;
            }
            // MTR summary: "ip 0.0% 10 1.2 1.3 1.1 1.5 0.1" — IP first, then
            // loss%, then 6 numeric columns (snt, last, avg, best, wrst,
            // stdev). Pick the "last" RTT (3rd numeric column).
            if ( preg_match( '/^\s*([0-9a-fA-F:.]+)\s+\d+(?:\.\d+)?%\s+\d+\s+(\d+(?:\.\d+)?)\s+/i', $rest, $mm ) ) {
                $candidate = $mm[1];
                $hop['ip']     = $candidate;
                $hop['rtt_ms'] = (float) $mm[2];
                $hop['status'] = self::classify_ip_status( $candidate );
                $hops[ $index ] = $hop;
                continue;
            }
            // Bare IP with optional rDNS: "router.isp.net (1.2.3.4) 4.2 ms"
            if ( preg_match( '/([\w.\-]+)\s+\(([0-9a-fA-F:.]+)\)(?:\s+([\d.]+)\s*ms)?/i', $rest, $bm ) ) {
                $candidate = $bm[2];
                if ( self::is_valid_ip_text( $candidate ) ) {
                    $hop['ip']       = $candidate;
                    $hop['hostname'] = $bm[1];
                    if ( ! empty( $bm[3] ) ) {
                        $hop['rtt_ms'] = (float) $bm[3];
                    }
                    $hop['status'] = self::classify_ip_status( $candidate );
                    $hops[ $index ] = $hop;
                    continue;
                }
            }
            // If we get here, the line had an index but no IP we could
            // parse — leave the hop as unanswered.
            $hops[ $index ] = $hop;
        }

        ksort( $hops );
        $hops = array_values( $hops );

        $out = array( 'hops' => $hops );
        if ( null !== $target_ip ) {
            $out['target_ip'] = $target_ip;
        }
        if ( null !== $target_host ) {
            $out['target_host'] = $target_host;
        }
        return $out;
    }

    private static function is_valid_ip_text( string $candidate ): bool {
        return (bool) filter_var( $candidate, FILTER_VALIDATE_IP );
    }

    /**
     * Map a parsed hop's IP to its visibility status:
     *   - 'public'     — globally routable
     *   - 'private'    — RFC1918 / loopback / link-local / reserved
     *   - 'unanswered' — IP is null
     */
    private static function classify_ip_status( ?string $ip ): string {
        if ( null === $ip || '' === $ip ) {
            return 'unanswered';
        }
        return self::is_public_ip_simple( $ip ) ? 'public' : 'private';
    }

    /**
     * Geolocate a list of parsed hops. Public hops are looked up via
     * IpFallback; private / unanswered hops keep their order but get
     * null coordinates. The order is preserved.
     *
     * @param array<int,array{index:int,ip:?string,hostname:?string,rtt_ms:?float,status:string}> $hops
     * @return array<int,array<string,mixed>>
     */
    private static function geolocate_hop_list( array $hops ): array {
        $out = array();
        foreach ( $hops as $h ) {
            $ip     = $h['ip'] ?? null;
            $status = $h['status'] ?? 'unanswered';
            if ( 'public' === $status && null !== $ip ) {
                $intel     = IpFallback::lookup( $ip );
                $record    = self::geo_record_from_intel( $ip, (string) ( $h['hostname'] ?? '' ), $intel );
                $record['index']    = (int) $h['index'];
                $record['rtt_ms']   = isset( $h['rtt_ms'] ) ? (float) $h['rtt_ms'] : null;
                $record['status']   = 'public';
                $record['hostname'] = $h['hostname'] ?? $record['hostname'];
                $out[] = $record;
            } else {
                // Keep the row but with no coordinates and the right label.
                $out[] = array(
                    'index'        => (int) $h['index'],
                    'ip'           => $ip,
                    'hostname'     => $h['hostname'] ?? null,
                    'rtt_ms'       => isset( $h['rtt_ms'] ) ? (float) $h['rtt_ms'] : null,
                    'status'       => $status,
                    'lat'          => null,
                    'lon'          => null,
                    'city'         => '',
                    'country'      => '',
                    'country_code' => '',
                    'asn'          => '',
                    'isp'          => '',
                    'confidence'   => 'unknown',
                    'flag'         => '',
                );
            }
        }
        return $out;
    }

    /**
     * Convert an IpFallback intel dict into a normalised geo record the
     * frontend can consume. Handles the case where latitude / longitude /
     * city / country are missing (returns nulls / empty strings, never
     * guesses).
     *
     * @return array<string,mixed>
     */
    private static function geo_record_from_intel( string $ip, string $fallback_hostname, array $intel ): array {
        $lat          = isset( $intel['latitude'] ) && is_numeric( $intel['latitude'] ) ? (float) $intel['latitude'] : null;
        $lon          = isset( $intel['longitude'] ) && is_numeric( $intel['longitude'] ) ? (float) $intel['longitude'] : null;
        $country      = (string) ( $intel['country'] ?? $intel['country_code'] ?? '' );
        $country_code = (string) ( $intel['country_code'] ?? '' );
        // Some providers return a long country name in `country`. Try to
        // derive a 2-letter ISO code when only the name is present.
        if ( '' === $country_code && '' !== $country ) {
            $country_code = strtoupper( substr( $country, 0, 2 ) );
        }
        $city         = (string) ( $intel['city'] ?? '' );
        $asn          = (string) ( $intel['asn'] ?? '' );
        $isp          = (string) ( $intel['isp'] ?? $intel['org'] ?? '' );
        $hostname     = (string) ( $intel['reverse'] ?? $intel['hostname'] ?? $fallback_hostname );

        // Confidence heuristic: country + city + ASN → medium; country
        // only → low; nothing → unknown. We never claim "high" because IP
        // geolocation is inherently approximate — unless the hostname
        // carries an authoritative facility code (Phase 30a).
        $confidence = 'unknown';
        $overridden_by_host = false;
        if ( '' !== $country && '' !== $city && '' !== $asn ) {
            $confidence = 'medium';
        } elseif ( '' !== $country ) {
            $confidence = 'low';
        }

        // Phase 30a: hostname-driven location override.
        //
        // Some providers (Hurricane Electric / AS6939, many CDNs, etc.)
        // advertise the *same* IP from many countries via anycast. The
        // MaxMind / IP2Location registration of that IP block often
        // points at one specific country (the one where the block was
        // allocated), not the country the router physically sits in.
        //
        // When the hostname carries an authoritative IATA / facility code
        // (`be7.core3.par2.he.net` → Paris, `be4.core2.mrs1.he.net` →
        // Marseille, `lo0-0.gw1.cjj1.us.linode.com` → Newark), trust the
        // hostname over the IP-registered country. Escalate confidence
        // to `high` because the facility is named explicitly in DNS.
        $host_hint = self::parse_host_location( $hostname );
        if ( null !== $host_hint ) {
            $city         = $host_hint['city'];
            $country      = $host_hint['country_name'];
            $country_code = $host_hint['country_code'];
            $lat          = $host_hint['lat'];
            $lon          = $host_hint['lon'];
            $confidence   = 'high';
            $overridden_by_host = true;
        }

        return array(
            'ip'           => $ip,
            'hostname'     => $hostname,
            'lat'          => $lat,
            'lon'          => $lon,
            'city'         => $city,
            'country'      => $country,
            'country_code' => $country_code,
            'asn'          => $asn,
            'isp'          => $isp,
            'confidence'   => $confidence,
            'flag'         => self::country_flag( $country_code ?: $country ),
            // Phase 30a: meta flag for the frontend so it can label the
            // hop as "facility-verified" vs "ip-registered".
            'host_override' => $overridden_by_host,
        );
    }

    /**
     * Extract an authoritative {city, country} from a router hostname.
     *
     * Recognises the common IATA / facility codes used by the major
     * anycast / peering networks (Hurricane Electric, Linode, DigitalOcean,
     * Vultr, Cloudflare, AWS, GCP, OVH, Hetzner, etc.). Returns null
     * when the hostname doesn't carry a recognised code — callers then
     * fall back to whatever the IP-intel provider returned.
     *
     * @return array{city:string, country_name:string, country_code:string, lat:float, lon:float}|null
     */
    private static function parse_host_location( string $hostname ): ?array {
        if ( '' === $hostname ) {
            return null;
        }
        $host = strtolower( $hostname );

        // Hurricane Electric convention: <role>.<coreN>.<iata>N.he.net
        //   be7.core3.par2.he.net  → Paris, FR
        //   be4.core2.mrs1.he.net  → Marseille, FR
        //   core1.lhr1.he.net      → London, GB
        // The IATA code sits in the last label before `he.net`.
        if ( str_ends_with( $host, '.he.net' ) ) {
            $parts = explode( '.', $host );
            // last = he.net, second-to-last is iata + digit suffix.
            $iata_label = $parts[ count( $parts ) - 2 ] ?? '';
            $iata       = preg_replace( '/[^a-z]/', '', $iata_label );
            if ( isset( self::IATA_TO_LOCATION()[ $iata ] ) ) {
                return self::IATA_TO_LOCATION()[ $iata ];
            }
        }

        // Linode convention: lo<role>-<n>.<dc>.<region>.<country>.linode.com
        //   lo0-0.gw1.cjj1.us.linode.com → Newark, US (cjj = Chicago + jitter)
        //   liXXXX.members.linode.com    → fallback
        // Linode's three-letter codes are mostly facility IDs, not IATA;
        // we keep a curated map of the most-common ones and return null
        // otherwise (so MaxMind wins).
        if ( str_ends_with( $host, '.linode.com' ) ) {
            $country = strtolower( $parts[ count( explode( '.', $host ) ) - 2 ] ?? '' );
            // Map TLD-style country to a capital city if known — but
            // since the IP-registered city is usually already correct
            // for Linode, we mostly skip these and only override the
            // well-known ambiguous cases.
            $linode_map = self::LINODE_DC_MAP();
            foreach ( $linode_map as $marker => $loc ) {
                if ( str_contains( $host, $marker ) ) {
                    return $loc;
                }
            }
            // For non-mapped Linode hostnames, the .us / .jp / .de suffix
            // is generally accurate enough — return null and let the
            // IP-intel result stand.
            unset( $country );
        }

        // Generic: try matching any 3-letter label against the IATA
        // table. Many networks embed the IATA in a subdomain.
        if ( preg_match_all( '/(?:^|\.)([a-z]{3})(?:\d|$|-)/', $host, $matches ) ) {
            $iata_map = self::IATA_TO_LOCATION();
            foreach ( $matches[1] as $code ) {
                if ( isset( $iata_map[ $code ] ) ) {
                    return $iata_map[ $code ];
                }
            }
        }

        return null;
    }

    /**
     * IATA airport / metro code → canonical location. Used as the
     * authoritative source for anycast routers whose hostname embeds
     * the code (e.g. Hurricane Electric's `par2` / `mrs1` convention).
     *
     * Coordinates are city centroids, accurate enough for hop
     * visualisation. The map renderer never draws a polyline to a
     * coordinate more precise than this anyway.
     *
     * @return array<string,array{city:string, country_name:string, country_code:string, lat:float, lon:float}>
     */
    private static function IATA_TO_LOCATION(): array {
        return array(
            // North America
            'ewr' => array( 'city' => 'Newark',  'country_name' => 'United States', 'country_code' => 'US', 'lat' => 40.7357, 'lon' => -74.1724 ),
            'jfk' => array( 'city' => 'New York', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 40.6413, 'lon' => -73.7781 ),
            'lga' => array( 'city' => 'New York', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 40.7769, 'lon' => -73.8740 ),
            'ord' => array( 'city' => 'Chicago', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 41.9742, 'lon' => -87.9073 ),
            'sjc' => array( 'city' => 'San Jose', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 37.3382, 'lon' => -121.8863 ),
            'sfo' => array( 'city' => 'San Francisco', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 37.6213, 'lon' => -122.3790 ),
            'lax' => array( 'city' => 'Los Angeles', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 33.9416, 'lon' => -118.4085 ),
            'sea' => array( 'city' => 'Seattle', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 47.4502, 'lon' => -122.3088 ),
            'den' => array( 'city' => 'Denver',  'country_name' => 'United States', 'country_code' => 'US', 'lat' => 39.8561, 'lon' => -104.6737 ),
            'atl' => array( 'city' => 'Atlanta', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 33.6407, 'lon' => -84.4277 ),
            'mia' => array( 'city' => 'Miami',   'country_name' => 'United States', 'country_code' => 'US', 'lat' => 25.7959, 'lon' => -80.2870 ),
            'iad' => array( 'city' => 'Ashburn', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 39.0438, 'lon' => -77.4874 ),
            'dca' => array( 'city' => 'Washington', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 38.8512, 'lon' => -77.0402 ),
            'bos' => array( 'city' => 'Boston',  'country_name' => 'United States', 'country_code' => 'US', 'lat' => 42.3656, 'lon' => -71.0096 ),
            'yyz' => array( 'city' => 'Toronto', 'country_name' => 'Canada',        'country_code' => 'CA', 'lat' => 43.6777, 'lon' => -79.6248 ),
            'yul' => array( 'city' => 'Montreal','country_name' => 'Canada',        'country_code' => 'CA', 'lat' => 45.4577, 'lon' => -73.7497 ),
            'mex' => array( 'city' => 'Mexico City','country_name' => 'Mexico',     'country_code' => 'MX', 'lat' => 19.4361, 'lon' => -99.0719 ),
            // Europe
            'lhr' => array( 'city' => 'London',  'country_name' => 'United Kingdom', 'country_code' => 'GB', 'lat' => 51.4700, 'lon' => -0.4543 ),
            'lgw' => array( 'city' => 'London',  'country_name' => 'United Kingdom', 'country_code' => 'GB', 'lat' => 51.1537, 'lon' => -0.1821 ),
            'par' => array( 'city' => 'Paris',   'country_name' => 'France',         'country_code' => 'FR', 'lat' => 49.0097, 'lon' =>  2.5479 ),
            'cdg' => array( 'city' => 'Paris',   'country_name' => 'France',         'country_code' => 'FR', 'lat' => 49.0097, 'lon' =>  2.5479 ),
            'mrs' => array( 'city' => 'Marseille','country_name' => 'France',        'country_code' => 'FR', 'lat' => 43.4393, 'lon' =>  5.2214 ),
            'fra' => array( 'city' => 'Frankfurt','country_name' => 'Germany',       'country_code' => 'DE', 'lat' => 50.0379, 'lon' =>  8.5622 ),
            'ams' => array( 'city' => 'Amsterdam','country_name' => 'Netherlands',   'country_code' => 'NL', 'lat' => 52.3105, 'lon' =>  4.7683 ),
            'bru' => array( 'city' => 'Brussels','country_name' => 'Belgium',        'country_code' => 'BE', 'lat' => 50.9014, 'lon' =>  4.4844 ),
            'mad' => array( 'city' => 'Madrid',  'country_name' => 'Spain',          'country_code' => 'ES', 'lat' => 40.4936, 'lon' => -3.5668 ),
            'bcn' => array( 'city' => 'Barcelona','country_name' => 'Spain',         'country_code' => 'ES', 'lat' => 41.2974, 'lon' =>  2.0833 ),
            'mil' => array( 'city' => 'Milan',   'country_name' => 'Italy',          'country_code' => 'IT', 'lat' => 45.6306, 'lon' =>  8.7281 ),
            'rom' => array( 'city' => 'Rome',    'country_name' => 'Italy',          'country_code' => 'IT', 'lat' => 41.8003, 'lon' => 12.2389 ),
            'vie' => array( 'city' => 'Vienna',  'country_name' => 'Austria',        'country_code' => 'AT', 'lat' => 48.1103, 'lon' => 16.5697 ),
            'zur' => array( 'city' => 'Zurich',  'country_name' => 'Switzerland',    'country_code' => 'CH', 'lat' => 47.4647, 'lon' =>  8.5492 ),
            'cph' => array( 'city' => 'Copenhagen','country_name' => 'Denmark',      'country_code' => 'DK', 'lat' => 55.6181, 'lon' => 12.6561 ),
            'sto' => array( 'city' => 'Stockholm','country_name' => 'Sweden',        'country_code' => 'SE', 'lat' => 59.6519, 'lon' => 17.9186 ),
            'osl' => array( 'city' => 'Oslo',    'country_name' => 'Norway',         'country_code' => 'NO', 'lat' => 60.1976, 'lon' => 11.1004 ),
            'hel' => array( 'city' => 'Helsinki','country_name' => 'Finland',        'country_code' => 'FI', 'lat' => 60.3172, 'lon' => 24.9633 ),
            'dub' => array( 'city' => 'Dublin',  'country_name' => 'Ireland',        'country_code' => 'IE', 'lat' => 53.4264, 'lon' => -6.2499 ),
            'waw' => array( 'city' => 'Warsaw',  'country_name' => 'Poland',         'country_code' => 'PL', 'lat' => 52.1657, 'lon' => 20.9671 ),
            'prg' => array( 'city' => 'Prague',  'country_name' => 'Czechia',        'country_code' => 'CZ', 'lat' => 50.1008, 'lon' => 14.2632 ),
            'lis' => array( 'city' => 'Lisbon',  'country_name' => 'Portugal',       'country_code' => 'PT', 'lat' => 38.7813, 'lon' => -9.1359 ),
            'ath' => array( 'city' => 'Athens',  'country_name' => 'Greece',         'country_code' => 'GR', 'lat' => 37.9364, 'lon' => 23.9445 ),
            // Asia / Pacific
            'nrt' => array( 'city' => 'Tokyo',   'country_name' => 'Japan',          'country_code' => 'JP', 'lat' => 35.7720, 'lon' => 140.3929 ),
            'kix' => array( 'city' => 'Osaka',   'country_name' => 'Japan',          'country_code' => 'JP', 'lat' => 34.4348, 'lon' => 135.2440 ),
            'icn' => array( 'city' => 'Seoul',   'country_name' => 'South Korea',    'country_code' => 'KR', 'lat' => 37.4602, 'lon' => 126.4407 ),
            'hkg' => array( 'city' => 'Hong Kong','country_name' => 'Hong Kong',     'country_code' => 'HK', 'lat' => 22.3080, 'lon' => 113.9185 ),
            'sin' => array( 'city' => 'Singapore','country_name' => 'Singapore',     'country_code' => 'SG', 'lat' => 1.3644,  'lon' => 103.9915 ),
            'syd' => array( 'city' => 'Sydney',  'country_name' => 'Australia',      'country_code' => 'AU', 'lat' => -33.9399, 'lon' => 151.1753 ),
            'mel' => array( 'city' => 'Melbourne','country_name' => 'Australia',     'country_code' => 'AU', 'lat' => -37.6733, 'lon' => 144.8430 ),
            'bom' => array( 'city' => 'Mumbai',  'country_name' => 'India',          'country_code' => 'IN', 'lat' => 19.0896, 'lon' => 72.8656 ),
            'del' => array( 'city' => 'Delhi',   'country_name' => 'India',          'country_code' => 'IN', 'lat' => 28.5562, 'lon' => 77.1000 ),
            'blr' => array( 'city' => 'Bangalore','country_name' => 'India',         'country_code' => 'IN', 'lat' => 13.1986, 'lon' => 77.7066 ),
            'pek' => array( 'city' => 'Beijing', 'country_name' => 'China',          'country_code' => 'CN', 'lat' => 40.0799, 'lon' => 116.6031 ),
            'pvg' => array( 'city' => 'Shanghai','country_name' => 'China',          'country_code' => 'CN', 'lat' => 31.1443, 'lon' => 121.8083 ),
            'tpe' => array( 'city' => 'Taipei',  'country_name' => 'Taiwan',         'country_code' => 'TW', 'lat' => 25.0797, 'lon' => 121.2342 ),
            'bkk' => array( 'city' => 'Bangkok', 'country_name' => 'Thailand',       'country_code' => 'TH', 'lat' => 13.6900, 'lon' => 100.7501 ),
            'kul' => array( 'city' => 'Kuala Lumpur','country_name' => 'Malaysia',   'country_code' => 'MY', 'lat' => 2.7456,  'lon' => 101.7099 ),
            'cgk' => array( 'city' => 'Jakarta', 'country_name' => 'Indonesia',      'country_code' => 'ID', 'lat' => -6.1256, 'lon' => 106.6559 ),
            'man' => array( 'city' => 'Manila',  'country_name' => 'Philippines',    'country_code' => 'PH', 'lat' => 14.5086, 'lon' => 121.0194 ),
            'dxb' => array( 'city' => 'Dubai',   'country_name' => 'United Arab Emirates','country_code' => 'AE', 'lat' => 25.2532, 'lon' => 55.3657 ),
            'tlv' => array( 'city' => 'Tel Aviv','country_name' => 'Israel',         'country_code' => 'IL', 'lat' => 32.0114, 'lon' => 34.8867 ),
            'ist' => array( 'city' => 'Istanbul','country_name' => 'Turkey',         'country_code' => 'TR', 'lat' => 41.2606, 'lon' => 28.7406 ),
            // South America / Africa / Oceania
            'gru' => array( 'city' => 'Sao Paulo','country_name' => 'Brazil',        'country_code' => 'BR', 'lat' => -23.4356, 'lon' => -46.4731 ),
            'eze' => array( 'city' => 'Buenos Aires','country_name' => 'Argentina',  'country_code' => 'AR', 'lat' => -34.8222, 'lon' => -58.5358 ),
            'scl' => array( 'city' => 'Santiago', 'country_name' => 'Chile',         'country_code' => 'CL', 'lat' => -33.3930, 'lon' => -70.7858 ),
            'lim' => array( 'city' => 'Lima',    'country_name' => 'Peru',           'country_code' => 'PE', 'lat' => -12.0219, 'lon' => -77.1143 ),
            'bog' => array( 'city' => 'Bogota',  'country_name' => 'Colombia',       'country_code' => 'CO', 'lat' => 4.7016,  'lon' => -74.1469 ),
            'jnb' => array( 'city' => 'Johannesburg','country_name' => 'South Africa','country_code' => 'ZA', 'lat' => -26.1392, 'lon' => 28.2460 ),
            'cpt' => array( 'city' => 'Cape Town','country_name' => 'South Africa',  'country_code' => 'ZA', 'lat' => -33.9648, 'lon' => 18.6017 ),
            'cai' => array( 'city' => 'Cairo',   'country_name' => 'Egypt',          'country_code' => 'EG', 'lat' => 30.1219, 'lon' => 31.4056 ),
            'los' => array( 'city' => 'Lagos',   'country_name' => 'Nigeria',        'country_code' => 'NG', 'lat' =>  6.5774, 'lon' =>  3.3211 ),
            'nbo' => array( 'city' => 'Nairobi', 'country_name' => 'Kenya',          'country_code' => 'KE', 'lat' => -1.3192, 'lon' => 36.9277 ),
            'akl' => array( 'city' => 'Auckland','country_name' => 'New Zealand',    'country_code' => 'NZ', 'lat' => -37.0082, 'lon' => 174.7850 ),
        );
    }

    /**
     * Linode's three-letter datacenter codes → canonical location.
     * Only includes the codes that conflict with their IP-registered
     * country (most are accurate and don't need overriding).
     *
     * @return array<string,array{city:string, country_name:string, country_code:string, lat:float, lon:float}>
     */
    private static function LINODE_DC_MAP(): array {
        return array(
            // 'cjj' → Newark, NJ (not Chicago; Linode's "cjj" stands for
            // "Chicago jitter" but the actual egress is Newark).
            'cjj' => array( 'city' => 'Newark', 'country_name' => 'United States', 'country_code' => 'US', 'lat' => 40.7357, 'lon' => -74.1724 ),
            // Add more curated overrides here if the user reports other
            // Linode mismatches.
        );
    }

    /**
     * Strip the port suffix and any whitespace the visitor may have included.
     */
    private static function normalize_target( string $raw ): string {
        $raw = trim( $raw );
        $raw = preg_replace( '#^https?://#i', '', $raw );
        $raw = preg_replace( '#/.*$#', '', $raw );
        return trim( $raw );
    }

    /**
     * Great-circle distance in km (haversine).
     */
    private static function haversine_km( float $lat1, float $lng1, float $lat2, float $lng2 ): float {
        $R = 6371.0;
        $toRad = static function ( float $d ): float {
            return $d * M_PI / 180.0;
        };
        $dLat = $toRad( $lat2 - $lat1 );
        $dLng = $toRad( $lng2 - $lng1 );
        $a = sin( $dLat / 2 ) * sin( $dLat / 2 ) +
             cos( $toRad( $lat1 ) ) * cos( $toRad( $lat2 ) ) *
             sin( $dLng / 2 ) * sin( $dLng / 2 );
        return $R * 2 * atan2( sqrt( $a ), sqrt( 1 - $a ) );
    }

    /**
     * Convert an ISO 3166-1 alpha-2 country code into its regional-indicator
     * Unicode flag emoji. Unknown / empty codes yield an empty string so
     * callers can safely concatenate.
     */
    public static function country_flag( string $cc ): string {
        $cc = strtoupper( trim( $cc ) );
        if ( '' === $cc || strlen( $cc ) !== 2 ) {
            return '';
        }
        $a = ord( $cc[0] ) - 0x41;
        $b = ord( $cc[1] ) - 0x41;
        if ( $a < 0 || $a > 25 || $b < 0 || $b > 25 ) {
            return '';
        }
        // Regional indicator symbols are U+1F1E6..U+1F1FF.
        return mb_chr( 0x1F1E6 + $a, 'UTF-8' ) . mb_chr( 0x1F1E6 + $b, 'UTF-8' );
    }

    /**
     * GET /settings (admin)
     */
    public function get_settings( WP_REST_Request $request ) {
        $settings = get_option( Settings::OPTION_KEY, array() );
        // Never return secrets over the wire.
        unset(
            $settings['secret_salt'],
            $settings['ip_api_key'],
            $settings['reputation_api_key'],
            $settings['whois_api_key'],
            $settings['maxmind_license_key']
        );
        return rest_ensure_response( $settings );
    }

    /**
     * POST /settings (admin)
     */
    public function update_settings( WP_REST_Request $request ) {
        $input  = (array) $request->get_json_params();
        $sanitized = Settings::sanitize( $input );
        update_option( Settings::OPTION_KEY, $sanitized );
        return rest_ensure_response( array( 'updated' => true ) );
    }

    /**
     * Decode the client signal blob attached to scan requests.
     */
    private function collect_client_signals( WP_REST_Request $request ): array {
        $json = $request->get_json_params();
        if ( ! is_array( $json ) ) {
            return array();
        }
        $allowed_top = array( 'user_agent', 'screen', 'color_depth', 'pixel_ratio', 'timezone', 'language', 'languages', 'platform', 'hardware_concurrency', 'device_memory', 'touch_support', 'cookies', 'do_not_track', 'webgl', 'canvas', 'audio', 'fonts', 'webrtc', 'dns_test_result', 'canvas_hash', 'audio_hash', 'webgl_renderer', 'webgl_vendor', 'font_list', 'connection_quality' );
        $out = array();
        foreach ( $allowed_top as $key ) {
            if ( isset( $json[ $key ] ) ) {
                $out[ $key ] = $this->sanitize_signal( $key, $json[ $key ] );
            }
        }
        return $out;
    }

    /**
     * Best-effort sanitization of a single client signal.
     */
    private function sanitize_signal( string $key, $value ) {
        if ( is_bool( $value ) || is_numeric( $value ) ) {
            return $value;
        }
        if ( is_array( $value ) ) {
            $clean = array();
            foreach ( $value as $k => $v ) {
                $clean[ sanitize_key( (string) $k ) ] = is_scalar( $v ) ? sanitize_text_field( (string) $v ) : null;
            }
            return $clean;
        }
        if ( 'webrtc' === $key ) {
            if ( ! is_array( $value ) ) {
                return array();
            }
            $clean = array();
            $clean['supported'] = ! empty( $value['supported'] );
            $candidates = isset( $value['candidates'] ) && is_array( $value['candidates'] ) ? $value['candidates'] : array();
            $cleaned_candidates = array();
            foreach ( $candidates as $cand ) {
                if ( ! is_array( $cand ) ) {
                    continue;
                }
                $ip   = isset( $cand['ip'] )   ? sanitize_text_field( (string) $cand['ip'] ) : '';
                $type = isset( $cand['type'] ) ? sanitize_text_field( (string) $cand['type'] ) : '';
                if ( '' === $ip || '' === $type ) {
                    continue;
                }
                $cleaned_candidates[] = array( 'ip' => $ip, 'type' => $type );
            }
            $clean['candidates'] = $cleaned_candidates;
            return $clean;
        }
        return sanitize_text_field( (string) $value );
    }
}