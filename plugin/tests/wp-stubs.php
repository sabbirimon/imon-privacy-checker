<?php
/**
 * WordPress function stubs for the unit test suite.
 *
 * Each stub is the minimum implementation needed by the plugin classes we
 * exercise. A static `WpState` bag lets tests seed and inspect mocked calls
 * (options, transients, current-user-can, etc.).
 *
 * @package PrivacyChecker\Tests
 */

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
    define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
    define( 'MINUTE_IN_SECONDS', 60 );
}
if ( ! defined( 'PRIVACY_CHECKER_DIR' ) ) {
    define( 'PRIVACY_CHECKER_DIR', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'PRIVACY_CHECKER_URL' ) ) {
    define( 'PRIVACY_CHECKER_URL', 'https://example.test/wp-content/plugins/privacy-checker/' );
}
if ( ! defined( 'PRIVACY_CHECKER_VERSION' ) ) {
    define( 'PRIVACY_CHECKER_VERSION', '1.0.0' );
}
if ( ! defined( 'PRIVACY_CHECKER_REST_NS' ) ) {
    define( 'PRIVACY_CHECKER_REST_NS', 'privacy-checker/v1' );
}

if ( ! class_exists( 'WpState', false ) ) {
final class WpState {
    /** @var array<string,mixed> */
    public static array $options = array();

    /** @var array<string,mixed> */
    public static array $transients = array();

    /** @var array<int,array{name:string,args:array}> */
    public static array $actions = array();

    /** @var array<int,array{filter:string,value:mixed,extra:mixed}> */
    public static array $filters = array();

    /** @var array<int,array{type:string,message:string}> */
    public static array $errors = array();

    /** @var array<string,bool> */
    public static array $caps = array();

    public static function reset(): void {
        self::$options    = array();
        self::$transients = array();
        self::$actions    = array();
        self::$filters    = array();
        self::$errors     = array();
        self::$caps       = array();
        if ( isset( $GLOBALS['wpdb'] ) && isset( $GLOBALS['wpdb']->tables ) ) {
            $GLOBALS['wpdb']->tables = array();
            $GLOBALS['wpdb']->insert_id = 0;
        }
    }
}
}

if ( ! function_exists( 'get_option' ) ) {
    function get_option( string $key, $default = false ) {
        return array_key_exists( $key, WpState::$options ) ? WpState::$options[ $key ] : $default;
    }
}
if ( ! function_exists( 'update_option' ) ) {
    function update_option( string $key, $value, $autoload = null ): bool {
        WpState::$options[ $key ] = $value;
        return true;
    }
}
if ( ! function_exists( 'add_option' ) ) {
    function add_option( string $key, $value, $deprecated = '', $autoload = 'yes' ): bool {
        if ( array_key_exists( $key, WpState::$options ) ) {
            return false;
        }
        WpState::$options[ $key ] = $value;
        return true;
    }
}
if ( ! function_exists( 'delete_option' ) ) {
    function delete_option( string $key ): bool {
        unset( WpState::$options[ $key ] );
        return true;
    }
}

if ( ! function_exists( 'get_transient' ) ) {
    function get_transient( string $key ) {
        return WpState::$transients[ $key ] ?? null;
    }
}
if ( ! function_exists( 'set_transient' ) ) {
    function set_transient( string $key, $value, int $expiration = 0 ): bool {
        WpState::$transients[ $key ] = $value;
        return true;
    }
}
if ( ! function_exists( 'delete_transient' ) ) {
    function delete_transient( string $key ): bool {
        unset( WpState::$transients[ $key ] );
        return true;
    }
}

if ( ! function_exists( 'add_action' ) ) {
    function add_action( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
        WpState::$actions[] = array(
            'name' => $hook,
            'args' => array( $callback, $priority, $accepted_args ),
        );
        return true;
    }
}
if ( ! function_exists( 'add_filter' ) ) {
    function add_filter( string $hook, callable $callback, int $priority = 10, int $accepted_args = 1 ): bool {
        WpState::$filters[] = array(
            'filter' => $hook,
            'value'  => $callback,
            'extra'  => $priority,
        );
        return true;
    }
}
if ( ! function_exists( 'apply_filters' ) ) {
    function apply_filters( string $hook, $value, ...$args ) {
        foreach ( WpState::$filters as $f ) {
            if ( $f['filter'] === $hook && is_callable( $f['value'] ) ) {
                $value = call_user_func( $f['value'], $value, ...$args );
            }
        }
        return $value;
    }
}

if ( ! function_exists( 'current_user_can' ) ) {
    function current_user_can( string $cap, ...$args ): bool {
        return ! empty( WpState::$caps[ $cap ] );
    }
}
if ( ! function_exists( 'wp_get_current_user' ) ) {
    function wp_get_current_user(): object {
        return (object) array( 'ID' => 1, 'user_login' => 'admin' );
    }
}
if ( ! function_exists( 'wp_generate_password' ) ) {
    function wp_generate_password( int $length = 12, bool $special = true ): string {
        return substr( str_replace( array( '/', '+', '=' ), '', base64_encode( random_bytes( max( $length, 16 ) ) ) ), 0, $length );
    }
}
if ( ! function_exists( 'sanitize_text_field' ) ) {
    function sanitize_text_field( string $str ): string {
        return trim( strip_tags( $str ) );
    }
}
if ( ! function_exists( 'sanitize_key' ) ) {
    function sanitize_key( string $str ): string {
        return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $str ) );
    }
}
if ( ! function_exists( 'esc_url_raw' ) ) {
    function esc_url_raw( string $url ): string {
        return filter_var( trim( $url ), FILTER_SANITIZE_URL ) ?: '';
    }
}
if ( ! function_exists( 'wp_json_encode' ) ) {
    function wp_json_encode( $data, int $flags = 0, int $depth = 512 ): string|false {
        return json_encode( $data, $flags, $depth );
    }
}
if ( ! function_exists( 'wp_send_json' ) ) {
    function wp_send_json( $data, int $status = 200 ): void {
        WpState::$actions[] = array( 'name' => 'wp_send_json', 'args' => array( $data, $status ) );
    }
}
if ( ! function_exists( 'rest_ensure_response' ) ) {
    function rest_ensure_response( $data ) {
        return is_array( $data ) ? $data : array( 'value' => $data );
    }
}
if ( ! function_exists( 'wp_safe_redirect' ) ) {
    function wp_safe_redirect( string $url, int $status = 302, string $x_redirect_by = 'wp_safe_redirect' ): bool {
        WpState::$actions[] = array( 'name' => 'wp_safe_redirect', 'args' => array( $url, $status ) );
        return true;
    }
}
if ( ! function_exists( 'admin_url' ) ) {
    function admin_url( string $path = '', string $scheme = 'admin' ): string {
        return 'https://example.test/wp-admin/' . ltrim( $path, '/' );
    }
}
if ( ! function_exists( 'home_url' ) ) {
    function home_url( string $path = '' ): string {
        return 'https://example.test' . $path;
    }
}
if ( ! function_exists( 'wp_parse_url' ) ) {
    function wp_parse_url( string $url, int $component = -1 ) {
        return parse_url( $url, $component );
    }
}
if ( ! function_exists( 'wp_remote_get' ) ) {
    function wp_remote_get( string $url, array $args = array() ) {
        return new \WP_Error( 'no_http', 'wp_remote_get is stubbed.' );
    }
}
if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
    function wp_remote_retrieve_response_code( $response ): int {
        return 0;
    }
}
if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
    function wp_remote_retrieve_body( $response ): string {
        return '';
    }
}
if ( ! function_exists( 'wp_tempnam' ) ) {
    function wp_tempnam( string $prefix = '' ): string|false {
        $f = tempnam( sys_get_temp_dir(), $prefix );
        return $f ?: false;
    }
}
if ( ! function_exists( 'is_wp_error' ) ) {
    function is_wp_error( $thing ): bool {
        return $thing instanceof \WP_Error;
    }
}
if ( ! function_exists( 'rest_url' ) ) {
    function rest_url( string $path = '' ): string {
        return 'https://example.test/wp-json/' . ltrim( $path, '/' );
    }
}
if ( ! function_exists( 'wp_die' ) ) {
    function wp_die( $message = '', $title = '', array $args = array() ): void {
        throw new \RuntimeException( 'wp_die: ' . ( is_string( $message ) ? $message : wp_json_encode( $message ) ) );
    }
}
if ( ! function_exists( '__' ) ) {
    function __( string $text, string $domain = 'default' ): string {
        return $text;
    }
}
if ( ! function_exists( 'esc_html__' ) ) {
    function esc_html__( string $text, string $domain = 'default' ): string {
        return $text;
    }
}
if ( ! function_exists( 'esc_attr__' ) ) {
    function esc_attr__( string $text, string $domain = 'default' ): string {
        return $text;
    }
}
if ( ! function_exists( 'esc_html' ) ) {
    function esc_html( string $text ): string {
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
}
if ( ! function_exists( 'esc_attr' ) ) {
    function esc_attr( string $text ): string {
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
}
if ( ! function_exists( 'esc_html_e' ) ) {
    function esc_html_e( string $text, string $domain = 'default' ): void {
        echo htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
}
if ( ! function_exists( 'esc_textarea' ) ) {
    function esc_textarea( string $text ): string {
        return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
    }
}
if ( ! function_exists( 'wp_kses' ) ) {
    function wp_kses( string $string, array $allowed_html ): string {
        // Stub: drop all tags not in allowed list. Good enough for unit tests.
        return strip_tags( $string );
    }
}
if ( ! function_exists( 'wp_kses_post' ) ) {
    function wp_kses_post( $data ): string {
        return is_string( $data ) ? strip_tags( $data ) : '';
    }
}
if ( ! function_exists( 'checked' ) ) {
    function checked( $checked, $current = true, bool $display = true ): string {
        $result = (string) $checked === (string) $current ? ' checked="checked"' : '';
        if ( $display ) {
            return $result;
        }
        return $result;
    }
}
if ( ! function_exists( 'selected' ) ) {
    function selected( $selected, $current = true, bool $display = true ): string {
        $result = (string) $selected === (string) $current ? ' selected="selected"' : '';
        if ( $display ) {
            return $result;
        }
        return $result;
    }
}
if ( ! function_exists( 'wp_nonce_field' ) ) {
    function wp_nonce_field( string $action, string $name = '_wpnonce', bool $referer = true, bool $display = true ): string {
        return '<input type="hidden" name="' . esc_attr( $name ) . '" value="stub_nonce" />';
    }
}
if ( ! function_exists( 'check_admin_referer' ) ) {
    function check_admin_referer( string $action, string $query_arg = '_wpnonce' ): int|false {
        return 1;
    }
}
if ( ! function_exists( 'add_query_arg' ) ) {
    function add_query_arg( $key, $value = null, string $url = '' ): string {
        if ( is_array( $key ) ) {
            $params = $key;
        } else {
            $params = array( $key => $value );
        }
        $sep = strpos( $url, '?' ) === false ? '?' : '&';
        $pairs = array();
        foreach ( $params as $k => $v ) {
            $pairs[] = rawurlencode( (string) $k ) . '=' . rawurlencode( (string) $v );
        }
        return $url . $sep . implode( '&', $pairs );
    }
}
if ( ! function_exists( 'register_setting' ) ) {
    function register_setting( string $group, string $name, array $args = array() ): void {}
}
if ( ! function_exists( 'add_settings_section' ) ) {
    function add_settings_section( string $id, string $title, callable $callback, string $page ): void {}
}
if ( ! function_exists( 'add_settings_field' ) ) {
    function add_settings_field( string $id, string $title, callable $callback, string $page, string $section = 'default', array $args = array() ): void {}
}
if ( ! function_exists( 'add_menu_page' ) ) {
    function add_menu_page( $page_title, $menu_title, $capability, $menu_slug, $callback = '', $icon_url = '', $position = null ): string {
        return $menu_slug;
    }
}
if ( ! function_exists( 'add_submenu_page' ) ) {
    function add_submenu_page( $parent_slug, $page_title, $menu_title, $capability, $menu_slug, $callback = '' ): string|false {
        return $menu_slug;
    }
}
if ( ! function_exists( 'register_rest_route' ) ) {
    function register_rest_route( string $namespace, string $route, array $args, bool $override = false ): bool {
        return true;
    }
}
if ( ! function_exists( 'wp_enqueue_style' ) ) {
    function wp_enqueue_style( string $handle, string $src, array $deps = array(), $ver = false, string $media = 'all' ): void {}
}
if ( ! function_exists( 'wp_enqueue_script' ) ) {
    function wp_enqueue_script( string $handle, string $src, array $deps = array(), $ver = false, bool $in_footer = false ): void {}
}
if ( ! function_exists( 'wp_localize_script' ) ) {
    function wp_localize_script( string $handle, string $object_name, array $data ): bool {
        return true;
    }
}
if ( ! function_exists( 'size_format' ) ) {
    function size_format( int $bytes, int $decimals = 0 ): string {
        $units = array( 'B', 'KB', 'MB', 'GB', 'TB' );
        $bytes = max( $bytes, 0 );
        $pow   = floor( ( $bytes ? log( $bytes ) : 0 ) / log( 1024 ) );
        $pow   = min( $pow, count( $units ) - 1 );
        $bytes /= pow( 1024, $pow );
        return round( $bytes, $decimals ) . ' ' . $units[ $pow ];
    }
}
if ( ! function_exists( 'gmdate' ) ) {
    function gmdate( string $format, ?int $timestamp = null ): string {
        return \gmdate( $format, $timestamp );
    }
}
if ( ! function_exists( 'wp_upload_dir' ) ) {
    function wp_upload_dir(): array {
        return array(
            'basedir' => sys_get_temp_dir() . '/pc-uploads',
            'baseurl' => 'https://example.test/wp-content/uploads',
            'path'    => sys_get_temp_dir() . '/pc-uploads',
            'url'     => 'https://example.test/wp-content/uploads',
            'error'   => false,
        );
    }
}
if ( ! function_exists( 'wp_mkdir_p' ) ) {
    function wp_mkdir_p( string $target ): bool {
        if ( is_dir( $target ) ) {
            return true;
        }
        return mkdir( $target, 0755, true );
    }
}
if ( ! function_exists( 'wp_schedule_event' ) ) {
    function wp_schedule_event( int $timestamp, string $recurrence, string $hook, array $args = array() ): bool {
        WpState::$actions[] = array( 'name' => 'wp_schedule_event:' . $hook, 'args' => array( $timestamp, $recurrence ) );
        return true;
    }
}
if ( ! function_exists( 'wp_next_scheduled' ) ) {
    function wp_next_scheduled( string $hook, array $args = array() ): int|false {
        return false;
    }
}
if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
    function wp_clear_scheduled_hook( string $hook, array $args = array() ): int|false {
        return 0;
    }
}
if ( ! function_exists( 'register_activation_hook' ) ) {
    function register_activation_hook( string $file, callable $callback ): void {}
}
if ( ! function_exists( 'register_deactivation_hook' ) ) {
    function register_deactivation_hook( string $file, callable $callback ): void {}
}
if ( ! function_exists( 'plugin_dir_path' ) ) {
    function plugin_dir_path( string $file ): string {
        return dirname( $file ) . '/';
    }
}
if ( ! function_exists( 'plugin_dir_url' ) ) {
    function plugin_dir_url( string $file ): string {
        return 'https://example.test/wp-content/plugins/privacy-checker/';
    }
}
if ( ! function_exists( 'load_plugin_textdomain' ) ) {
    function load_plugin_textdomain( string $domain, string $deprecated = '', string $plugin_rel_path = '' ): bool {
        return true;
    }
}
if ( ! function_exists( 'is_admin' ) ) {
    function is_admin(): bool {
        return false;
    }
}
if ( ! function_exists( 'wp_send_json_error' ) ) {
    function wp_send_json_error( $data = null, int $status = 200 ): void {
        WpState::$errors[] = array( 'type' => 'json_error', 'message' => (string) wp_json_encode( $data ) );
    }
}
if ( ! function_exists( 'wp_send_json_success' ) ) {
    function wp_send_json_success( $data = null, int $status = 200 ): void {
        WpState::$actions[] = array( 'name' => 'wp_send_json_success', 'args' => array( $data, $status ) );
    }
}

// WP_REST_Server constants the REST class references.
if ( ! defined( 'WP_REST_Server::READABLE' ) ) {
    class WP_REST_Server {
        const READABLE   = 'GET';
        const CREATABLE  = 'POST';
        const EDITABLE   = 'POST, PUT, PATCH';
        const DELETABLE  = 'DELETE';
    }
}

/**
 * Minimal $wpdb stub for unit tests. Tracks all queries for inspection
 * and provides just enough methods that our plugin classes don't crash.
 */
if ( ! class_exists( 'WP_REST_Request', false ) ) {
final class WP_REST_Request {
    public string $method;
    public string $route;
    /** @var array<string,mixed> */
    public array $params;
    /** @var array<string,mixed> */
    public array $body;
    /** @var array<string,string> */
    public array $headers = array();
    public function __construct( string $method = 'GET', string $route = '', array $params = array() ) {
        $this->method = $method;
        $this->route  = $route;
        $this->params = $params;
        $this->body   = array();
    }
    public function get_param( string $key ) {
        return $this->params[ $key ] ?? null;
    }
    public function get_json_params(): array {
        return $this->body;
    }
    public function get_header( string $key ): string {
        $needle = strtolower( $key );
        foreach ( $this->headers as $name => $value ) {
            if ( strtolower( $name ) === $needle ) {
                return $value;
            }
        }
        return '';
    }
    public function set_header( string $key, string $value ): void {
        $this->headers[ $key ] = $value;
    }
    public function get_route(): string {
        return $this->route;
    }
}
}
if ( ! class_exists( 'wpdb_stub', false ) ) {
final class wpdb_stub {
    public string $prefix = 'wp_';
    public string $options = 'wp_options';
    public int $insert_id = 0;
    /** @var array<int,string> */
    public array $queries = array();
    /** @var array<int,array<string,mixed>> */
    public array $rows = array();
    /**
     * Per-table in-memory store so tests can exercise real CRUD semantics.
     * Tables registered via register_table() surface here keyed by table name.
     * @var array<string, array<int, array<string, mixed>>>
     */
    public array $tables = array();

    public function register_table( string $name ): void {
        if ( ! isset( $this->tables[ $name ] ) ) {
            $this->tables[ $name ] = array();
        }
    }
    public function query( string $sql ): int|false {
        $this->queries[] = $sql;
        return 1;
    }
    public function prepare( string $sql, ...$args ): string {
        // Tiny sprintf-style stub; real wpdb uses %s/%d placeholders.
        return vsprintf( str_replace( array( '%s', '%d', '%f' ), array( "'%s'", '%d', '%f' ), $sql ), $args );
    }
    public function get_var( string $sql, int $x = 0, int $y = 0 ): ?string {
        $this->queries[] = $sql;
        return null;
    }
    public function get_charset_collate(): string {
        return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci';
    }
    public function get_results( string $sql, string $output = 'OBJECT' ): array {
        $this->queries[] = $sql;
        return array();
    }
    public function get_row( string $sql, string $output = 'ARRAY_A', int $y = 0 ): ?array {
        $this->queries[] = $sql;
        // Crude: try to identify the table from the SQL, then return first row
        // where the column referenced in WHERE matches.
        $table = null;
        if ( preg_match( '/\bFROM\s+([a-zA-Z0-9_]+)/', $sql, $m ) ) {
            $table = $m[1];
        }
        if ( null === $table || empty( $this->tables[ $table ] ) ) {
            return null;
        }
        // Hash-lookup.
        if ( preg_match( "/\\btoken_hash\\s*=\\s*'([^']+)'/", $sql, $hm ) ) {
            foreach ( $this->tables[ $table ] as $row ) {
                if ( isset( $row['token_hash'] ) && $row['token_hash'] === $hm[1] ) {
                    return $row;
                }
            }
        }
        if ( preg_match( '/\bid\s*=\s*(\d+)/', $sql, $idm ) ) {
            $id = (int) $idm[1];
            foreach ( $this->tables[ $table ] as $row ) {
                if ( isset( $row['id'] ) && (int) $row['id'] === $id ) {
                    return $row;
                }
            }
        }
        return null;
    }
    public function insert( string $table, array $data, array $formats = array() ): int|false {
        $this->queries[] = "INSERT INTO {$table}";
        if ( ! isset( $this->tables[ $table ] ) ) {
            $this->tables[ $table ] = array();
        }
        $this->insert_id = count( $this->tables[ $table ] ) + 1;
        $data['id'] = $this->insert_id;
        $this->tables[ $table ][ $this->insert_id ] = $data;
        return 1;
    }
    public function update( string $table, array $data, array $where, array $formats = array(), array $where_formats = array() ): int|false {
        $this->queries[] = "UPDATE {$table}";
        if ( empty( $this->tables[ $table ] ) ) {
            return 0;
        }
        $updated = 0;
        foreach ( $this->tables[ $table ] as $key => $row ) {
            $match = true;
            foreach ( $where as $col => $val ) {
                if ( ! isset( $row[ $col ] ) || (string) $row[ $col ] !== (string) $val ) {
                    $match = false;
                    break;
                }
            }
            if ( $match ) {
                foreach ( $data as $col => $val ) {
                    $this->tables[ $table ][ $key ][ $col ] = $val;
                }
                $updated++;
            }
        }
        return $updated;
    }
    public function delete( string $table, array $where, array $formats = array() ): int|false {
        $this->queries[] = "DELETE FROM {$table}";
        if ( empty( $this->tables[ $table ] ) ) {
            return 0;
        }
        $deleted = 0;
        foreach ( $this->tables[ $table ] as $key => $row ) {
            $match = true;
            foreach ( $where as $col => $val ) {
                if ( ! isset( $row[ $col ] ) || (string) $row[ $col ] !== (string) $val ) {
                    $match = false;
                    break;
                }
            }
            if ( $match ) {
                unset( $this->tables[ $table ][ $key ] );
                $deleted++;
            }
        }
        return $deleted;
    }
    public function dbdelta( string $sql, bool $execute = true ): array {
        $this->queries[] = $sql;
        return array();
    }
}
}
$GLOBALS['wpdb'] = new wpdb_stub();
