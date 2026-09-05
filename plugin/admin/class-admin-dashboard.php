<?php
/**
 * Admin dashboard — system status, charts, recent events, tools.
 *
 * Renders the "Privacy Checker → Dashboard" submenu page. The Settings page
 * remains the primary configuration surface; the Dashboard is an at-a-glance
 * monitoring view.
 *
 * @package PrivacyChecker\Admin
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\AdminCharts;
use PrivacyChecker\EventLog;
use PrivacyChecker\IpFallback;
use PrivacyChecker\MaxmindManager;
use PrivacyChecker\Plugin;
use PrivacyChecker\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminDashboard {

	public const MENU_SLUG = 'privacy-checker';
	public const DASHBOARD_SLUG = 'privacy-checker';
	public const SETTINGS_SLUG = 'privacy-checker-settings';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );

		// Admin-post handlers for inline actions (reorder chain, maxmind download, log clear, flush cache).
		add_action( 'admin_post_pc_reorder_chain', array( $this, 'handle_reorder_chain' ) );
		add_action( 'admin_post_pc_maxmind_download', array( $this, 'handle_maxmind_download' ) );
		add_action( 'admin_post_pc_log_clear', array( $this, 'handle_log_clear' ) );
		add_action( 'admin_post_pc_flush_all_cache', array( $this, 'handle_flush_all_cache' ) );
	}

	public function register_menu(): void {
		// Top-level menu.
		add_menu_page(
			__( 'IMON', 'privacy-checker' ),
			__( 'IMON', 'privacy-checker' ),
			'manage_options',
			self::DASHBOARD_SLUG,
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			81
		);

		// First submenu (Dashboard) reuses the same slug as the parent so it
		// is the default landing page.
		add_submenu_page(
			self::DASHBOARD_SLUG,
			__( 'Dashboard', 'privacy-checker' ),
			__( 'Dashboard', 'privacy-checker' ),
			'manage_options',
			self::DASHBOARD_SLUG,
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			self::DASHBOARD_SLUG,
			__( 'Settings', 'privacy-checker' ),
			__( 'Settings', 'privacy-checker' ),
			'manage_options',
			self::SETTINGS_SLUG,
			array( Admin::class, 'render_page' )
		);
	}

	public function enqueue( string $hook ): void {
		// Only on our screens.
		if ( false === strpos( $hook, self::DASHBOARD_SLUG ) && false === strpos( $hook, self::SETTINGS_SLUG ) ) {
			return;
		}
		wp_enqueue_style(
			'pc-admin-dashboard',
			PRIVACY_CHECKER_URL . 'admin/assets/admin-dashboard.css',
			array(),
			PRIVACY_CHECKER_VERSION
		);
	}

	/* ---------- Handlers ---------- */

	public function handle_reorder_chain(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_reorder_chain' );
		$order = isset( $_POST['order'] ) && is_array( $_POST['order'] )
			? array_map( 'sanitize_key', wp_unslash( (array) $_POST['order'] ) )
			: array();
		$clean = array();
		foreach ( $order as $k ) {
			if ( in_array( $k, Settings::allowed_chain_keys(), true ) && ! in_array( $k, $clean, true ) ) {
				$clean[] = $k;
			}
		}
		if ( empty( $clean ) ) {
			$clean = IpFallback::default_chain();
		}
		Plugin::instance()->update_setting( 'provider_chain_ip', $clean );
		wp_safe_redirect( add_query_arg( array( 'page' => self::DASHBOARD_SLUG, 'pc_msg' => 'chain_saved' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function handle_maxmind_download(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_maxmind_download' );
		$result = MaxmindManager::download_now();
		$status = $result['ok'] ? 'mm_ok' : 'mm_err';
		wp_safe_redirect( add_query_arg(
			array(
				'page' => self::DASHBOARD_SLUG,
				'pc_msg' => $status,
				'pc_mm'  => $result['downloaded'],
			),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	public function handle_log_clear(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_log_clear' );
		EventLog::clear();
		wp_safe_redirect( add_query_arg( array( 'page' => self::DASHBOARD_SLUG, 'pc_msg' => 'log_cleared' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function handle_flush_all_cache(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_flush_all_cache' );
		global $wpdb;
		$wpdb->query(
			"DELETE FROM {$wpdb->options}
			 WHERE option_name LIKE '_transient_pc\\_%'
			    OR option_name LIKE '_transient_timeout_pc\\_%'"
		);
		wp_safe_redirect( add_query_arg( array( 'page' => self::DASHBOARD_SLUG, 'pc_msg' => 'cache_flushed' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	/* ---------- Render ---------- */

	public function render_dashboard(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
		}
		require_once PRIVACY_CHECKER_DIR . 'admin/views/dashboard.php';
	}
}