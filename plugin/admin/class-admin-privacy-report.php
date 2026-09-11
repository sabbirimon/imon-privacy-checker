<?php
/**
 * Privacy Report Inspector — admin submenu page.
 *
 * Renders the PrivacyChecker\PrivacyReport::build() output against a
 * "self-scan" payload constructed server-side from the admin's own
 * request (no client signals available in admin context).
 *
 * The inspector is read-only and exists so admins can:
 *   - See exactly what visitors see, category by category.
 *   - Verify the weighted-avg arithmetic: the rendered panel shows
 *     "(sum of percent*weight) / sum_of_weight = overall" with the
 *     actual numbers, so the weighting can be sanity-checked at a
 *     glance.
 *   - Debug the provider chain when tuning — runs against the same
 *     IpFallback::lookup() the visitor flow uses, just without the
 *     browser-side signals (fingerprint / WebRTC / connection_quality
 *     / local_network).
 *
 * Per Phase 8 design note: there are NO client signals here. The
 * categories that depend on those inputs get empty / unknown defaults
 * — same fail-closed pattern used everywhere else in the plugin. A
 * banner at the top of the view makes that explicit so admins don't
 * confuse "unknown" rows with broken data.
 *
 * @package PrivacyChecker\Admin
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\Admin\AdminDashboard;
use PrivacyChecker\AnonymityScorer;
use PrivacyChecker\BrowserVersions;
use PrivacyChecker\Fingerprint;
use PrivacyChecker\IpDetector;
use PrivacyChecker\IpFallback;
use PrivacyChecker\Plugin;
use PrivacyChecker\PrivacyReport;
use PrivacyChecker\ProxyDetector;
use PrivacyChecker\Reputation;
use PrivacyChecker\TlsInfo;
use PrivacyChecker\Webrtc;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminPrivacyReport {

	public const MENU_SLUG = 'privacy-checker-privacy-report';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}

	public function register_menu(): void {
		// Position: Dashboard → Privacy Report → Settings (existing order).
		// 11 decimal places — between Dashboard and Settings — keeps the
		// new submenu in the natural reading order without forcing a
		// hard-coded index that would shift when other submenus land.
		add_submenu_page(
			AdminDashboard::DASHBOARD_SLUG,
			__( 'Privacy Report Inspector', 'privacy-checker' ),
			__( 'Privacy Report', 'privacy-checker' ),
			'manage_options',
			self::MENU_SLUG,
			array( $this, 'render' )
		);
	}

	public function enqueue( string $hook ): void {
		// Only on our specific page — avoid loading admin.css on every
		// WP admin page (this is in addition to Admin::enqueue() which
		// gates on the parent slug).
		if ( false === strpos( $hook, self::MENU_SLUG ) ) {
			return;
		}
		wp_enqueue_style(
			'pc-admin-privacy-report',
			PRIVACY_CHECKER_URL . 'admin/assets/admin.css',
			array(),
			PRIVACY_CHECKER_VERSION
		);
	}

	/**
	 * Build the self-scan payload used by the inspector.
	 *
	 * Runs everything server-side: IP detection, IP intel lookup
	 * (full IpFallback chain — same one visitors see), proxy
	 * classification, reputation, UA parse, security posture. The
	 * categories that depend on browser signals (fingerprint,
	 * WebRTC, connection_quality, local_network) get unknown/empty
	 * defaults and are tagged as such in the banner.
	 *
	 * Pure function over the current request — no caching, no I/O
	 * beyond IpFallback's own cache. Cheap enough to regenerate on
	 * every page load. If a future contributor wants caching, the
	 * seam is `Cache::remember('pc_privacy_report_selfscan', 60, ...)`.
	 *
	 * @return array<string,mixed>
	 */
	public static function build_self_scan(): array {
		$detected = IpDetector::detect();
		$ipv4     = (string) ( $detected['ipv4'] ?? '' );
		$ipv6     = (string) ( $detected['ipv6'] ?? '' );

		$connection = array(
			'ipv4'   => $ipv4,
			'ipv6'   => $ipv6,
			'source' => (string) ( $detected['source'] ?? '' ),
		);

		if ( '' !== $ipv4 ) {
			$connection['intel'] = IpFallback::lookup( $ipv4 );

			try {
				$connection['proxy'] = ProxyDetector::classify_with_lists(
					array_merge( $connection['intel'], array( 'ip' => $ipv4 ) )
				);
			} catch ( \Throwable $e ) {
				$connection['proxy'] = array(
					'category'   => 'unknown',
					'label'      => 'Unknown',
					'confidence' => 'low',
					'reasons'    => array(),
					'score'      => 0,
				);
			}
		}

		$reputation = ( '' !== $ipv4 )
			? Reputation::check( $ipv4 )
			: array(
				'status'  => 'unknown',
				'message' => 'No IPv4 address available to check.',
			);

		$ua_parsed = Fingerprint::parse_user_agent(
			(string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' )
		);

		$security_posture = array(
			'tls'     => TlsInfo::current_request_info(),
			'browser' => BrowserVersions::check(
				(string) ( $ua_parsed['browser'] ?? '' ),
				self::major_version_from_string( $ua_parsed['version'] ?? null )
			),
		);

		// Surface the proxy verdict + anonymity consistency at the
		// connection level so PrivacyReport::build() can fold them in
		// the same way the orchestrator does for visitors.
		try {
			$connection['anonymity'] = AnonymityScorer::score(
				$connection['intel'] ?? array(),
				Webrtc::summarize( array() ), // unknown WebRTC
				$connection['proxy'] ?? array(),
				(string) ( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '' ), // no client timezone
				null
			);
		} catch ( \Throwable $e ) {
			$connection['anonymity'] = array(
				'consistent' => null,
				'score'      => null,
				'mismatches' => array(),
				'summary'    => '',
			);
		}

		return array(
			'generated_at'      => gmdate( 'c' ),
			'request_ip'        => array(
				'ipv4'    => $ipv4,
				'ipv6'    => $ipv6,
				'is_mock' => Plugin::instance()->is_dev_mode(),
			),
			'connection'        => $connection,
			'security_posture'  => $security_posture,
			'reputation'        => $reputation,
			'user_agent'        => $ua_parsed,
			'fingerprint'       => array( 'level' => 'unknown', 'bits' => 0 ),
			'fingerprint_hashes'=> array(),
			'webrtc'            => Webrtc::summarize( array() ),
			'dns_test'          => array(
				'configured' => \PrivacyChecker\DnsTest::is_configured(),
			),
			'connection_quality'=> array(),
			'local_network'     => array(),
		);
	}

	/**
	 * Helper: extract the leading digits from a UA version string like
	 * "130.0.1" → 130. Mirrors ScannerOrchestrator::major_version_from_string()
	 * (which is private); kept in sync manually since duplication is
	 * cheaper than reflection here.
	 *
	 * @param mixed $version
	 * @return int|null
	 */
	private static function major_version_from_string( $version ): ?int {
		if ( ! is_string( $version ) || '' === $version ) {
			return null;
		}
		$head = explode( '.', $version, 2 )[0];
		return ctype_digit( $head ) ? (int) $head : null;
	}

	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
		}

		$scan   = self::build_self_scan();
		$report = PrivacyReport::build( $scan );

		require PRIVACY_CHECKER_DIR . 'admin/views/privacy-report-inspector.php';
	}
}
