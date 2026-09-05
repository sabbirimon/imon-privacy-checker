<?php
/**
 * Admin dashboard view.
 *
 * Aggregates: provider status tiles, fallback-chain reorder UI, charts,
 * recent events log, tools, and inline documentation.
 *
 * @package PrivacyChecker\Admin
 */

use PrivacyChecker\AdminCharts;
use PrivacyChecker\DnsTest;
use PrivacyChecker\EventLog;
use PrivacyChecker\IpFallback;
use PrivacyChecker\MaxmindManager;
use PrivacyChecker\NetworkProbe;
use PrivacyChecker\Plugin;
use PrivacyChecker\Providers\IpApiComProvider;
use PrivacyChecker\Providers\IpapiProvider;
use PrivacyChecker\Providers\IpinfoProvider;
use PrivacyChecker\Providers\MaxmindProvider;
use PrivacyChecker\Providers\MockIpProvider;
use PrivacyChecker\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$chain         = IpFallback::read_chain();
$mm_status     = MaxmindManager::get_status();
$days          = (int) Plugin::instance()->setting( 'dashboard_chart_days', 7 );
$logs_by_day   = EventLog::counts_by_day( $days );
$recent_events = EventLog::recent( 25 );
$rest_url      = rest_url( PRIVACY_CHECKER_REST_NS . '/' );

/**
 * Map a provider key to a friendly label + a status test.
 */
$providers = array(
	'maxmind'    => array(
		'label' => MaxmindProvider::class !== null ? 'MaxMind GeoLite2 (local)' : 'MaxMind',
		'ready' => ! empty( $mm_status['files']['GeoLite2-City.mmdb'] ) || ! empty( $mm_status['files']['GeoLite2-ASN.mmdb'] ) || ! empty( $mm_status['files']['GeoLite2-Country.mmdb'] ),
		'note'  => $mm_status['license_key_set']
			? sprintf( '%d files cached', count( $mm_status['files'] ) )
			: 'No license key set',
	),
	'ip-api-com' => array(
		'label' => 'ip-api.com (free)',
		'ready' => (bool) Plugin::instance()->setting( 'ip_api_com_enabled', true ),
		'note'  => Plugin::instance()->setting( 'ip_api_com_enabled', true ) ? 'Free tier (45 req/min)' : 'Disabled',
	),
	'ipinfo'     => array(
		'label' => 'ipinfo.io',
		'ready' => true,
		'note'  => Plugin::instance()->setting( 'ip_api_key' ) !== '' ? 'API key configured' : 'Free tier (no key)',
	),
	'ipapi'      => array(
		'label' => 'ipapi.com',
		'ready' => true,
		'note'  => 'Free tier (no key)',
	),
	'mock'       => array(
		'label' => 'Mock (Development)',
		'ready' => true,
		'note'  => 'Safety net only',
	),
);

/**
 * Construct a per-day "provider usage" series from the recent events log.
 * Falls back to mock distribution when logging is disabled.
 */
$provider_counts = array();
foreach ( $recent_events as $ev ) {
	if ( 'ip-fallback' === $ev['source'] ) {
		// Messages look like: "Resolved 1.1.1.1 via ip-api-com (ok)".
		if ( preg_match( '/via\s+([a-z\-]+)/', (string) $ev['message'], $m ) ) {
			$key                                     = $m[1];
			$provider_counts[ $key ]                 = ( $provider_counts[ $key ] ?? 0 ) + 1;
		}
	}
}
if ( empty( $provider_counts ) ) {
	$provider_counts = array( 'mock' => 0 );
}

/**
 * Diagnostics tiles — DNS leak test, ping / latency, port scan.
 *
 * Each tile reads from transient-backed probe state where possible. We never
 * run a probe from the dashboard render; we only surface what we already know
 * about configuration. The "ready" state means "configured + enabled" — the
 * admin can then click through to the tool page to actually try a probe.
 */
$dns_configured  = (bool) Plugin::instance()->setting( 'dns_test_enabled', false );
$dns_provider    = (string) Plugin::instance()->setting( 'dns_provider', 'doh-fanout' );
$dns_state       = DnsTest::is_configured()
	? array( 'class' => 'active', 'label' => __( 'Configured', 'privacy-checker' ) )
		: ( 'none' === $dns_provider
			? array( 'class' => 'idle', 'label' => __( 'Disabled', 'privacy-checker' ) )
			: array( 'class' => 'idle', 'label' => __( 'Provider not ready', 'privacy-checker' ) )
		);
$dns_note        = sprintf(
	'%s · %s',
	esc_html( $dns_provider ),
	(int) Plugin::instance()->setting( 'dns_query_timeout_sec', 3 ) . 's timeout'
);

$ping_targets    = (array) Plugin::instance()->setting( 'ping_targets', NetworkProbe::default_ping_targets() );
$ping_state      = ! empty( $ping_targets )
	? array( 'class' => 'active', 'label' => sprintf( _n( '%d target', '%d targets', count( $ping_targets ), 'privacy-checker' ), count( $ping_targets ) ) )
	: array( 'class' => 'idle', 'label' => __( 'No targets', 'privacy-checker' ) );
$ping_note       = sprintf( '%s · %ss timeout', count( $ping_targets ), (float) Plugin::instance()->setting( 'ping_timeout_sec', 1.5 ) );

$port_allowlist  = (array) Plugin::instance()->setting( 'port_scan_allowlist', array() );
$port_mode       = empty( $port_allowlist )
	? __( 'Self-only', 'privacy-checker' )
	: sprintf( _n( '%d allowlist entry', '%d allowlist entries', count( $port_allowlist ), 'privacy-checker' ), count( $port_allowlist ) );
$port_state      = array( 'class' => 'active', 'label' => $port_mode );
$port_note       = sprintf(
	'%s · %ss timeout',
	(int) Plugin::instance()->setting( 'port_scan_timeout_sec', 1.0 ),
	implode( ', ', array_map( 'intval', (array) Plugin::instance()->setting( 'port_scan_default_ports', NetworkProbe::default_port_scan_ports() ) ) )
);

$diagnostics_tiles = array(
	'dns_test' => array(
		'title'  => __( 'DNS Leak Test', 'privacy-checker' ),
		'state'  => $dns_state,
		'note'   => $dns_note,
		'link'   => admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG . '#pc_dns_test' ),
	),
	'ping' => array(
		'title'  => __( 'Ping / Latency', 'privacy-checker' ),
		'state'  => $ping_state,
		'note'   => $ping_note,
		'link'   => admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG . '#pc_ping' ),
	),
	'port_scan' => array(
		'title'  => __( 'Port Scan', 'privacy-checker' ),
		'state'  => $port_state,
		'note'   => $port_note,
		'link'   => admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG . '#pc_port_scan' ),
	),
	'rate_limits' => array(
		// Phase 8.3 — at-a-glance summary of every rate-limit knob
		// shipped across Phases 1 + 8 (scan / lookup / security /
		// connection_echo / dns_probe / ping / port_scan). The link
		// anchors at #pc_rate where the master Rate Limiting section
		// already renders scan/lookup/security; the others live in
		// their respective sections and aren't re-rendered here.
		'title'  => __( 'Rate Limits', 'privacy-checker' ),
		'state'  => array( 'class' => 'active', 'label' => __( 'Configured', 'privacy-checker' ) ),
		'note'   => sprintf(
			'Scan %1$d · Lookup %2$d · Security %3$d · Echo %4$d · DNS %5$d · Ping %6$d · Port %7$d',
			(int) Plugin::instance()->setting( 'rate_limit_scan', 60 ),
			(int) Plugin::instance()->setting( 'rate_limit_lookup', 30 ),
			(int) Plugin::instance()->setting( 'rate_limit_security', 10 ),
			(int) Plugin::instance()->setting( 'rate_limit_connection_echo', 60 ),
			(int) Plugin::instance()->setting( 'rate_limit_dns_probe', 5 ),
			(int) Plugin::instance()->setting( 'rate_limit_ping', 30 ),
			(int) Plugin::instance()->setting( 'rate_limit_port_scan', 10 )
		),
		'link'   => admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG . '#pc_rate' ),
	),
);

$cache_hits = array();
$cache_miss = array();
foreach ( $logs_by_day as $day => $count ) {
	// Approximate: half the events are cache hits. Real values come from a
	// future "cache" source.
	$cache_hits[ $day ] = (int) floor( $count / 2 );
	$cache_miss[ $day ] = (int) ceil( $count / 2 );
}

$flash = isset( $_GET['pc_msg'] ) ? sanitize_key( wp_unslash( (string) $_GET['pc_msg'] ) ) : '';
?>
<div class="wrap pc-admin pc-admin-dashboard">
	<h1><?php esc_html_e( 'IMON — Dashboard', 'privacy-checker' ); ?></h1>

	<?php if ( 'chain_saved' === $flash ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Fallback chain updated.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'mm_ok' === $flash ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php
			printf(
				/* translators: %d = number of databases downloaded */
				esc_html__( 'MaxMind download succeeded (%d database(s) refreshed).', 'privacy-checker' ),
				(int) ( $_GET['pc_mm'] ?? 0 )
			);
		?></p></div>
	<?php elseif ( 'mm_err' === $flash ) : ?>
		<div class="notice notice-error is-dismissible"><p><?php esc_html_e( 'MaxMind download failed. Check the MaxMind license key and server outbound HTTPS.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'log_cleared' === $flash ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Event log cleared.', 'privacy-checker' ); ?></p></div>
	<?php elseif ( 'cache_flushed' === $flash ) : ?>
		<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Cache flushed.', 'privacy-checker' ); ?></p></div>
	<?php endif; ?>

	<section class="pc-section" aria-labelledby="pc-status-title">
		<h2 id="pc-status-title"><?php esc_html_e( 'System status', 'privacy-checker' ); ?></h2>
		<ul class="pc-tiles" role="list">
			<?php foreach ( $providers as $key => $info ) :
				$active = in_array( $key, $chain, true );
				?>
				<li class="pc-tile pc-tile--<?php echo esc_attr( $active ? 'active' : 'idle' ); ?>" role="listitem">
					<h3 class="pc-tile__title"><?php echo esc_html( $info['label'] ); ?></h3>
					<p class="pc-tile__note"><?php echo esc_html( $info['note'] ); ?></p>
					<p class="pc-tile__state">
						<span class="pc-dot" aria-hidden="true"></span>
						<?php echo $active
							? esc_html__( 'Active in chain', 'privacy-checker' )
							: esc_html__( 'Idle', 'privacy-checker' ); ?>
					</p>
				</li>
			<?php endforeach; ?>
		</ul>
	</section>

	<section class="pc-section" aria-labelledby="pc-diagnostics-title">
		<h2 id="pc-diagnostics-title"><?php esc_html_e( 'Diagnostics probes', 'privacy-checker' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'DNS leak test, ping, and port-scan probes. Each tile shows configuration status; click through to run the probe.', 'privacy-checker' ); ?>
		</p>
		<ul class="pc-tiles" role="list">
			<?php foreach ( $diagnostics_tiles as $tile ) : ?>
				<li class="pc-tile pc-tile--<?php echo esc_attr( $tile['state']['class'] ); ?>" role="listitem">
					<h3 class="pc-tile__title"><?php echo esc_html( $tile['title'] ); ?></h3>
					<p class="pc-tile__note"><?php echo esc_html( $tile['note'] ); ?></p>
					<p class="pc-tile__state">
						<span class="pc-dot" aria-hidden="true"></span>
						<?php echo esc_html( $tile['state']['label'] ); ?>
					</p>
					<p class="pc-tile__actions">
						<a class="button" href="<?php echo esc_url( $tile['link'] ); ?>">
							<?php esc_html_e( 'Configure →', 'privacy-checker' ); ?>
						</a>
					</p>
				</li>
			<?php endforeach; ?>
		</ul>
	</section>

	<section class="pc-section" aria-labelledby="pc-chain-title">
		<h2 id="pc-chain-title"><?php esc_html_e( 'IP provider fallback chain', 'privacy-checker' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Providers are tried top-to-bottom. The first one that returns useful data wins. Reorder to match your needs; the Mock provider is always available as the last-resort safety net.', 'privacy-checker' ); ?>
		</p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="pc_reorder_chain" />
			<?php wp_nonce_field( 'pc_reorder_chain' ); ?>
			<ol class="pc-chain" role="list">
				<?php foreach ( $chain as $idx => $key ) :
					$label = $providers[ $key ]['label'] ?? $key;
					?>
					<li class="pc-chain__item">
						<span class="pc-chain__pos"><?php echo (int) ( $idx + 1 ); ?></span>
						<input type="hidden" name="order[]" value="<?php echo esc_attr( $key ); ?>" />
						<span class="pc-chain__name"><?php echo esc_html( $label ); ?></span>
						<span class="pc-chain__key"><?php echo esc_html( $key ); ?></span>
					</li>
				<?php endforeach; ?>
			</ol>
			<p class="description">
				<?php esc_html_e( 'Edit the chain from the Settings page. The order persists across requests.', 'privacy-checker' ); ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG ) ); ?>">
					<?php esc_html_e( 'Open Settings →', 'privacy-checker' ); ?>
				</a>
			</p>
			<?php /* Order is fully managed via Settings page; dashboard shows read-only view + chain reset. */ ?>
			<button class="button" name="pc_action" value="reset"><?php esc_html_e( 'Reset to recommended order', 'privacy-checker' ); ?></button>
		</form>
	</section>

	<section class="pc-section" aria-labelledby="pc-maxmind-title">
		<h2 id="pc-maxmind-title"><?php esc_html_e( 'MaxMind local cache', 'privacy-checker' ); ?></h2>
		<p>
			<?php
			printf(
				/* translators: %s = path */
				esc_html__( 'Database directory: %s', 'privacy-checker' ),
				'<code>' . esc_html( $mm_status['dir'] ) . '</code>'
			);
			?>
		</p>
		<p>
			<?php esc_html_e( 'Last refresh:', 'privacy-checker' ); ?>
			<strong>
				<?php
				if ( $mm_status['last_update'] > 0 ) {
					echo esc_html( gmdate( 'Y-m-d H:i', $mm_status['last_update'] ) ) . ' UTC';
				} else {
					esc_html_e( 'never', 'privacy-checker' );
				}
				?>
			</strong>
			—
			<?php echo $mm_status['license_key_set']
				? esc_html__( 'license key set', 'privacy-checker' )
				: esc_html__( 'no license key', 'privacy-checker' ); ?>
		</p>
		<table class="widefat pc-files">
			<thead>
				<tr>
					<th><?php esc_html_e( 'File', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Size', 'privacy-checker' ); ?></th>
					<th><?php esc_html_e( 'Modified', 'privacy-checker' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php if ( empty( $mm_status['files'] ) ) : ?>
					<tr><td colspan="3"><em><?php esc_html_e( 'No .mmdb files cached yet. Click "Download now" after adding your MaxMind license key.', 'privacy-checker' ); ?></em></td></tr>
				<?php else : ?>
					<?php foreach ( $mm_status['files'] as $name => $meta ) : ?>
						<tr>
							<td><code><?php echo esc_html( $name ); ?></code></td>
							<td><?php echo esc_html( size_format( (int) $meta['size'] ) ); ?></td>
							<td><?php echo esc_html( gmdate( 'Y-m-d H:i', (int) $meta['mtime'] ) ) . ' UTC'; ?></td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
			</tbody>
		</table>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1rem">
			<input type="hidden" name="action" value="pc_maxmind_download" />
			<?php wp_nonce_field( 'pc_maxmind_download' ); ?>
			<button type="submit" class="button button-primary">
				<?php esc_html_e( 'Download MaxMind databases now', 'privacy-checker' ); ?>
			</button>
			<span class="description"><?php esc_html_e( 'Requires a license key in Settings → IMON.', 'privacy-checker' ); ?></span>
		</form>

		<p class="pc-attribution">
			<?php esc_html_e( 'GeoLite2 data is provided by MaxMind under CC BY-SA 4.0: This product includes GeoLite2 data created by MaxMind, available from maxmind.com.', 'privacy-checker' ); ?>
		</p>
	</section>

	<section class="pc-section" aria-labelledby="pc-charts-title">
		<h2 id="pc-charts-title"><?php esc_html_e( 'Activity (last 7 days)', 'privacy-checker' ); ?></h2>
		<?php if ( ! EventLog::enabled() ) : ?>
			<p class="description">
				<?php
				printf(
					/* translators: %s = URL */
					wp_kses(
						__( 'Charts use the event log. Enable event logging on the <a href="%s">Settings page</a> to start collecting data.', 'privacy-checker' ),
						array( 'a' => array( 'href' => array() ) )
					),
					esc_url( admin_url( 'admin.php?page=' . \PrivacyChecker\Admin\AdminDashboard::SETTINGS_SLUG ) )
				);
				?>
			</p>
		<?php else : ?>
			<div class="pc-charts">
				<?php echo AdminCharts::line( $logs_by_day, __( 'Events per day', 'privacy-checker' ) ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
				<?php echo AdminCharts::stacked_bar( $cache_hits, $cache_miss, __( 'Cache hit / miss (estimated)', 'privacy-checker' ) ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
				<?php echo AdminCharts::pie( $provider_counts, __( 'Provider usage', 'privacy-checker' ) ); // phpcs:ignore WordPress.Security.EscapeOutput ?>
			</div>
		<?php endif; ?>
	</section>

	<section class="pc-section" aria-labelledby="pc-events-title">
		<h2 id="pc-events-title"><?php esc_html_e( 'Recent events', 'privacy-checker' ); ?></h2>
		<?php if ( ! EventLog::enabled() ) : ?>
			<p class="description"><?php esc_html_e( 'Event logging is disabled. Enable it in Settings to populate this table.', 'privacy-checker' ); ?></p>
		<?php else : ?>
			<table class="widefat pc-events">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Time', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Level', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Source', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Message', 'privacy-checker' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $recent_events ) ) : ?>
						<tr><td colspan="4"><em><?php esc_html_e( 'No events yet.', 'privacy-checker' ); ?></em></td></tr>
					<?php else : ?>
						<?php foreach ( $recent_events as $ev ) : ?>
							<tr>
								<td><code><?php echo esc_html( $ev['created_at'] ); ?></code></td>
								<td><span class="pc-level pc-level--<?php echo esc_attr( $ev['level'] ); ?>"><?php echo esc_html( $ev['level'] ); ?></span></td>
								<td><code><?php echo esc_html( $ev['source'] ); ?></code></td>
								<td><?php echo esc_html( $ev['message'] ); ?></td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:0.5rem">
				<input type="hidden" name="action" value="pc_log_clear" />
				<?php wp_nonce_field( 'pc_log_clear' ); ?>
				<button type="submit" class="button"><?php esc_html_e( 'Clear event log', 'privacy-checker' ); ?></button>
			</form>
		<?php endif; ?>
	</section>

	<section class="pc-section" aria-labelledby="pc-tools-title">
		<h2 id="pc-tools-title"><?php esc_html_e( 'Tools', 'privacy-checker' ); ?></h2>
		<div class="pc-tools">
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="pc_flush_all_cache" />
				<?php wp_nonce_field( 'pc_flush_all_cache' ); ?>
				<button type="submit" class="button"><?php esc_html_e( 'Flush all plugin transients', 'privacy-checker' ); ?></button>
			</form>
			<a class="button" href="<?php echo esc_url( $rest_url . 'scan/ip' ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Test scan endpoint (opens JSON)', 'privacy-checker' ); ?></a>
			<a class="button" href="<?php echo esc_url( home_url( '/wp-json/' . PRIVACY_CHECKER_REST_NS ) ); ?>" target="_blank" rel="noopener"><?php esc_html_e( 'Open REST API root', 'privacy-checker' ); ?></a>
		</div>
	</section>

	<section class="pc-section" aria-labelledby="pc-docs-title">
		<h2 id="pc-docs-title"><?php esc_html_e( 'How it works', 'privacy-checker' ); ?></h2>
		<details>
			<summary><?php esc_html_e( 'How the fallback chain works', 'privacy-checker' ); ?></summary>
			<p><?php esc_html_e( 'When a visitor runs the scanner, the plugin asks the first provider in the chain for geolocation. If that provider is unavailable, rate-limited, returns no useful data, or throws, it transparently moves to the next provider. The very last entry is always "Mock" so the UI never crashes.', 'privacy-checker' ); ?></p>
		</details>
		<details>
			<summary><?php esc_html_e( 'Why the DNS test is not configured by default', 'privacy-checker' ); ?></summary>
			<p><?php esc_html_e( 'A reliable DNS leak test requires dedicated DNS infrastructure (an authoritative server the visitor\'s resolver queries). Without that, the only honest answer is "unable to determine". The plugin ships with the plumbing; you wire in your own DNS provider via the privacy_checker_dns_hostname and privacy_checker_dns_verify filters.', 'privacy-checker' ); ?></p>
		</details>
		<details>
			<summary><?php esc_html_e( 'How rate limiting works', 'privacy-checker' ); ?></summary>
			<p><?php esc_html_e( 'Rate limits are enforced using SHA-256 hashes of (salt + IP + bucket + minute). The raw IP is never stored. When the limit is hit the endpoint returns HTTP 429 with a Retry-After header. Limits are configurable per bucket in Settings.', 'privacy-checker' ); ?></p>
		</details>
	</section>
</div>
<?php
// Silence the unused variable lint.
unset( $rest_url );
?>