<?php
/**
 * Admin subpage: GeoIP databases + external services catalog.
 *
 * Lets operators:
 *   • Upload GeoIP .bin/.mmdb/.zip files (with auto-extract + category tagging).
 *   • Manage external integration credentials (vendor, label, endpoint, key).
 *   • See database inventory at a glance (country / city / ASN).
 *   • Delete obsolete databases.
 *
 * Stored credentials are write-only in the UI: the existing key is never
 * rendered back to the browser. Each integration can be enabled / disabled.
 *
 * @package PrivacyChecker\Admin
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\GeoIpDatabase;
use PrivacyChecker\Plugin;
use PrivacyChecker\ServicesCatalog;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminDatabases {

	public const SLUG = 'privacy-checker-databases';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_post_pc_db_upload',    array( $this, 'handle_db_upload' ) );
		add_action( 'admin_post_pc_db_delete',    array( $this, 'handle_db_delete' ) );
		add_action( 'admin_post_pc_service_add',  array( $this, 'handle_service_add' ) );
		add_action( 'admin_post_pc_service_save', array( $this, 'handle_service_save' ) );
		add_action( 'admin_post_pc_service_delete', array( $this, 'handle_service_delete' ) );
	}

	public function register_menu(): void {
		add_submenu_page(
			AdminDashboard::DASHBOARD_SLUG,
			__( 'GeoIP & Services', 'privacy-checker' ),
			__( 'GeoIP & Services', 'privacy-checker' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render_page' )
		);
	}

	/* ---------- Handlers ---------- */

	public function handle_db_upload(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_db_upload' );

		$category = sanitize_key( wp_unslash( $_POST['category'] ?? 'misc' ) );
		$allowed  = array( 'geoip', 'country', 'city', 'asn', 'geoproxy', 'proxy', 'datacenter', 'mobile', 'cidr', 'reputation', 'tor', 'vpn', 'misc' );
		if ( ! in_array( $category, $allowed, true ) ) {
			$category = 'misc';
		}

		if ( empty( $_FILES['database'] ) || ! is_array( $_FILES['database'] ) ) {
			$this->redirect_err( 'no_file' );
		}
		$file = $_FILES['database'];
		if ( ! empty( $file['error'] ) ) {
			$this->redirect_err( 'upload_failed' );
		}

		$result = GeoIpDatabase::store_upload( $file, $category );
		if ( is_wp_error( $result ) ) {
			$this->redirect_err( $result->get_error_code() );
		}
		$this->redirect_ok( 'db_uploaded', array( 'name' => basename( (string) $result ) ) );
	}

	public function handle_db_delete(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_db_delete' );
		$name = sanitize_file_name( wp_unslash( $_POST['name'] ?? '' ) );
		$ok   = GeoIpDatabase::delete( $name );
		$this->redirect_ok( $ok ? 'db_deleted' : 'db_missing' );
	}

	public function handle_service_add(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_service_add' );
		$id = ServicesCatalog::add(
			(string) ( $_POST['vendor'] ?? '' ),
			(string) ( $_POST['label'] ?? '' ),
			(string) ( $_POST['endpoint'] ?? '' ),
			(string) ( $_POST['api_key'] ?? '' ),
			(bool)   ! empty( $_POST['enabled'] )
		);
		$this->redirect_ok( 'service_added', array( 'id' => $id ) );
	}

	public function handle_service_save(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_service_save' );
		$id = (int) ( $_POST['id'] ?? 0 );
		if ( $id <= 0 ) {
			$this->redirect_err( 'bad_id' );
		}
		ServicesCatalog::save(
			$id,
			(string) ( $_POST['label'] ?? '' ),
			(string) ( $_POST['endpoint'] ?? '' ),
			'' !== (string) ( $_POST['api_key'] ?? '' ) ? (string) $_POST['api_key'] : null,
			(bool)   ! empty( $_POST['enabled'] )
		);
		$this->redirect_ok( 'service_saved' );
	}

	public function handle_service_delete(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_service_delete' );
		$id = (int) ( $_POST['id'] ?? 0 );
		ServicesCatalog::delete( $id );
		$this->redirect_ok( 'service_deleted' );
	}

	private function redirect_ok( string $msg, array $extra = array() ): void {
		$args = array_merge( array( 'page' => self::SLUG, 'pc_msg' => $msg ), $extra );
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}
	private function redirect_err( string $code ): void {
		$this->redirect_ok( 'err_' . $code );
	}

	/* ---------- Render ---------- */

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
		}

		$databases = GeoIpDatabase::list_with_meta();
		$services  = ServicesCatalog::list_all();
		?>
		<div class="wrap pc-databases">
			<h1><?php esc_html_e( 'GeoIP databases & external services', 'privacy-checker' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Upload local GeoIP database files (BIN, MMDB, ZIP, CSV-CIDR) and manage API credentials for external sites/services you want to integrate. The plugin auto-detects file types and extracts zips.', 'privacy-checker' ); ?>
			</p>

			<?php $this->render_notice(); ?>

			<h2><?php esc_html_e( 'Upload a database', 'privacy-checker' ); ?></h2>
			<form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pc-databases__upload">
				<?php wp_nonce_field( 'pc_db_upload' ); ?>
				<input type="hidden" name="action" value="pc_db_upload" />
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="pc-db-file"><?php esc_html_e( 'Database file', 'privacy-checker' ); ?></label></th>
						<td>
							<input type="file" id="pc-db-file" name="database" accept=".bin,.mmdb,.zip,.csv,.dat,.gz" required />
							<p class="description">
								<?php esc_html_e( 'Accepts .bin (IP2Location), .mmdb (MaxMind), .zip archives (auto-extracted), .csv (CIDR blocks with country/asn columns).', 'privacy-checker' ); ?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="pc-db-category"><?php esc_html_e( 'Category', 'privacy-checker' ); ?></label></th>
						<td>
							<select id="pc-db-category" name="category">
								<optgroup label="<?php esc_attr_e( 'GeoIP databases', 'privacy-checker' ); ?>">
									<option value="geoip"><?php esc_html_e( 'GeoIP (generic)', 'privacy-checker' ); ?></option>
									<option value="country"><?php esc_html_e( 'GeoIP — Country', 'privacy-checker' ); ?></option>
									<option value="city"><?php esc_html_e( 'GeoIP — City / region', 'privacy-checker' ); ?></option>
									<option value="asn"><?php esc_html_e( 'GeoIP — ASN / ISP', 'privacy-checker' ); ?></option>
								</optgroup>
								<optgroup label="<?php esc_attr_e( 'Proxy detection', 'privacy-checker' ); ?>">
									<option value="geoproxy"><?php esc_html_e( 'GeoProxy (provider-level)', 'privacy-checker' ); ?></option>
									<option value="tor"><?php esc_html_e( 'Tor exit-node list (one IP per line)', 'privacy-checker' ); ?></option>
									<option value="vpn"><?php esc_html_e( 'VPN provider IP ranges', 'privacy-checker' ); ?></option>
									<option value="proxy"><?php esc_html_e( 'Proxy / open-proxy list', 'privacy-checker' ); ?></option>
									<option value="datacenter"><?php esc_html_e( 'Datacenter / hosting ranges', 'privacy-checker' ); ?></option>
									<option value="mobile"><?php esc_html_e( 'Mobile carrier ranges', 'privacy-checker' ); ?></option>
								</optgroup>
								<optgroup label="<?php esc_attr_e( 'Other', 'privacy-checker' ); ?>">
									<option value="cidr"><?php esc_html_e( 'CIDR block list (custom)', 'privacy-checker' ); ?></option>
									<option value="reputation"><?php esc_html_e( 'IP reputation / blacklist', 'privacy-checker' ); ?></option>
									<option value="misc"><?php esc_html_e( 'Misc / other', 'privacy-checker' ); ?></option>
								</optgroup>
							</select>
							<p class="description"><?php esc_html_e( 'Tag so this database shows up correctly in the inventory list.', 'privacy-checker' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Upload database', 'privacy-checker' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Database inventory', 'privacy-checker' ); ?></h2>
			<?php if ( empty( $databases ) ) : ?>
				<p class="description"><?php esc_html_e( 'No databases uploaded yet. Use the form above or drop files into wp-content/uploads/privacy-checker-geoip/.', 'privacy-checker' ); ?></p>
			<?php else : ?>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'File', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Category', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Format', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Size', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Modified', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Action', 'privacy-checker' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $databases as $db ) : ?>
						<tr>
							<td><code><?php echo esc_html( $db['name'] ); ?></code></td>
							<td><?php echo esc_html( $db['category'] ); ?></td>
							<td><?php echo esc_html( $db['format'] ); ?></td>
							<td><?php echo esc_html( size_format( (int) $db['size'] ) ); ?></td>
							<td><?php echo esc_html( $db['modified'] ); ?></td>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this database?', 'privacy-checker' ) ); ?>');">
									<?php wp_nonce_field( 'pc_db_delete' ); ?>
									<input type="hidden" name="action" value="pc_db_delete" />
									<input type="hidden" name="name" value="<?php echo esc_attr( $db['name'] ); ?>" />
									<button type="submit" class="button button-link-delete"><?php esc_html_e( 'Delete', 'privacy-checker' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2><?php esc_html_e( 'External services & integrations', 'privacy-checker' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Register each external service or site you want IMON to talk to. The API key field is write-only — the existing key is never rendered back to the browser.', 'privacy-checker' ); ?></p>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pc-databases__service">
				<?php wp_nonce_field( 'pc_service_add' ); ?>
				<input type="hidden" name="action" value="pc_service_add" />
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="pc-svc-vendor"><?php esc_html_e( 'Vendor', 'privacy-checker' ); ?></label></th>
						<td>
							<select id="pc-svc-vendor" name="vendor">
								<option value="maxmind">MaxMind</option>
								<option value="ip2location">IP2Location</option>
								<option value="ipinfo">IPinfo</option>
								<option value="ipapi">ipapi.is</option>
								<option value="ip-api-com">ip-api.com</option>
								<option value="cloudflare">Cloudflare</option>
								<option value="abuseipdb">AbuseIPDB</option>
								<option value="custom"><?php esc_html_e( 'Custom / other', 'privacy-checker' ); ?></option>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="pc-svc-label"><?php esc_html_e( 'Label', 'privacy-checker' ); ?></label></th>
						<td><input type="text" id="pc-svc-label" name="label" required class="regular-text" placeholder="My IP2Location token" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="pc-svc-endpoint"><?php esc_html_e( 'Endpoint / download URL', 'privacy-checker' ); ?></label></th>
						<td><input type="url" id="pc-svc-endpoint" name="endpoint" class="regular-text code" placeholder="https://www.ip2location.com/download?token=…" /></td>
					</tr>
					<tr>
						<th scope="row"><label for="pc-svc-key"><?php esc_html_e( 'API key / token', 'privacy-checker' ); ?></label></th>
						<td>
							<input type="password" autocomplete="off" id="pc-svc-key" name="api_key" class="regular-text" />
							<p class="description"><?php esc_html_e( 'Stored hashed/side-loaded into the vendor file. Never returned in API responses.', 'privacy-checker' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Enabled', 'privacy-checker' ); ?></th>
						<td><label><input type="checkbox" name="enabled" value="1" checked /> <?php esc_html_e( 'Use this service in fallback chains.', 'privacy-checker' ); ?></label></td>
					</tr>
				</table>
				<?php submit_button( __( 'Add service', 'privacy-checker' ) ); ?>
			</form>

			<?php if ( ! empty( $services ) ) : ?>
				<table class="widefat striped pc-databases__services">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Vendor', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Label', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Endpoint', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Key', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Enabled', 'privacy-checker' ); ?></th>
							<th><?php esc_html_e( 'Action', 'privacy-checker' ); ?></th>
						</tr>
					</thead>
					<tbody>
					<?php foreach ( $services as $svc ) : ?>
						<tr>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
								<?php wp_nonce_field( 'pc_service_save' ); ?>
								<input type="hidden" name="action" value="pc_service_save" />
								<input type="hidden" name="id" value="<?php echo (int) $svc['id']; ?>" />
								<td><code><?php echo esc_html( $svc['vendor'] ); ?></code></td>
								<td><input type="text" name="label" value="<?php echo esc_attr( $svc['label'] ); ?>" /></td>
								<td><input type="url" name="endpoint" value="<?php echo esc_attr( $svc['endpoint'] ); ?>" class="regular-text code" /></td>
								<td><input type="password" autocomplete="off" name="api_key" placeholder="<?php echo esc_attr( $svc['has_key'] ? '••••••' : '' ); ?>" /></td>
								<td><label><input type="checkbox" name="enabled" value="1" <?php checked( ! empty( $svc['enabled'] ) ); ?> /></label></td>
								<td>
									<button type="submit" class="button"><?php esc_html_e( 'Save', 'privacy-checker' ); ?></button>
								</td>
							</form>
							<td>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this service entry?', 'privacy-checker' ) ); ?>');">
									<?php wp_nonce_field( 'pc_service_delete' ); ?>
									<input type="hidden" name="action" value="pc_service_delete" />
									<input type="hidden" name="id" value="<?php echo (int) $svc['id']; ?>" />
									<button type="submit" class="button button-link-delete"><?php esc_html_e( 'Delete', 'privacy-checker' ); ?></button>
								</form>
							</td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_notice(): void {
		$msg = isset( $_GET['pc_msg'] ) ? sanitize_key( wp_unslash( $_GET['pc_msg'] ) ) : '';
		if ( '' === $msg ) {
			return;
		}
		$kind = str_starts_with( $msg, 'err_' ) ? 'error' : 'success';
		echo '<div class="notice notice-' . esc_attr( $kind ) . ' inline"><p>' . esc_html( $msg ) . '</p></div>';
	}
}
