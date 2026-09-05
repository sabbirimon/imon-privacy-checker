<?php
/**
 * Admin subpage: API tokens.
 *
 * Issue, list and revoke the opaque API tokens that external clients
 * (bots, AI agents, integration services) use to authenticate against the
 * privacy REST API. Tokens are stored as SHA-256 hashes; the plaintext
 * is returned exactly once at creation.
 *
 * @package PrivacyChecker\Admin
 */

declare( strict_types=1 );

namespace PrivacyChecker\Admin;

use PrivacyChecker\ApiTokens;
use PrivacyChecker\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AdminApiTokens {

	public const SLUG = 'privacy-checker-api-tokens';

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_post_pc_api_tokens_issue', array( $this, 'handle_issue' ) );
		add_action( 'admin_post_pc_api_tokens_revoke', array( $this, 'handle_revoke' ) );
	}

	public function register_menu(): void {
		add_submenu_page(
			AdminDashboard::DASHBOARD_SLUG,
			__( 'API Tokens', 'privacy-checker' ),
			__( 'API Tokens', 'privacy-checker' ),
			'manage_options',
			self::SLUG,
			array( $this, 'render_page' )
		);
	}

	public function handle_issue(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_api_tokens_issue' );

		$label      = (string) ( $_POST['label'] ?? '' );
		$rate_limit = (int)    ( $_POST['rate_limit'] ?? 120 );
		$raw_scopes = (array)  ( $_POST['scopes'] ?? array() );
		$scopes     = array_values( array_filter( array_map( 'strval', $raw_scopes ) ) );

		$issued = ApiTokens::issue( $label, $scopes, $rate_limit, get_current_user_id() );

		// Pass the plaintext through to the next page render via a transient
		// keyed to the issuing user. The plaintext is NEVER persisted.
		set_transient( 'pc_token_issued_' . get_current_user_id(), $issued, 2 * MINUTE_IN_SECONDS );

		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'pc_msg' => 'token_issued' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function handle_revoke(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'privacy-checker' ) );
		}
		check_admin_referer( 'pc_api_tokens_revoke' );
		$id = (int) ( $_POST['id'] ?? 0 );
		ApiTokens::revoke( $id );
		wp_safe_redirect( add_query_arg( array( 'page' => self::SLUG, 'pc_msg' => 'token_revoked' ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'privacy-checker' ) );
		}
		$enabled = ApiTokens::enabled();
		$tokens  = ApiTokens::list_all();
		$just_issued = get_transient( 'pc_token_issued_' . get_current_user_id() );
		if ( $just_issued ) {
			delete_transient( 'pc_token_issued_' . get_current_user_id() );
		}
		$base = esc_url_raw( rest_url( PRIVACY_CHECKER_REST_NS . '/' ) );
		?>
		<div class="wrap pc-api-tokens">
			<h1><?php esc_html_e( 'API Tokens', 'privacy-checker' ); ?></h1>
			<p class="description">
				<?php esc_html_e( 'Issue opaque tokens for non-UI callers (bots, AI agents, integration services). Tokens authenticate against the privacy REST API via the standard Authorization: Bearer header.', 'privacy-checker' ); ?>
			</p>

			<?php if ( ! $enabled ) : ?>
				<div class="notice notice-warning inline">
					<p><?php esc_html_e( 'API tokens are disabled. Enable the "API access" option in Settings to use them.', 'privacy-checker' ); ?></p>
				</div>
			<?php endif; ?>

			<?php if ( is_array( $just_issued ) && ! empty( $just_issued['token'] ) ) : ?>
				<div class="notice notice-success inline">
					<p><strong><?php esc_html_e( 'New token issued. Copy it now — it will not be shown again.', 'privacy-checker' ); ?></strong></p>
					<pre class="pc-api-tokens__secret" id="pc-token-plaintext"><?php echo esc_html( $just_issued['token'] ); ?></pre>
					<p>
						<button type="button" class="button" id="pc-token-copy"><?php esc_html_e( 'Copy', 'privacy-checker' ); ?></button>
						<span class="description"><?php esc_html_e( 'Label:', 'privacy-checker' ); ?> <code><?php echo esc_html( $just_issued['label'] ); ?></code></span>
						<span class="description"><?php esc_html_e( 'Prefix:', 'privacy-checker' ); ?> <code><?php echo esc_html( $just_issued['prefix'] ); ?></code></span>
					</p>
				</div>
			<?php endif; ?>

			<h2><?php esc_html_e( 'Issue a new token', 'privacy-checker' ); ?></h2>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="pc-api-tokens__form">
				<?php wp_nonce_field( 'pc_api_tokens_issue' ); ?>
				<input type="hidden" name="action" value="pc_api_tokens_issue" />
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="pc-api-tokens-label"><?php esc_html_e( 'Label', 'privacy-checker' ); ?></label></th>
						<td>
							<input type="text" id="pc-api-tokens-label" name="label" required class="regular-text" placeholder="zapier-bot / agent-acme" />
							<p class="description"><?php esc_html_e( 'Human identifier for the client. Shown in the list. Not exposed to the client.', 'privacy-checker' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Scopes', 'privacy-checker' ); ?></th>
						<td>
							<fieldset>
								<?php foreach ( ApiTokens::all_scopes() as $scope => $desc ) : ?>
									<label style="display:block;margin-bottom:0.35rem;">
										<input type="checkbox" name="scopes[]" value="<?php echo esc_attr( $scope ); ?>" checked />
										<code><?php echo esc_html( $scope ); ?></code> — <?php echo esc_html( $desc ); ?>
									</label>
								<?php endforeach; ?>
							</fieldset>
							<p class="description"><?php esc_html_e( 'Tick only the endpoints this client needs.', 'privacy-checker' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="pc-api-tokens-rl"><?php esc_html_e( 'Per-minute rate limit', 'privacy-checker' ); ?></label></th>
						<td>
							<input type="number" id="pc-api-tokens-rl" name="rate_limit" value="120" min="1" max="100000" step="1" />
							<p class="description"><?php esc_html_e( 'Independent of the visitor IP rate limit. Increase for paying customers.', 'privacy-checker' ); ?></p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Issue token', 'privacy-checker' ) ); ?>
			</form>

			<h2><?php esc_html_e( 'Issued tokens', 'privacy-checker' ); ?></h2>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'ID', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Label', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Prefix', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Scopes', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Rate/min', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Created', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Last used', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Status', 'privacy-checker' ); ?></th>
						<th><?php esc_html_e( 'Action', 'privacy-checker' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( empty( $tokens ) ) : ?>
						<tr><td colspan="9"><?php esc_html_e( 'No tokens yet.', 'privacy-checker' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $tokens as $row ) : ?>
							<tr>
								<td><?php echo (int) $row['id']; ?></td>
								<td><?php echo esc_html( $row['label'] ); ?></td>
								<td><code><?php echo esc_html( $row['token_prefix'] ); ?>…</code></td>
								<td><?php
									$scopes = is_array( $row['scopes'] ) ? $row['scopes'] : array();
									echo esc_html( implode( ', ', $scopes ) );
								?></td>
								<td><?php echo (int) $row['rate_limit_per_minute']; ?></td>
								<td><?php echo esc_html( $row['created_at'] ); ?></td>
								<td><?php echo $row['last_used_at'] ? esc_html( $row['last_used_at'] ) : '—'; ?></td>
								<td>
									<?php if ( ! empty( $row['revoked'] ) ) : ?>
										<span class="dashicons dashicons-no" style="color:#a00"></span> <?php esc_html_e( 'Revoked', 'privacy-checker' ); ?>
									<?php else : ?>
										<span class="dashicons dashicons-yes" style="color:#080"></span> <?php esc_html_e( 'Active', 'privacy-checker' ); ?>
									<?php endif; ?>
								</td>
								<td>
									<?php if ( empty( $row['revoked'] ) ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('<?php echo esc_js( __( 'Revoke this token? Clients using it will start getting 401s.', 'privacy-checker' ) ); ?>');">
											<?php wp_nonce_field( 'pc_api_tokens_revoke' ); ?>
											<input type="hidden" name="action" value="pc_api_tokens_revoke" />
											<input type="hidden" name="id" value="<?php echo (int) $row['id']; ?>" />
											<button type="submit" class="button button-link-delete"><?php esc_html_e( 'Revoke', 'privacy-checker' ); ?></button>
										</form>
									<?php else : ?>
										—
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>

			<h2><?php esc_html_e( 'Example: call the API', 'privacy-checker' ); ?></h2>
			<pre class="pc-api-tokens__example"><code>curl -sS \
  -H "Authorization: Bearer pc_live_…" \
  "<?php echo esc_html( $base ); ?>scan"</code></pre>
			<p class="description"><?php
				printf(
					/* translators: %s = REST namespace, e.g. privacy-checker/v1 */
					esc_html__( 'Base URL: %s. The Bearer token is sent in the Authorization header. The same endpoints work for the public UI (with nonce cookies).', 'privacy-checker' ),
					esc_html( $base )
				);
			?></p>
		</div>
		<script>
		(function () {
			var btn = document.getElementById('pc-token-copy');
			var pre = document.getElementById('pc-token-plaintext');
			if (btn && pre) {
				btn.addEventListener('click', function () {
					var text = pre.textContent || '';
					if (navigator.clipboard && navigator.clipboard.writeText) {
						navigator.clipboard.writeText(text).then(function () {
							btn.textContent = '<?php echo esc_js( __( 'Copied', 'privacy-checker' ) ); ?>';
						});
					} else {
						var r = document.createRange();
						r.selectNodeContents(pre);
						var s = window.getSelection();
						s.removeAllRanges();
						s.addRange(r);
						document.execCommand('copy');
						s.removeAllRanges();
					}
				});
			}
		}());
		</script>
		<?php
	}
}
