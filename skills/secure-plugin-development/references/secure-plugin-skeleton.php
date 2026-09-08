<?php
/**
 * Plugin Name:       Secure Plugin Skeleton
 * Description:        Minimal secure-by-default plugin: ABSPATH guard, capability-gated
 *                     admin page, and the full verify -> authorize -> sanitize -> act
 *                     -> escape flow for a settings save.
 * Version:           1.0.0
 * Requires PHP:      7.4
 * Requires at least: 6.0
 * Text Domain:       my-plugin
 *
 * @package My_Plugin
 */

// Block direct access — every file, top of file.
defined( 'ABSPATH' ) || exit;

/**
 * Register the admin menu page (capability-gated by add_menu_page itself).
 */
add_action( 'admin_menu', 'my_plugin_register_menu' );
function my_plugin_register_menu() {
	add_menu_page(
		__( 'My Plugin', 'my-plugin' ),
		__( 'My Plugin', 'my-plugin' ),
		'manage_options',                 // Required capability.
		'my-plugin',
		'my_plugin_render_settings_page',
		'dashicons-shield'
	);
}

/**
 * Render the settings page. Re-check the capability — menu registration alone
 * is not a security boundary.
 */
function my_plugin_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to access this page.', 'my-plugin' ), 403 );
	}

	$api_key = get_option( 'my_plugin_api_key', '' ); // Safe default: empty.
	?>
	<div class="wrap">
		<h1><?php echo esc_html__( 'My Plugin Settings', 'my-plugin' ); ?></h1>

		<?php if ( isset( $_GET['updated'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display flag ?>
			<div class="notice notice-success"><p><?php echo esc_html__( 'Settings saved.', 'my-plugin' ); ?></p></div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="my_plugin_save_settings">
			<?php wp_nonce_field( 'my_plugin_save_settings', 'my_plugin_nonce' ); ?>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">
						<label for="my_plugin_api_key"><?php echo esc_html__( 'API Key', 'my-plugin' ); ?></label>
					</th>
					<td>
						<input
							type="text"
							id="my_plugin_api_key"
							name="my_plugin_api_key"
							class="regular-text"
							value="<?php echo esc_attr( $api_key ); ?>"
						>
					</td>
				</tr>
			</table>

			<?php submit_button( __( 'Save Settings', 'my-plugin' ) ); ?>
		</form>
	</div>
	<?php
}

/**
 * Handle the settings submission: verify -> authorize -> sanitize -> act -> redirect.
 */
add_action( 'admin_post_my_plugin_save_settings', 'my_plugin_save_settings' );
function my_plugin_save_settings() {
	// 1. CSRF: verify nonce (dies on failure).
	check_admin_referer( 'my_plugin_save_settings', 'my_plugin_nonce' );

	// 2. AuthZ: verify capability.
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to do this.', 'my-plugin' ), 403 );
	}

	// 3. Sanitize input (unslash first).
	$api_key = isset( $_POST['my_plugin_api_key'] )
		? sanitize_text_field( wp_unslash( $_POST['my_plugin_api_key'] ) )
		: '';

	// 4. Act.
	update_option( 'my_plugin_api_key', $api_key );

	// 5. Redirect back (safe redirect, internal only).
	wp_safe_redirect( add_query_arg( 'updated', '1', admin_url( 'admin.php?page=my-plugin' ) ) );
	exit;
}
