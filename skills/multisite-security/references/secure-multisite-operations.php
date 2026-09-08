<?php
/**
 * Secure multisite operations reference.
 *
 * Demonstrates validating a blog id, checking user membership, switching context,
 * and always restoring. Network-level options are gated by manage_network_options.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Add a network admin menu page.
 */
add_action( 'network_admin_menu', 'my_plugin_add_network_admin_page' );
function my_plugin_add_network_admin_page() {
	add_menu_page(
		__( 'My Plugin Network', 'my-plugin' ),
		__( 'My Plugin', 'my-plugin' ),
		'manage_network_options',
		'my-plugin-network',
		'my_plugin_render_network_page'
	);
}

function my_plugin_render_network_page() {
	if ( ! current_user_can( 'manage_network_options' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<p><?php esc_html_e( 'Network-wide settings go here.', 'my-plugin' ); ?></p>
	</div>
	<?php
}

/**
 * Read a post count from a site the current user belongs to.
 *
 * @param int $blog_id Requested blog id.
 * @return int|WP_Error Post count, or error.
 */
function my_plugin_get_site_post_count( $blog_id ) {
	if ( ! is_multisite() ) {
		return new WP_Error( 'not_multisite', __( 'Not a multisite installation.', 'my-plugin' ) );
	}

	$blog_id = absint( $blog_id );
	$site    = get_site( $blog_id );
	if ( ! $site ) {
		return new WP_Error( 'invalid_site', __( 'Invalid site.', 'my-plugin' ) );
	}

	$user_id = get_current_user_id();
	if ( ! is_user_member_of_blog( $user_id, $blog_id ) && ! current_user_can( 'manage_network' ) ) {
		return new WP_Error( 'forbidden', __( 'You cannot access this site.', 'my-plugin' ) );
	}

	switch_to_blog( $blog_id );

	// After switching, re-check if the user may read posts on this site.
	if ( ! user_can( $user_id, 'read' ) ) {
		restore_current_blog();
		return new WP_Error( 'forbidden', __( 'You cannot read this site.', 'my-plugin' ) );
	}

	$count = wp_count_posts()->publish;
	restore_current_blog();

	return (int) $count;
}

/**
 * Save a per-site option from a network admin request.
 */
function my_plugin_save_site_option() {
	check_admin_referer( 'my_plugin_save_site_option', 'my_plugin_site_option_nonce' );

	if ( ! current_user_can( 'manage_network_options' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	$blog_id = isset( $_POST['blog_id'] ) ? absint( wp_unslash( $_POST['blog_id'] ) ) : 0;
	$value   = isset( $_POST['value'] ) ? sanitize_text_field( wp_unslash( $_POST['value'] ) ) : '';

	$site = get_site( $blog_id );
	if ( ! $site ) {
		wp_die( esc_html__( 'Invalid site.', 'my-plugin' ), 400 );
	}

	switch_to_blog( $blog_id );
	update_option( 'my_plugin_site_setting', $value );
	restore_current_blog();

	wp_safe_redirect( network_admin_url( 'admin.php?page=my-plugin-network&updated=1' ) );
	exit;
}
