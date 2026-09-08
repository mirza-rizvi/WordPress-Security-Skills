<?php
/**
 * Secure AJAX handler reference (admin-ajax.php).
 *
 * Demonstrates the full, copy-paste-ready flow for a privileged AJAX action:
 *   enqueue + localize nonce  ->  verify nonce  ->  check capability
 *   ->  unslash + sanitize     ->  act           ->  JSON response (fail closed).
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Enqueue the front-end/admin script and hand it a freshly created nonce.
 */
add_action( 'admin_enqueue_scripts', 'my_plugin_enqueue_ajax_script' );
function my_plugin_enqueue_ajax_script() {
	wp_enqueue_script(
		'my-plugin-ajax',
		plugins_url( 'js/my-plugin-ajax.js', __FILE__ ),
		array(),
		'1.0.0',
		true
	);

	// Pass the AJAX URL and a nonce scoped to this specific action.
	wp_localize_script(
		'my-plugin-ajax',
		'myPluginAjax',
		array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'my_plugin_update_thing' ),
		)
	);
}

/**
 * Handle the AJAX request. Registered for logged-in users only (no _nopriv).
 */
add_action( 'wp_ajax_my_plugin_update_thing', 'my_plugin_handle_ajax' );
function my_plugin_handle_ajax() {
	// 1. Verify the nonce. The third arg (false) means: do not auto-die, so we
	// can return a clean JSON error instead.
	if ( ! check_ajax_referer( 'my_plugin_update_thing', 'nonce', false ) ) {
		wp_send_json_error(
			array( 'message' => __( 'Security check failed.', 'my-plugin' ) ),
			403
		);
	}

	// 2. Verify capability. The nonce does NOT authorize — this does.
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error(
			array( 'message' => __( 'You are not allowed to do this.', 'my-plugin' ) ),
			403
		);
	}

	// 3. Unslash + sanitize every piece of input, with sane defaults.
	$thing_id = isset( $_POST['thing_id'] ) ? absint( wp_unslash( $_POST['thing_id'] ) ) : 0;
	$label    = isset( $_POST['label'] )
		? sanitize_text_field( wp_unslash( $_POST['label'] ) )
		: '';

	if ( 0 === $thing_id || '' === $label ) {
		wp_send_json_error(
			array( 'message' => __( 'Missing or invalid parameters.', 'my-plugin' ) ),
			400
		);
	}

	// 4. Do the work (example: store post meta the current user can edit).
	if ( ! current_user_can( 'edit_post', $thing_id ) ) {
		wp_send_json_error(
			array( 'message' => __( 'You cannot edit this item.', 'my-plugin' ) ),
			403
		);
	}
	update_post_meta( $thing_id, '_my_plugin_label', $label );

	// 5. Success response. Escape any values that may be rendered client-side.
	wp_send_json_success(
		array(
			'thing_id' => $thing_id,
			'label'    => esc_html( $label ),
		)
	);
}
