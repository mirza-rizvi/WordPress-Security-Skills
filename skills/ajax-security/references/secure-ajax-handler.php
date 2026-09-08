<?php
/**
 * Secure admin-ajax.php handler reference.
 *
 * Integration-only privileged AJAX handler, not a standalone plugin.
 * Requires a plugin bootstrap and js/my-plugin-ajax.js beside this file.
 * The commented client request needs a real form, target user and error UI.
 * See ../SKILL.md for the client contract; no public lookup is implemented.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Enqueue script and pass the AJAX URL + nonce to JavaScript.
 * ---------------------------------------------------------------------- */
add_action( 'admin_enqueue_scripts', 'my_plugin_enqueue_ajax_assets' );
function my_plugin_enqueue_ajax_assets() {
	wp_enqueue_script(
		'my-plugin-ajax',
		plugins_url( 'js/my-plugin-ajax.js', __FILE__ ),
		array(),
		'1.0.0',
		true
	);

	wp_localize_script(
		'my-plugin-ajax',
		'myPluginAjax',
		array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'my_plugin_update_profile' ),
		)
	);
}

/*
-------------------------------------------------------------------------
 * Privileged AJAX handler: wp_ajax_* (logged-in users only).
 * ---------------------------------------------------------------------- */
add_action( 'wp_ajax_my_plugin_update_profile', 'my_plugin_ajax_update_profile' );
function my_plugin_ajax_update_profile() {
	// 1. Verify the nonce. false = do not auto-die, so we can return JSON.
	if ( ! check_ajax_referer( 'my_plugin_update_profile', 'nonce', false ) ) {
		wp_send_json_error(
			array( 'message' => __( 'Security check failed.', 'my-plugin' ) ),
			403
		);
	}

	// 2. Verify capability. The nonce does NOT authorize.
	if ( ! current_user_can( 'edit_posts' ) ) {
		wp_send_json_error(
			array( 'message' => __( 'You are not allowed to do this.', 'my-plugin' ) ),
			403
		);
	}

	// 3. Unslash + sanitize every input field.
	$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
	$bio     = isset( $_POST['bio'] )
		? sanitize_textarea_field( wp_unslash( $_POST['bio'] ) )
		: '';

	if ( $user_id <= 0 ) {
		wp_send_json_error(
			array( 'message' => __( 'Invalid user.', 'my-plugin' ) ),
			400
		);
	}

	// 4. Authorize the target user, not just the general editing capability.
	if ( ! current_user_can( 'edit_user', $user_id ) ) {
		wp_send_json_error( array( 'message' => __( 'Forbidden.', 'my-plugin' ) ), 403 );
	}
	update_user_meta( $user_id, 'my_plugin_bio', $bio );

	// 5. Return a success response; escape any values rendered client-side.
	wp_send_json_success(
		array(
			'user_id' => $user_id,
			'bio'     => esc_html( $bio ),
		)
	);
}

/* Public lookups need a real public-data query and abuse controls.
 * This reference intentionally registers no unfinished nopriv endpoint. */

/*
-------------------------------------------------------------------------
 * Example JavaScript (place in js/my-plugin-ajax.js).
 *
 * jQuery example:
 *   jQuery.post( myPluginAjax.ajaxUrl, {
 *     action: 'my_plugin_update_profile',
 *     nonce:  myPluginAjax.nonce,
 *     user_id: 1,
 *     bio: 'Hello world'
 *   } );
 *
 * Modern fetch example:
 *   const data = new FormData();
 *   data.append( 'action', 'my_plugin_update_profile' );
 *   data.append( 'nonce', myPluginAjax.nonce );
 *   data.append( 'user_id', '1' );
 *   data.append( 'bio', 'Hello world' );
 *   fetch( myPluginAjax.ajaxUrl, { method: 'POST', body: data } );
 * ---------------------------------------------------------------------- */
