<?php
/**
 * Secure admin-ajax.php handler reference.
 *
 * Demonstrates the full flow for a privileged AJAX action and a safe public
 * (nopriv) action. Request handlers always verify the nonce, check a capability,
 * sanitize input, and exit through wp_send_json_*.
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

	// 4. Do the work (example: update a user meta field the current user can edit).
	update_user_meta( $user_id, 'my_plugin_bio', $bio );

	// 5. Return a success response; escape any values rendered client-side.
	wp_send_json_success(
		array(
			'user_id' => $user_id,
			'bio'     => esc_html( $bio ),
		)
	);
}

/*
-------------------------------------------------------------------------
 * Public AJAX handler: wp_ajax_nopriv_* (logged-out visitors).
 *
 * Use only for truly anonymous, rate-limited, non-sensitive actions.
 * Never use nopriv for writes that affect other users or privileged data.
 * ---------------------------------------------------------------------- */
add_action( 'wp_ajax_nopriv_my_plugin_public_lookup', 'my_plugin_ajax_public_lookup' );
function my_plugin_ajax_public_lookup() {
	// Public actions still need a nonce to prevent CSRF from other sites.
	if ( ! check_ajax_referer( 'my_plugin_public_lookup', 'nonce', false ) ) {
		wp_send_json_error(
			array( 'message' => __( 'Security check failed.', 'my-plugin' ) ),
			403
		);
	}

	// No current_user_can() here because the user is anonymous. Apply rate
	// limiting and restrict the action to safe, public data only.
	$term = isset( $_POST['term'] )
		? sanitize_text_field( wp_unslash( $_POST['term'] ) )
		: '';

	if ( strlen( $term ) < 2 ) {
		wp_send_json_error(
			array( 'message' => __( 'Term too short.', 'my-plugin' ) ),
			400
		);
	}

	$results = array(); // Fetch public data based on $term.

	wp_send_json_success(
		array( 'results' => $results )
	);
}

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
