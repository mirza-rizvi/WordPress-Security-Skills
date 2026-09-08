<?php
/**
 * Secure REST endpoint reference.
 *
 * Demonstrates: versioned namespace, real permission_callback with a per-object
 * capability check, fully declared args (sanitize + validate), escaped output,
 * and WP_Error failure paths with HTTP status codes.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

add_action( 'rest_api_init', 'my_plugin_register_routes' );

function my_plugin_register_routes() {
	// Public read of a computed value (intentionally open).
	register_rest_route(
		'my-plugin/v1',
		'/status',
		array(
			'methods'             => WP_REST_Server::READABLE, // GET
			'callback'            => 'my_plugin_rest_status',
			'permission_callback' => '__return_true', // intentional: public, non-sensitive
		)
	);

	// Authenticated, per-object write.
	register_rest_route(
		'my-plugin/v1',
		'/notes/(?P<id>\d+)',
		array(
			'methods'             => WP_REST_Server::EDITABLE, // POST/PUT/PATCH
			'callback'            => 'my_plugin_rest_save_note',
			'permission_callback' => 'my_plugin_rest_can_edit',
			'args'                => array(
				'id'   => array(
					'required'          => true,
					'validate_callback' => static function ( $value ) {
						return is_numeric( $value ) && (int) $value > 0;
					},
					'sanitize_callback' => 'absint',
				),
				'note' => array(
					'required'          => true,
					'type'              => 'string',
					'sanitize_callback' => 'sanitize_textarea_field',
					'validate_callback' => static function ( $value ) {
						return is_string( $value ) && strlen( $value ) <= 2000;
					},
				),
			),
		)
	);
}

/**
 * Authorization: the current user must be able to edit this specific post.
 *
 * @param WP_REST_Request $request Request.
 * @return true|WP_Error
 */
function my_plugin_rest_can_edit( WP_REST_Request $request ) {
	$id = absint( $request['id'] );

	if ( ! current_user_can( 'edit_post', $id ) ) {
		return new WP_Error(
			'rest_forbidden',
			__( 'You are not allowed to edit this item.', 'my-plugin' ),
			array( 'status' => 403 )
		);
	}
	return true;
}

/**
 * Public status callback.
 */
function my_plugin_rest_status() {
	return rest_ensure_response(
		array(
			'version' => '1.0.0',
			'time'    => time(),
		)
	);
}

/**
 * Save callback. Params are already sanitized/validated by the args schema.
 */
function my_plugin_rest_save_note( WP_REST_Request $request ) {
	$id   = absint( $request['id'] );
	$note = $request['note']; // already sanitized via sanitize_textarea_field

	if ( ! get_post( $id ) ) {
		return new WP_Error(
			'rest_not_found',
			__( 'Item not found.', 'my-plugin' ),
			array( 'status' => 404 )
		);
	}

	update_post_meta( $id, '_my_plugin_note', $note );

	// Escape values that the client may inject into the DOM.
	return rest_ensure_response(
		array(
			'id'   => $id,
			'note' => esc_html( $note ),
		)
	);
}
