<?php
/**
 * Secure WooCommerce order handler reference.
 *
 * Demonstrates loading an order with wc_get_order(), verifying the
 * edit_shop_order capability, sanitizing input with wc_clean, using the
 * WC_Order CRUD API, and escaping customer PII on output.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Update a custom note on an order from an admin AJAX request.
 */
function my_plugin_update_order_note() {
	check_ajax_referer( 'my_plugin_update_order_note', 'nonce', false );

	if ( ! current_user_can( 'edit_shop_orders' ) ) {
		wp_send_json_error( array( 'message' => __( 'Forbidden.', 'my-plugin' ) ), 403 );
	}

	$order_id = isset( $_POST['order_id'] ) ? absint( wp_unslash( $_POST['order_id'] ) ) : 0;
	$note     = isset( $_POST['note'] ) ? wc_clean( wp_unslash( $_POST['note'] ) ) : '';

	$order = $order_id ? wc_get_order( $order_id ) : false;
	if ( ! $order ) {
		wp_send_json_error( array( 'message' => __( 'Invalid order.', 'my-plugin' ) ), 400 );
	}

	// Per-object capability check.
	if ( ! current_user_can( 'edit_shop_order', $order_id ) ) {
		wp_send_json_error( array( 'message' => __( 'You cannot edit this order.', 'my-plugin' ) ), 403 );
	}

	$order->update_meta_data( '_my_plugin_internal_note', $note );
	$order->save();

	wp_send_json_success(
		array(
			'order_id' => $order_id,
			'note'     => esc_html( $note ),
		)
	);
}
add_action( 'wp_ajax_my_plugin_update_order_note', 'my_plugin_update_order_note' );

/**
 * Render a customer email safely.
 *
 * @param WC_Order $order Order object.
 */
function my_plugin_render_customer_email( $order ) {
	$email = $order->get_billing_email();
	printf(
		'<a href="%s">%s</a>',
		esc_url( 'mailto:' . $email ),
		esc_html( $email )
	);
}

/**
 * Register a custom WooCommerce REST endpoint for orders.
 */
add_action( 'rest_api_init', 'my_plugin_register_wc_order_endpoint' );
function my_plugin_register_wc_order_endpoint() {
	register_rest_route(
		'my-plugin/v1',
		'/orders/(?P<id>\d+)/status',
		array(
			'methods'             => 'POST',
			'callback'            => 'my_plugin_update_order_status',
			'permission_callback' => function ( $request ) {
				return current_user_can( 'edit_shop_order', $request['id'] );
			},
			'args'                => array(
				'id'     => array( 'type' => 'integer' ),
				'status' => array(
					'type' => 'string',
					'enum' => array( 'pending', 'processing', 'on-hold', 'completed', 'cancelled', 'refunded' ),
				),
			),
		)
	);
}

/**
 * Update order status via REST.
 *
 * @param WP_REST_Request $request Request object.
 * @return WP_REST_Response|WP_Error Response or error.
 */
function my_plugin_update_order_status( $request ) {
	$order_id = absint( $request['id'] );
	$order    = wc_get_order( $order_id );
	if ( ! $order ) {
		return new WP_Error( 'invalid_order', __( 'Invalid order.', 'my-plugin' ), array( 'status' => 404 ) );
	}

	$status = wc_clean( $request['status'] );
	$order->set_status( $status );
	$order->save();

	return rest_ensure_response(
		array(
			'id'     => $order_id,
			'status' => $order->get_status(),
		)
	);
}
