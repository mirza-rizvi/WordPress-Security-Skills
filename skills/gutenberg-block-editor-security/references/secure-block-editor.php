<?php
/**
 * Secure Gutenberg block editor reference.
 *
 * Demonstrates a dynamic block render_callback that sanitizes and escapes
 * attributes, plus a register_rest_field() update callback that checks
 * capabilities and sanitizes values.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Register a dynamic block with typed attributes and a render callback.
 * ---------------------------------------------------------------------- */
add_action( 'init', 'my_plugin_register_alert_block' );
function my_plugin_register_alert_block() {
	if ( ! function_exists( 'register_block_type' ) ) {
		return;
	}

	register_block_type(
		'my-plugin/alert',
		array(
			'attributes'      => array(
				'message' => array(
					'type'    => 'string',
					'default' => '',
				),
				'level'   => array(
					'type'    => 'string',
					'default' => 'info',
				),
			),
			'render_callback' => 'my_plugin_render_alert_block',
		)
	);
}

function my_plugin_render_alert_block( $attributes ) {
	$message = isset( $attributes['message'] ) ? sanitize_text_field( $attributes['message'] ) : '';

	$allowed_levels = array( 'info', 'warning', 'error' );
	$level          = isset( $attributes['level'] ) ? sanitize_key( $attributes['level'] ) : 'info';
	$level          = in_array( $level, $allowed_levels, true ) ? $level : 'info';

	$wrapper = get_block_wrapper_attributes(
		array(
			'class' => 'my-plugin-alert my-plugin-alert--' . sanitize_html_class( $level ),
		)
	);

	return '<div ' . $wrapper . '>' . esc_html( $message ) . '</div>';
}

/*
-------------------------------------------------------------------------
 * Register a REST field used by a block sidebar plugin.
 * ---------------------------------------------------------------------- */
add_action( 'rest_api_init', 'my_plugin_register_block_rest_field' );
function my_plugin_register_block_rest_field() {
	register_rest_field(
		'post',
		'my_plugin_sidebar_note',
		array(
			'get_callback'    => 'my_plugin_get_sidebar_note',
			'update_callback' => 'my_plugin_update_sidebar_note',
			'schema'          => array(
				'type'        => 'string',
				'arg_options' => array(
					'sanitize_callback' => 'wp_kses_post',
				),
			),
		)
	);
}

function my_plugin_get_sidebar_note( $object ) {
	return get_post_meta( $object['id'], '_my_plugin_sidebar_note', true );
}

function my_plugin_update_sidebar_note( $value, $object ) {
	if ( ! current_user_can( 'edit_post', $object->ID ) ) {
		return new WP_Error(
			'forbidden',
			__( 'You cannot edit this post.', 'my-plugin' ),
			array( 'status' => 403 )
		);
	}

	update_post_meta( $object->ID, '_my_plugin_sidebar_note', wp_kses_post( $value ) );
	return true;
}

/*
-------------------------------------------------------------------------
 * Example JavaScript (for the block editor):
 *
 * import apiFetch from '@wordpress/api-fetch';
 *
 * apiFetch( {
 *     path: '/wp/v2/posts/' + postId,
 *     method: 'POST',
 *     data: { my_plugin_sidebar_note: '<p>Safe markup</p>' },
 * } ).then( response => { ... } );
 *
 * apiFetch attaches X-WP-Nonce automatically for same-site requests.
 * ---------------------------------------------------------------------- */
