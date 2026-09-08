<?php
/**
 * Capability check reference: admin page, AJAX, per-object action, REST callback.
 *
 * Authorization (current_user_can) answers "is this user allowed?".
 * It is always paired with a nonce, which answers "did this come from us?".
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * 1. Admin page — capability enforced at registration AND on render.
 * ---------------------------------------------------------------------- */
add_action(
	'admin_menu',
	function () {
		add_submenu_page(
			'tools.php',
			__( 'My Tool', 'my-plugin' ),
			__( 'My Tool', 'my-plugin' ),
			'manage_options', // capability required to see the menu
			'my-tool',
			'my_plugin_render_tool'
		);
	}
);

function my_plugin_render_tool() {
	// Re-check: the page URL is directly reachable regardless of the menu.
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You do not have permission to access this page.', 'my-plugin' ), 403 );
	}
	echo '<div class="wrap"><h1>' . esc_html__( 'My Tool', 'my-plugin' ) . '</h1></div>';
}

/*
-------------------------------------------------------------------------
 * 2. AJAX handler — nonce, then capability, then act.
 * ---------------------------------------------------------------------- */
add_action(
	'wp_ajax_my_plugin_clear_log',
	function () {
		check_ajax_referer( 'my_plugin_clear_log', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Forbidden', 'my-plugin' ) ), 403 );
		}

		delete_option( 'my_plugin_log' );
		wp_send_json_success();
	}
);

/*
-------------------------------------------------------------------------
 * 3. Per-object action — meta capability with the object ID.
 * ---------------------------------------------------------------------- */
add_action(
	'admin_post_my_plugin_trash_post',
	function () {
		$post_id = isset( $_GET['post'] ) ? absint( wp_unslash( $_GET['post'] ) ) : 0;

		check_admin_referer( 'my_plugin_trash_post_' . $post_id );

		// edit_post / delete_post respect ownership and post-type rules.
		if ( ! $post_id || ! current_user_can( 'delete_post', $post_id ) ) {
			wp_die( esc_html__( 'You cannot delete this post.', 'my-plugin' ), 403 );
		}

		wp_trash_post( $post_id );
		wp_safe_redirect( admin_url( 'edit.php' ) );
		exit;
	}
);

/*
-------------------------------------------------------------------------
 * 4. REST route — real permission_callback (capability + per-object).
 * ---------------------------------------------------------------------- */
add_action(
	'rest_api_init',
	function () {
		register_rest_route(
			'my/v1',
			'/posts/(?P<id>\d+)',
			array(
				'methods'             => WP_REST_Server::EDITABLE, // POST/PUT/PATCH
				'callback'            => 'my_plugin_rest_update',
				'permission_callback' => function ( WP_REST_Request $request ) {
					$id = absint( $request['id'] );
					if ( ! current_user_can( 'edit_post', $id ) ) {
						return new WP_Error(
							'rest_forbidden',
							__( 'You cannot edit this post.', 'my-plugin' ),
							array( 'status' => 403 )
						);
					}
					return true;
				},
				'args'                => array(
					'id' => array(
						'validate_callback' => static function ( $value ) {
							return is_numeric( $value );
						},
					),
				),
			)
		);
	}
);

function my_plugin_rest_update( WP_REST_Request $request ) {
	$id    = absint( $request['id'] );
	$title = sanitize_text_field( $request->get_param( 'title' ) );
	wp_update_post(
		array(
			'ID'         => $id,
			'post_title' => $title,
		)
	);
	return rest_ensure_response( array( 'updated' => true ) );
}
