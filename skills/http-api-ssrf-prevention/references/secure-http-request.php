<?php
/**
 * Secure outbound HTTP request reference.
 *
 * Demonstrates validating a user-supplied webhook URL against an explicit host
 * allowlist, using wp_safe_remote_post, checking for errors, and handling the
 * response safely.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Deliver a payload to a user-configured webhook URL.
 *
 * validate-skills:ignore-state-change-checks — this helper performs an outbound
 * request; the surrounding caller must verify nonce + capability before invoking it.
 *
 * @param string $url     Target URL (from user input or options).
 * @param array  $payload Data to send.
 * @return array|WP_Error Response array on success, WP_Error on failure.
 */
function my_plugin_send_webhook( $url, $payload ) {
	$allowed_hosts = array( 'api.example.com', 'hooks.example.com' );

	// 1. Basic URL shape.
	$url = esc_url_raw( $url );
	if ( empty( $url ) ) {
		return new WP_Error( 'invalid_url', __( 'Invalid URL.', 'my-plugin' ) );
	}

	// 2. Host allowlist.
	$host = wp_parse_url( $url, PHP_URL_HOST );
	if ( ! $host || ! in_array( strtolower( $host ), $allowed_hosts, true ) ) {
		return new WP_Error( 'invalid_host', __( 'Host is not allowed.', 'my-plugin' ) );
	}

	// 3. WordPress SSRF guard (blocks private/loopback ranges, non-http/https schemes).
	if ( ! wp_http_validate_url( $url ) ) {
		return new WP_Error( 'unsafe_url', __( 'URL is not safe.', 'my-plugin' ) );
	}

	// 4. Safe request: rejects unsafe URLs and validates redirects.
	$response = wp_safe_remote_post(
		$url,
		array(
			'body'        => wp_json_encode( $payload ),
			'headers'     => array( 'Content-Type' => 'application/json' ),
			'timeout'     => 15,
			'redirection' => 2,
		)
	);

	// 5. Handle errors and response code.
	if ( is_wp_error( $response ) ) {
		return $response;
	}

	$code = wp_remote_retrieve_response_code( $response );
	if ( $code < 200 || $code >= 300 ) {
		return new WP_Error( 'unexpected_status', __( 'Unexpected response status.', 'my-plugin' ), array( 'status' => $code ) );
	}

	return $response;
}

/**
 * Example caller: an admin form that saves a webhook URL.
 */
function my_plugin_handle_webhook_form() {
	check_admin_referer( 'my_plugin_save_webhook', 'my_plugin_webhook_nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	$url = isset( $_POST['webhook_url'] )
		? esc_url_raw( wp_unslash( $_POST['webhook_url'] ) )
		: '';

	if ( empty( $url ) ) {
		wp_safe_redirect( add_query_arg( 'error', 'empty', wp_get_referer() ) );
		exit;
	}

	// Test the URL before saving it.
	$test = my_plugin_send_webhook( $url, array( 'event' => 'test' ) );
	if ( is_wp_error( $test ) ) {
		wp_safe_redirect( add_query_arg( 'error', 'request_failed', wp_get_referer() ) );
		exit;
	}

	update_option( 'my_plugin_webhook_url', $url );
	wp_safe_redirect( add_query_arg( 'updated', '1', wp_get_referer() ) );
	exit;
}
