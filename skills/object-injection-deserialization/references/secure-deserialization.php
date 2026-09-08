<?php
/**
 * Secure deserialization / import reference.
 *
 * Demonstrates rejecting PHP-serialized input and using JSON as the safe
 * interchange format. When unserialize is unavoidable, it disables class
 * instantiation.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Import configuration from an uploaded JSON file.
 *
 * validate-skills:ignore-state-change-checks — the caller must verify nonce +
 * capability before invoking this helper.
 *
 * @param string $file_path Path to the uploaded file.
 * @return array|WP_Error Imported data or error.
 */
function my_plugin_import_config( $file_path ) {
	// Reject anything that looks like PHP serialized data.
	$raw = file_get_contents( $file_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	if ( false === $raw ) {
		return new WP_Error( 'read_failed', __( 'Could not read import file.', 'my-plugin' ) );
	}

	if ( is_serialized( $raw ) ) {
		return new WP_Error( 'serialized_input', __( 'Serialized PHP files are not allowed.', 'my-plugin' ) );
	}

	$data = json_decode( $raw, true );
	if ( null === $data || json_last_error() !== JSON_ERROR_NONE ) {
		return new WP_Error( 'invalid_json', __( 'Invalid JSON file.', 'my-plugin' ) );
	}

	if ( ! is_array( $data ) ) {
		return new WP_Error( 'invalid_shape', __( 'Import file must contain an object.', 'my-plugin' ) );
	}

	// Validate expected shape and sanitize each member.
	$clean = array();
	if ( isset( $data['api_key'] ) ) {
		$clean['api_key'] = sanitize_text_field( $data['api_key'] );
	}
	if ( isset( $data['webhook_url'] ) ) {
		$clean['webhook_url'] = esc_url_raw( $data['webhook_url'] );
	}
	$clean['enabled'] = ! empty( $data['enabled'] ) ? 1 : 0;

	return $clean;
}

/**
 * Safely read a trusted, internally stored serialized value.
 *
 * Use this only for data your plugin serialized itself and that users cannot
 * influence. Even then, disable class instantiation.
 *
 * @param string $serialized Internally generated serialized value.
 * @return mixed|false Decoded value, or false on failure.
 */
function my_plugin_safe_unserialize( $serialized ) {
	if ( ! is_serialized( $serialized ) ) {
		return false;
	}

	// PHP 7.0+: prevent object instantiation entirely.
	$options = array( 'allowed_classes' => false );

	// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize
	return @unserialize( $serialized, $options );
}

/**
 * Example caller: an admin import form.
 */
function my_plugin_handle_import() {
	check_admin_referer( 'my_plugin_import', 'my_plugin_import_nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	if ( empty( $_FILES['import_file'] ) ) {
		wp_safe_redirect( add_query_arg( 'error', 'no_file', wp_get_referer() ) );
		exit;
	}

	require_once ABSPATH . 'wp-admin/includes/file.php';
	$upload = wp_handle_upload(
		$_FILES['import_file'],
		array( 'test_form' => false )
	);

	if ( isset( $upload['error'] ) ) {
		wp_safe_redirect( add_query_arg( 'error', 'upload_failed', wp_get_referer() ) );
		exit;
	}

	$result = my_plugin_import_config( $upload['file'] );
	wp_delete_file( $upload['file'] );

	if ( is_wp_error( $result ) ) {
		wp_safe_redirect( add_query_arg( 'error', $result->get_error_code(), wp_get_referer() ) );
		exit;
	}

	update_option( 'my_plugin_options', $result );
	wp_safe_redirect( add_query_arg( 'updated', '1', wp_get_referer() ) );
	exit;
}
