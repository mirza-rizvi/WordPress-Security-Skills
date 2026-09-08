<?php
/**
 * Secure file upload handler.
 *
 * Flow: nonce -> capability -> wp_handle_upload -> wp_check_filetype_and_ext
 *       allowlist -> store. Optionally attach to the media library.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

add_action( 'admin_post_my_plugin_upload', 'my_plugin_handle_upload' );

function my_plugin_handle_upload() {
	// 1. CSRF.
	check_admin_referer( 'my_plugin_upload', 'my_plugin_upload_nonce' );

	// 2. Capability.
	if ( ! current_user_can( 'upload_files' ) ) {
		wp_die( esc_html__( 'You are not allowed to upload files.', 'my-plugin' ), 403 );
	}

	// 3. Presence check.
	if ( empty( $_FILES['my_file']['name'] ) ) {
		wp_die( esc_html__( 'No file was provided.', 'my-plugin' ), 400 );
	}

	$file = $_FILES['my_file']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- validated below by core helpers

	// 4. Verify the actual type/extension against an explicit allowlist.
	$allowed = array(
		'jpg|jpeg' => 'image/jpeg',
		'png'      => 'image/png',
		'gif'      => 'image/gif',
		'pdf'      => 'application/pdf',
	);
	$check   = wp_check_filetype_and_ext(
		$file['tmp_name'],
		sanitize_file_name( $file['name'] ),
		$allowed
	);
	if ( empty( $check['ext'] ) || empty( $check['type'] ) ) {
		wp_die( esc_html__( 'File type not allowed.', 'my-plugin' ), 400 );
	}

	// 5. Let core validate, sanitize the name, and place the file safely.
	require_once ABSPATH . 'wp-admin/includes/file.php';
	$overrides = array(
		'test_form' => false,           // not a standard wp form
		'mimes'     => $allowed,        // restrict to our allowlist
	);
	$result    = wp_handle_upload( $file, $overrides );

	if ( isset( $result['error'] ) ) {
		wp_die( esc_html( $result['error'] ), 400 );
	}

	// 6. (Optional) register as a media attachment.
	require_once ABSPATH . 'wp-admin/includes/image.php';
	require_once ABSPATH . 'wp-admin/includes/media.php';

	$attachment_id = wp_insert_attachment(
		array(
			'post_mime_type' => $result['type'],
			'post_title'     => sanitize_file_name( basename( $result['file'] ) ),
			'post_status'    => 'inherit',
		),
		$result['file']
	);
	if ( ! is_wp_error( $attachment_id ) ) {
		wp_update_attachment_metadata(
			$attachment_id,
			wp_generate_attachment_metadata( $attachment_id, $result['file'] )
		);
	}

	// 7. Redirect back; escape any value that becomes output.
	wp_safe_redirect( add_query_arg( 'uploaded', '1', wp_get_referer() ) );
	exit;
}

/**
 * Secure download/read handler — confine any path built from input to a base dir.
 */
add_action( 'admin_post_my_plugin_download', 'my_plugin_handle_download' );
function my_plugin_handle_download() {
	check_admin_referer( 'my_plugin_download', 'nonce' );
	if ( ! current_user_can( 'upload_files' ) ) {
		wp_die( esc_html__( 'Forbidden', 'my-plugin' ), 403 );
	}

	$base    = realpath( wp_upload_dir()['basedir'] );
	$request = sanitize_file_name( wp_unslash( $_GET['file'] ?? '' ) );
	$target  = $request ? realpath( $base . DIRECTORY_SEPARATOR . $request ) : false;

	// Reject traversal / files outside the base directory.
	if ( false === $target || 0 !== strpos( $target, $base . DIRECTORY_SEPARATOR ) ) {
		wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
	}

	header( 'Content-Type: application/octet-stream' );
	header( 'Content-Disposition: attachment; filename="' . basename( $target ) . '"' );
	readfile( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streaming a confirmed in-bounds file
	exit;
}
