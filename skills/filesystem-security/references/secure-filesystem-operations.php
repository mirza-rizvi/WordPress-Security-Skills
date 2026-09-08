<?php
/**
 * Secure filesystem operations reference.
 *
 * Demonstrates base-directory containment for reading and deleting files, plus
 * WP_Filesystem usage for writes. Every state-changing caller must verify nonce
 * + capability before invoking these helpers.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/**
 * Resolve a user-provided filename under a known base directory.
 *
 * @param string $base_dir Absolute base directory.
 * @param string $filename User-supplied filename.
 * @return string|false Absolute path if safe, false otherwise.
 */
function my_plugin_resolve_file( $base_dir, $filename ) {
	$base = realpath( $base_dir );
	if ( false === $base ) {
		return false;
	}

	$filename = sanitize_file_name( $filename );
	if ( '' === $filename ) {
		return false;
	}

	$target = realpath( $base . '/' . $filename );
	if ( false === $target ) {
		// The file may not exist yet; still validate the resolved parent path.
		$target = realpath( $base ) . '/' . $filename;
	}

	$base_with_sep = rtrim( $base, '/\\' ) . DIRECTORY_SEPARATOR;
	if ( strpos( wp_normalize_path( $target ), wp_normalize_path( $base_with_sep ) ) !== 0 ) {
		return false;
	}

	return $target;
}

/**
 * Serve a file download from the exports directory.
 *
 * validate-skills:ignore-state-change-checks — read-only operation; caller must
 * verify capability.
 *
 * @param string $filename Requested filename.
 */
function my_plugin_serve_export( $filename ) {
	$base_dir = WP_CONTENT_DIR . '/my-plugin-exports';
	$target   = my_plugin_resolve_file( $base_dir, $filename );

	if ( false === $target || ! is_file( $target ) || ! is_readable( $target ) ) {
		wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
	}

	header( 'Content-Type: application/octet-stream' );
	header( 'Content-Disposition: attachment; filename="' . esc_attr( basename( $target ) ) . '"' );
	header( 'Content-Length: ' . filesize( $target ) );
	readfile( $target );
	exit;
}

/**
 * Delete a file from the exports directory.
 *
 * validate-skills:ignore-state-change-checks — caller must verify nonce + capability.
 *
 * @param string $filename Requested filename.
 * @return bool True on success, false on failure.
 */
function my_plugin_delete_export( $filename ) {
	$base_dir = WP_CONTENT_DIR . '/my-plugin-exports';
	$target   = my_plugin_resolve_file( $base_dir, $filename );

	if ( false === $target || ! is_file( $target ) ) {
		return false;
	}

	return wp_delete_file( $target );
}

/**
 * Write data to a file under the exports directory using WP_Filesystem.
 *
 * validate-skills:ignore-state-change-checks — caller must verify nonce + capability.
 *
 * @param string $filename Requested filename.
 * @param string $data     File contents.
 * @return bool|WP_Error True on success, error on failure.
 */
function my_plugin_write_export( $filename, $data ) {
	$base_dir = WP_CONTENT_DIR . '/my-plugin-exports';
	$target   = my_plugin_resolve_file( $base_dir, $filename );

	if ( false === $target ) {
		return new WP_Error( 'invalid_file', __( 'Invalid filename.', 'my-plugin' ) );
	}

	if ( ! function_exists( 'request_filesystem_credentials' ) ) {
		require_once ABSPATH . 'wp-admin/includes/file.php';
	}

	global $wp_filesystem;
	$url   = admin_url( 'admin-post.php?action=my_plugin_export' );
	$creds = request_filesystem_credentials( $url );
	if ( false === $creds || ! WP_Filesystem( $creds ) ) {
		return new WP_Error( 'filesystem', __( 'Could not initialize filesystem.', 'my-plugin' ) );
	}

	if ( ! wp_mkdir_p( dirname( $target ) ) ) {
		return new WP_Error( 'mkdir', __( 'Could not create directory.', 'my-plugin' ) );
	}

	return $wp_filesystem->put_contents( $target, $data, FS_CHMOD_FILE );
}
