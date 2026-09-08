<?php
/**
 * Secure secret storage reference.
 *
 * Demonstrates storing a service API key either as a wp-config.php constant
 * (preferred) or encrypted in the options table with libsodium. The plaintext
 * key is never persisted.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Configuration constants that belong in wp-config.php:
 *
 * define( 'MY_PLUGIN_API_KEY',            'sk-live-...' );
 * define( 'MY_PLUGIN_ENCRYPTION_KEY',     'base64-encoded-32-byte-key' );
 * ---------------------------------------------------------------------- */

/**
 * Retrieve the service API key.
 *
 * @return string|false The key, or false if not configured.
 */
function my_plugin_get_api_key() {
	// Preferred: key lives in wp-config.php and is never in the database.
	if ( defined( 'MY_PLUGIN_API_KEY' ) ) {
		return MY_PLUGIN_API_KEY;
	}

	// Fallback: decrypt from the options table.
	$encrypted = get_option( 'my_plugin_api_key_encrypted', '' );
	if ( ! $encrypted ) {
		return false;
	}

	return my_plugin_decrypt_secret( $encrypted );
}

/**
 * Encrypt a secret with libsodium (PHP 7.2+).
 *
 * @param string $plaintext Secret to encrypt.
 * @return string Base64-encoded nonce + ciphertext.
 */
function my_plugin_encrypt_secret( $plaintext ) {
	if ( ! defined( 'MY_PLUGIN_ENCRYPTION_KEY' ) ) {
		return '';
	}

	$key    = sodium_base642bin( MY_PLUGIN_ENCRYPTION_KEY, SODIUM_BASE64_VARIANT_ORIGINAL );
	$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
	$cipher = sodium_crypto_secretbox( $plaintext, $nonce, $key );

	return base64_encode( $nonce . $cipher );
}

/**
 * Decrypt a libsodium secret.
 *
 * @param string $encoded Base64-encoded nonce + ciphertext.
 * @return string|false Plaintext on success, false on failure.
 */
function my_plugin_decrypt_secret( $encoded ) {
	if ( ! defined( 'MY_PLUGIN_ENCRYPTION_KEY' ) ) {
		return false;
	}

	$raw    = base64_decode( $encoded, true );
	$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
	$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
	$key    = sodium_base642bin( MY_PLUGIN_ENCRYPTION_KEY, SODIUM_BASE64_VARIANT_ORIGINAL );

	return sodium_crypto_secretbox_open( $cipher, $nonce, $key );
}

/**
 * Save the API key submitted from a settings form.
 */
function my_plugin_save_api_key() {
	check_admin_referer( 'my_plugin_save_api_key', 'my_plugin_api_key_nonce' );

	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
	}

	$key = isset( $_POST['my_plugin_api_key'] )
		? sanitize_text_field( wp_unslash( $_POST['my_plugin_api_key'] ) )
		: '';

	if ( '' === $key ) {
		delete_option( 'my_plugin_api_key_encrypted' );
		wp_safe_redirect( add_query_arg( 'updated', '1', wp_get_referer() ) );
		exit;
	}

	if ( defined( 'MY_PLUGIN_API_KEY' ) ) {
		// Key is managed in wp-config.php; do not persist it in options.
		wp_safe_redirect( add_query_arg( 'updated', '1', wp_get_referer() ) );
		exit;
	}

	$encrypted = my_plugin_encrypt_secret( $key );
	if ( '' === $encrypted ) {
		wp_safe_redirect( add_query_arg( 'error', 'encrypt', wp_get_referer() ) );
		exit;
	}

	update_option( 'my_plugin_api_key_encrypted', $encrypted );
	wp_safe_redirect( add_query_arg( 'updated', '1', wp_get_referer() ) );
	exit;
}

/**
 * Generate and store a hashed API token for a user.
 *
 * Returns the plaintext token once; after that only the hash is stored.
 *
 * @param int $user_id User ID.
 * @return string|WP_Error The plaintext token, or error.
 */
function my_plugin_create_api_token( $user_id ) {
	$token      = wp_generate_password( 32, false );
	$token_hash = wp_hash_password( $token );

	update_user_meta( $user_id, 'my_plugin_api_token_hash', $token_hash );

	return $token;
}

/**
 * Verify a submitted API token against the stored hash.
 *
 * @param int    $user_id User ID.
 * @param string $token   Submitted token.
 * @return bool True if valid.
 */
function my_plugin_verify_api_token( $user_id, $token ) {
	$hash = get_user_meta( $user_id, 'my_plugin_api_token_hash', true );
	if ( ! $hash ) {
		return false;
	}

	return wp_check_password( $token, $hash );
}
