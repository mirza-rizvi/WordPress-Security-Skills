<?php
/**
 * Secure WP-CLI command reference.
 *
 * Demonstrates sanitizing arguments, using $wpdb->prepare(), confirming
 * destructive actions, and loading an explicit user context when needed.
 *
 * @package My_Plugin
 */

// WP-CLI loads commands outside the normal admin bootstrap.
// The ABSPATH guard is still best practice when the file is reachable by URL.
defined( 'ABSPATH' ) || exit;

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

/**
 * Secure WP-CLI command class.
 *
 * validate-skills:ignore-state-change-checks — WP-CLI is a command-line surface
 * with no web nonce; destructive actions are gated by WP_CLI::confirm() and,
 * where applicable, an explicit --user plus current_user_can().
 */
class My_Plugin_CLI_Command {

	/**
	 * Purge old log entries.
	 *
	 * ## OPTIONS
	 *
	 * [<days>]
	 * : Delete logs older than this many days. Default: 30.
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * ## EXAMPLES
	 *
	 *     wp my-plugin logs purge 7
	 *     wp my-plugin logs purge --yes
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function purge( $args, $assoc_args ) {
		$days = isset( $args[0] ) ? absint( $args[0] ) : 30;
		if ( $days <= 0 ) {
			WP_CLI::error( 'Days must be a positive integer.' );
		}

		if ( ! isset( $assoc_args['yes'] ) ) {
			WP_CLI::confirm( "Delete logs older than {$days} days?" );
		}

		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );
		$count  = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}my_plugin_logs WHERE created_at < %s",
				$cutoff
			)
		);

		WP_CLI::success( "Deleted {$count} log entries." );
	}

	/**
	 * Update a plugin setting.
	 *
	 * ## OPTIONS
	 *
	 * <value>
	 * : New setting value.
	 *
	 * [--user=<user>]
	 * : User ID, login, or email to run as. Required for capability checks.
	 *
	 * ## EXAMPLES
	 *
	 *     wp my-plugin setting update "new value" --user=admin
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 */
	public function update( $args, $assoc_args ) {
		if ( ! isset( $args[0] ) ) {
			WP_CLI::error( 'A value is required.' );
		}
		$value = sanitize_text_field( $args[0] );

		if ( isset( $assoc_args['user'] ) ) {
			$user = get_user_by( 'login', $assoc_args['user'] );
			if ( ! $user ) {
				$user = get_user_by( 'id', (int) $assoc_args['user'] );
			}
			if ( ! $user && is_email( $assoc_args['user'] ) ) {
				$user = get_user_by( 'email', $assoc_args['user'] );
			}
			if ( $user ) {
				wp_set_current_user( $user->ID );
			}
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			WP_CLI::error( 'This command requires --user with manage_options capability.' );
		}

		update_option( 'my_plugin_setting', $value );
		WP_CLI::success( 'Setting updated.' );
	}
}

WP_CLI::add_command( 'my-plugin', 'My_Plugin_CLI_Command' );
