<?php
/**
 * Secure WordPress cron job reference.
 *
 * Demonstrates scheduling a recurring event, verifying stored context inside the
 * callback, and clearing hooks on deactivation. Cron callbacks run with no
 * current user, so authorization must be re-checked from stored context.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

const MY_PLUGIN_CRON_HOOK = 'my_plugin_daily_cleanup';

/*
-------------------------------------------------------------------------
 * Schedule the recurring event (no duplicates).
 * ---------------------------------------------------------------------- */
add_action( 'init', 'my_plugin_schedule_cleanup' );
function my_plugin_schedule_cleanup() {
	if ( ! wp_next_scheduled( MY_PLUGIN_CRON_HOOK ) ) {
		wp_schedule_event( time(), 'daily', MY_PLUGIN_CRON_HOOK );
	}
}

/*
-------------------------------------------------------------------------
 * Cron callback: act only on safe, stored configuration.
 *
 * validate-skills:ignore-state-change-checks — cron callbacks run with no
 * current user; authorization is enforced by the stored settings saved by an
 * admin via a nonce + capability form, and by the daily recurrence policy.
 * ---------------------------------------------------------------------- */
add_action( MY_PLUGIN_CRON_HOOK, 'my_plugin_run_daily_cleanup' );
function my_plugin_run_daily_cleanup() {
	// Read stored settings (the policy was already approved when they were saved).
	$settings = get_option( 'my_plugin_cleanup_settings', array() );
	$enabled  = ! empty( $settings['enabled'] );
	$days     = isset( $settings['retention_days'] ) ? absint( $settings['retention_days'] ) : 30;

	if ( ! $enabled || $days <= 0 ) {
		return;
	}

	// Validate the cutoff before using it in a query.
	$cutoff = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );
	if ( false === $cutoff ) {
		return;
	}

	global $wpdb;
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->prefix}my_plugin_logs WHERE created_at < %s",
			$cutoff
		)
	);
}

/*
-------------------------------------------------------------------------
 * Queue a one-time, per-user job from an admin action.
 * ---------------------------------------------------------------------- */
function my_plugin_queue_user_export( $user_id ) {
	// Verify capability in the request that queues the job.
	if ( ! current_user_can( 'manage_options' ) ) {
		return new WP_Error( 'forbidden', __( 'Forbidden.', 'my-plugin' ) );
	}

	$user_id = absint( $user_id );
	$user    = get_userdata( $user_id );
	if ( ! $user ) {
		return new WP_Error( 'invalid_user', __( 'Invalid user.', 'my-plugin' ) );
	}

	$args = array(
		'user_id'   => $user_id,
		'queued_by' => get_current_user_id(),
	);

	wp_schedule_single_event( time(), 'my_plugin_run_user_export', array( $args ) );
	return true;
}

add_action( 'my_plugin_run_user_export', 'my_plugin_run_user_export_callback' );
function my_plugin_run_user_export_callback( $args ) {
	// Re-verify the stored context; current_user_can() is meaningless here.
	$user_id   = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : 0;
	$queued_by = isset( $args['queued_by'] ) ? absint( $args['queued_by'] ) : 0;

	if ( $user_id <= 0 || $queued_by <= 0 ) {
		return;
	}

	// Verify the queueing user still has permission and the target user exists.
	if ( ! user_can( $queued_by, 'manage_options' ) || ! get_userdata( $user_id ) ) {
		return;
	}

	my_plugin_generate_user_export( $user_id );
}

/*
-------------------------------------------------------------------------
 * Clean up scheduled events when the plugin is deactivated.
 * ---------------------------------------------------------------------- */
register_deactivation_hook( __FILE__, 'my_plugin_deactivate_cron' );
function my_plugin_deactivate_cron() {
	wp_clear_scheduled_hook( MY_PLUGIN_CRON_HOOK );
	wp_clear_scheduled_hook( 'my_plugin_run_user_export' );
}

/* Integration requirement: the host plugin must provide
 * my_plugin_generate_user_export( $user_id ) before enabling this module.
 * It must create and deliver the real export with access-controlled storage
 * and retention. It is a project callback, not a WordPress API. See ../SKILL.md. */
