<?php
/**
 * Privacy integration reference: personal data exporter + eraser + policy content.
 *
 * Lets the admin's Tools -> Export/Erase Personal Data screens cover your plugin's
 * data, and surfaces suggested privacy-policy text. Assumes a custom subscribers
 * table {$wpdb->prefix}my_subs( email, name, ip ).
 *
 * validate-skills:ignore-state-change-checks — exporter/eraser callbacks are invoked
 * by core's privacy tools (which enforce admin capabilities); record_subscriber() must
 * be called from a handler that already verified nonce + capability.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Exporter — return the user's data in paginated chunks.
 * ---------------------------------------------------------------------- */
add_filter( 'wp_privacy_personal_data_exporters', 'my_plugin_register_exporter' );
function my_plugin_register_exporter( $exporters ) {
	$exporters['my-plugin'] = array(
		'exporter_friendly_name' => __( 'My Plugin Subscribers', 'my-plugin' ),
		'callback'               => 'my_plugin_data_exporter',
	);
	return $exporters;
}

function my_plugin_data_exporter( $email_address, $page = 1 ) {
	global $wpdb;

	$email = sanitize_email( $email_address );
	$row   = $wpdb->get_row(
		$wpdb->prepare( "SELECT email, name, ip FROM {$wpdb->prefix}my_subs WHERE email = %s", $email )
	);

	$export_items = array();
	if ( $row ) {
		$export_items[] = array(
			'group_id'    => 'my-plugin-subscribers',
			'group_label' => __( 'Subscriptions', 'my-plugin' ),
			'item_id'     => 'subscriber-' . md5( $email ),
			'data'        => array(
				array(
					'name'  => __( 'Email', 'my-plugin' ),
					'value' => $row->email,
				),
				array(
					'name'  => __( 'Name', 'my-plugin' ),
					'value' => $row->name,
				),
				array(
					'name'  => __( 'IP (anonymized)', 'my-plugin' ),
					'value' => $row->ip,
				),
			),
		);
	}

	return array(
		'data' => $export_items,
		'done' => true, // single page of data
	);
}

/*
-------------------------------------------------------------------------
 * Eraser — delete/anonymize the data and report what happened.
 * ---------------------------------------------------------------------- */
add_filter( 'wp_privacy_personal_data_erasers', 'my_plugin_register_eraser' );
function my_plugin_register_eraser( $erasers ) {
	$erasers['my-plugin'] = array(
		'eraser_friendly_name' => __( 'My Plugin Subscribers', 'my-plugin' ),
		'callback'             => 'my_plugin_data_eraser',
	);
	return $erasers;
}

function my_plugin_data_eraser( $email_address, $page = 1 ) {
	global $wpdb;

	$email   = sanitize_email( $email_address );
	$deleted = $wpdb->delete( $wpdb->prefix . 'my_subs', array( 'email' => $email ), array( '%s' ) );

	return array(
		'items_removed'  => ( $deleted > 0 ),
		'items_retained' => false,
		'messages'       => array(),
		'done'           => true,
	);
}

/*
-------------------------------------------------------------------------
 * Suggested privacy policy content.
 * ---------------------------------------------------------------------- */
add_action( 'admin_init', 'my_plugin_add_privacy_policy_content' );
function my_plugin_add_privacy_policy_content() {
	if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
		return;
	}
	$content = sprintf(
		'<p>%s</p>',
		esc_html__(
			'When you subscribe, we store your email, name, and an anonymized IP address. We retain this until you unsubscribe or request erasure.',
			'my-plugin'
		)
	);
	wp_add_privacy_policy_content( __( 'My Plugin', 'my-plugin' ), wp_kses_post( $content ) );
}

/*
-------------------------------------------------------------------------
 * Capture: minimize + anonymize at the point of collection.
 * ---------------------------------------------------------------------- */
function my_plugin_record_subscriber( $email, $name ) {
	global $wpdb;

	$raw_ip = isset( $_SERVER['REMOTE_ADDR'] )
		? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
		: '';

	$wpdb->insert(
		$wpdb->prefix . 'my_subs',
		array(
			'email' => sanitize_email( $email ),
			'name'  => sanitize_text_field( $name ),
			'ip'    => wp_privacy_anonymize_ip( $raw_ip ),
		),
		array( '%s', '%s', '%s' )
	);
}
