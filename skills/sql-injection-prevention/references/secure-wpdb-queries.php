<?php
/**
 * Secure $wpdb query patterns. Every dynamic value is parameterized via prepare().
 *
 * Prefer high-level APIs (WP_Query, get_posts, $wpdb->insert/update/delete) when they
 * fit; drop to raw SQL only when necessary, and then always with prepare().
 *
 * validate-skills:ignore-state-change-checks — data-layer query patterns only;
 * real request handlers must add nonce + capability checks around these calls.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

global $wpdb;

/* 1. Single typed value ----------------------------------------------------- */
$id  = absint( $_GET['id'] ?? 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$row = $wpdb->get_row(
	$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}my_orders WHERE id = %d", $id )
);

/* 2. Multiple values, mixed types ------------------------------------------- */
$status = sanitize_key( $_GET['status'] ?? 'open' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$min    = (float) ( $_GET['min'] ?? 0 );             // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$rows   = $wpdb->get_results(
	$wpdb->prepare(
		"SELECT * FROM {$wpdb->prefix}my_orders WHERE status = %s AND total >= %f",
		$status,
		$min
	)
);

/* 3. LIKE search — esc_like() first, then %s -------------------------------- */
$term = sanitize_text_field( wp_unslash( $_GET['q'] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$like = '%' . $wpdb->esc_like( $term ) . '%';
$hits = $wpdb->get_results(
	$wpdb->prepare( "SELECT * FROM {$wpdb->prefix}my_orders WHERE customer LIKE %s", $like )
);

/* 4. IN() list — one placeholder per value ---------------------------------- */
$ids = array_filter( array_map( 'absint', (array) ( $_POST['ids'] ?? array() ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
if ( ! empty( $ids ) ) {
	$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->prefix}my_orders WHERE id IN ($placeholders)",
			$ids
		)
	);
}

/* 5. Allowlisted ORDER BY (identifiers cannot be data-parameterized) -------- */
$orderby = sanitize_key( $_GET['orderby'] ?? 'created' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$order   = strtoupper( sanitize_key( $_GET['order'] ?? 'desc' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$columns = array( 'created', 'customer', 'total' );
$orderby = in_array( $orderby, $columns, true ) ? $orderby : 'created';
$order   = ( 'ASC' === $order ) ? 'ASC' : 'DESC';
$sorted  = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}my_orders ORDER BY {$orderby} {$order}" );
// On WP 6.2+ you may instead bind identifiers with %i:
// $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}my_orders ORDER BY %i", $orderby );

/* 6. Reusable dynamic IN-list helper -------------------------------------- */
function my_plugin_prepare_in_list( $values, $placeholder ) {
	$values = array_values( array_filter( (array) $values ) );
	if ( empty( $values ) ) {
		return array( '', array() );
	}

	$allowed = array( '%d', '%s', '%f' );
	if ( ! in_array( $placeholder, $allowed, true ) ) {
		return array( '', array() );
	}

	$placeholders = implode( ',', array_fill( 0, count( $values ), $placeholder ) );
	return array( $placeholders, $values );
}

// Usage:
// list( $in, $ids ) = my_plugin_prepare_in_list( $ids, '%d' );
// $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}t WHERE id IN ($in)", $ids ) );

/* 7. insert / update / delete with format specifiers ------------------------ */
$wpdb->insert(
	$wpdb->prefix . 'my_orders',
	array(
		'customer' => sanitize_text_field( wp_unslash( $_POST['customer'] ?? '' ) ), // phpcs:ignore WordPress.Security.NonceVerification.Missing
		'total'    => (float) ( $_POST['total'] ?? 0 ),                               // phpcs:ignore WordPress.Security.NonceVerification.Missing
	),
	array( '%s', '%f' )
);

$wpdb->update(
	$wpdb->prefix . 'my_orders',
	array( 'status' => 'closed' ),       // data
	array( 'id' => $id ),                // where
	array( '%s' ),                       // data format
	array( '%d' )                        // where format
);

$wpdb->delete( $wpdb->prefix . 'my_orders', array( 'id' => $id ), array( '%d' ) );
