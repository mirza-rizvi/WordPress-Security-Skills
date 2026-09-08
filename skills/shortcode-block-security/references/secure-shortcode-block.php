<?php
/**
 * Secure shortcode and dynamic block render callback reference.
 *
 * Demonstrates normalizing attributes, validating against allowlists, and
 * escaping every rendered value for its output context.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Secure shortcode: [my_plugin_card title="..." link="..." style="..."]
 * ---------------------------------------------------------------------- */
add_action( 'init', 'my_plugin_register_shortcodes' );
function my_plugin_register_shortcodes() {
	add_shortcode( 'my_plugin_card', 'my_plugin_card_shortcode' );
}

function my_plugin_card_shortcode( $atts, $content = null ) {
	$atts = shortcode_atts(
		array(
			'title' => '',
			'link'  => '',
			'style' => 'default',
		),
		$atts,
		'my_plugin_card'
	);

	// Sanitize each attribute to type.
	$title = sanitize_text_field( $atts['title'] );
	$link  = esc_url_raw( $atts['link'] );

	$allowed_styles = array( 'default', 'featured', 'compact' );
	$style          = in_array( $atts['style'], $allowed_styles, true ) ? $atts['style'] : 'default';

	$classes = array( 'my-plugin-card', 'my-plugin-card--' . sanitize_html_class( $style ) );

	// Build markup with context-correct escaping.
	$output = '<div class="' . esc_attr( implode( ' ', $classes ) ) . '">';
	if ( $link ) {
		$output .= '<h3><a href="' . esc_url( $link ) . '">' . esc_html( $title ) . '</a></h3>';
	} else {
		$output .= '<h3>' . esc_html( $title ) . '</h3>';
	}
	if ( null !== $content ) {
		$output .= '<div class="my-plugin-card__content">' . wp_kses_post( $content ) . '</div>';
	}
	$output .= '</div>';

	return $output;
}

/*
-------------------------------------------------------------------------
 * Secure dynamic block render callback.
 *
 * Example block.json attributes:
 *   "heading": { "type": "string", "default": "" }
 *   "bgColor": { "type": "string", "default": "#ffffff" }
 *   "link":    { "type": "string", "default": "" }
 * ---------------------------------------------------------------------- */
function my_plugin_render_banner_block( $attributes, $content ) {
	$heading  = isset( $attributes['heading'] ) ? sanitize_text_field( $attributes['heading'] ) : '';
	$bg_color = isset( $attributes['bgColor'] ) ? sanitize_hex_color( $attributes['bgColor'] ) : '#ffffff';
	$link     = isset( $attributes['link'] ) ? esc_url_raw( $attributes['link'] ) : '';

	$wrapper_attributes = get_block_wrapper_attributes(
		array(
			'class' => 'my-plugin-banner',
			'style' => 'background-color: ' . esc_attr( $bg_color ) . ';',
		)
	);

	$output = '<div ' . $wrapper_attributes . '>';
	if ( $link ) {
		$output .= '<a href="' . esc_url( $link ) . '">' . esc_html( $heading ) . '</a>';
	} else {
		$output .= esc_html( $heading );
	}
	$output .= '</div>';

	return $output;
}

add_action( 'init', 'my_plugin_register_banner_block' );
function my_plugin_register_banner_block() {
	if ( ! function_exists( 'register_block_type' ) ) {
		return;
	}

	register_block_type(
		'my-plugin/banner',
		array(
			'attributes'      => array(
				'heading' => array(
					'type'    => 'string',
					'default' => '',
				),
				'bgColor' => array(
					'type'    => 'string',
					'default' => '#ffffff',
				),
				'link'    => array(
					'type'    => 'string',
					'default' => '',
				),
			),
			'render_callback' => 'my_plugin_render_banner_block',
		)
	);
}
