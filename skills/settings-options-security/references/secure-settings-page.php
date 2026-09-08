<?php
/**
 * Secure Settings API page reference.
 *
 * Demonstrates register_setting with a sanitize_callback, a section + field,
 * an options.php form, and safe output escaping. Request handling is delegated
 * to core's options.php, which enforces the nonce and capability checks.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
-------------------------------------------------------------------------
 * Register the setting, section, and field on admin_init.
 * ---------------------------------------------------------------------- */
add_action( 'admin_init', 'my_plugin_register_settings' );
function my_plugin_register_settings() {
	register_setting(
		'my_plugin_group',
		'my_plugin_options',
		array(
			'type'              => 'array',
			'sanitize_callback' => 'my_plugin_sanitize_options',
			'default'           => array(
				'api_key'     => '',
				'webhook_url' => '',
				'enabled'     => 0,
			),
		)
	);

	add_settings_section(
		'my_plugin_main_section',
		__( 'Integration Settings', 'my-plugin' ),
		'my_plugin_section_callback',
		'my-plugin'
	);

	add_settings_field(
		'my_plugin_api_key_field',
		__( 'API Key', 'my-plugin' ),
		'my_plugin_api_key_field_callback',
		'my-plugin',
		'my_plugin_main_section'
	);

	add_settings_field(
		'my_plugin_webhook_url_field',
		__( 'Webhook URL', 'my-plugin' ),
		'my_plugin_webhook_url_field_callback',
		'my-plugin',
		'my_plugin_main_section'
	);

	add_settings_field(
		'my_plugin_enabled_field',
		__( 'Enable integration', 'my-plugin' ),
		'my_plugin_enabled_field_callback',
		'my-plugin',
		'my_plugin_main_section'
	);
}

function my_plugin_section_callback() {
	echo '<p>' . esc_html__( 'Configure the external integration.', 'my-plugin' ) . '</p>';
}

function my_plugin_api_key_field_callback() {
	$options = get_option( 'my_plugin_options', array() );
	$api_key = isset( $options['api_key'] ) ? $options['api_key'] : '';
	?>
	<input
		type="text"
		name="my_plugin_options[api_key]"
		value="<?php echo esc_attr( $api_key ); ?>"
		class="regular-text"
	/>
	<?php
}

function my_plugin_webhook_url_field_callback() {
	$options = get_option( 'my_plugin_options', array() );
	$url     = isset( $options['webhook_url'] ) ? $options['webhook_url'] : '';
	?>
	<input
		type="url"
		name="my_plugin_options[webhook_url]"
		value="<?php echo esc_attr( $url ); ?>"
		class="regular-text"
	/>
	<?php
}

function my_plugin_enabled_field_callback() {
	$options = get_option( 'my_plugin_options', array() );
	$enabled = ! empty( $options['enabled'] );
	?>
	<label>
		<input
			type="checkbox"
			name="my_plugin_options[enabled]"
			value="1"
			<?php checked( $enabled ); ?>
		/>
		<?php esc_html_e( 'Enable the integration', 'my-plugin' ); ?>
	</label>
	<?php
}

/**
 * Recursively sanitize the array option against a known schema.
 *
 * @param array $input Raw submitted value.
 * @return array Sanitized value.
 */
function my_plugin_sanitize_options( $input ) {
	$clean = array();

	if ( isset( $input['api_key'] ) ) {
		$clean['api_key'] = sanitize_text_field( wp_unslash( $input['api_key'] ) );
	}

	if ( isset( $input['webhook_url'] ) ) {
		$clean['webhook_url'] = esc_url_raw( wp_unslash( $input['webhook_url'] ) );
	}

	$clean['enabled'] = ! empty( $input['enabled'] ) ? 1 : 0;

	return $clean;
}

/*
-------------------------------------------------------------------------
 * Add the admin menu page (gated by manage_options).
 * ---------------------------------------------------------------------- */
add_action( 'admin_menu', 'my_plugin_add_settings_page' );
function my_plugin_add_settings_page() {
	add_options_page(
		__( 'My Plugin Settings', 'my-plugin' ),
		__( 'My Plugin', 'my-plugin' ),
		'manage_options',
		'my-plugin',
		'my_plugin_render_settings_page'
	);
}

function my_plugin_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<form method="post" action="options.php">
			<?php
			settings_fields( 'my_plugin_group' );
			do_settings_sections( 'my-plugin' );
			submit_button();
			?>
		</form>
	</div>
	<?php
}
