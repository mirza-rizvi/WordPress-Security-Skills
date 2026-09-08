<?php
/**
 * Dependency and supply-chain security reference.
 *
 * Shows the four load-bearing defenses for third-party code:
 *  1. Gate loading on declared PHP / WordPress minimums.
 *  2. Enqueue core handles instead of bundling stale library copies.
 *  3. Pin exact versions and add Subresource Integrity to CDN assets.
 *  4. Confine local includes to the plugin's own reviewed files.
 *
 * Runtime code loading from the network (eval, remote include) appears only in
 * comment blocks: there is no hardened variant to demonstrate, so nothing in
 * this file executes a fetched payload.
 *
 * Integration-only example; not an installable plugin. Requires WordPress 6.2+
 * and PHP 7.4+, a plugin bootstrap, assets/js/app.js beside this file, and
 * reports/monthly-sales.php + reports/yearly-totals.php beside this file.
 * These project assets/templates are not supplied. See ../SKILL.md for setup.
 *
 * @package my-plugin
 */

defined( 'ABSPATH' ) || exit;

/*
|--------------------------------------------------------------------------
| 1. Minimum runtime gate.
|--------------------------------------------------------------------------
|
| Guard the PHP and WordPress minimums with version_compare() and refuse to
| load on anything older. Old stacks keep collecting exploits, and the CDN
| helper below requires the WP_HTML_Tag_Processor class (WordPress 6.2+).
|
| A top-level return inside a plugin file stops loading without fatals.
*/

const MY_PLUGIN_MIN_PHP = '7.4';
const MY_PLUGIN_MIN_WP  = '6.2';

if ( version_compare( PHP_VERSION, MY_PLUGIN_MIN_PHP, '<' )
	|| version_compare( get_bloginfo( 'version' ), MY_PLUGIN_MIN_WP, '<' ) ) {
	return;
}

/*
|--------------------------------------------------------------------------
| 2. Core handles first.
|--------------------------------------------------------------------------
|
| WordPress registers jQuery, Underscore, Backbone, media libraries, and the
| block-editor React build under documented handles (see the handle table in
| the wp_register_script() docs). Bundled duplicates drift out of date and
| conflict with plugins and themes that rely on the core version, which core
| patches and you do not.
*/

// ❌ Insecure: ships jQuery 1.12.4 next to core's maintained copy.
// wp_enqueue_script( 'my-plugin-jquery', plugins_url( 'vendor/jquery-1.12.4.min.js', __FILE__ ), array(), '1.12.4' );

add_action( 'wp_enqueue_scripts', 'my_plugin_enqueue_assets' );

/**
 * Enqueue assets using core handles wherever one exists.
 *
 * @return void
 */
function my_plugin_enqueue_assets() {
	// ✅ Secure: ask for the handle; core picks the version it ships and patches.
	wp_enqueue_script( 'jquery' );

	// First-party bundle: local file, exact version string for cache busting.
	wp_enqueue_script(
		'my-plugin-app',
		plugins_url( 'assets/js/app.js', __FILE__ ),
		array( 'jquery' ),
		'1.4.2',
		array(
			'strategy'  => 'defer',
			'in_footer' => true,
		)
	);
}

/*
|--------------------------------------------------------------------------
| 3. CDN assets: exact version URL plus Subresource Integrity.
|--------------------------------------------------------------------------
|
| Self-host if you can. If the asset must come from a CDN, pin an exact
| version (never latest.js) and attach integrity + crossorigin attributes so
| a swapped file cannot execute.
|
| Compute the hash for each pinned file once per version bump:
|
|   curl --fail --silent --show-error --location \
|     https://cdn.jsdelivr.net/npm/chart.js@4.1.2/dist/chart.umd.min.js -o chart.js && \
|     openssl dgst -sha384 -binary chart.js | openssl base64 -A
|
| Prefix the result with "sha384-" and store it below. For stylesheets, mirror
| the same allowlist through the style_loader_tag filter.
*/

/**
 * Map of CDN handles to their pinned source, integrity hash, and version.
 *
 * @return array<string, array<string, string>> Handle => {src, integrity, version}.
 */
function my_plugin_cdn_assets() {
	return array(
		'my-plugin-charts' => array(
			'src'       => 'https://cdn.jsdelivr.net/npm/chart.js@4.1.2/dist/chart.umd.min.js',
			// SHA-384 of the pinned CDN bytes; recompute on each asset update.
			'integrity' => 'sha384-XrBQI0kDtx9BrWRwpNT9b09Lwj2M8nnf2tO+zYxJ6IyROBmC05l4AdGWLt2ix1cs',
			// Matches the version pinned in the src URL path.
			'version'   => '4.1.2',
		),
	);
}

add_action( 'wp_enqueue_scripts', 'my_plugin_enqueue_cdn_assets' );

/**
 * Enqueue the pinned CDN scripts.
 *
 * @return void
 */
function my_plugin_enqueue_cdn_assets() {
	foreach ( my_plugin_cdn_assets() as $handle => $asset ) {
		// Version matches the pinned URL; load in the footer.
		wp_enqueue_script( $handle, $asset['src'], array(), $asset['version'], true );
	}
}

add_filter( 'script_loader_tag', 'my_plugin_add_sri_to_cdn_script', 10, 3 );

/**
 * Add Subresource Integrity attributes to the pinned CDN scripts.
 *
 * SRI makes the browser refuse to run a file whose bytes no longer match the
 * recorded hash, which is exactly the failure mode of a compromised CDN.
 *
 * @param string $tag    The <script> tag for the enqueued script.
 * @param string $handle The script's registered handle.
 * @param string $src    The script's source URL.
 * @return string The filtered script tag.
 */
function my_plugin_add_sri_to_cdn_script( $tag, $handle, $src ) {
	$assets = my_plugin_cdn_assets();

	if ( ! isset( $assets[ $handle ] ) ) {
		return $tag;
	}

	// Accept only the exact pin or WordPress's exact version-query variant.
	// Prefix matching accepts sibling paths; returning the old tag fails open.
	$asset           = $assets[ $handle ];
	$allowed_sources = array( $asset['src'], add_query_arg( 'ver', $asset['version'], $asset['src'] ) );
	if ( ! is_string( $src ) || ! in_array( $src, $allowed_sources, true ) ) {
		return '';
	}

	$tags = new WP_HTML_Tag_Processor( $tag );

	// Earlier filters can change the tag without changing the supplied $src.
	if ( ! $tags->next_tag( 'script' ) || $src !== $tags->get_attribute( 'src' ) ) {
		return '';
	}
	$tags->set_attribute( 'integrity', $asset['integrity'] );
	$tags->set_attribute( 'crossorigin', 'anonymous' );

	return $tags->get_updated_html();
}

/*
|--------------------------------------------------------------------------
| 4. Local includes: allowlist + validate_file() + realpath containment.
|--------------------------------------------------------------------------
|
| Templates that ship inside the plugin may be loaded by name, but the name
| is still treated as input: allowlist it, validate it, resolve it, and
| confirm the resolved path stays inside the plugin's own directory. This
| loads code you shipped and reviewed -- never anything fetched from the
| network. See the filesystem-security skill for the full pattern.
*/

/**
 * Render a report template that ships inside the plugin.
 *
 * @param string $report_name Template name, e.g. "monthly-sales".
 * @return void
 */
function my_plugin_render_report_template( $report_name ) {
	$allowed = array( 'monthly-sales', 'yearly-totals' );

	$report_name = sanitize_file_name( (string) $report_name );

	if ( ! in_array( $report_name, $allowed, true ) ) {
		return;
	}

	// validate_file() rejects traversal, drive letters, and stream wrappers.
	if ( 0 !== validate_file( $report_name ) ) {
		return;
	}

	$base   = realpath( __DIR__ . '/reports' );
	$target = realpath( __DIR__ . '/reports/' . $report_name . '.php' );

	if ( false === $base || false === $target
		|| 0 !== strpos( $target, $base . '/' ) ) {
		return;
	}

	// ✅ Secure: resolved file is inside the plugin and on the allowlist.
	include $target;
}

/*
|--------------------------------------------------------------------------
| 5. Never ship these: runtime code loading from the network.
|--------------------------------------------------------------------------
|
| Each pattern below executes whatever a remote server returns. They appear
| only as comments because there is no hardened variant: the fix is to not do
| it. Updates ship through the WordPress.org update channel, or a signed
| self-hosted channel. Update packages travel over the network too; install
| them through the verified update workflow, not eval/include of fetched bytes.
|
| ❌ Insecure: eval() of a fetched body is RCE by design, and the plugin dies
| when the remote host dies.
|
| $response = wp_remote_get( 'https://example.com/updater.php' );
| $body     = wp_remote_retrieve_body( $response );
| eval( $body );
|
| ❌ Insecure: include of a payload pulled in over HTTP, or a phar:// stream,
| which can trigger deserialization on read.
|
| include 'php://temp'; // if the bytes in it were fetched from the network
| include 'phar://' . $attachment_path;
|
| ❌ Insecure: removed dynamic-code constructs. create_function() was removed
| in PHP 8; the preg /e modifier was removed in PHP 7. Both execute strings
| as code, which is the point.
|
| $double = create_function( '$a', 'return $a * 2;' );
| $bold   = preg_replace( '/<b>(.*?)<\/b>/e', 'strtoupper("$1")', $html );
*/
