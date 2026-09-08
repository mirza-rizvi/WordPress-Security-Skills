<?php
/**
 * Secure HTTP security headers reference module.
 *
 * Demonstrates: one baseline header policy on all three WordPress surfaces
 * (front-end via the wp_headers filter, wp-login.php via login_init, wp-admin
 * via admin_init), a CSP that ships Report-Only first with a per-response nonce
 * wired into enqueued and inline scripts, a custom session cookie with
 * Secure/HttpOnly/SameSite, HTTPS-only core auth cookies, and REST origin
 * restriction through core's allowlist filters.
 *
 * @package My_Plugin
 */

defined( 'ABSPATH' ) || exit;

/*
 * Surface wiring. WP::send_headers() applies wp_headers on front-end template
 * loads, before any output. login_init fires in wp-login.php before output;
 * login_head fires inside the login <head>, after output has started, so
 * header() would be a silent no-op there. admin_init fires in wp-admin before
 * the page renders.
 */
add_filter( 'wp_headers', 'myplugin_front_end_security_headers' );
add_action( 'login_init', 'myplugin_login_security_headers' );
add_action( 'admin_init', 'myplugin_admin_security_headers' );

/*
 * CSP nonce pipeline: attribute on our enqueued script tags, plus attributes on
 * every inline script tag printed through wp_get_inline_script_tag() (which is
 * where wp_add_inline_script() output goes).
 */
add_filter( 'script_loader_tag', 'myplugin_csp_script_loader_tag', 10, 2 );
add_filter( 'wp_inline_script_attributes', 'myplugin_csp_inline_script_attributes' );

add_action( 'wp_enqueue_scripts', 'myplugin_enqueue_front_end' );

/*
 * REST CORS: restrict which origins core may reflect. The allowed_http_origins
 * extension below is a site-specific choice; uncomment after editing the host.
 */
add_filter( 'http_origin', 'myplugin_restrict_http_origin' );
// add_filter( 'allowed_http_origins', 'myplugin_extra_allowed_origins' );

/*
 * Core auth cookies: force the Secure flag on HTTPS-only sites.
 */
add_filter( 'secure_auth_cookie', 'myplugin_force_secure_auth_cookie' );
add_filter( 'secure_logged_in_cookie', 'myplugin_force_secure_auth_cookie' );

/**
 * Baseline response headers for front-end template loads.
 *
 * wp_headers only fires on front-end main-query requests; login and admin are
 * wired separately below. Returning the headers here lets WP send them as one
 * batch, and keeps them visible to caching layers that read WP's header list.
 *
 * @param array $headers Headers WP is about to send.
 * @return array Filtered headers.
 */
function myplugin_front_end_security_headers( $headers ) {
	$headers['X-Content-Type-Options'] = 'nosniff';
	$headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';

	// SAMEORIGIN, not DENY: the Customizer and theme previews iframe the
	// front-end from the same origin, and oEmbed previews frame posts.
	$headers['X-Frame-Options'] = 'SAMEORIGIN';

	// Ship the policy observed first; flip the key to Content-Security-Policy
	// once the violation console is quiet.
	$headers['Content-Security-Policy-Report-Only'] = myplugin_csp_policy();

	// Optional, site-dependent: denies powerful browser features by default.
	// $headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()';

	$hsts = myplugin_hsts_header_value();
	if ( $hsts ) {
		$headers['Strict-Transport-Security'] = $hsts;
	}

	return $headers;
}

/**
 * Baseline headers for wp-login.php.
 *
 * Fires on login_init, before wp-login.php prints any HTML, so header() works.
 */
function myplugin_login_security_headers() {
	myplugin_send_security_headers();
}

/**
 * Baseline headers for wp-admin.
 *
 * admin_init runs after authentication and before any admin page output.
 */
function myplugin_admin_security_headers() {
	myplugin_send_security_headers();
}

/**
 * Shared header() implementation for the login and admin surfaces.
 *
 * Keep the values identical to the front-end set in
 * myplugin_front_end_security_headers(); one policy, three surfaces.
 */
function myplugin_send_security_headers() {
	if ( headers_sent() ) {
		return;
	}

	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'Content-Security-Policy-Report-Only: ' . myplugin_csp_policy() );

	$hsts = myplugin_hsts_header_value();
	if ( $hsts ) {
		header( 'Strict-Transport-Security: ' . $hsts );
	}
}

/**
 * HSTS value, only meaningful on sites that are HTTPS-only by policy.
 *
 * max-age is a commitment for the whole domain: once a browser caches it, a
 * broken certificate makes the site unreachable until the age expires. Server
 * layer config (nginx / .htaccess) is the better home; see the
 * wp-hardening-best-practices skill.
 *
 * @return string Header value, or empty string when the site is not HTTPS-only.
 */
function myplugin_hsts_header_value() {
	return is_ssl() ? 'max-age=31536000' : '';
}

/**
 * Per-response CSP nonce.
 *
 * NOT wp_create_nonce(): that returns a CSRF token, bound to the user and
 * session, reused across requests for the session window, and printed into
 * pages by design. A CSP nonce must be unpredictable and fresh per response.
 *
 * @return string 32 hex characters.
 */
function myplugin_csp_nonce() {
	static $nonce = null;

	if ( null === $nonce ) {
		$nonce = bin2hex( random_bytes( 16 ) );
	}

	return $nonce;
}

/**
 * The policy, shipped as Report-Only until violations are triaged.
 *
 * Caching note: a full-page cache freezes this string, including the nonce,
 * into cached HTML. Either exclude pages with this header from full-page
 * caching, or compute the header at the edge per request.
 *
 * @return string Directive list.
 */
function myplugin_csp_policy() {
	$directives = array(
		"default-src 'self'",
		"script-src 'self' 'nonce-" . myplugin_csp_nonce() . "'",
		// Enforcing style-src needs the same nonce treatment via the
		// style_loader_tag filter; keep it observed or self-only at first.
		"style-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'self'",
	);

	return implode( '; ', $directives );
}

/**
 * Attach the per-response nonce to our own enqueued script tags.
 *
 * Nonce only handles you ship: a blanket str_replace() across every script tag
 * claims trust in third-party output you do not control.
 *
 * @param string $tag    The <script> tag for the enqueued script.
 * @param string $handle The script handle.
 * @return string Filtered tag.
 */
function myplugin_csp_script_loader_tag( $tag, $handle ) {
	$nonced_handles = array( 'myplugin-frontend' );

	if ( ! in_array( $handle, $nonced_handles, true ) ) {
		return $tag;
	}

	return str_replace( '<script ', '<script nonce="' . esc_attr( myplugin_csp_nonce() ) . '" ', $tag );
}

/**
 * Nonce inline script tags, including wp_add_inline_script() output.
 *
 * Inline scripts do not pass through script_loader_tag: they are printed by
 * wp_get_inline_script_tag(), whose attributes flow through this filter. Under
 * an enforced CSP an inline script without the nonce is blocked, so core,
 * theme, and plugin inline scripts all need this once you enforce.
 *
 * @param array $attributes Key-value <script> tag attributes.
 * @return array Filtered attributes.
 */
function myplugin_csp_inline_script_attributes( $attributes ) {
	$attributes['nonce'] = myplugin_csp_nonce();

	return $attributes;
}

/**
 * Example enqueue: the handle list in myplugin_csp_script_loader_tag() is the
 * single source of truth for which tags get the nonce.
 */
function myplugin_enqueue_front_end() {
	wp_enqueue_script(
		'myplugin-frontend',
		plugins_url( 'js/frontend.js', __FILE__ ),
		array(),
		'1.0.0',
		true
	);

	// Printed inside a <script> tag built by wp_get_inline_script_tag(); the
	// wp_inline_script_attributes filter above gives it the nonce.
	wp_add_inline_script( 'myplugin-frontend', 'window.MYPLUGIN_BOOT = true;' );
}

/**
 * Custom session cookie with all three flags set (PHP 7.3+ options array).
 *
 * SameSite=None requires Secure=true or browsers reject the cookie entirely.
 * Default to Lax; use None only for a documented cross-site flow.
 *
 * @param string $token   Cookie value.
 * @param int    $expires Expiry timestamp; 0 for a session cookie.
 * @return bool True when the cookie header was sent.
 */
function myplugin_set_session_cookie( $token, $expires = 0 ) {
	if ( headers_sent() ) {
		return false;
	}

	return setcookie(
		'myplugin_session',
		$token,
		array(
			'expires'  => $expires,
			'path'     => '/',
			'domain'   => '',
			'secure'   => true,
			'httponly' => true,
			'samesite' => 'Lax',
		)
	);
}

/**
 * Per-user pages must not be cached where another user could read them.
 */
function myplugin_send_no_cache_headers() {
	if ( ! headers_sent() ) {
		nocache_headers();
	}
}

/**
 * Force the Secure flag on core auth cookies (HTTPS-only sites).
 *
 * Core already sends auth cookies with HttpOnly hardcoded to true in
 * wp_set_auth_cookie(); there is no auth_cookie_httponly hook. Core sends no
 * SameSite attribute, so browsers apply their default (Lax). Secure is the
 * filterable part, via secure_auth_cookie and secure_logged_in_cookie.
 *
 * @param bool $secure Whether the cookie should only be sent over HTTPS.
 * @return bool
 */
function myplugin_force_secure_auth_cookie( $secure ) {
	return true;
}

/**
 * Restrict the origins core may reflect into CORS headers.
 *
 * rest_send_cors_headers() reflects the request Origin into
 * Access-Control-Allow-Origin together with Access-Control-Allow-Credentials:
 * true, and does not consult the allowlist. An empty http_origin means core
 * sends no CORS headers at all.
 *
 * Recursion trap: is_allowed_http_origin() calls get_http_origin(), which
 * applies this very filter. Compare against get_allowed_http_origins()
 * directly; it parses admin_url()/home_url() and does not recurse.
 *
 * @param string $origin The request origin, possibly filtered already.
 * @return string The origin, or an empty string when not allowed.
 */
function myplugin_restrict_http_origin( $origin ) {
	if ( '' === $origin ) {
		return $origin;
	}

	if ( ! in_array( $origin, get_allowed_http_origins(), true ) ) {
		return '';
	}

	return $origin;
}

/**
 * Add a trusted partner origin to core's allowlist.
 *
 * get_allowed_http_origins() always includes the site's own admin and home
 * URLs over http and https. Extend, do not replace: replacing drops the
 * site's own origins. Wire up with:
 * add_filter( 'allowed_http_origins', 'myplugin_extra_allowed_origins' );
 *
 * @param array $origins Allowed origins.
 * @return array Filtered origins.
 */
function myplugin_extra_allowed_origins( $origins ) {
	$origins[] = 'https://partner.example';

	return $origins;
}
