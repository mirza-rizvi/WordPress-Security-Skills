<?php
/**
 * Secure WordPress authentication and session reference.
 *
 * Demonstrates the core primitives every login path should build on:
 *  - Brute-force throttling via the wp_authenticate_user filter plus the
 *    wp_login_failed / wp_login actions, with a transient counter keyed on
 *    username + hashed REMOTE_ADDR.
 *  - Uniform login error text via the login_errors filter, so the login
 *    page cannot be used to enumerate accounts.
 *  - Session destruction when identity or trust changes (password reset,
 *    password change, role elevation, admin-forced logout).
 *  - A custom login form that keeps core in charge of credential checking,
 *    cookies, and redirects (wp_signon + nonce + wp_safe_redirect).
 *
 * Every hook and function used here exists in WordPress core and is linked
 * from this skill's SKILL.md to its developer.wordpress.org page.
 */

defined( 'ABSPATH' ) || exit;

/*
 * Throttle policy: 5 failures per username+IP pair, sliding 15-minute window.
 * Tune per site, but never ship a login endpoint with no throttling at all:
 * WordPress core applies no rate limiting to wp-login.php or wp_signon().
 */
const MYAUTH_MAX_ATTEMPTS   = 5;
const MYAUTH_LOCKOUT_WINDOW = 15 * MINUTE_IN_SECONDS;
const MYAUTH_TRANSIENT_BASE = 'myauth_throttle_';

/* -------------------------------------------------------------------------
 * Client IP used for rate limiting.
 *
 * There is no core get_client_ip() helper. Read $_SERVER['REMOTE_ADDR']:
 * it is the only address the web server itself observed. X-Forwarded-For
 * and friends are client-controlled request headers; trusting them lets an
 * attacker rotate a fresh "IP" on every request and defeat IP-keyed
 * throttling entirely. Only map to a forwarded header when the direct
 * peer is a trusted proxy you control.
 * ---------------------------------------------------------------------- */
function myauth_client_ip() {
	// phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- REMOTE_ADDR is set by the web server, not user input.
	$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';

	return is_string( $ip ) ? $ip : '';
}

/* -------------------------------------------------------------------------
 * Throttle bucket key: username + IP, hashed.
 *
 * Why the compound key:
 *  - IP only: everyone behind one NAT or office proxy shares a bucket, so a
 *    single careless user locks out a whole network.
 *  - Username only: an attacker can deliberately lock a victim out of their
 *    account (denial of service) by spamming failures for that name.
 *  - Username + IP: one credential-stuffing campaign gets throttled while
 *    unrelated users stay unaffected. The username is lowercased so "Admin"
 *    and "admin" share a bucket; the IP is hashed so raw addresses are not
 *    persisted in the options table under attacker-controlled names.
 * ---------------------------------------------------------------------- */
function myauth_throttle_key( $username ) {
	$ip = myauth_client_ip();

	return MYAUTH_TRANSIENT_BASE . md5( strtolower( (string) $username ) . '|' . $ip );
}

/* -------------------------------------------------------------------------
 * Increment the counter on every failed login.
 *
 * wp_login_failed fires for wrong passwords, unknown users, and also for
 * attempts our throttle blocks (wp_authenticate() fires it whenever the
 * authenticate filter chain returns a WP_Error). Blocked attempts therefore
 * extend the lockout: sustained guessing does not wait out a fixed window.
 * ---------------------------------------------------------------------- */
add_action( 'wp_login_failed', 'myauth_record_failed_login' );
function myauth_record_failed_login( $username ) {
	$username = (string) $username;

	// Key the submitted identifier. If it resolved to an account through a
	// different name (email login), key the canonical login too, or the
	// lockout check on the WP_User would never see the failures.
	$keys = array( myauth_throttle_key( $username ) );
	$user = get_user_by( 'login', $username );
	if ( ! $user ) {
		$user = get_user_by( 'email', $username );
	}
	if ( $user && strtolower( $user->user_login ) !== strtolower( $username ) ) {
		$keys[] = myauth_throttle_key( $user->user_login );
	}

	foreach ( $keys as $key ) {
		// Re-setting the transient restarts its TTL, so the window slides
		// forward with sustained attempts instead of expiring mid-attack.
		set_transient( $key, (int) get_transient( $key ) + 1, MYAUTH_LOCKOUT_WINDOW );
	}
}

/* -------------------------------------------------------------------------
 * Enforce the throttle.
 *
 * wp_authenticate_user runs inside wp_authenticate_username_password() and
 * wp_authenticate_email_password() AFTER core has verified the credentials,
 * and before wp_set_auth_cookie() is ever reached. Returning a WP_Error
 * here blocks the login; returning anything else passes through.
 * ---------------------------------------------------------------------- */
add_filter( 'wp_authenticate_user', 'myauth_check_throttle', 10, 2 );
function myauth_check_throttle( $user, $password ) {
	// A previous check already failed (unknown user, bad password). Return
	// the original error untouched instead of masking it with our own.
	if ( is_wp_error( $user ) ) {
		return $user;
	}

	$count = (int) get_transient( myauth_throttle_key( $user->user_login ) );
	if ( MYAUTH_MAX_ATTEMPTS <= $count ) {
		return new WP_Error(
			'myauth_too_many_attempts',
			sprintf(
				/* translators: %d: number of minutes. */
				esc_html__( 'Too many failed logins. Try again in %d minutes.', 'my-auth' ),
				(int) ( MYAUTH_LOCKOUT_WINDOW / MINUTE_IN_SECONDS )
			)
		);
	}

	return $user;
}

/* -------------------------------------------------------------------------
 * Clear the counter on success.
 *
 * wp_login fires only after a fully successful sign-on. Without this, a
 * legitimate user who once hit 4 failures stays one typo away from a
 * lockout forever (until the transient TTL expires on its own).
 * ---------------------------------------------------------------------- */
add_action( 'wp_login', 'myauth_clear_failed_logins', 10, 1 );
function myauth_clear_failed_logins( $user_login ) {
	delete_transient( myauth_throttle_key( $user_login ) );
}

/* -------------------------------------------------------------------------
 * Uniform login errors (anti user-enumeration).
 *
 * WordPress' default messages differ for unknown usernames ("invalid
 * username") and known ones ("incorrect password for username X"), so the
 * login form works as an account-existence oracle. Replacing the whole
 * error block with one static message removes that signal for every
 * login surface that goes through wp-login.php.
 *
 * The filtered value is echoed unescaped, so return only static, escaped
 * text. Never interpolate request data back into it.
 * ---------------------------------------------------------------------- */
add_filter( 'login_errors', 'myauth_uniform_login_error' );
function myauth_uniform_login_error( $errors ) {
	unset( $errors );

	return esc_html__( 'Invalid username or password.', 'my-auth' );
}

/* -------------------------------------------------------------------------
 * Session destruction when identity or trust changes.
 *
 * Auth cookies stay valid as long as their session token exists in the
 * user's session store. Changing the password alone does NOT invalidate
 * issued cookies; only destroying the sessions does.
 * ---------------------------------------------------------------------- */

/**
 * Password reset through the "lost your password?" flow.
 *
 * after_password_reset fires when an anonymous visitor (or the user) sets a
 * new password from a reset link. Every existing session could belong to an
 * attacker who knew the old credentials, so destroy ALL sessions for the
 * account. wp_destroy_all_sessions() only touches the current user, which
 * is not the account owner here — use WP_Session_Tokens::get_instance().
 */
add_action( 'after_password_reset', 'myauth_destroy_sessions_after_reset' );
function myauth_destroy_sessions_after_reset( $user ) {
	WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
}

/**
 * Password change through the profile screen.
 *
 * profile_update fires on every user update, so compare the stored hash with
 * the pre-update one and act only on real password changes. A password
 * change by the user themselves kills every OTHER session (a stolen cookie
 * in an attacker's browser dies) while the current session survives so the
 * user is not logged out of the device they are using. When someone else
 * (an admin) changed the password, no current session can be assumed:
 * destroy everything.
 */
add_action( 'profile_update', 'myauth_destroy_sessions_on_password_change', 10, 2 );
function myauth_destroy_sessions_on_password_change( $user_id, $old_user_data ) {
	$user = get_userdata( $user_id );
	if ( ! $user instanceof WP_User || ! $old_user_data instanceof WP_User ) {
		return;
	}
	if ( $user->user_pass === $old_user_data->user_pass ) {
		return; // Password untouched; nothing to revoke.
	}

	if ( get_current_user_id() === (int) $user_id ) {
		// Keep this device signed in, evict every other session token.
		wp_destroy_other_sessions();
	} else {
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
	}
}

/**
 * Role elevation or demotion.
 *
 * Sessions outlive role changes: a low-privilege session that survives a
 * promotion keeps working, and a session that survives a demotion can keep
 * its old capabilities until capabilities are re-evaluated. Destroying all
 * sessions forces a fresh login under the new trust level on every device.
 */
add_action( 'profile_update', 'myauth_destroy_sessions_on_role_change', 10, 2 );
function myauth_destroy_sessions_on_role_change( $user_id, $old_user_data ) {
	$user = get_userdata( $user_id );
	if ( ! $user instanceof WP_User || ! $old_user_data instanceof WP_User ) {
		return;
	}
	if ( (array) $user->roles === (array) $old_user_data->roles ) {
		return; // Roles unchanged.
	}

	WP_Session_Tokens::get_instance( $user_id )->destroy_all();
}

/**
 * Administrator forces a logout for an arbitrary account (suspected
 * compromise, offboarding).
 *
 * The wp_destroy_*_sessions() helpers operate on the CURRENT user only.
 * For a different account go through WP_Session_Tokens::get_instance().
 * This is a state-changing privileged action: verify the capability AND a
 * nonce at the callsite before calling it.
 */
function myauth_admin_force_logout( $user_id ) {
	if ( ! current_user_can( 'edit_users' ) ) {
		return new WP_Error(
			'myauth_forbidden',
			esc_html__( 'You are not allowed to manage user sessions.', 'my-auth' )
		);
	}

	// The admin-screen button that calls this must have rendered
	// wp_nonce_field( 'myauth_force_logout_' . $user_id ) and this routine
	// must be reached only after check_admin_referer( ... ) passed.
	WP_Session_Tokens::get_instance( absint( $user_id ) )->destroy_all();

	return true;
}

/* -------------------------------------------------------------------------
 * Custom login form: core does the security work.
 *
 * A front-end login page is fine — rolling your own credential check is not.
 * This handler:
 *   1. verifies a nonce (check_admin_referer) so third-party sites cannot
 *      silently sign visitors in (login CSRF);
 *   2. delegates credential checking to wp_signon(), which runs the full
 *      wp_authenticate_username_password() flow: user lookup, the
 *      wp_check_password() bcrypt comparison, all authenticate filters
 *      (including the throttle above), and core cookie issuance;
 *   3. re-validates any client-supplied redirect target with
 *      wp_validate_redirect() before wp_safe_redirect(), so redirect_to
 *      cannot be used as an open redirect into a phishing page.
 *
 * Runs on init because wp_signon() sends auth cookie headers, which must
 * happen before any output.
 * ---------------------------------------------------------------------- */
add_action( 'init', 'myauth_handle_login_post' );
function myauth_handle_login_post() {
	if ( empty( $_POST['myauth_login'] ) ) {
		return;
	}

	check_admin_referer( 'myauth_login', 'myauth_nonce' );

	$username = isset( $_POST['myauth_log'] ) ? sanitize_user( wp_unslash( $_POST['myauth_log'] ), true ) : '';
	// Do not sanitize passwords: they may legitimately contain any character.
	$password = isset( $_POST['myauth_pwd'] ) ? (string) $_POST['myauth_pwd'] : '';
	$remember = ! empty( $_POST['myauth_remember'] );
	$redirect = isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : '';

	$user = wp_signon(
		array(
			'user_login'    => $username,
			'user_password' => $password,
			'remember'      => $remember,
		),
		''
	);

	if ( is_wp_error( $user ) ) {
		// Redirect with a flag instead of printing the underlying error:
		// the login_errors filter owns failure messaging, and the generic
		// page text keeps the account-existence oracle closed here too.
		wp_safe_redirect( home_url( '/login/?myauth=failed' ) );
		exit;
	}

	// wp_validate_redirect() allows only same-host URLs and falls back to
	// home_url( '/' ) for anything else; wp_safe_redirect() re-validates.
	$target = wp_validate_redirect( $redirect, home_url( '/' ) );
	wp_safe_redirect( $target );
	exit;
}

/**
 * The form itself: a nonce field plus autocomplete-safe inputs. The fixed
 * redirect_to points at home; never echo a request parameter back into it.
 */
add_shortcode( 'myauth_login_form', 'myauth_render_login_form' );
function myauth_render_login_form() {
	if ( is_user_logged_in() ) {
		return '<p>' . esc_html__( 'You are already signed in.', 'my-auth' ) . '</p>';
	}

	ob_start();
	?>
	<form method="post" action="">
		<?php wp_nonce_field( 'myauth_login', 'myauth_nonce' ); ?>
		<p>
			<label for="myauth_log"><?php echo esc_html__( 'Username', 'my-auth' ); ?></label>
			<input type="text" id="myauth_log" name="myauth_log" autocomplete="username" required>
		</p>
		<p>
			<label for="myauth_pwd"><?php echo esc_html__( 'Password', 'my-auth' ); ?></label>
			<input type="password" id="myauth_pwd" name="myauth_pwd" autocomplete="current-password" required>
		</p>
		<p>
			<label>
				<input type="checkbox" name="myauth_remember" value="1">
				<?php echo esc_html__( 'Remember me', 'my-auth' ); ?>
			</label>
		</p>
		<input type="hidden" name="redirect_to" value="<?php echo esc_url( home_url( '/' ) ); ?>">
		<button type="submit" name="myauth_login" value="1"><?php echo esc_html__( 'Sign in', 'my-auth' ); ?></button>
	</form>
	<?php
	return (string) ob_get_clean();
}
