---
name: authentication-session-security
description: >
  Use when code logs users in or out, sets or clears auth cookies, manages
  session tokens, throttles failed logins, or builds a custom login form in
  WordPress. Enforces wp_signon() and core session primitives over hand-rolled
  credential checks, adds brute-force throttling via the wp_authenticate_user
  filter keyed on username + IP, destroys sessions after password or role
  changes, makes login error messages uniform to stop user enumeration, and
  validates redirect_to with wp_safe_redirect() to close open redirects.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, authentication, sessions, login"
---

# Authentication & session security

## When to use this skill

Use this skill whenever code touches the login or session lifecycle:

- Signing users in with `wp_signon()` or a custom login form / endpoint.
- Any `wp_ajax_nopriv_` or REST route that accepts a username and password.
- Reading or setting auth cookies, or handling "remember me".
- Creating, listing, or destroying sessions (`WP_Session_Tokens`).
- Handling `wp_login_failed`, `wp_login`, password changes, or role changes.
- Building a front-end login page that redirects via `redirect_to`.
- Gating behavior on `is_user_logged_in()`.

WordPress ships complete, battle-tested authentication primitives: `wp_signon()`
for credential checks, signed hashed auth cookies, and per-user session stores.
Vulnerabilities come from agents rolling custom auth beside them — unthrottled
custom login endpoints, hand-rolled cookies, sessions kept alive after a
privilege change, and user enumeration through login error messages.

Related: see the `secrets-credentials-management` skill for how secrets and
hashes are stored, the `capability-permission-checks` skill for authorization
after login, and the `input-sanitization-validation` skill for redirect input
handling.

## Core principles (and why they matter)

1. **Never implement credential checking yourself.** `wp_signon()` runs the full
   `wp_authenticate_username_password()` flow: user lookup, `wp_check_password()`
   against the stored bcrypt hash, every `authenticate` filter, and cookie
   issuance. A custom `md5()`/`sha1()`/`==` comparison is a catastrophic bug —
   it bypasses password hashing policy and usually leaks timing or stores
   replayable secrets.
2. **Throttle failed logins; core has no rate limiting.** WordPress applies zero
   rate limiting to `wp-login.php` or `wp_signon()`. Increment a transient
   counter on `wp_login_failed`, block in the `wp_authenticate_user` filter once
   it exceeds a threshold, and clear it on `wp_login`. Key on username + IP
   combined: IP-only punishes everyone behind one NAT gateway, username-only
   lets an attacker lock a victim out of their own account.
3. **Read IPs from `$_SERVER['REMOTE_ADDR']` only.** There is no core
   `get_client_ip()`. `X-Forwarded-For` and similar headers are client-
   controlled; trusting them lets an attacker rotate a fresh "IP" per request
   and defeat IP-keyed throttling.
4. **Destroy sessions when identity or trust changes.** Core auth cookies embed
   a fragment of the stored password hash, so a password change invalidates
   previously issued cookies — but the session tokens themselves remain in the
   store. `wp_destroy_other_sessions()` after a password change;
   `wp_destroy_all_sessions()` or
   `WP_Session_Tokens::get_instance( $user_id )->destroy_all()` when an admin
   forces a logout or a role is elevated or demoted.
5. **Let core set auth cookies.** Never `setcookie()` your own login-state
   token. Core cookies are HMAC-signed, expiring, and tied to the session
   store. Tune core behavior through verified filters only:
   `auth_cookie_expiration` (duration), `secure_auth_cookie` /
   `secure_logged_in_cookie` (HTTPS-only).
6. **Do not leak account existence.** Default login messages differ for unknown
   usernames vs wrong passwords, giving attackers a free account-existence
   oracle. The `login_errors` filter can make every failure message uniform.
7. **Validate redirects; authentication is not authorization.** A login form
   that trusts `redirect_to` is an open redirect (phishing pivot) — pass it
   through `wp_validate_redirect()` and send with `wp_safe_redirect()`. And
   `is_user_logged_in()` proves identity only; gate actions with
   `current_user_can()`.

## Step-by-step implementation

1. Sign users in with `wp_signon()` and check the result:
   ```php
   $user = wp_signon(
       array(
           'user_login'    => $username,
           'user_password' => $password,
           'remember'      => $remember,
       ),
       ''
   );
   if ( is_wp_error( $user ) ) {
       // Generic failure path; see the login_errors filter below.
   }
   ```
   Call it before output is sent (e.g. on `init`); it sets cookie headers.
2. Throttle failed logins. Register once — these hooks fire for every login
   surface, including `wp-login.php`, `wp_ajax_nopriv_` handlers, and REST
   routes that go through `wp_signon()`:
   ```php
   // Increment on every failure (wrong password, unknown user, blocked attempt).
   add_action( 'wp_login_failed', 'my_plugin_record_failed_login' );

   // Block once the counter exceeds the threshold.
   add_filter( 'wp_authenticate_user', 'my_plugin_check_throttle', 10, 2 );
   // The callback: return a WP_Error when the counter is over the limit;
   // return $user untouched otherwise (it may already be a WP_Error).

   // Reset on success so one bad week does not lock the user out.
   add_action( 'wp_login', 'my_plugin_clear_failed_logins', 10, 2 );
   ```
   Counter: `set_transient( $key, $count, $window )` with
   `$key = 'my_plugin_throttle_' . md5( strtolower( $username ) . '|' . $ip )`.
   Sensible defaults: 5 attempts per 15 minutes.
3. Make login failures uniform with the `login_errors` filter. The filtered
   value is echoed unescaped — return only static, escaped text.
4. Destroy sessions on identity/trust changes:
   - Password reset from a reset link: hook `after_password_reset`, call
     `WP_Session_Tokens::get_instance( $user->ID )->destroy_all()`.
   - Password change via profile screen: hook `profile_update`, compare the
     stored hash with the old one; if changed and the actor is the user, call
     `wp_destroy_other_sessions()`, else `destroy_all()` for that user.
   - Role elevation/demotion: hook `profile_update`, compare roles, then
     `WP_Session_Tokens::get_instance( $user_id )->destroy_all()`.
   - Current user logout-everywhere: `wp_destroy_all_sessions()`.
   ```php
   add_filter( 'auth_cookie_expiration', 'my_plugin_cookie_expiry', 10, 3 );
   function my_plugin_cookie_expiry( $length, $user_id, $remember ) {
       if ( ! $remember && user_can( $user_id, 'manage_options' ) ) {
           return 2 * DAY_IN_SECONDS; // Short admin sessions unless "remember me".
       }
       return $length;
   }
   ```
6. After login, redirect only to validated targets:
   ```php
   $target = wp_validate_redirect( $redirect_to, home_url( '/' ) );
   wp_safe_redirect( $target );
   exit;
   ```
7. Custom login forms need a nonce (`wp_nonce_field` at render,
   `check_admin_referer` at submit) so third-party sites cannot silently sign
   visitors in, and must still delegate the credential check to `wp_signon()`.
8. After login, check capabilities before privileged actions:
   `current_user_can( 'edit_posts' )` or `user_can( $user_id, $cap )`.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Authentication & session security — cheatsheet](references/cheatsheet.md) | Choosing the applicable WordPress API or control for authentication and session management. |
| [Authentication & session security — deployment checklist](references/checklist.md) | Before final verification of the authentication & session security controls. |
| [Secure authentication and sessions](references/secure-authentication.php) | Implementing the login, throttling, session-revocation, and safe-redirect flow. |

## Common AI mistakes / anti-patterns

### Mistake 1 — Rolling a custom credential check

```php
// ❌ Insecure: md5 comparison beside core auth; bypasses bcrypt and any plugin's checks.
$user = get_user_by( 'login', $_POST['user'] );
if ( $user && md5( $_POST['pass'] ) === get_user_meta( $user->ID, 'pass_hash', true ) ) {
    my_plugin_grant_access( $user );
}
```

```php
// ✅ Secure: wp_signon() runs the entire core flow, including wp_check_password().
add_action( 'init', 'my_plugin_handle_login' );
function my_plugin_handle_login() {
    if ( empty( $_POST['my_plugin_login'] ) ) {
        return;
    }
    check_admin_referer( 'my_plugin_login', 'my_plugin_nonce' );
    $user = wp_signon( array(
        'user_login'    => sanitize_user( wp_unslash( $_POST['user'] ), true ),
        'user_password' => isset( $_POST['pass'] ) ? (string) $_POST['pass'] : '',
        'remember'      => ! empty( $_POST['remember'] ),
    ), '' );
    if ( is_wp_error( $user ) ) {
        wp_safe_redirect( home_url( '/login/?my_plugin=failed' ) );
        exit;
    }
}
```

### Mistake 2 — Unthrottled custom login endpoint

```php
// ❌ Insecure: a nopriv AJAX login with no rate limit — unlimited online guessing.
add_action( 'wp_ajax_nopriv_my_login', 'my_plugin_ajax_login' );
function my_plugin_ajax_login() {
    $user = wp_signon( array(
        'user_login'    => sanitize_user( wp_unslash( $_POST['log'] ), true ),
        'user_password' => (string) $_POST['pwd'],
    ), '' );
    wp_send_json( is_wp_error( $user ) ? array( 'ok' => false ) : array( 'ok' => true ) );
}
```

```php
// ✅ Secure: same handler, but the site-wide throttle hooks are installed once:
add_action( 'wp_login_failed', 'my_plugin_record_failed_login' );
add_filter( 'wp_authenticate_user', 'my_plugin_check_throttle', 10, 2 );
add_action( 'wp_login', 'my_plugin_clear_failed_logins', 10, 2 );
// wp_signon() routes through wp_authenticate(), so AJAX, REST, and
// wp-login.php logins all pass the same counter and lockout.
```

### Mistake 3 — Throttle keyed on IP only

```php
// ❌ Insecure: 5 failures per IP; one office NAT or CGNAT locks out hundreds
// of unrelated users, and X-Forwarded-For is attacker-controlled anyway.
$key = 'throttle_' . $_SERVER['REMOTE_ADDR'];
```

```php
// ✅ Secure: username + REMOTE_ADDR combined, IP hashed into the key.
$ip   = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
$key  = 'throttle_' . md5( strtolower( $username ) . '|' . $ip );
```

### Mistake 4 — Hand-rolled "remember me" cookie

```php
// ❌ Insecure: plaintext user id in a cookie is a one-line auth bypass.
setcookie( 'myauth', (string) $user_id, time() + MONTH_IN_SECONDS, '/' );
```

```php
// ✅ Secure: let wp_signon() / wp_set_auth_cookie() issue core cookies; the
// 'remember' credential already extends their lifetime. If a custom token is
// truly unavoidable, store only its hash server-side (wp_hash_password()) and
// compare with hash_equals() — but prefer core cookies.
$user = wp_signon( array(
    'user_login'    => $username,
    'user_password' => $password,
    'remember'      => true,
), '' );
```

### Mistake 5 — Treating a password rotation as complete revocation

```php
// ❌ Incomplete: core cookies stop validating (the cookie hash embeds part of
// the new password hash), but the old session tokens remain stored, and any
// flow that re-issues a cookie from a stored token keeps working.
function my_plugin_change_password( $user_id, $new_plaintext ) {
    wp_set_password( $new_plaintext, $user_id );
}
```

```php
// ✅ Secure: rotate the password, then evict every session for that account.
function my_plugin_change_password( $user_id, $new_plaintext ) {
    wp_set_password( $new_plaintext, $user_id );
    WP_Session_Tokens::get_instance( $user_id )->destroy_all();
}
// For self-service changes keep the current device signed in instead:
// wp_destroy_other_sessions() after wp_get_session_token() confirms a session.
```

### Mistake 6 — Verbose login errors and unvalidated `redirect_to`

```php
// ❌ Insecure: echoes which usernames exist and accepts any redirect target.
add_action( 'init', function () {
    $user = wp_signon( array(), '' );
    if ( is_wp_error( $user ) ) {
        echo $user->get_error_message(); // "invalid username" vs "incorrect password".
    }
    wp_redirect( $_GET['redirect_to'] ); // Attacker-chosen offsite URL.
    exit;
} );
```

```php
// ✅ Secure: uniform error text; validated redirect target.
add_filter( 'login_errors', 'my_plugin_uniform_login_error' );
function my_plugin_uniform_login_error() {
    return esc_html__( 'Invalid username or password.', 'my-plugin' );
}

$target = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '';
wp_safe_redirect( wp_validate_redirect( $target, home_url( '/' ) ) );
exit;
```

## Correct code examples

A complete commented module — throttle (`wp_authenticate_user` +
`wp_login_failed`/`wp_login`), uniform `login_errors`, session destruction on
password/role changes, and a custom login form using `wp_signon` +
`check_admin_referer` + `wp_safe_redirect` — is in
[`references/secure-authentication.php`](references/secure-authentication.php).

Also: [`references/checklist.md`](references/checklist.md) (deployment checklist)
and [`references/cheatsheet.md`](references/cheatsheet.md) (goal → API table).

## Checklist

- [ ] Every login path calls `wp_signon()`; no custom `md5`/`sha1`/`==` password comparison exists.
- [ ] Failed logins are throttled and the counter is keyed on username + IP (not IP alone).
- [ ] The throttle counter increments on `wp_login_failed`, is enforced in `wp_authenticate_user`, and clears on `wp_login`.
- [ ] Client IP comes from `$_SERVER['REMOTE_ADDR']`; `X-Forwarded-For` is not trusted.
- [ ] `login_errors` returns one uniform message; no username echo in failure output.
- [ ] Password resets destroy all sessions for the account (`after_password_reset`).
- [ ] Password changes destroy other sessions; role changes destroy all sessions for that user.
- [ ] No `setcookie()` call implements login state; core auth cookies are used.
- [ ] Cookie lifetime is tuned only via `auth_cookie_expiration` (and HTTPS-only via `secure_auth_cookie` / `secure_logged_in_cookie` where needed).
- [ ] Every `redirect_to` / post-login target passes `wp_validate_redirect()` before `wp_safe_redirect()`.
- [ ] Custom login forms include a nonce (`wp_nonce_field` + `check_admin_referer`).
- [ ] Post-login privileged actions check `current_user_can()` / `user_can()`, not just `is_user_logged_in()`.

## Official references

- [`wp_signon()`](https://developer.wordpress.org/reference/functions/wp_signon/)
- [`wp_authenticate()`](https://developer.wordpress.org/reference/functions/wp_authenticate/)
- [`wp_authenticate_user` filter](https://developer.wordpress.org/reference/hooks/wp_authenticate_user/)
- [`wp_login_failed` action](https://developer.wordpress.org/reference/hooks/wp_login_failed/)
- [`wp_login` action](https://developer.wordpress.org/reference/hooks/wp_login/)
- [`login_errors` filter](https://developer.wordpress.org/reference/hooks/login_errors/)
- [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/) / [`wp_clear_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_clear_auth_cookie/)
- [`wp_logout()`](https://developer.wordpress.org/reference/functions/wp_logout/)
- [`auth_cookie_expiration` filter](https://developer.wordpress.org/reference/hooks/auth_cookie_expiration/)
- [`secure_auth_cookie` filter](https://developer.wordpress.org/reference/hooks/secure_auth_cookie/)
- [`secure_logged_in_cookie` filter](https://developer.wordpress.org/reference/hooks/secure_logged_in_cookie/)
- [`wp_get_session_token()`](https://developer.wordpress.org/reference/functions/wp_get_session_token/) / [`wp_destroy_current_session()`](https://developer.wordpress.org/reference/functions/wp_destroy_current_session/) / [`wp_destroy_other_sessions()`](https://developer.wordpress.org/reference/functions/wp_destroy_other_sessions/) / [`wp_destroy_all_sessions()`](https://developer.wordpress.org/reference/functions/wp_destroy_all_sessions/)
- [`WP_Session_Tokens`](https://developer.wordpress.org/reference/classes/wp_session_tokens/)
- [`after_password_reset`](https://developer.wordpress.org/reference/hooks/after_password_reset/) / [`profile_update`](https://developer.wordpress.org/reference/hooks/profile_update/) actions
- [`wp_set_password()`](https://developer.wordpress.org/reference/functions/wp_set_password/)
- [`wp_hash_password()`](https://developer.wordpress.org/reference/functions/wp_hash_password/) / [`wp_check_password()`](https://developer.wordpress.org/reference/functions/wp_check_password/)
- [`wp_safe_redirect()`](https://developer.wordpress.org/reference/functions/wp_safe_redirect/) / [`wp_validate_redirect()`](https://developer.wordpress.org/reference/functions/wp_validate_redirect/)
- [`get_transient()`](https://developer.wordpress.org/reference/functions/get_transient/) / [`set_transient()`](https://developer.wordpress.org/reference/functions/set_transient/) / [`delete_transient()`](https://developer.wordpress.org/reference/functions/delete_transient/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/) / [`user_can()`](https://developer.wordpress.org/reference/functions/user_can/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
