# Authentication & session security — cheatsheet

Quick lookup: goal → core API → notes. All functions/filters/actions verified
against developer.wordpress.org.

## Login and logout

| Goal | Core API | Notes |
| --- | --- | --- |
| Check credentials and sign in | `wp_signon( $credentials, $secure_cookie )` | Only supported way to verify a password. Runs user lookup, `wp_check_password()`, all `authenticate` filters, sets cookies. Call before output. |
| Raw authentication without cookies | `wp_authenticate( $username, $password )` | Returns `WP_User` or `WP_Error`; does not set cookies. |
| Issue auth cookies for a user | `wp_set_auth_cookie( $user_id, $remember, $secure )` | Use only inside a verified login flow. |
| Log the current user out | `wp_logout()` | Clears auth cookies and destroys the current session. |
| Clear cookies only | `wp_clear_auth_cookie()` | Part of logout flow; rarely called alone. |
| Who is logged in | `is_user_logged_in()`, `wp_get_current_user()` | Authentication only — not authorization. |

## Brute-force throttling

| Goal | Core API | Notes |
| --- | --- | --- |
| Count failed attempts | `wp_login_failed` action | Fires for wrong passwords, unknown users, and blocked attempts. |
| Block when over threshold | `wp_authenticate_user` filter | Return a `WP_Error` to stop the login; return `$user` untouched otherwise. |
| Reset counter on success | `wp_login` action | Fires only after a fully successful sign-on. |
| Persist the counter | `set_transient()` / `get_transient()` / `delete_transient()` | Key on `md5( strtolower( $username ) . '\|' . $ip )`; re-setting refreshes the TTL (sliding window). |
| Client IP | `$_SERVER['REMOTE_ADDR']` | No core `get_client_ip()`. Never trust `X-Forwarded-For`; it is client-controlled. |

## Session destruction

| Goal | Core API | Notes |
| --- | --- | --- |
| Current session token | `wp_get_session_token()` | Returns the token from the `logged_in` cookie, or `''` if not logged in. |
| Kill other devices, keep this one | `wp_destroy_other_sessions()` | Use after a self-service password change. |
| Kill everything for the current user | `wp_destroy_all_sessions()` | Use for "log out everywhere". |
| Kill everything for any user | `WP_Session_Tokens::get_instance( $user_id )->destroy_all()` | The only option for a user who is not logged in right now (password reset, role change, admin-forced logout). |
| Kill all but one token, any user | `WP_Session_Tokens::get_instance( $user_id )->destroy_others( $token )` | Underlying store API. |
| After a lost-password reset | `after_password_reset` action | Fires during the reset flow; destroy all sessions for that user. |
| After profile/password/role update | `profile_update` action | Compare `$user->user_pass` or `$user->roles` with `$old_user_data` before destroying. |
| After any logout | `wp_logout` action | Fires with the user id after `wp_logout()` completes. |

## Cookies and redirects

| Goal | Core API | Notes |
| --- | --- | --- |
| Change cookie lifetime | `auth_cookie_expiration` filter | Args: `($length, $user_id, $remember)`; default 14 days. Never replace cookies with `setcookie()`. |
| Force HTTPS-only auth cookie | `secure_auth_cookie` filter | Args: `($secure, $user_id)`. |
| Force HTTPS-only logged-in cookie | `secure_logged_in_cookie` filter | Args: `($secure_logged_in_cookie, $user_id, $secure)`. |
| Validate a redirect target | `wp_validate_redirect( $location, $fallback )` | Same-host URLs only; returns the fallback otherwise. |
| Send a safe redirect | `wp_safe_redirect( $location )` | Re-validates internally; always `exit;` after. |
| Nonce for the login form | `wp_nonce_field()` + `check_admin_referer()` | Stops login CSRF on custom login pages. |

## Password storage (for completeness — prefer `wp_signon()`)

| Goal | Core API | Notes |
| --- | --- | --- |
| Hash a password | `wp_hash_password( $plaintext )` | Portable bcrypt (phpass). |
| Verify a password | `wp_check_password( $plaintext, $hash, $user_id )` | Only if you must check outside `wp_signon()`; constant-time. |
| Set a new password | `wp_set_password( $plaintext, $user_id )` | Hashes internally; follow with session destruction. |

## Authorization after login

| Goal | Core API | Notes |
| --- | --- | --- |
| Gate current user | `current_user_can( $capability )` | Always for privilege-gated actions. |
| Gate another user | `user_can( $user_id, $capability )` | e.g. re-verify stored context in callbacks. |

Related: see the `nonces-csrf-protection` skill for nonce mechanics and the
`capability-permission-checks` skill for capability checks.
