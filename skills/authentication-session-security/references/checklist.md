# Authentication & session security — deployment checklist

- [ ] Every login path calls `wp_signon()`; no custom `md5`/`sha1`/`==` password comparison exists.
- [ ] Failed logins are throttled and the counter is keyed on username + IP (not IP alone).
- [ ] The throttle counter increments on `wp_login_failed`, is enforced in `wp_authenticate_user`, and clears on `wp_login`.
- [ ] Throttle thresholds and lockout window are defined as constants (e.g. 5 attempts / 15 minutes) and reviewed per site.
- [ ] Client IP comes from `$_SERVER['REMOTE_ADDR']`; `X-Forwarded-For` is not trusted.
- [ ] `login_errors` returns one uniform message; no username echo in failure output.
- [ ] Password resets destroy all sessions for the account (`after_password_reset` → `WP_Session_Tokens::get_instance( $user->ID )->destroy_all()`).
- [ ] Password changes destroy other sessions; role changes destroy all sessions for that user (`profile_update` handlers compare stored hash / roles before acting).
- [ ] No `setcookie()` call implements login state; core auth cookies are used exclusively.
- [ ] Cookie lifetime is tuned only via `auth_cookie_expiration` (and HTTPS-only via `secure_auth_cookie` / `secure_logged_in_cookie` where needed).
- [ ] Every `redirect_to` / post-login target passes `wp_validate_redirect()` before `wp_safe_redirect()`.
- [ ] Custom login forms include a nonce (`wp_nonce_field` + `check_admin_referer`).
- [ ] Custom login handlers run before output (e.g. on `init`) because `wp_signon()` sets cookie headers.
- [ ] Post-login privileged actions check `current_user_can()` / `user_can()`, not just `is_user_logged_in()`.
- [ ] AJAX (`wp_ajax_nopriv_`) and REST login routes go through `wp_signon()` so the site-wide throttle applies to them too.
