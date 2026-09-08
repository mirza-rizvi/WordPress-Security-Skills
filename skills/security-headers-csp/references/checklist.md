# HTTP security headers checklist

Use this checklist before shipping any response-header change. Verify per
surface: front-end, wp-admin, and wp-login.php are three different code paths.

## Surfaces

- [ ] Front-end baseline is set through the `wp_headers` filter (or the `send_headers` action), not scattered `header()` calls inside templates.
- [ ] wp-login.php is covered by a hook that fires before output: `login_init`. Do not send headers from `login_head`; it fires inside the login `<head>`, after HTML output has started, so `header()` is a silent no-op there.
- [ ] wp-admin is covered by `admin_init`, using one shared function with the login hook.
- [ ] All three surfaces carry the same policy; no surface is left bare.

## Per-header values

- [ ] `X-Content-Type-Options: nosniff` on every surface.
- [ ] `X-Frame-Options: SAMEORIGIN` (or CSP `frame-ancestors 'self'`); never site-wide `DENY`. The Customizer and theme previews iframe the front-end from the same origin; oEmbed previews frame posts.
- [ ] `Referrer-Policy: strict-origin-when-cross-origin` on every surface.
- [ ] `Permissions-Policy` set deliberately, not copied blindly; each denied feature checked against real usage.
- [ ] `Strict-Transport-Security` only on sites committed to HTTPS-only (HSTS is cached by browsers; a broken certificate makes the domain unreachable). Prefer server-layer config; see the `wp-hardening-best-practices` skill.
- [ ] No pre-existing header removed (for example core's frame protection on admin) without a documented reason and a replacement.

## CSP

- [ ] Policy first shipped as `Content-Security-Policy-Report-Only`; violations observed in the browser console or a reporting endpoint you control.
- [ ] Enforcement is a rename to `Content-Security-Policy` only after the violation log is quiet.
- [ ] `script-src` uses `'self'` plus a per-response nonce (`'nonce-...'`); no `unsafe-inline`, no `*`.
- [ ] The nonce is generated fresh per response with `random_bytes()` + `bin2hex()`. Never `wp_create_nonce()`: that is a CSRF token, user-bound and reused across requests.
- [ ] Nonce attributes attached to enqueued scripts via `script_loader_tag`, restricted to your own handles.
- [ ] Inline scripts (`wp_add_inline_script()`, plus core/theme/plugin inline output) nonced via the `wp_inline_script_attributes` filter; under an enforced CSP, any un-nonced inline script is blocked.
- [ ] If `style-src` is enforced, the same nonce treatment applied via `style_loader_tag`.
- [ ] Full-page caching checked: a cache that freezes HTML freezes the nonce into cached responses.
- [ ] Escaping remains the primary XSS defense; the CSP is the second layer, not a substitute. See the `output-escaping` skill.

## Cookies

- [ ] Every custom cookie sets `Secure`, `HttpOnly`, and `SameSite` via the PHP 7.3+ options array.
- [ ] `SameSite=None` only together with `Secure: true`; otherwise browsers reject the cookie. Default to `Lax`.
- [ ] Per-user pages send `nocache_headers()` so one user's page is not served from a shared cache.
- [ ] Core auth cookies: `Secure` forced via `secure_auth_cookie` / `secure_logged_in_cookie` on HTTPS-only sites. `HttpOnly` is already hardcoded by core (`wp_set_auth_cookie()`); no `auth_cookie_httponly` hook exists.

## REST CORS

- [ ] No `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`, anywhere.
- [ ] `$_SERVER['HTTP_ORIGIN']` is never reflected into CORS headers by plugin code; core's `rest_send_cors_headers()` already reflects it, so restrict it via the `http_origin` filter instead.
- [ ] Partner origins added through the `allowed_http_origins` filter (extend the list; do not replace it and drop the site's own origins).
- [ ] Endpoint authorization still enforced per request; CORS is browser policy, not authentication. See the `rest-api-security` skill.

## Verification

- [ ] `curl -sI https://site/`, `curl -sI https://site/wp-login.php`, and an admin page each show the baseline headers.
- [ ] Browser console is clean of CSP violations on key templates (home, single post, search, login).
- [ ] Customizer preview and an oEmbed preview still work after frame headers ship.
