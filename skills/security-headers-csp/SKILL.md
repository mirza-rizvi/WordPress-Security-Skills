---
name: security-headers-csp
description: >
  Use when adding HTTP response headers to a WordPress site or plugin:
  Content-Security-Policy (or Report-Only), X-Content-Type-Options, frame
  protection (X-Frame-Options or frame-ancestors), Referrer-Policy,
  Permissions-Policy, HSTS, Secure/HttpOnly/SameSite cookie flags, or CORS on
  REST responses. Covers the wp_headers filter, the send_headers, login_init
  and admin_init surfaces, per-request CSP nonces via script_loader_tag, and
  REST origin restriction through core's allowlist. Headers are the second XSS
  layer after output escaping, and they also stop clickjacking and MIME
  sniffing.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, http-headers, csp, clickjacking, cors"
---

# HTTP security headers, CSP & cookie flags

## When to use this skill

Use this skill whenever code touches HTTP responses on any WordPress surface:

- Adding response headers (front-end, wp-admin, or wp-login.php).
- Building a Content-Security-Policy, migrating Report-Only to enforced, or wiring script nonces.
- Choosing frame protection without breaking the Customizer preview or oEmbed frames.
- Setting Secure / HttpOnly / SameSite on a custom cookie, or forcing Secure on core auth cookies.
- Deciding what REST responses may reflect into Access-Control-Allow-Origin.
- Reviewing code that calls `header()`, reads `$_SERVER['HTTP_ORIGIN']`, or filters `wp_headers`.

Response headers are the second layer. Output escaping prevents XSS; headers
contain the blast radius when escaping was missed somewhere, and they stop whole
attack classes escaping cannot: clickjacking, MIME sniffing, and inline script
injection. Agents rarely add headers. When they do, they tend to add a blanket
CSP that admins disable, or CORS wide open.

Related: see the `output-escaping` skill for the primary XSS defense, the
`rest-api-security` skill for endpoint authorization, and the
`wp-hardening-best-practices` skill for server-layer TLS and .htaccess config.

## Core principles (and why they matter)

1. **Headers mitigate; escaping prevents.** A CSP is not an XSS fix. It limits
   what an injected script can load and whether it runs at all. Ship both.
2. **Three surfaces, one policy.** Front-end template loads fire `send_headers`
   and the `wp_headers` filter. wp-login.php and wp-admin do not run the main
   query, so they never reach that code: use `login_init` for the login screen
   and `admin_init` for admin, both before output, with one shared function
   calling `header()`. `login_head` fires inside the login page `<head>`, after
   HTML output has started: `header()` there is a silent no-op. It is only good
   for `<meta http-equiv>` fallbacks.
3. **Frame control must permit same-origin framing.** The Customizer and theme
   previews iframe the front-end from the same origin; oEmbed previews frame
   posts. `X-Frame-Options: SAMEORIGIN` (or CSP `frame-ancestors 'self'`) is the
   safe default. Blanket DENY breaks the Customizer preview.
4. **CSP ships incrementally.** Start with `Content-Security-Policy-Report-Only`,
   triage violation reports, then enforce. Enforcing a strict policy on day one
   breaks the site and teaches admins to delete your headers.
5. **A CSP nonce is not a CSRF nonce.** Generate it fresh per response with
   `random_bytes()` + `bin2hex()`. `wp_create_nonce()` returns a CSRF token:
   user-bound, reused across requests for the session window, and designed to be
   printed into the page. Wrong tool for `script-src 'nonce-...'`.
6. **Inline scripts do not inherit the nonce.** `wp_add_inline_script()` output
   is printed by `wp_get_inline_script_tag()`, not through your
   `script_loader_tag` filter. Nonce it via the `wp_inline_script_attributes`
   filter.
7. **Restrict CORS with core's allowlist, never reflection.** Core's
   `rest_send_cors_headers()` reflects the request `Origin` into
   `Access-Control-Allow-Origin` together with
   `Access-Control-Allow-Credentials: true`, and does not consult the allowlist.
   Filter `http_origin` so disallowed origins produce no CORS headers at all;
   extend the allowlist with `allowed_http_origins`. Never send
   `Access-Control-Allow-Origin: *` together with credentials.
8. **Cookie flags are cheap and mandatory.** Every custom cookie: `Secure`,
   `HttpOnly`, `SameSite`, via the PHP 7.3+ options array. Core auth cookies
   already send `HttpOnly` (hardcoded in `wp_set_auth_cookie()`, no
   `auth_cookie_httponly` hook exists); the filterable part is `Secure` via
   `secure_auth_cookie` / `secure_logged_in_cookie`.
9. **HSTS is a domain commitment.** Send it only from an HTTPS-only site: once
   cached, a broken certificate makes the domain unreachable. Server-layer
   config (nginx / .htaccess) is the better home.
10. **Do not strip headers you did not add** (for example, removing core's frame
    protection) without a documented reason and a replacement.

## Step-by-step implementation

1. Add the baseline to the front-end through `wp_headers` (full module:
   [`references/secure-security-headers.php`](references/secure-security-headers.php)):

   ```php
   add_filter( 'wp_headers', 'myplugin_front_end_security_headers' );
   function myplugin_front_end_security_headers( $headers ) {
       $headers['X-Content-Type-Options'] = 'nosniff';
       $headers['Referrer-Policy']        = 'strict-origin-when-cross-origin';
       $headers['X-Frame-Options']        = 'SAMEORIGIN';
       return $headers;
   }
   ```

2. Cover the other two surfaces with one shared function hooked to `login_init`
   and `admin_init`; it calls `header( 'Header: value' )` per header, guarded by
   `headers_sent()`.
3. Decide frame policy: `SAMEORIGIN` / `frame-ancestors 'self'` unless the site
   is documented to never be framed. Do not use DENY site-wide.
4. Write the CSP and ship it as `Content-Security-Policy-Report-Only` first.
   Build `script-src` around a per-response nonce:

   ```php
   function myplugin_csp_nonce() {
       static $nonce = null;
       if ( null === $nonce ) {
           $nonce = bin2hex( random_bytes( 16 ) );
       }
       return $nonce;
   }
   ```

5. Attach the nonce to enqueued scripts through `script_loader_tag`, limited to
   your own handles. Nonce `wp_add_inline_script()` output through
   `wp_inline_script_attributes`. If you enforce `style-src`, do the same via
   `style_loader_tag`.
6. Watch the Report-Only console/violation output until it is quiet, then rename
   the header to `Content-Security-Policy`.
7. Set cookie flags with the PHP 7.3+ options array. On HTTPS-only sites, force
   `Secure` on core auth cookies with `secure_auth_cookie`.
8. Restrict REST CORS: filter `http_origin` to return an empty string unless the
   origin is in `get_allowed_http_origins()`; add partner origins through the
   `allowed_http_origins` filter.
9. Verify: `curl -sI` one URL per surface, plus the browser console for CSP
   violations. Re-check after enabling full-page caching: a cache that freezes
   HTML freezes the per-response nonce.

## Common AI mistakes / anti-patterns

### Mistake 1 - CSP theater

```php
// ❌ Insecure: permits everything; any inline or remote script runs. Pure theater.
header( 'Content-Security-Policy: script-src * unsafe-inline' );
```

```php
// ✅ Secure: self plus a per-response nonce; observed in Report-Only before enforcing.
header( "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-" . myplugin_csp_nonce() . "'" );
```

### Mistake 2 - Enforcing without ever running Report-Only

```php
// ❌ Insecure: strict enforced CSP from day one breaks theme/plugin assets;
// the admin's first fix is deleting your header.
header( "Content-Security-Policy: default-src 'self'" );
```

```php
// ✅ Secure: identical policy, observed only. Enforce after violations are triaged.
header( "Content-Security-Policy-Report-Only: default-src 'self'" );
```

### Mistake 3 - Reflecting Origin with credentials

```php
// ❌ Insecure: any site can read logged-in users' responses; reflection plus
// credentials is a full cross-origin grant to everyone.
header( 'Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN'] );
header( 'Access-Control-Allow-Credentials: true' );
```

```php
// ✅ Secure: keep core's header logic, and restrict what it may reflect via the
// http_origin filter. Empty origin means core sends no CORS headers.
add_filter( 'http_origin', 'myplugin_restrict_http_origin' );
function myplugin_restrict_http_origin( $origin ) {
    if ( '' !== $origin && ! in_array( $origin, get_allowed_http_origins(), true ) ) {
        return '';
    }
    return $origin;
}
```

### Mistake 4 - Headers on the front-end only

```php
// ❌ Insecure: login and admin get nothing; the login form is a favorite
// framing and injection target.
add_filter( 'wp_headers', 'myplugin_front_end_security_headers' ); // and nothing else
```

```php
// ✅ Secure: one shared function, three surfaces.
add_action( 'login_init', 'myplugin_login_security_headers' );
add_action( 'admin_init', 'myplugin_admin_security_headers' );
```

### Mistake 5 - Using `wp_create_nonce()` as a CSP nonce

```php
// ❌ Insecure: a CSRF token is user-bound and reused across requests; it is
// also printed into forms anyway. Leakage stays valid for the session window.
$nonce = wp_create_nonce( 'csp' );
header( "Content-Security-Policy: script-src 'self' 'nonce-$nonce'" );
```

```php
// ✅ Secure: fresh unpredictable value per response.
header( "Content-Security-Policy: script-src 'self' 'nonce-" . bin2hex( random_bytes( 16 ) ) . "'" );
```

### Mistake 6 - Blanket `X-Frame-Options: DENY`

```php
// ❌ Insecure: DENY forbids same-origin framing; the Customizer preview and
// oEmbed previews stop working.
$headers['X-Frame-Options'] = 'DENY';
```

```php
// ✅ Secure: allow same-origin framing only.
$headers['X-Frame-Options'] = 'SAMEORIGIN';
// Or in the CSP: frame-ancestors 'self'
```

### Mistake 7 - `SameSite=None` without `Secure`

```php
// ❌ Insecure: browsers reject SameSite=None over insecure contexts; the
// cookie silently disappears, or ships cross-site without TLS.
setcookie( 'myplugin_session', $token, array( 'samesite' => 'None' ) );
```

```php
// ✅ Secure: None only together with Secure; default to Lax otherwise.
setcookie(
    'myplugin_session',
    $token,
    array(
        'expires'  => 0,
        'path'     => '/',
        'secure'   => true,
        'httponly' => true,
        'samesite' => 'None',
    )
);
```

## Correct code examples

The complete module (all three surfaces, CSP Report-Only with nonce pipeline,
custom cookie helper, HTTPS-only auth cookies, REST origin restriction) is in
[`references/secure-security-headers.php`](references/secure-security-headers.php).
Per-header values, what each header stops, and caveats are in
[`references/headers-cheatsheet.md`](references/headers-cheatsheet.md).
Pre-ship review list: [`references/checklist.md`](references/checklist.md).

## Checklist

- [ ] Front-end headers set via `wp_headers` (or `send_headers`), not scattered `header()` calls in templates.
- [ ] wp-login.php covered via `login_init` (not `login_head`: that fires after output starts); wp-admin via `admin_init`.
- [ ] Frame protection is `SAMEORIGIN` / `frame-ancestors 'self'`, not site-wide DENY.
- [ ] CSP ran as `Content-Security-Policy-Report-Only` first; violations triaged before enforcement.
- [ ] CSP nonce generated per response with `random_bytes()` + `bin2hex()`.
- [ ] Enqueued scripts nonced only for plugin handles via `script_loader_tag`.
- [ ] Inline scripts nonced via `wp_inline_script_attributes`.
- [ ] Full-page caching behavior checked: no frozen nonce in cached HTML.
- [ ] No `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`; REST origins restricted through core's allowlist filters.
- [ ] Custom cookies set `Secure`, `HttpOnly`, `SameSite`; `SameSite=None` only with `Secure`.
- [ ] Core auth cookie `Secure` forced via `secure_auth_cookie` / `secure_logged_in_cookie` on HTTPS-only sites.
- [ ] HSTS sent only on HTTPS-only sites, or configured at the server layer.
- [ ] No pre-existing headers removed without a documented reason.
- [ ] Verified per surface with `curl -sI` and the browser CSP console.

## Official references

- [`wp_headers` filter](https://developer.wordpress.org/reference/hooks/wp_headers/)
- [`send_headers` action](https://developer.wordpress.org/reference/hooks/send_headers/)
- [`login_init` action](https://developer.wordpress.org/reference/hooks/login_init/)
- [`login_head` action](https://developer.wordpress.org/reference/hooks/login_head/)
- [`admin_init` action](https://developer.wordpress.org/reference/hooks/admin_init/)
- [`script_loader_tag` filter](https://developer.wordpress.org/reference/hooks/script_loader_tag/)
- [`style_loader_tag` filter](https://developer.wordpress.org/reference/hooks/style_loader_tag/)
- [`wp_inline_script_attributes` filter](https://developer.wordpress.org/reference/hooks/wp_inline_script_attributes/)
- [`wp_add_inline_script()`](https://developer.wordpress.org/reference/functions/wp_add_inline_script/)
- [`wp_enqueue_script()`](https://developer.wordpress.org/reference/functions/wp_enqueue_script/)
- [`wp_get_inline_script_tag()`](https://developer.wordpress.org/reference/functions/wp_get_inline_script_tag/)
- [`nocache_headers()`](https://developer.wordpress.org/reference/functions/nocache_headers/)
- [`rest_send_cors_headers()`](https://developer.wordpress.org/reference/functions/rest_send_cors_headers/)
- [`get_http_origin()`](https://developer.wordpress.org/reference/functions/get_http_origin/)
- [`is_allowed_http_origin()`](https://developer.wordpress.org/reference/functions/is_allowed_http_origin/)
- [`get_allowed_http_origins()`](https://developer.wordpress.org/reference/functions/get_allowed_http_origins/)
- [`http_origin` filter](https://developer.wordpress.org/reference/hooks/http_origin/)
- [`allowed_http_origins` filter](https://developer.wordpress.org/reference/hooks/allowed_http_origins/)
- [`secure_auth_cookie` filter](https://developer.wordpress.org/reference/hooks/secure_auth_cookie/)
- [`secure_logged_in_cookie` filter](https://developer.wordpress.org/reference/hooks/secure_logged_in_cookie/)
- [`wp_set_auth_cookie()`](https://developer.wordpress.org/reference/functions/wp_set_auth_cookie/)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [MDN: Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [MDN: CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
