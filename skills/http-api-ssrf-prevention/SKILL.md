---
name: http-api-ssrf-prevention
description: >
  Use when a plugin or theme makes outbound HTTP requests with the WordPress
  HTTP API - wp_remote_get, wp_remote_post, wp_remote_request - especially when
  any part of the URL comes from user input, options, or webhooks. Uses
  wp_safe_remote_* with wp_http_validate_url, allowlists hosts, blocks internal
  and metadata addresses, and checks is_wp_error plus the response code. Prevents
  server-side request forgery.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, http, ssrf, webhooks"
---

# HTTP API & SSRF prevention

## When to use this skill

Use this skill whenever code makes an outbound HTTP request:

- Fetching a user-supplied URL (webhook, import, avatar, feed, oEmbed-like lookup).
- Calling an external API from a setting, form, or scheduled job.
- Using `wp_remote_get()`, `wp_remote_post()`, or `wp_remote_request()`.
- Building a URL from `$_GET`, `$_POST`, options, or remote configuration.

If any part of the URL is influenced by users or remote state, treat it as an SSRF
sink. `wp_safe_remote_*()` runs `wp_http_validate_url()` on the URL and every
redirect, blocking private/loopback ranges by default.

Related: see the `rest-api-security` skill for inbound REST endpoints and the
`input-sanitization-validation` skill for general URL sanitization.

## Core principles (and why they matter)

1. **`wp_safe_remote_*()` for untrusted URLs.** `wp_safe_remote_get()` and
   `wp_safe_remote_post()` set `reject_unsafe_urls`, which validates the URL and
   redirects against private/loopback ranges.
2. **Allowlist hosts, don't blocklist.** A blocklist will miss `metadata.google.internal`,
   `localhost` aliases, IP-encoding tricks, and redirect chains. Allow only the hosts
   and ports you intend to call.
3. **Validate before the request.** Run `wp_http_validate_url()` or compare the parsed host
   against an allowlist before calling the HTTP API.
4. **Check `is_wp_error()` and the response code.** A failed request can leak internal
   error messages or be confused with valid data.
5. **Escape fetched data before output.** The response body is untrusted input; escape or
   sanitize it before rendering.
6. **Don't follow redirects blindly.** `wp_safe_remote_*()` validates redirect targets, but
   if you manually chase redirects you may re-enter internal space.

## Step-by-step implementation

1. Determine whether the URL is trusted (hardcoded, signed) or untrusted (user input).
2. For untrusted URLs:
   - Parse the host and compare it to an explicit allowlist.
   - Run `wp_http_validate_url()` as an additional guard.
   - Use `wp_safe_remote_get()` / `wp_safe_remote_post()`.
3. For trusted URLs, `wp_remote_*()` is acceptable but still validate the shape.
4. Handle `is_wp_error()` and check the response code with `wp_remote_retrieve_response_code()`.
5. Sanitize or escape the response body before use/output.
6. Log failures without exposing secrets or internal network details.

## Common AI mistakes / anti-patterns

### Mistake 1 — `wp_remote_get()` on user input with no validation

```php
// ❌ Insecure: SSRF to internal services, metadata endpoints, or localhost.
$response = wp_remote_get( $_POST['url'] );
```

```php
// ✅ Secure: allowlist host, validate URL, use safe remote, check errors.
$url = isset( $_POST['url'] ) ? esc_url_raw( wp_unslash( $_POST['url'] ) ) : '';
$allowed_hosts = array( 'api.example.com', 'hooks.example.com' );
$host          = wp_parse_url( $url, PHP_URL_HOST );

if ( ! $host || ! in_array( strtolower( $host ), $allowed_hosts, true ) ) {
    wp_die( esc_html__( 'Invalid URL.', 'my-plugin' ), 400 );
}

if ( ! wp_http_validate_url( $url ) ) {
    wp_die( esc_html__( 'URL is not safe.', 'my-plugin' ), 400 );
}

$response = wp_safe_remote_get( $url );
if ( is_wp_error( $response ) ) {
    wp_die( esc_html__( 'Request failed.', 'my-plugin' ), 502 );
}
$code = wp_remote_retrieve_response_code( $response );
if ( 200 !== $code ) {
    wp_die( esc_html__( 'Unexpected response.', 'my-plugin' ), 502 );
}
$body = wp_remote_retrieve_body( $response );
```

### Mistake 2 — Trusting the URL scheme without checking

```php
// ❌ Insecure: file://, ftp://, gopher://, or php:// wrappers may be reachable.
$response = wp_remote_get( $_POST['url'] );
```

```php
// ✅ Secure: wp_http_validate_url() allows only http/https.
if ( ! wp_http_validate_url( $url ) ) {
    wp_die( esc_html__( 'Only HTTP/HTTPS URLs are allowed.', 'my-plugin' ), 400 );
}
```

### Mistake 3 — Reflecting fetched body unescaped

```php
// ❌ Insecure: fetched HTML/JSON may contain XSS payloads.
echo wp_remote_retrieve_body( $response );
```

```php
// ✅ Secure: treat the body as untrusted and escape for the output context.
$body = wp_remote_retrieve_body( $response );
echo '<pre>' . esc_html( $body ) . '</pre>';
```

### Mistake 4 — Allowing internal IPs through a host allowlist bypass

```php
// ❌ Insecure: resolves to 127.0.0.1 or metadata service.
$allowed_hosts = array( 'localhost', '169.254.169.254' );
```

```php
// ✅ Secure: do not allow localhost or link-local ranges; rely on wp_http_validate_url.
$allowed_hosts = array( 'api.example.com' );
```

### Mistake 5 — Ignoring `is_wp_error()`

```php
// ❌ Insecure: $response['body'] may not exist; errors may leak internals.
$body = $response['body'];
```

```php
// ✅ Secure: branch on is_wp_error() before reading the response.
if ( is_wp_error( $response ) ) {
    error_log( 'HTTP request failed: ' . $response->get_error_message() );
    return false;
}
$body = wp_remote_retrieve_body( $response );
```

## Correct code examples

A complete, copy-paste-ready webhook fetch handler with host allowlist + safe remote +
response validation is in [`references/secure-http-request.php`](references/secure-http-request.php).

## Checklist

- [ ] Untrusted URLs use `wp_safe_remote_get()` / `wp_safe_remote_post()`.
- [ ] The host is allowlisted before the request is made.
- [ ] `wp_http_validate_url()` is used as an additional guard.
- [ ] Only `http`/`https` schemes are accepted.
- [ ] `is_wp_error()` is checked before reading the response.
- [ ] The response code is validated.
- [ ] Fetched data is sanitized/escaped before output or storage.
- [ ] Failures are logged without exposing secrets or internal network details.
- [ ] Redirect chains are validated (safe remote does this automatically).

## Official references

- [HTTP API — Plugin Handbook](https://developer.wordpress.org/plugins/http-api/)
- [`wp_safe_remote_get()`](https://developer.wordpress.org/reference/functions/wp_safe_remote_get/)
- [`wp_safe_remote_post()`](https://developer.wordpress.org/reference/functions/wp_safe_remote_post/)
- [`wp_remote_request()`](https://developer.wordpress.org/reference/functions/wp_remote_request/)
- [`wp_http_validate_url()`](https://developer.wordpress.org/reference/functions/wp_http_validate_url/)
- [`wp_remote_retrieve_body()`](https://developer.wordpress.org/reference/functions/wp_remote_retrieve_body/)
- [`wp_remote_retrieve_response_code()`](https://developer.wordpress.org/reference/functions/wp_remote_retrieve_response_code/)
- [`is_wp_error()`](https://developer.wordpress.org/reference/functions/is_wp_error/)
- [`esc_url_raw()`](https://developer.wordpress.org/reference/functions/esc_url_raw/)
- [`http_request_host_is_external` filter](https://developer.wordpress.org/reference/hooks/http_request_host_is_external/)
- [OWASP — Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
