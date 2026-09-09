---
name: ajax-security
description: >
  Use when registering or handling WordPress AJAX over admin-ajax.php -
  wp_ajax_{action} / wp_ajax_nopriv_{action} hooks, JavaScript that posts to
  admin_url('admin-ajax.php'), or wp.apiFetch / fetch calls to custom actions.
  Verifies the nonce with check_ajax_referer, gates the action with
  current_user_can, unslashes and sanitizes every field, and replies with
  wp_send_json_success / wp_send_json_error. Prevents CSRF, broken access
  control, and injection on the AJAX surface.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, javascript, ajax, csrf, nonce"
---

# AJAX security

## When to use this skill

Use this skill whenever code registers or handles an AJAX action through WordPress's
`admin-ajax.php` endpoint:

- `add_action( 'wp_ajax_{action}', ... )` for logged-in users.
- `add_action( 'wp_ajax_nopriv_{action}', ... )` for logged-out visitors.
- JavaScript posting to `admin_url( 'admin-ajax.php' )` with jQuery, `fetch`, or `wp.apiFetch`.
- Returning JSON, HTML fragments, or any server-computed data from an AJAX handler.

If the request changes state or exposes privileged data, it needs a nonce **and** a
capability check. `wp_ajax_nopriv_*` is intentionally unauthenticated — never use it for
admin actions.

Related: see the `nonces-csrf-protection` skill for the full nonce lifecycle and the
`rest-api-security` skill for REST endpoints.

## Core principles (and why they matter)

1. **`wp_ajax_*` vs `wp_ajax_nopriv_*` are different trust boundaries.** `nopriv` fires for
   anonymous visitors; use it only for truly public actions. Privileged actions must use
   `wp_ajax_*`.
2. **Nonce + capability for privileged actions.** `check_ajax_referer()` checks a CSRF
   token, not authenticated origin or authorization; `current_user_can()` checks permission.
3. **Sanitize every input field.** `$_POST` values in AJAX are just as attacker-controllable
   as any other request. `wp_unslash()` then sanitize to type before use.
4. **Exit through `wp_send_json_*` or `wp_die()`.** Never echo raw output and fall through.
   JSON responses keep the contract explicit and prevent accidental HTML/PHP leakage.
5. **Scope the nonce to the action.** A nonce for `my_plugin_delete_item_42` cannot be
   replayed to delete item 99.
6. **Fail closed.** Any failed check returns a JSON error or dies; the handler never continues
   to act.
7. **Throttle anonymous and expensive actions before the work.** Public nonces can be
   obtained and replayed by attackers; they are not rate limits. Transient counters
   are best-effort load shedding only: read/increment/write is non-atomic and cached
   entries can disappear early. Strict limits need an atomic shared backend or an
   edge/server limiter with defined windows, trusted client identity, and failure policy.

## Step-by-step implementation

1. Register the handler with the correct hook (`wp_ajax_*` for authenticated, `wp_ajax_nopriv_*`
   for public).
2. Enqueue the script and pass the AJAX URL + nonce via `wp_localize_script()` or
   `wp_add_inline_script()`.
3. In the handler, verify the nonce first with `check_ajax_referer( $action, $query_arg, false )`.
   Passing `false` lets you return a clean JSON error instead of dying with `-1`.
4. Check `current_user_can()` immediately after the nonce.
5. `wp_unslash()` and sanitize every `$_POST` / `$_GET` field, using the right sanitizer for the
   type (`absint`, `sanitize_text_field`, `sanitize_key`, `sanitize_email`, etc.).
6. Enforce the abuse policy **before** queries, mail, or other expensive actions; return
   `wp_send_json_error( ..., 429 )` when rejected. Use an atomic limiter where bypass
   would create a security or cost risk; a transient is only a best-effort supplement.
7. Perform the authorized action.
8. Return `wp_send_json_success()` or `wp_send_json_error()` and stop.

## Common AI mistakes / anti-patterns

### Mistake 1 — No nonce verification

```php
// ❌ Insecure: any site can POST to this action and trigger the handler.
add_action( 'wp_ajax_my_plugin_vote', function () {
    $post_id = absint( $_POST['post_id'] );
    update_post_meta( $post_id, '_votes', get_post_meta( $post_id, '_votes', true ) + 1 );
    wp_send_json_success();
} );
```

```php
// ✅ Secure: verify nonce, then capability, then act.
add_action( 'wp_ajax_my_plugin_vote', 'my_plugin_ajax_vote' );
function my_plugin_ajax_vote() {
    if ( ! check_ajax_referer( 'my_plugin_vote', 'nonce', false ) ) {
        wp_send_json_error( array( 'message' => __( 'Security check failed.', 'my-plugin' ) ), 403 );
    }
    if ( ! current_user_can( 'edit_posts' ) ) {
        wp_send_json_error( array( 'message' => __( 'Forbidden.', 'my-plugin' ) ), 403 );
    }
    $post_id = isset( $_POST['post_id'] ) ? absint( wp_unslash( $_POST['post_id'] ) ) : 0;
    if ( $post_id <= 0 ) {
        wp_send_json_error( array( 'message' => __( 'Invalid post.', 'my-plugin' ) ), 400 );
    }
    update_post_meta( $post_id, '_votes', get_post_meta( $post_id, '_votes', true ) + 1 );
    wp_send_json_success();
}
```

### Mistake 2 — Using `wp_ajax_nopriv_*` for a privileged action

```php
// ❌ Insecure: anonymous users can now save settings.
add_action( 'wp_ajax_nopriv_my_plugin_save_settings', 'my_plugin_save_settings' );
```

```php
// ✅ Secure: privileged actions use wp_ajax_* only.
add_action( 'wp_ajax_my_plugin_save_settings', 'my_plugin_save_settings' );
function my_plugin_save_settings() {
    check_ajax_referer( 'my_plugin_save_settings', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => __( 'Forbidden.', 'my-plugin' ) ), 403 );
    }
    // ...sanitize + save...
    wp_send_json_success();
}
```

### Mistake 3 — Echoing raw `$_POST` or building HTML without escaping

```php
// ❌ Insecure: reflected XSS.
echo '<div>' . $_POST['message'] . '</div>';
```

```php
// ✅ Secure: escape at the point of output, even inside a JSON payload.
$message = sanitize_text_field( wp_unslash( $_POST['message'] ?? '' ) );
wp_send_json_success( array( 'html' => '<div>' . esc_html( $message ) . '</div>' ) );
```

### Mistake 4 — Forgetting `wp_unslash()`

```php
// ❌ Risky: WordPress slashes superglobals; data may contain escaped quotes.
$label = sanitize_text_field( $_POST['label'] );
```

```php
// ✅ Secure: unslash first, then sanitize.
$label = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';
```

### Mistake 5 — Trusting `is_user_logged_in()` instead of a capability

```php
// ❌ Insecure: every logged-in user, including subscribers, can run this.
if ( is_user_logged_in() ) {
    delete_option( 'my_plugin_config' );
}
```

```php
// ✅ Secure: check a real capability.
if ( ! current_user_can( 'manage_options' ) ) {
    wp_send_json_error( array( 'message' => __( 'Forbidden.', 'my-plugin' ) ), 403 );
}
```

### Mistake 6 — Unthrottled public action

```php
// ❌ Insecure: anonymous endpoint, no rate limit — unbounded cost per visitor.
add_action( 'wp_ajax_nopriv_my_plugin_search', 'my_plugin_ajax_search' );
function my_plugin_ajax_search() {
    $q = isset( $_POST['q'] ) ? sanitize_text_field( wp_unslash( $_POST['q'] ) ) : '';
    wp_send_json_success( my_plugin_run_expensive_query( $q ) );
}
```

```php
// Best-effort only: public, read-only search with bounded output.
add_action( 'wp_ajax_nopriv_my_plugin_search', 'my_plugin_ajax_search' );
function my_plugin_ajax_search() {
    if ( ! isset( $_POST['q'] ) || ! is_string( $_POST['q'] ) || strlen( $_POST['q'] ) > 200 ) {
        wp_send_json_error( array( 'message' => 'Invalid query.' ), 400 );
    }
    $q = sanitize_text_field( wp_unslash( $_POST['q'] ) );
    if ( '' === $q ) {
        wp_send_json_error( array( 'message' => 'Query required.' ), 400 );
    }
    // Fixed minute buckets; counters can race or be evicted. Not a strict quota.
    $ip     = $_SERVER['REMOTE_ADDR'] ?? '';
    $window = intdiv( time(), MINUTE_IN_SECONDS );
    $key    = 'my_plugin_rl_' . wp_hash( 'search|' . $ip . '|' . $window );
    $count  = (int) get_transient( $key );
    if ( $count >= 20 ) {
        wp_send_json_error( array( 'message' => __( 'Too many requests.', 'my-plugin' ) ), 429 );
    }
    set_transient( $key, $count + 1, MINUTE_IN_SECONDS );

    // The counter is checked before the query, never after sending the response.
    $ids = get_posts( array(
        's'           => $q,
        'post_type'   => 'post',
        'post_status' => 'publish',
        'numberposts' => 10,
        'fields'      => 'ids',
    ) );
    wp_send_json_success( $ids );
}
```

This read-only public search does not use a nonce as an abuse control. State-changing
or privileged handlers still need their CSRF and capability checks. Fixed windows
allow bursts across boundaries; parallel requests can lose counter increments, and
cache eviction/storage failure can reset this best-effort counter. Do not use it as
the sole control for mail sending, paid APIs, voting integrity, or brute-force defense.

`REMOTE_ADDR` identifies the direct peer: behind a proxy it may identify the proxy,
not the visitor, and shared NATs group users together. Only trust forwarded addresses
after a configured trusted proxy strips client-supplied headers and supplies a
validated address; never read arbitrary `X-Forwarded-For` directly. Strict distributed
limits need an atomic shared operation (including expiry, e.g. a Redis script), or
an edge/server limiter on all relevant routes. See `authentication-session-security`
for login-specific considerations.

## Correct code examples

A complete, copy-paste-ready AJAX handler (PHP + JavaScript) is in
[`references/secure-ajax-handler.php`](references/secure-ajax-handler.php).

## Checklist

- [ ] The action is registered on `wp_ajax_*` for privileged flows or `wp_ajax_nopriv_*` only
      when the action is truly public.
- [ ] The handler verifies the nonce with `check_ajax_referer()` before acting.
- [ ] A `current_user_can()` check runs immediately after nonce verification.
- [ ] Every `$_POST` / `$_GET` field is `wp_unslash()`-ed and sanitized to type.
- [ ] The handler exits via `wp_send_json_success()`, `wp_send_json_error()`, or `wp_die()`.
- [ ] Output inside JSON responses is escaped for its context (`esc_html`, `esc_attr`, `esc_url`).
- [ ] The nonce action string is specific and scoped (e.g., includes an object id).
- [ ] Secrets are never returned to the browser or logged.
- [ ] Abuse controls run before expensive actions; strict limits use atomic shared or edge enforcement, not transients.
- [ ] Client identity accounts for trusted proxies/shared IPs; arbitrary forwarded headers are not trusted.

## Official references

- [Transients API — early expiry and caching semantics](https://developer.wordpress.org/apis/transients/)

- [AJAX in Plugins — Plugin Handbook](https://developer.wordpress.org/plugins/javascript/ajax/)
- [`check_ajax_referer()`](https://developer.wordpress.org/reference/functions/check_ajax_referer/)
- [`wp_create_nonce()`](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
- [`wp_send_json_success()`](https://developer.wordpress.org/reference/functions/wp_send_json_success/)
- [`wp_send_json_error()`](https://developer.wordpress.org/reference/functions/wp_send_json_error/)
- [`wp_localize_script()`](https://developer.wordpress.org/reference/functions/wp_localize_script/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/)
- [`wp_unslash()`](https://developer.wordpress.org/reference/functions/wp_unslash/)
- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
