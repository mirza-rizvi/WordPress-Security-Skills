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
license: MIT
metadata:
  tags: [wordpress, security, php, javascript, ajax, csrf, nonce]
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
2. **Nonce + capability, always together.** `check_ajax_referer()` proves the request came
   from your site; `current_user_can()` proves the user is allowed to perform the action.
3. **Sanitize every input field.** `$_POST` values in AJAX are just as attacker-controllable
   as any other request. `wp_unslash()` then sanitize to type before use.
4. **Exit through `wp_send_json_*` or `wp_die()`.** Never echo raw output and fall through.
   JSON responses keep the contract explicit and prevent accidental HTML/PHP leakage.
5. **Scope the nonce to the action.** A nonce for `my_plugin_delete_item_42` cannot be
   replayed to delete item 99.
6. **Fail closed.** Any failed check returns a JSON error or dies; the handler never continues
   to act.

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
6. Perform the action.
7. Return `wp_send_json_success()` or `wp_send_json_error()` and stop.

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

## Official references

- [AJAX in Plugins — Plugin Handbook](https://developer.wordpress.org/plugins/javascript/ajax/)
- [`check_ajax_referer()`](https://developer.wordpress.org/reference/functions/check_ajax_referer/)
- [`wp_create_nonce()`](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
- [`wp_send_json_success()`](https://developer.wordpress.org/reference/functions/wp_send_json_success/)
- [`wp_send_json_error()`](https://developer.wordpress.org/reference/functions/wp_send_json_error/)
- [`wp_localize_script()`](https://developer.wordpress.org/reference/functions/wp_localize_script/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/)
- [`wp_unslash()`](https://developer.wordpress.org/reference/functions/wp_unslash/)
- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
