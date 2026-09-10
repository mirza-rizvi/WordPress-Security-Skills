---
name: nonces-csrf-protection
description: >
  Use when handling any form submission, AJAX request, admin-post action, settings
  page, link that triggers an action, or any other user-initiated request in a
  WordPress plugin or theme. Generates nonces with wp_nonce_field / wp_create_nonce
  and verifies them with check_admin_referer, check_ajax_referer, or wp_verify_nonce,
  always paired with a capability check, to prevent CSRF. Apply proactively whenever
  code accepts or acts on a request.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, nonce, csrf, ajax, forms"
---

# Nonces & CSRF protection in WordPress

## When to use this skill

Use this skill whenever code **accepts or acts on a request** that changes state or
performs a privileged action. Concretely:

- HTML `<form>` submissions (admin or front-end) handled via `admin-post.php`,
  `admin_post_*`, or a settings page.
- `admin-ajax.php` handlers (`wp_ajax_*`, `wp_ajax_nopriv_*`) and `fetch()`/jQuery AJAX.
- Action links such as "Delete", "Approve", "Activate" that carry a query argument.
- Settings API pages (the Settings API adds a nonce automatically — verify you are not
  bypassing it).
- Any custom endpoint reached over `$_GET` / `$_POST` / `$_REQUEST`.

If a request only **reads** public data and changes nothing, a nonce is not required —
but the moment it writes, deletes, or triggers a side effect, it is mandatory.

> A nonce is **not** authentication and **not** authorization. It proves the request
> came from a page your site generated, defeating CSRF. You still need a capability
> check (`current_user_can`) to prove the user is *allowed* to do the thing. Always
> use both. See the `capability-permission-checks` skill.

## Core principles (and why they matter)

1. **Every state-changing request needs a nonce.** CSRF works by tricking a logged-in
   admin's browser into submitting a forged request. A nonce the attacker cannot guess
   breaks that attack.
2. **Nonce + capability are a pair, never a substitute.** The nonce says "this request
   came from us"; the capability check says "this user may do this." A nonce alone lets
   any logged-in subscriber perform admin actions; a capability check alone leaves you
   open to CSRF.
3. **Tie the nonce to a specific action.** Use a unique, descriptive action string
   (e.g. `delete_widget_42`) rather than a generic one. A nonce scoped to "delete widget
   42" cannot be replayed to delete widget 99 or to do something unrelated.
4. **Verify on the server, every time.** Generating a nonce does nothing on its own. The
   security comes from verifying it on the receiving side *before* acting.
5. **Fail closed.** If verification fails, stop — `wp_die()`, return a 403, or send a
   JSON error. Never fall through to the action.
6. **Nonces expire (default ~24h) and are per-user.** They are single-action tokens, not
   long-lived secrets. Don't store or reuse them; regenerate per page render.

## Step-by-step implementation

1. **Generate** the nonce where the request originates:
   - In a form: `wp_nonce_field( 'my_action', 'my_nonce' )` (prints a hidden field).
   - In a URL: `wp_nonce_url( $url, 'my_action', 'my_nonce' )`.
   - For JS/AJAX: `wp_create_nonce( 'my_action' )`, passed to the script via
     `wp_localize_script()` or `wp_add_inline_script()`.
2. **Send** it with the request (hidden field, query arg, or AJAX payload / header).
3. **Verify** it on the server *first*, before reading other input or acting:
   - Form via `admin-post.php`: `check_admin_referer( 'my_action', 'my_nonce' )`.
   - AJAX: `check_ajax_referer( 'my_action', 'nonce' )`.
   - Manual / REST-ish: `wp_verify_nonce( $nonce, 'my_action' )` and branch on the result.
4. **Check capability** immediately after: `if ( ! current_user_can( 'manage_options' ) )`.
5. **Then** `wp_unslash()` + sanitize the input, do the work, and escape any output.
6. **Fail closed** on any failure with `wp_die()` or `wp_send_json_error()`.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Nonce / CSRF verification checklist](references/checklist.md) | Before final verification of the nonce / csrf verification controls. |
| [Secure AJAX nonce flow](references/secure-ajax-handler.php) | Implementing the privileged AJAX flow from nonce generation through verification, authorization, and JSON response. |

## Common AI mistakes / anti-patterns

### Mistake 1 — Verifying the nonce but skipping the capability check

```php
// ❌ Insecure: nonce proves the request shape, NOT that the user is allowed.
add_action( 'admin_post_delete_thing', function () {
    check_admin_referer( 'delete_thing' );
    delete_thing( absint( $_POST['id'] ) ); // any logged-in user can reach this
} );
```

```php
// ✅ Secure: nonce AND capability.
add_action( 'admin_post_delete_thing', function () {
    check_admin_referer( 'delete_thing' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to do this.', 'my-plugin' ), 403 );
    }
    delete_thing( absint( wp_unslash( $_POST['id'] ?? 0 ) ) );
} );
```

### Mistake 2 — Reading `wp_verify_nonce()` as a boolean and ignoring the result

`wp_verify_nonce()` returns `1`, `2`, or **`false`** — not a clean boolean, and crucially
the call has no effect unless you branch on it.

```php
// ❌ Insecure: result is computed and thrown away; the action always runs.
wp_verify_nonce( $_POST['my_nonce'], 'my_action' );
save_settings();
```

```php
// ✅ Secure: branch on the result and fail closed.
$nonce = isset( $_POST['my_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['my_nonce'] ) ) : '';
if ( ! wp_verify_nonce( $nonce, 'my_action' ) ) {
    wp_die( esc_html__( 'Security check failed.', 'my-plugin' ), 403 );
}
save_settings();
```

### Mistake 3 — Generic / reused action strings

```php
// ❌ Insecure: a single global action lets a valid nonce be replayed across endpoints.
wp_nonce_field( 'nonce' );           // action = "nonce"
check_admin_referer( 'nonce' );
```

```php
// ✅ Secure: specific, scoped action string (include the object id when relevant).
wp_nonce_field( 'delete_widget_' . $widget_id, 'widget_nonce' );
check_admin_referer( 'delete_widget_' . $widget_id, 'widget_nonce' );
```

### Mistake 4 — `wp_ajax_nopriv_*` for a privileged action

`wp_ajax_nopriv_*` fires for **logged-out** visitors. Wiring a sensitive action there
exposes it to the public.

```php
// ❌ Insecure: settings save reachable by anonymous users.
add_action( 'wp_ajax_nopriv_save_api_key', 'save_api_key' );
```

```php
// ✅ Secure: privileged actions use wp_ajax_* only, plus nonce + capability inside.
add_action( 'wp_ajax_save_api_key', 'save_api_key' );
function save_api_key() {
    check_ajax_referer( 'save_api_key', 'nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error( array( 'message' => 'Forbidden' ), 403 );
    }
    // ...sanitize + save...
    wp_send_json_success();
}
```

### Mistake 5 — Echoing the nonce without escaping, or building it by hand

```php
// ❌ Insecure / fragile: manual markup, unescaped output.
echo '<input type="hidden" name="n" value="' . wp_create_nonce( 'act' ) . '">';
```

```php
// ✅ Secure: let core print the (already-escaped) field, or escape explicitly.
wp_nonce_field( 'act', 'n' );
// If you must build a URL by hand, escape it:
$url = wp_nonce_url( admin_url( 'admin-post.php?action=act' ), 'act', 'n' );
echo '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Do it', 'my-plugin' ) . '</a>';
```

### Mistake 6 — Trusting `check_ajax_referer()` to also authorize

`check_admin_referer()` and `check_ajax_referer()` only verify the nonce (and referer).
They do **not** check capabilities. Add `current_user_can()` yourself.

## Correct code examples

### Admin form submitted to `admin-post.php`

```php
<?php
/**
 * Render the settings form.
 */
function my_plugin_render_form() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    ?>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
        <input type="hidden" name="action" value="my_plugin_save">
        <?php wp_nonce_field( 'my_plugin_save', 'my_plugin_nonce' ); ?>
        <input type="text" name="api_key" value="">
        <?php submit_button( __( 'Save', 'my-plugin' ) ); ?>
    </form>
    <?php
}

/**
 * Handle the submission.
 */
add_action( 'admin_post_my_plugin_save', 'my_plugin_handle_save' );
function my_plugin_handle_save() {
    // 1. Verify the nonce (fails closed via wp_die on mismatch).
    check_admin_referer( 'my_plugin_save', 'my_plugin_nonce' );

    // 2. Verify capability.
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You are not allowed to do this.', 'my-plugin' ), 403 );
    }

    // 3. Unslash + sanitize input.
    $api_key = isset( $_POST['api_key'] )
        ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) )
        : '';

    // 4. Do the work.
    update_option( 'my_plugin_api_key', $api_key );

    // 5. Redirect back safely.
    wp_safe_redirect( add_query_arg( 'updated', 'true', wp_get_referer() ) );
    exit;
}
```

For the full AJAX flow (PHP handler + JS), see
[`references/secure-ajax-handler.php`](references/secure-ajax-handler.php).

### Header-based and JSON nonces for REST / modern fetch

When a form is not available, send the nonce in a header or JSON body. The REST API
expects `X-WP-Nonce` with a nonce created via `wp_create_nonce( 'wp_rest' )`.

```js
// JavaScript: fetch with X-WP-Nonce header.
fetch( '/wp-json/my-plugin/v1/thing', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-WP-Nonce': myPluginData.nonce, // created with wp_create_nonce( 'wp_rest' )
    },
    body: JSON.stringify( { id: 1 } ),
} );
```

```js
// Or use @wordpress/api-fetch, which attaches the REST nonce automatically.
import apiFetch from '@wordpress/api-fetch';

apiFetch( {
    path: 'my-plugin/v1/thing',
    method: 'POST',
    data: { id: 1 },
} );
```

On the server, the REST API verifies the `X-WP-Nonce` header when you use a real
`permission_callback`. Do not use `__return_true` for state-changing REST routes.

Related: see the `ajax-security` skill for the admin-ajax flow and the
`rest-api-security` skill for REST-specific permission handling.

## Checklist

Before finishing any request-handling code, confirm:

- [ ] Every state-changing request generates a nonce (`wp_nonce_field`,
      `wp_nonce_url`, or `wp_create_nonce`).
- [ ] The action string is **specific** and includes the target object id where relevant.
- [ ] The server verifies the nonce **before** doing anything else
      (`check_admin_referer` / `check_ajax_referer` / branched `wp_verify_nonce`).
- [ ] A capability check (`current_user_can`) runs alongside the nonce check.
- [ ] `wp_verify_nonce()` results are branched on; the action does not run on failure.
- [ ] Privileged AJAX uses `wp_ajax_*` (not `wp_ajax_nopriv_*`).
- [ ] On failure the code fails closed (`wp_die`, 403, or `wp_send_json_error`).
- [ ] Input is `wp_unslash()`-ed and sanitized after verification.
- [ ] Nonce values printed to the page are escaped (or produced by core helpers).

## Official references

- [Nonces — Plugin Handbook](https://developer.wordpress.org/apis/security/nonces/)
- [`wp_nonce_field()`](https://developer.wordpress.org/reference/functions/wp_nonce_field/)
- [`wp_create_nonce()`](https://developer.wordpress.org/reference/functions/wp_create_nonce/)
- [`wp_nonce_url()`](https://developer.wordpress.org/reference/functions/wp_nonce_url/)
- [`wp_verify_nonce()`](https://developer.wordpress.org/reference/functions/wp_verify_nonce/)
- [`check_admin_referer()`](https://developer.wordpress.org/reference/functions/check_admin_referer/)
- [`check_ajax_referer()`](https://developer.wordpress.org/reference/functions/check_ajax_referer/)
- [Securing Input & Output — Plugin Handbook](https://developer.wordpress.org/apis/security/)
- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
