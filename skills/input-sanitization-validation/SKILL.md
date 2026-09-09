---
name: input-sanitization-validation
description: >
  Use when reading any external input in WordPress — $_GET, $_POST, $_REQUEST,
  $_COOKIE, REST params, shortcode/block attributes, option/meta values, or remote
  API responses. Unslashes then sanitizes to the correct type (sanitize_text_field,
  sanitize_email, absint, sanitize_key, wp_kses_post, esc_url_raw) and validates
  values against expected sets. Apply proactively before storing or using any
  untrusted value.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, sanitization, validation, input"
---

# Input sanitization & validation

## When to use this skill

Use this skill whenever a value enters your code from outside:

- Superglobals: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER`.
- REST API parameters, AJAX payloads, form fields.
- Shortcode attributes, block attributes, widget settings.
- Values read back from `get_option`, post meta, or user meta that originated from users.
- Bodies returned by remote APIs (`wp_remote_get`, etc.).

**Sanitize on input, escape on output** — two different jobs. This skill covers input;
see `output-escaping` for output.

## Core principles (and why they matter)

1. **All external input is untrusted.** Even data from your own admin screens can be
   forged (CSRF) or tampered with. Sanitize regardless of source.
2. **Unslash before sanitizing.** WordPress adds slashes to superglobals. Calling
   `wp_unslash()` first prevents corrupted data (`it\'s` instead of `it's`) and ensures
   sanitizers see the real value.
3. **Sanitize to the expected type.** A function that expects an integer should call
   `absint()`; an email, `sanitize_email()`. Type-appropriate sanitizing shrinks the
   attack surface far more than a generic catch-all.
4. **Validation ≠ sanitization.** Sanitizing cleans a value; validating rejects values
   that don't belong. Use both: sanitize the shape, then validate against allowed sets
   (`in_array` with strict comparison, range checks, `is_email`).
5. **Prefer allowlists over blocklists.** Define what is permitted, reject the rest.
6. **Sanitize rich content with `wp_kses`/`wp_kses_post`**, never with `strip_tags` —
   `strip_tags` leaves dangerous attributes and is not XSS-safe.

## Step-by-step implementation

1. **Confirm the value is set** with `isset()` / null coalescing and a safe default.
2. **Unslash:** `wp_unslash( $_POST['x'] )`.
3. **Sanitize to type:** pick the function matching the data (see cheatsheet).
4. **Validate:** check ranges, allowed values, formats; reject invalid input.
5. **Use or store** the clean value. Re-escape when later output.

```php
$status   = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '';
$allowed  = array( 'draft', 'publish', 'pending' );
$status   = in_array( $status, $allowed, true ) ? $status : 'draft'; // validate + fallback
```

## Common AI mistakes / anti-patterns

### Mistake 1 — Sanitizing without unslashing

```php
// ❌ Insecure/buggy: slashes corrupt the value and bypass intent.
$name = sanitize_text_field( $_POST['name'] );
```

```php
// ✅ Correct: unslash first.
$name = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
```

### Mistake 2 — Using `strip_tags()` as if it were XSS-safe

```php
// ❌ Insecure: strip_tags keeps event handlers/attributes and is not escaping.
$bio = strip_tags( $_POST['bio'] );
update_user_meta( $user_id, 'bio', $bio );
```

```php
// ✅ Secure: allow a known-safe subset with wp_kses_post (or a custom allowlist).
$bio = isset( $_POST['bio'] ) ? wp_kses_post( wp_unslash( $_POST['bio'] ) ) : '';
update_user_meta( $user_id, 'bio', $bio );
```

### Mistake 3 — Wrong sanitizer for the type

```php
// ❌ Insecure: text sanitizer on something that must be an integer / URL.
$post_id = sanitize_text_field( $_GET['post_id'] ); // "12 OR 1=1" survives as a string
$link    = sanitize_text_field( $_POST['link'] );   // allows javascript: scheme
```

```php
// ✅ Secure: type-correct sanitizers.
$post_id = absint( $_GET['post_id'] ?? 0 );
$link    = esc_url_raw( wp_unslash( $_POST['link'] ?? '' ) ); // for storage; esc_url for output
```

### Mistake 4 — Sanitizing but never validating

```php
// ❌ Weak: clean string, but any value is accepted.
$role = sanitize_key( wp_unslash( $_POST['role'] ?? '' ) );
$user->set_role( $role ); // attacker sends "administrator"
```

```php
// ✅ Secure: validate against an allowlist.
$role    = sanitize_key( wp_unslash( $_POST['role'] ?? '' ) );
$allowed = array( 'subscriber', 'contributor', 'author' );
if ( ! in_array( $role, $allowed, true ) ) {
    wp_die( esc_html__( 'Invalid role.', 'my-plugin' ), 400 );
}
$user->set_role( $role );
```

### Mistake 5 — Sanitizing arrays as if they were scalars

```php
// ❌ Buggy/insecure: passing an array to a scalar sanitizer.
$ids = sanitize_text_field( $_POST['ids'] ); // returns "" for arrays
```

```php
// ✅ Correct: map the sanitizer across the array.
$ids = isset( $_POST['ids'] ) && is_array( $_POST['ids'] )
    ? array_map( 'absint', wp_unslash( $_POST['ids'] ) )
    : array();
```

### Mistake 6 — Open redirect via unvalidated URL

```php
// ❌ Insecure: attacker can redirect to a phishing site.
$redirect = $_GET['redirect_to'];
wp_redirect( $redirect );
exit;
```

```php
// ✅ Secure: validate redirect targets with wp_validate_redirect and use wp_safe_redirect.
$redirect = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
$redirect = wp_validate_redirect( $redirect, admin_url() );
wp_safe_redirect( $redirect );
exit;
```

### Mistake 7 — Trusting the whole request array (mass assignment)

```php
// ❌ Insecure: every client-supplied field is written through — including ones
// the form never rendered. A forged POST adds post_author or post_status=publish.
wp_update_post( wp_unslash( $_POST['post'] ) );

foreach ( $_POST['settings'] as $key => $value ) {
    update_user_meta( $user_id, 'my_plugin_' . sanitize_key( $key ), $value );
}
```

```php
// Inside an authenticated admin-post handler; the form uses
// wp_nonce_field( 'my_plugin_edit_post_' . $post_id ).
$raw = $_POST['post'] ?? null;
if ( ! is_array( $raw )
    || ! isset( $raw['ID'], $raw['post_title'], $raw['post_content'] )
    || ! is_string( $raw['ID'] )
    || ! is_string( $raw['post_title'] )
    || ! is_string( $raw['post_content'] )
) {
    wp_die( 'Invalid payload.', '', array( 'response' => 400 ) );
}
$post_id = filter_var( wp_unslash( $raw['ID'] ), FILTER_VALIDATE_INT, array(
    'options' => array( 'min_range' => 1 ),
) );
if ( false === $post_id ) {
    wp_die( 'Invalid post ID.', '', array( 'response' => 400 ) );
}
check_admin_referer( 'my_plugin_edit_post_' . $post_id );
$post = get_post( $post_id );
if ( ! $post || 'post' !== $post->post_type || ! current_user_can( 'edit_post', $post_id ) ) {
    wp_die( 'Forbidden.', '', array( 'response' => 403 ) );
}
// Build only the allowed fields. Never merge the request back into this array.
$data = array(
    'ID'           => $post_id,
    'post_title'   => sanitize_text_field( wp_unslash( $raw['post_title'] ) ),
    'post_content' => wp_kses_post( wp_unslash( $raw['post_content'] ) ),
);
$result = wp_update_post( wp_slash( $data ), true );
if ( is_wp_error( $result ) ) {
    wp_die( 'Update failed.', '', array( 'response' => 500 ) );
}
```

Mass assignment writes client-selected fields that the endpoint never intended to
expose. `wp_update_post()` does not perform the caller's capability check; its
`post_author` and `post_status` fields must not become writable by accident. A user
role is not a post field, but generic user/meta writers have analogous risks. Avoid
`extract( $_POST )` too: it lets request keys overwrite local variables.

For REST routes, `args` validates declared parameters; it does **not** automatically
reject or remove undeclared parameters. Construct an explicit persistence payload
rather than forwarding `$request->get_params()`. The Settings API can store one
array option, but its `sanitize_callback` must validate shape and build an explicit
allowlist of nested fields. Authorization and CSRF protection remain separate.

Related: see the `output-escaping` skill for the redirect "escape" context and the
`settings-options-security` skill for recursively sanitizing nested option arrays.

## Correct code examples

A complete reference of input types mapped to the correct sanitize/validate functions —
text, email, int, float, key, slug, URL, HTML, arrays, JSON — is in
[`references/sanitization-cheatsheet.md`](references/sanitization-cheatsheet.md).

```php
// Settings array sanitized field-by-field on save.
function my_plugin_sanitize_settings( $input ) {
    $clean = array();
    $clean['email']   = sanitize_email( $input['email'] ?? '' );
    $clean['count']   = absint( $input['count'] ?? 0 );
    $clean['enabled'] = ! empty( $input['enabled'] ) ? 1 : 0;
    $clean['note']    = wp_kses_post( $input['note'] ?? '' );

    if ( ! is_email( $clean['email'] ) ) {
        $clean['email'] = '';
        add_settings_error( 'my_plugin', 'bad_email', __( 'Invalid email.', 'my-plugin' ) );
    }
    return $clean;
}
```

## Checklist

- [ ] Every superglobal read is guarded with `isset()` and a default.
- [ ] `wp_unslash()` is applied before sanitizing superglobal data.
- [ ] Each value uses the sanitizer matching its type (see cheatsheet).
- [ ] Rich HTML uses `wp_kses` / `wp_kses_post`, never `strip_tags`, for safety.
- [ ] Values are validated against allowed sets / ranges after sanitizing.
- [ ] Arrays are sanitized element-by-element (`array_map`).
- [ ] URLs use `esc_url_raw()` for storage (`esc_url()` for display).
- [ ] Bulk updates validate container/scalar shapes, authorize each target object, and build explicit field allowlists.
- [ ] Settings API registrations supply a `sanitize_callback`.

## Official references

- [`WP_REST_Request::has_valid_params()`](https://developer.wordpress.org/reference/classes/wp_rest_request/has_valid_params/)
- [`wp_update_post()`](https://developer.wordpress.org/reference/functions/wp_update_post/)
- [`current_user_can()` — object capabilities](https://developer.wordpress.org/reference/functions/current_user_can/)

- [Data Validation — Common APIs Handbook](https://developer.wordpress.org/apis/security/data-validation/)
- [Sanitizing Data — Plugin Handbook](https://developer.wordpress.org/apis/security/sanitizing/)
- [`sanitize_text_field()`](https://developer.wordpress.org/reference/functions/sanitize_text_field/)
- [`sanitize_email()`](https://developer.wordpress.org/reference/functions/sanitize_email/)
- [`absint()`](https://developer.wordpress.org/reference/functions/absint/)
- [`sanitize_key()`](https://developer.wordpress.org/reference/functions/sanitize_key/)
- [`wp_kses_post()`](https://developer.wordpress.org/reference/functions/wp_kses_post/)
- [`esc_url_raw()`](https://developer.wordpress.org/reference/functions/esc_url_raw/)
- [`wp_unslash()`](https://developer.wordpress.org/reference/functions/wp_unslash/)
- [OWASP — Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
