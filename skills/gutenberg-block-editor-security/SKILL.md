---
name: gutenberg-block-editor-security
description: >
  Use when building dynamic blocks or block-editor features - a render_callback,
  server-side rendered blocks via ServerSideRender, REST-backed block data, or
  register_rest_field for the editor. Sanitizes block attributes per type,
  escapes server render output, sets a real permission_callback on editor REST
  surfaces, and handles RichText content with wp_kses. Prevents stored XSS and
  broken access control in the editor.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, javascript, gutenberg, block-editor, xss, rest"
---

# Gutenberg block editor security

## When to use this skill

Use this skill whenever code interacts with the block editor beyond simple static blocks:

- Building dynamic blocks with a PHP `render_callback`.
- Using `ServerSideRender` to fetch server-rendered markup in the editor.
- Exposing or saving block data via `register_rest_field()`.
- Handling `RichText` content or allowing markup in block attributes.
- Enqueuing block-editor assets that call custom REST endpoints.

The block editor trusts server-rendered HTML and REST field values. If the server
returns unescaped data or allows unauthorized writes, the vulnerability lands inside
the editor UI and the saved post content.

Related: see the `shortcode-block-security` skill for attribute sanitization basics
and the `rest-api-security` skill for REST endpoints.

## Core principles (and why they matter)

1. **Block attributes are user input.** Declaring a type in `block.json` validates shape
   but does not sanitize HTML or JavaScript. Sanitize in `render_callback`.
2. **Server render output must be escaped.** The editor and front-end both render the
   callback's return value; escape for the context (HTML, attribute, URL, rich text).
3. **Editor REST fields need real permission callbacks.** `register_rest_field()` `update_callback`
   must check `current_user_can( 'edit_post', $post_id )` or a matching capability.
4. **RichText allows markup — constrain it.** Use `wp_kses_post()` or a custom allowlist
   instead of raw storage.
5. **`ServerSideRender` requests are REST requests.** They are public unless the block's
   REST route or render callback enforces capability checks.
6. **Use `apiFetch` with the `X-WP-Nonce` header.** Modern editor JS uses `apiFetch`, which
   adds the nonce automatically for same-site REST requests.

## Step-by-step implementation

1. Define block attributes in `block.json` with types and defaults.
2. In the PHP `render_callback`, sanitize each attribute before use.
3. Build markup with escaped values (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`).
4. If the block needs server-side rendering in the editor, ensure the underlying data source
   enforces permissions.
5. For `register_rest_field()` used by the block:
   - Add `schema` with `arg_options` sanitize/validate callbacks.
   - In `update_callback`, check the acting user's capability on the object.
6. For `RichText`, sanitize on save with `wp_kses_post()` and escape on render.

## Common AI mistakes / anti-patterns

### Mistake 1 — Render callback echoing attributes unescaped

```php
// ❌ Insecure: stored XSS through a block attribute.
function my_plugin_render_alert( $attributes ) {
    return '<div class="alert">' . $attributes['message'] . '</div>';
}
```

```php
// ✅ Secure: sanitize and escape the attribute.
function my_plugin_render_alert( $attributes ) {
    $message = isset( $attributes['message'] ) ? sanitize_text_field( $attributes['message'] ) : '';
    return '<div class="alert">' . esc_html( $message ) . '</div>';
}
```

### Mistake 2 — `register_rest_field` update_callback with no capability check

```php
// ❌ Insecure: any authenticated user can update the field.
register_rest_field( 'post', 'my_plugin_meta', array(
    'get_callback'    => function ( $object ) {
        return get_post_meta( $object['id'], '_my_plugin_meta', true );
    },
    'update_callback' => function ( $value, $object ) {
        update_post_meta( $object->ID, '_my_plugin_meta', $value );
    },
) );
```

```php
// ✅ Secure: check capability before updating; sanitize value.
register_rest_field(
    'post',
    'my_plugin_meta',
    array(
        'get_callback'    => function ( $object ) {
            return get_post_meta( $object['id'], '_my_plugin_meta', true );
        },
        'update_callback' => function ( $value, $object ) {
            if ( ! current_user_can( 'edit_post', $object->ID ) ) {
                return new WP_Error( 'forbidden', __( 'You cannot edit this post.', 'my-plugin' ), array( 'status' => 403 ) );
            }
            update_post_meta( $object->ID, '_my_plugin_meta', sanitize_text_field( $value ) );
            return true;
        },
        'schema'          => array(
            'type'        => 'string',
            'arg_options' => array(
                'sanitize_callback' => 'sanitize_text_field',
            ),
        ),
    )
);
```

### Mistake 3 — Storing raw RichText without `wp_kses_post`

```php
// ❌ Insecure: RichText can contain script tags and event handlers.
update_post_meta( $post_id, '_my_plugin_note', $attributes['note'] );
```

```php
// ✅ Secure: constrain rich markup.
$note = isset( $attributes['note'] ) ? wp_kses_post( $attributes['note'] ) : '';
update_post_meta( $post_id, '_my_plugin_note', $note );
```

### Mistake 4 — `ServerSideRender` of privileged data without checks

```php
// ❌ Insecure: block preview reveals data the editor user may not be allowed to see.
function my_plugin_render_private( $attributes ) {
    return '<pre>' . get_option( 'my_plugin_secret_report' ) . '</pre>';
}
```

```php
// ✅ Secure: enforce the same capability in render_callback.
function my_plugin_render_private( $attributes ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return '<p>' . esc_html__( 'You do not have permission to view this.', 'my-plugin' ) . '</p>';
    }
    $report = get_option( 'my_plugin_secret_report', '' );
    return '<pre>' . esc_html( $report ) . '</pre>';
}
```

### Mistake 5 — Manual `fetch` without nonce

```js
// ❌ Insecure: custom fetch to a REST endpoint without the nonce.
fetch( '/wp-json/my-plugin/v1/data' )
  .then( r => r.json() );
```

```js
// ✅ Secure: use apiFetch, which attaches X-WP-Nonce automatically.
import apiFetch from '@wordpress/api-fetch';

apiFetch( { path: 'my-plugin/v1/data' } )
  .then( data => { /* ... */ } );
```

## Correct code examples

A secure dynamic block with `render_callback` and a REST field with permission checks
is in [`references/secure-block-editor.php`](references/secure-block-editor.php).

## Checklist

- [ ] Block attributes are declared in `block.json` with types and defaults.
- [ ] `render_callback` sanitizes every attribute before use.
- [ ] Server-rendered output is escaped for its context.
- [ ] `register_rest_field()` used by the block has schema + sanitize/validate callbacks.
- [ ] `register_rest_field()` `update_callback` checks the appropriate capability.
- [ ] `RichText` and rich markup are constrained with `wp_kses_post()` or a custom allowlist.
- [ ] `ServerSideRender` blocks enforce the same permissions as the front-end render.
- [ ] Editor JS uses `apiFetch` (or sends `X-WP-Nonce`) for same-site REST calls.
- [ ] No secrets are returned to the block editor for low-privilege users.

## Official references

- [Block Editor Handbook](https://developer.wordpress.org/block-editor/)
- [`register_block_type()`](https://developer.wordpress.org/reference/functions/register_block_type/)
- [`register_rest_field()`](https://developer.wordpress.org/reference/functions/register_rest_field/)
- [`get_block_wrapper_attributes()`](https://developer.wordpress.org/reference/functions/get_block_wrapper_attributes/)
- [`wp_kses_post()`](https://developer.wordpress.org/reference/functions/wp_kses_post/)
- [`esc_html()`](https://developer.wordpress.org/reference/functions/esc_html/)
- [`esc_attr()`](https://developer.wordpress.org/reference/functions/esc_attr/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/)
- [WordPress `apiFetch` package](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-api-fetch/)
- [ServerSideRender component](https://developer.wordpress.org/block-editor/reference-guides/packages/packages-server-side-render/)
