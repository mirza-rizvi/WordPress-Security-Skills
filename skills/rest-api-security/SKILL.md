---
name: rest-api-security
description: >
  Use when registering WordPress REST API routes with register_rest_route or building
  custom endpoints. Sets a real permission_callback (never __return_true for writes),
  defines args with sanitize_callback and validate_callback, enforces capabilities and
  per-object checks, and escapes any HTML in responses. Prevents broken access control
  and injection via the REST surface. Apply proactively to every registered route.
license: MIT
metadata:
  tags: [wordpress, security, php, rest-api, authorization, endpoints]
---

# REST API security

## When to use this skill

Use this skill whenever you expose a custom REST endpoint:

- Any `register_rest_route()` call.
- Endpoints backing a block editor, admin SPA, or front-end fetch.
- Routes that read private data or perform writes/deletes.
- Adding fields via `register_rest_field` / extending core routes.

The REST API is reachable by anyone who can reach the site. A missing or permissive
`permission_callback` is broken access control — among the most common WordPress
vulnerabilities.

## Core principles (and why they matter)

1. **`permission_callback` is mandatory and must be real.** It is the authorization
   boundary. `__return_true` means "anyone, including logged-out users" — never use it for
   writes, and rarely for reads of non-public data. (Core warns if it's omitted entirely.)
2. **Authorize per method and per object.** A route may allow `GET` publicly but require a
   capability for `POST`. Object routes (`/items/(?P<id>\d+)`) should check the user can act
   on *that* object.
3. **Declare `args` with sanitize + validate callbacks.** The REST framework will sanitize
   and validate inputs for you when you describe them — use it instead of ad-hoc parsing.
4. **Don't rely on nonces for authorization.** The `wp_rest` nonce (cookie auth) proves the
   request origin, like any nonce; capabilities still decide what's allowed.
5. **Escape HTML in responses.** JSON is not auto-safe if the client injects values into the
   DOM. Escape/normalize anything that may be rendered as markup.
6. **Use specific namespaces/versions** (`my-plugin/v1`) and least-privileged callbacks.

## Step-by-step implementation

1. Register on `rest_api_init` with a versioned namespace.
2. Set `permission_callback` to a function returning `true`/`false`/`WP_Error`, enforcing
   the right capability (and per-object check via the request args).
3. Define every parameter under `args` with `required`, `type`, `sanitize_callback`,
   `validate_callback`.
4. In the main `callback`, treat params as already sanitized but still escape on output.
5. Return `rest_ensure_response()` or a `WP_Error` with an HTTP status.

## Common AI mistakes / anti-patterns

### Mistake 1 — `permission_callback => __return_true` on a write

```php
// ❌ Insecure: anyone (even logged out) can write.
register_rest_route( 'my/v1', '/settings', array(
    'methods'             => 'POST',
    'callback'            => 'my_save_settings',
    'permission_callback' => '__return_true',
) );
```

```php
// ✅ Secure: enforce a capability.
register_rest_route( 'my/v1', '/settings', array(
    'methods'             => 'POST',
    'callback'            => 'my_save_settings',
    'permission_callback' => static function () {
        return current_user_can( 'manage_options' );
    },
) );
```

### Mistake 2 — Omitting `permission_callback` entirely

```php
// ❌ Insecure/broken: no callback → access control undefined (and a _doing_it_wrong notice).
register_rest_route( 'my/v1', '/data', array(
    'methods'  => 'GET',
    'callback' => 'my_get_data',
) );
```

```php
// ✅ Secure: explicit callback, even for public reads.
register_rest_route( 'my/v1', '/data', array(
    'methods'             => 'GET',
    'callback'            => 'my_get_data',
    'permission_callback' => '__return_true', // intentional: this data is public
) );
```

### Mistake 3 — Reading params without sanitize/validate

```php
// ❌ Insecure: raw param straight into a query/update.
function my_save_settings( WP_REST_Request $request ) {
    update_option( 'my_color', $request['color'] );
}
```

```php
// ✅ Secure: declare args; framework sanitizes/validates before callback runs.
register_rest_route( 'my/v1', '/settings', array(
    'methods'             => 'POST',
    'callback'            => 'my_save_settings',
    'permission_callback' => static fn() => current_user_can( 'manage_options' ),
    'args'                => array(
        'color' => array(
            'required'          => true,
            'type'              => 'string',
            'sanitize_callback' => 'sanitize_hex_color',
            'validate_callback' => static function ( $value ) {
                return (bool) sanitize_hex_color( $value );
            },
        ),
    ),
) );
function my_save_settings( WP_REST_Request $request ) {
    update_option( 'my_color', $request['color'] );
    return rest_ensure_response( array( 'saved' => true ) );
}
```

### Mistake 4 — No per-object authorization

```php
// ❌ Insecure: any user with edit_posts can edit ANY post via the endpoint.
'permission_callback' => static fn() => current_user_can( 'edit_posts' ),
```

```php
// ✅ Secure: check the specific object using the request.
'permission_callback' => static function ( WP_REST_Request $request ) {
    return current_user_can( 'edit_post', absint( $request['id'] ) );
},
```

### Mistake 5 — Returning unescaped HTML that the client renders

```php
// ❌ Risky: stored markup flows to the DOM unescaped client-side.
return array( 'title' => get_post_field( 'post_title', $id ) );
```

```php
// ✅ Safer: normalize/escape values that may be rendered as HTML.
return rest_ensure_response( array(
    'title' => esc_html( get_post_field( 'post_title', $id ) ),
) );
```

### Mistake 6 — `register_rest_field()` without a schema or permission check

```php
// ❌ Insecure: writable field with no capability gate or sanitization.
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
// ✅ Secure: schema with sanitize/validate + capability check on update.
register_rest_field(
    'post',
    'my_plugin_meta',
    array(
        'get_callback'    => function ( $object ) {
            return get_post_meta( $object['id'], '_my_plugin_meta', true );
        },
        'update_callback' => function ( $value, $object ) {
            if ( ! current_user_can( 'edit_post', $object->ID ) ) {
                return new WP_Error( 'forbidden', __( 'Forbidden.', 'my-plugin' ), array( 'status' => 403 ) );
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

### Mistake 7 — Forgetting batch endpoint authentication

WordPress supports `/wp-json/batch/v1` requests that invoke multiple routes in one HTTP
request. Each route's `permission_callback` is still enforced, so never rely on the batch
entry point being "internal" — every inner route must authorize itself. You can also use
the `rest_authentication_errors` filter to reject authentication globally when needed.

Related: see the `ajax-security` skill for when to use admin-ajax instead of REST, and the
`http-api-ssrf-prevention` skill for outbound HTTP calls from a REST callback.

## Correct code examples

A complete route with `permission_callback`, per-object check, `args`
sanitize/validate, and a `WP_Error` failure path is in
[`references/secure-rest-endpoint.php`](references/secure-rest-endpoint.php).

## Checklist

- [ ] Every route defines a `permission_callback` (no implicit/missing one).
- [ ] Writes/deletes enforce a capability; `__return_true` is used only for truly public reads.
- [ ] Per-object routes check the user can act on that object (using request args).
- [ ] Authorization differs by method where appropriate (read vs write).
- [ ] All params declared under `args` with `sanitize_callback` + `validate_callback`.
- [ ] Required params marked `required => true`; types declared.
- [ ] HTML in responses is escaped/normalized.
- [ ] Errors return `WP_Error` with an explicit HTTP status.
- [ ] Namespace is versioned and plugin-specific (`my-plugin/v1`).

## Official references

- [`register_rest_route()`](https://developer.wordpress.org/reference/functions/register_rest_route/)
- [Adding Custom Endpoints — REST API Handbook](https://developer.wordpress.org/rest-api/extending-the-rest-api/adding-custom-endpoints/)
- [Routes & Endpoints — permission_callback](https://developer.wordpress.org/rest-api/extending-the-rest-api/routes-and-endpoints/)
- [Argument schema, sanitize & validate callbacks](https://developer.wordpress.org/rest-api/extending-the-rest-api/schema/)
- [REST API authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/)
- [`register_rest_field()`](https://developer.wordpress.org/reference/functions/register_rest_field/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
