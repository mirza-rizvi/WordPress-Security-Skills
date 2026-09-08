---
name: capability-permission-checks
description: >
  Use when adding admin pages, menu items, AJAX/REST handlers, action links, or any
  code that performs a privileged operation in WordPress. Gates actions with
  current_user_can() using the correct capability (not roles), including per-object
  checks like edit_post, and pairs the check with a nonce. Prevents privilege
  escalation and broken access control. Apply proactively to every privileged code path.
license: MIT
metadata:
  tags: [wordpress, security, php, capabilities, authorization, access-control]
---

# Capability & permission checks (authorization)

## When to use this skill

Use this skill wherever code does something **not everyone should be able to do**:

- Admin menu/submenu pages and settings screens.
- AJAX (`wp_ajax_*`) and REST `permission_callback`s.
- `admin-post.php` handlers and action links (delete/approve/activate).
- Editing options, users, posts, taxonomies, files, or plugin state.
- Anything reading or writing another user's data.

Authorization answers "**is this user allowed?**" — distinct from the nonce, which
answers "did this request come from us?" (see `nonces-csrf-protection`). Use both.

## Core principles (and why they matter)

1. **Check capabilities, not roles.** Roles are bundles of capabilities that admins can
   reassign. `current_user_can( 'administrator' )` is a bug — test the *capability*
   (`manage_options`), so custom roles and multisite behave correctly.
2. **Use the most specific capability.** `manage_options` for settings, `edit_posts` to
   create posts, `edit_post`/`delete_post` (with an ID) for a *specific* post. Broad caps
   over-grant.
3. **Authorization and CSRF are independent.** A capability check without a nonce is
   CSRF-able; a nonce without a capability check lets any logged-in user act. Pair them.
4. **Re-check at every entry point.** Hiding a menu item or button is UX, not security.
   The handler that does the work must check again — the URL/endpoint is directly reachable.
5. **Per-object checks need the object ID.** `current_user_can( 'edit_post', $post_id )`
   respects ownership and post-type rules; `current_user_can( 'edit_posts' )` alone does not.
6. **Fail closed.** Deny by default; only proceed when the check explicitly passes.

## Step-by-step implementation

1. Identify the operation and the **capability** it requires (use a meta cap with an ID
   for per-object actions).
2. At the start of the handler, after the nonce check:
   `if ( ! current_user_can( $cap[, $object_id] ) ) { deny(); }`.
3. `deny()` = `wp_die( ..., 403 )`, `wp_send_json_error( ..., 403 )`, or a REST
   `WP_Error` with `rest_forbidden` / status 403.
4. For menus/REST, supply the capability where the API expects it
   (`add_menu_page` capability arg, REST `permission_callback`).
5. Never gate solely by hiding UI.

## Common AI mistakes / anti-patterns

### Mistake 1 — Checking the role instead of the capability

```php
// ❌ Insecure: roles are mutable; this misses custom/multisite setups.
if ( in_array( 'administrator', wp_get_current_user()->roles, true ) ) {
    do_admin_thing();
}
```

```php
// ✅ Secure: test the capability.
if ( current_user_can( 'manage_options' ) ) {
    do_admin_thing();
}
```

### Mistake 2 — Relying on a hidden menu/button as the boundary

```php
// ❌ Insecure: handler trusts that only admins saw the link.
add_action( 'admin_post_purge_cache', function () {
    purge_cache(); // directly reachable via admin-post.php by anyone logged in
} );
```

```php
// ✅ Secure: the handler re-checks nonce + capability.
add_action( 'admin_post_purge_cache', function () {
    check_admin_referer( 'purge_cache' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Forbidden', 'my-plugin' ), 403 );
    }
    purge_cache();
} );
```

### Mistake 3 — Generic capability where a per-object check is needed

```php
// ❌ Insecure: any author can edit ANY post, not just their own.
if ( current_user_can( 'edit_posts' ) ) {
    wp_update_post( array( 'ID' => $post_id, 'post_title' => $title ) );
}
```

```php
// ✅ Secure: meta capability with the object ID enforces ownership.
if ( ! current_user_can( 'edit_post', $post_id ) ) {
    wp_die( esc_html__( 'You cannot edit this post.', 'my-plugin' ), 403 );
}
wp_update_post( array( 'ID' => $post_id, 'post_title' => $title ) );
```

### Mistake 4 — REST route with no real permission callback

```php
// ❌ Insecure: open to the world.
register_rest_route( 'my/v1', '/settings', array(
    'methods'             => 'POST',
    'callback'            => 'my_save',
    'permission_callback' => '__return_true',
) );
```

```php
// ✅ Secure: enforce the capability in permission_callback.
register_rest_route( 'my/v1', '/settings', array(
    'methods'             => 'POST',
    'callback'            => 'my_save',
    'permission_callback' => function () {
        return current_user_can( 'manage_options' );
    },
) );
```

### Mistake 5 — Checking capability but never branching

```php
// ❌ Insecure: result ignored; action runs regardless.
current_user_can( 'delete_users' );
delete_user_account( $id );
```

```php
// ✅ Secure: branch and fail closed.
if ( ! current_user_can( 'delete_users' ) ) {
    wp_die( esc_html__( 'Forbidden', 'my-plugin' ), 403 );
}
delete_user_account( $id );
```

### Mistake 6 — Assigning roles or capabilities from request data

```php
// ❌ Insecure: privilege escalation by posting role=administrator.
$user->set_role( $_POST['role'] );
```

```php
// ✅ Secure: validate the role against a hardcoded allowlist.
$allowed_roles = array( 'subscriber', 'contributor', 'author' );
$role          = isset( $_POST['role'] ) ? sanitize_key( wp_unslash( $_POST['role'] ) ) : '';
if ( ! in_array( $role, $allowed_roles, true ) ) {
    wp_die( esc_html__( 'Invalid role.', 'my-plugin' ), 400 );
}
$user->set_role( $role );
```

### Mistake 7 — Directly adding capabilities via user meta

```php
// ❌ Insecure: grants arbitrary capabilities.
$user->add_cap( $_POST['capability'] );
```

```php
// ✅ Secure: never add capabilities from input; use role-based allowlists.
$allowed_caps = array( 'edit_posts', 'publish_posts' );
$cap          = isset( $_POST['capability'] ) ? sanitize_key( wp_unslash( $_POST['capability'] ) ) : '';
if ( ! in_array( $cap, $allowed_caps, true ) ) {
    wp_die( esc_html__( 'Invalid capability.', 'my-plugin' ), 400 );
}
$user->add_cap( $cap );
```

Related: see the `multisite-security` skill for network vs. site scope and the
`nonces-csrf-protection` skill for pairing these checks with a nonce.

## Correct code examples

A complete example covering an admin page, an AJAX handler, a per-object action, and a
REST permission callback is in
[`references/capability-check-example.php`](references/capability-check-example.php).

```php
// Common capabilities and when to use them.
current_user_can( 'manage_options' );          // site settings / options
current_user_can( 'edit_posts' );              // create/edit posts (general)
current_user_can( 'edit_post', $post_id );     // edit THIS post (ownership-aware)
current_user_can( 'publish_posts' );           // publish
current_user_can( 'upload_files' );            // media uploads
current_user_can( 'edit_users' );              // manage other users
current_user_can( 'install_plugins' );         // install/activate plugins
```

## Checklist

- [ ] Every privileged handler calls `current_user_can()` and branches on the result.
- [ ] Capabilities are tested, never roles.
- [ ] The most specific capability is used; per-object actions pass the object ID.
- [ ] The check is paired with a nonce verification on state-changing requests.
- [ ] Admin pages re-check the capability on render (not just at menu registration).
- [ ] REST routes define a real `permission_callback` (never `__return_true` for writes).
- [ ] AJAX handlers check capability after `check_ajax_referer`.
- [ ] Denied requests fail closed with a 403 / `WP_Error`.

## Official references

- [Checking User Capabilities — Plugin Handbook](https://developer.wordpress.org/plugins/security/checking-user-capabilities/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/)
- [Roles and Capabilities](https://developer.wordpress.org/plugins/users/roles-and-capabilities/)
- [`map_meta_cap()` and meta capabilities](https://developer.wordpress.org/reference/functions/map_meta_cap/)
- [`add_menu_page()`](https://developer.wordpress.org/reference/functions/add_menu_page/)
- [OWASP — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
