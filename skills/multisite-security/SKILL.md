---
name: multisite-security
description: >
  Use when writing code that runs on a WordPress multisite network -
  switch_to_blog, network admin pages, get_sites, or capabilities that differ
  between site and network scope. Uses manage_network /
  manage_network_options and is_super_admin correctly, restores context with
  restore_current_blog, isolates per-site data, and never trusts a blog id
  from input. Prevents cross-site data leakage and network privilege escalation.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, multisite, network, capabilities"
---

# Multisite security

## When to use this skill

Use this skill whenever code runs on a WordPress multisite network:

- Using `switch_to_blog()` to access another site's data.
- Adding network admin pages (`network_admin_menu`).
- Enumerating sites with `get_sites()`.
- Reading a `blog_id` from a request parameter or URL.
- Performing actions that affect the whole network vs. a single site.

On multisite, site administrator and network administrator are different roles.
Network-level actions require `manage_network` or `manage_network_options`, and
`switch_to_blog()` must always be paired with `restore_current_blog()`.

Related: see the `capability-permission-checks` skill for single-site capability
patterns.

## Core principles (and why they matter)

1. **Site admin != network admin.** A site administrator can do almost anything on their
   own site, but they must not manage network settings or access other sites' data.
   Network actions need `manage_network` / `manage_network_options`.
2. **Always pair `switch_to_blog()` with `restore_current_blog()`.** Forgetting to restore
   leaves the rest of the request running in the wrong site context, leaking or corrupting
   data.
3. **Re-check capabilities after switching.** Capabilities are evaluated in the current
   site context. After `switch_to_blog()`, the capability context changes; re-verify
   `current_user_can()` or `user_can()` if you act on the new site.
4. **Never trust a `blog_id` from input.** Validate it against allowed sites (e.g., sites
   the current user belongs to, or the network allowlist) before switching.
5. **Keep per-site data isolated.** Do not store site A's data in site B's options or
   tables unless the user explicitly authorized cross-site access.
6. **`is_super_admin()` is for network-level checks only.** Prefer `current_user_can( 'manage_network' )`
   for capabilities.

## Step-by-step implementation

1. Check `is_multisite()` before running multisite-specific code.
2. For network admin pages, gate with `current_user_can( 'manage_network_options' )`.
3. For site actions that read a `blog_id` from input:
   - Cast to integer.
   - Confirm the site exists (`get_site()`).
   - Confirm the current user may act on it (`user_can( $user_id, 'manage_sites' )` or
     membership checks).
4. Wrap the operation in `switch_to_blog()` / `restore_current_blog()`.
5. After switching, re-check capabilities if the action is privileged.
6. Return errors rather than silently failing or defaulting to the current site.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Multisite security checklist](references/checklist.md) | Before final verification of the multisite security controls. |
| [Secure multisite operations](references/secure-multisite-operations.php) | Implementing validated site switching, membership checks, context restoration, and network option updates. |

## Common AI mistakes / anti-patterns

### Mistake 1 — `switch_to_blog()` with an unvalidated blog id

```php
// ❌ Insecure: any blog id can be requested, including sites the user does not own.
$blog_id = (int) $_GET['blog_id'];
switch_to_blog( $blog_id );
$posts = get_posts();
restore_current_blog();
```

```php
// ✅ Secure: validate the blog id and the user's relationship to it.
$blog_id = isset( $_GET['blog_id'] ) ? absint( $_GET['blog_id'] ) : 0;
$site    = get_site( $blog_id );
if ( ! $site || ! is_user_member_of_blog( get_current_user_id(), $blog_id ) ) {
    wp_die( esc_html__( 'Invalid site.', 'my-plugin' ), 403 );
}

switch_to_blog( $blog_id );
$posts = get_posts();
restore_current_blog();
```

### Mistake 2 — Forgetting `restore_current_blog()`

```php
// ❌ Risky: subsequent code runs in the switched context.
foreach ( $blog_ids as $blog_id ) {
    switch_to_blog( $blog_id );
    do_something();
}
```

```php
// ✅ Secure: restore after each switch.
foreach ( $blog_ids as $blog_id ) {
    switch_to_blog( $blog_id );
    do_something();
    restore_current_blog();
}
```

### Mistake 3 — Using `manage_options` for a network action

```php
// ❌ Insecure: site admins have manage_options but cannot manage the network.
if ( current_user_can( 'manage_options' ) ) {
    update_site_option( 'my_plugin_network_key', $value );
}
```

```php
// ✅ Secure: network actions require manage_network / manage_network_options.
if ( ! current_user_can( 'manage_network_options' ) ) {
    wp_die( esc_html__( 'You do not have permission to manage network options.', 'my-plugin' ), 403 );
}
update_site_option( 'my_plugin_network_key', $value );
```

### Mistake 4 — Leaking data after a switch

```php
// ❌ Insecure: data fetched under site B is echoed on site A without re-checking.
switch_to_blog( $blog_id );
$title = get_bloginfo( 'name' );
restore_current_blog();
echo $title;
```

```php
// ✅ Secure: validate the user may read the target site, then escape output.
if ( ! is_user_member_of_blog( get_current_user_id(), $blog_id ) ) {
    return;
}
switch_to_blog( $blog_id );
$title = get_bloginfo( 'name' );
restore_current_blog();
echo esc_html( $title );
```

### Mistake 5 — Assuming `is_super_admin()` covers every case

```php
// ❌ Less precise: is_super_admin checks the super-admin list, not a capability.
if ( is_super_admin() ) {
    // do network thing
}
```

```php
// ✅ Secure: prefer the explicit network capability.
if ( current_user_can( 'manage_network' ) ) {
    // do network thing
}
```

## Correct code examples

A complete network-safe routine that validates a blog id, switches context, and restores
it is in [`references/secure-multisite-operations.php`](references/secure-multisite-operations.php).

## Checklist

- [ ] Multisite-specific code checks `is_multisite()` first.
- [ ] Network admin actions use `manage_network` / `manage_network_options`.
- [ ] `blog_id` values from input are cast to integers and validated.
- [ ] The user is confirmed to be a member of / allowed on the target site before switching.
- [ ] Every `switch_to_blog()` has a matching `restore_current_blog()`.
- [ ] Capabilities are re-checked after switching sites if the action is privileged.
- [ ] Per-site data is not leaked into another site's context.
- [ ] `is_super_admin()` is used only where the super-admin list is the correct gate.

## Official references

- [`is_multisite()`](https://developer.wordpress.org/reference/functions/is_multisite/)
- [`is_super_admin()`](https://developer.wordpress.org/reference/functions/is_super_admin/)
- [`current_user_can()`](https://developer.wordpress.org/reference/functions/current_user_can/)
- [`user_can()`](https://developer.wordpress.org/reference/functions/user_can/)
- [`switch_to_blog()`](https://developer.wordpress.org/reference/functions/switch_to_blog/)
- [`restore_current_blog()`](https://developer.wordpress.org/reference/functions/restore_current_blog/)
- [`get_sites()`](https://developer.wordpress.org/reference/functions/get_sites/)
- [`get_current_blog_id()`](https://developer.wordpress.org/reference/functions/get_current_blog_id/)
- [`network_admin_menu` hook](https://developer.wordpress.org/reference/hooks/network_admin_menu/)
- [`is_user_member_of_blog()`](https://developer.wordpress.org/reference/functions/is_user_member_of_blog/)
- [Multisite Network Administration](https://developer.wordpress.org/advanced-administration/multisite/)
