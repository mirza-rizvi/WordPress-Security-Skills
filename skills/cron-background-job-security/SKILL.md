---
name: cron-background-job-security
description: >
  Use when scheduling WordPress cron events with wp_schedule_event /
  wp_schedule_single_event or writing the callback that runs on a cron hook.
  Treats cron callbacks as running without a logged-in user, re-checks
  authorization against stored context rather than current_user_can, keeps
  secrets out of cron URLs, and validates any stored input the job consumes.
  Prevents unauthenticated privileged actions via the cron surface.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, cron, wp-cron, background-jobs"
---

# Cron & background job security

## When to use this skill

Use this skill whenever code schedules or runs WordPress cron events:

- Calling `wp_schedule_event()` or `wp_schedule_single_event()`.
- Writing a callback for a cron hook (`add_action( 'my_plugin_daily_sync', ... )`).
- Running jobs through `wp-cron.php`, including externally triggered real cron.
- Storing context (user ids, arguments) for a job to act on later.

Cron callbacks run with **no current user**. `current_user_can()` returns false for
everything, and `wp-cron.php` is publicly reachable. Authorization must be captured
at schedule time and re-verified inside the callback against stored context, not the
absent current user.

Related: see the `secrets-credentials-management` skill for keeping keys out of cron
URLs and the `capability-permission-checks` skill for normal request authorization.

## Core principles (and why they matter)

1. **No `current_user_can()` inside cron callbacks.** There is no logged-in user during
   cron execution. Capture the acting user or capability context when scheduling and
   re-verify it from stored data.
2. **`wp-cron.php` is public.** Anyone can trigger it. The callback itself must enforce
   authorization, not rely on the trigger being hidden.
3. **Do not put secrets in scheduled URLs or args.** Cron arguments are stored in the
   `cron` option; treat them as persistent but not secret.
4. **Sanitize and validate stored args.** The job reads args that were stored earlier;
   validate them again before acting.
5. **Use `wp_next_scheduled()` to prevent duplicates.** Without it, reactivations or
   repeated `init` hooks can schedule the same event many times.
6. **Clean up on deactivation.** Use `wp_clear_scheduled_hook()` so events don't run for
   a deactivated plugin.

## Step-by-step implementation

1. Schedule the event with `wp_next_scheduled()` guard:
   ```php
   if ( ! wp_next_scheduled( 'my_plugin_daily_sync' ) ) {
       wp_schedule_event( time(), 'daily', 'my_plugin_daily_sync' );
   }
   ```
2. If the job needs per-object authorization, store a user id or capability context
   alongside the args at schedule time (e.g., the user who queued a one-time export).
3. In the callback, re-verify the stored context:
   - Look up the user and check `user_can( $user_id, $capability )`.
   - Validate object ids with `get_post()` / `get_userdata()` and check ownership/permission.
4. Sanitize every stored arg before use.
5. Avoid passing secrets or raw user input as cron args.
6. On plugin deactivation, clear the hook.

## Common AI mistakes / anti-patterns

### Mistake 1 — Using `current_user_can()` inside a cron callback

```php
// ❌ Insecure: current_user_can is meaningless during cron; this always fails.
add_action( 'my_plugin_daily_sync', function () {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }
    my_plugin_sync();
} );
```

```php
// ✅ Secure: the scheduled event itself is the authorization boundary; validate data only.
add_action( 'my_plugin_daily_sync', 'my_plugin_run_daily_sync' );
function my_plugin_run_daily_sync() {
    $settings = get_option( 'my_plugin_sync_settings', array() );
    $endpoint = isset( $settings['endpoint'] ) ? esc_url_raw( $settings['endpoint'] ) : '';
    if ( ! $endpoint ) {
        return;
    }
    // No current_user_can needed — the fact the event was scheduled is the policy.
    my_plugin_sync( $endpoint );
}
```

### Mistake 2 — Passing a secret in the cron URL

```php
// ❌ Insecure: secret lands in the cron option and may appear in logs.
wp_schedule_single_event( time(), 'my_plugin_fetch', array( 'token' => $api_secret ) );
```

```php
// ✅ Secure: store the secret in a wp-config constant or encrypted option; pass only ids.
wp_schedule_single_event( time(), 'my_plugin_fetch', array( 'feed_id' => $feed_id ) );
// Callback reads the secret from a secure location.
```

### Mistake 3 — Trusting `$_GET` passed to a cron trigger

```php
// ❌ Insecure: wp-cron.php is public and $_GET is attacker-controllable.
add_action( 'my_plugin_run_export', function () {
    $user_id = (int) $_GET['user_id'];
    my_plugin_export_for_user( $user_id );
} );
```

```php
// ✅ Secure: capture and validate context at schedule time, then re-verify inside the job.
function my_plugin_queue_export( $user_id ) {
    if ( ! current_user_can( 'manage_options' ) ) {
        return false;
    }
    $user_id = absint( $user_id );
    wp_schedule_single_event( time(), 'my_plugin_run_export', array( 'user_id' => $user_id ) );
}

add_action( 'my_plugin_run_export', 'my_plugin_run_export_callback' );
function my_plugin_run_export_callback( $args ) {
    $user_id = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : 0;
    if ( $user_id <= 0 || ! user_can( $user_id, 'read' ) ) {
        return;
    }
    my_plugin_export_for_user( $user_id );
}
```

### Mistake 4 — Scheduling duplicate events

```php
// ❌ Risky: creates a new event on every init if not guarded.
add_action( 'init', function () {
    wp_schedule_event( time(), 'hourly', 'my_plugin_hourly' );
} );
```

```php
// ✅ Secure: guard with wp_next_scheduled().
add_action( 'init', function () {
    if ( ! wp_next_scheduled( 'my_plugin_hourly' ) ) {
        wp_schedule_event( time(), 'hourly', 'my_plugin_hourly' );
    }
} );
```

### Mistake 5 — Forgetting to unschedule on deactivation

```php
// ❌ Risky: scheduled hooks outlive the plugin — nothing clears them.
// (No register_deactivation_hook() anywhere in the plugin.)
register_activation_hook( __FILE__, function () {
    if ( ! wp_next_scheduled( 'my_plugin_hourly' ) ) {
        wp_schedule_event( time(), 'hourly', 'my_plugin_hourly' );
    }
} );
```

```php
// ✅ Secure: clear scheduled hooks on deactivation.
register_deactivation_hook( __FILE__, 'my_plugin_deactivate' );
function my_plugin_deactivate() {
    wp_clear_scheduled_hook( 'my_plugin_hourly' );
    wp_clear_scheduled_hook( 'my_plugin_daily_sync' );
}
```

## Correct code examples

An integration example — schedule, callback with stored-context verification, and
deactivation cleanup — is in [`references/secure-cron-job.php`](references/secure-cron-job.php).
It calls `my_plugin_generate_user_export( $user_id )`, a project callback your plugin
must provide (the file documents the contract); adapt names and hooks to your plugin.

## Checklist

- [ ] Cron callbacks do not rely on `current_user_can()`.
- [ ] Per-object jobs capture the acting user/context at schedule time and re-verify it in the callback.
- [ ] Secrets are not passed as cron arguments or embedded in cron URLs.
- [ ] Stored cron args are sanitized and validated before use.
- [ ] `wp_next_scheduled()` prevents duplicate scheduled events.
- [ ] Custom recurrence intervals are added via the `cron_schedules` filter before scheduling.
- [ ] Scheduled hooks are cleared on plugin deactivation.
- [ ] Failures are logged without exposing secrets or internal paths.

## Official references

- [`wp_schedule_event()`](https://developer.wordpress.org/reference/functions/wp_schedule_event/)
- [`wp_schedule_single_event()`](https://developer.wordpress.org/reference/functions/wp_schedule_single_event/)
- [`wp_next_scheduled()`](https://developer.wordpress.org/reference/functions/wp_next_scheduled/)
- [`wp_clear_scheduled_hook()`](https://developer.wordpress.org/reference/functions/wp_clear_scheduled_hook/)
- [`wp_unschedule_event()`](https://developer.wordpress.org/reference/functions/wp_unschedule_event/)
- [`user_can()`](https://developer.wordpress.org/reference/functions/user_can/)
- [`DISABLE_WP_CRON` constant](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#disable-cron)
- [Cron — Plugin Handbook](https://developer.wordpress.org/plugins/cron/)
- [OWASP — Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
