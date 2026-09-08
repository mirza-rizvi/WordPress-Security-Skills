---
name: wp-cli-security
description: >
  Use when registering a WP-CLI command with WP_CLI::add_command or writing
  command logic. Validates and sanitizes positional and associative arguments,
  does not assume a logged-in user or capability context, avoids printing
  secrets, and confirms destructive operations. Prevents injection and unsafe
  automation through the CLI surface.
license: MIT
metadata:
  tags: [wordpress, security, php, wp-cli, cli, automation]
---

# WP-CLI security

## When to use this skill

Use this skill whenever code registers or implements a WP-CLI command:

- `WP_CLI::add_command( 'my-plugin thing', ... )`.
- Writing a command class method that reads `$args` / `$assoc_args`.
- Running destructive operations (delete, reset, import, purge) from the command line.
- Returning data or logging progress from a CLI routine.

WP-CLI runs as the system user, often as root on containers or with broad file-system
permissions. It has **no WordPress current user** by default, so `current_user_can()`
does not authorize CLI actions. Arguments are still untrusted input.

Related: see the `capability-permission-checks` skill for normal web-request
authorization and the `cron-background-job-security` skill for scheduled jobs.

## Core principles (and why they matter)

1. **No `current_user_can()` in CLI by default.** There is no logged-in WordPress user.
   Either use `WP_CLI::launch_self()` with a `--user` flag, explicitly set a user with
   `--user`, or perform capability-independent maintenance tasks only.
2. **Sanitize every argument.** `$args` and `$assoc_args` can come from scripts, CI, or
   shell history; treat them as untrusted input.
3. **Use prepared statements for database access.** Do not interpolate `$args` into
   `$wpdb` queries.
4. **Confirm destructive actions.** `WP_CLI::confirm()` stops accidental data loss in
   automated runs.
5. **Never print secrets.** API keys, tokens, and passwords must not appear in CLI output,
   logs, or shell history.
6. **Be explicit about `--allow-root`.** Running as root is common in containers but
   dangerous; document it and avoid file ownership surprises.

## Step-by-step implementation

1. Register the command with `WP_CLI::add_command()` and a clear docblock.
2. In the command method, validate argument counts and sanitize each value to type.
3. For destructive commands, call `WP_CLI::confirm()` unless `--yes` is passed.
4. Use `$wpdb->prepare()` for any dynamic query.
5. Avoid echo; use `WP_CLI::log()`, `WP_CLI::success()`, or `WP_CLI::error()`.
6. If the command needs a user context, require `--user=<id|login|email>` and load it with
   `WP_User::get_data_by()` / `wp_set_current_user()`.

## Common AI mistakes / anti-patterns

### Mistake 1 — Interpolating `$args` into a query

```php
// ❌ Insecure: SQL injection via CLI argument.
$wpdb->query( "DELETE FROM {$wpdb->prefix}my_table WHERE id = {$args[0]}" );
```

```php
// ✅ Secure: use $wpdb->prepare().
$id = absint( $args[0] );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}my_table WHERE id = %d", $id ) );
```

### Mistake 2 — Assuming an admin user context

```php
// ❌ Insecure: current_user_can is meaningless without --user.
if ( current_user_can( 'manage_options' ) ) {
    update_option( 'my_plugin_key', $value );
}
```

```php
// ✅ Secure: require --user or gate by filesystem/CLI policy, not web capability.
class My_Plugin_CLI_Command {
    /**
     * Update a setting.
     *
     * ## OPTIONS
     * [--user=<user>]
     * : User to run as.
     */
    public function update_setting( $args, $assoc_args ) {
        if ( isset( $assoc_args['user'] ) ) {
            $user = get_user_by( 'login', $assoc_args['user'] );
            if ( $user ) {
                wp_set_current_user( $user->ID );
            }
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            WP_CLI::error( 'This command requires --user with manage_options capability.' );
        }

        update_option( 'my_plugin_key', sanitize_text_field( $args[0] ) );
        WP_CLI::success( 'Setting updated.' );
    }
}
```

### Mistake 3 — Printing secrets in output

```php
// ❌ Insecure: secret is now in shell history and terminal scrollback.
WP_CLI::log( 'Using API key: ' . $api_key );
```

```php
// ✅ Secure: log an identifier or redacted value.
WP_CLI::log( 'Using API key ending in: ' . substr( $api_key, -4 ) );
```

### Mistake 4 — Destructive command with no confirmation

```php
// ❌ Risky: a typo in CI wipes data.
public function purge( $args ) {
    $wpdb->query( "TRUNCATE {$wpdb->prefix}my_plugin_logs" );
}
```

```php
// ✅ Secure: require confirmation unless --yes is passed.
public function purge( $args, $assoc_args ) {
    if ( ! isset( $assoc_args['yes'] ) ) {
        WP_CLI::confirm( 'This will delete all logs. Are you sure?' );
    }
    global $wpdb;
    $wpdb->query( "TRUNCATE {$wpdb->prefix}my_plugin_logs" );
    WP_CLI::success( 'Logs purged.' );
}
```

### Mistake 5 — Trusting associative args without defaults

```php
// ❌ Fragile: missing key causes undefined array warning.
$days = $assoc_args['days'];
```

```php
// ✅ Secure: provide defaults and sanitize.
$days = isset( $assoc_args['days'] ) ? absint( $assoc_args['days'] ) : 30;
```

## Correct code examples

A complete secure WP-CLI command class is in
[`references/secure-wp-cli-command.php`](references/secure-wp-cli-command.php).

## Checklist

- [ ] Every CLI argument is sanitized to its expected type.
- [ ] Database queries use `$wpdb->prepare()`; no argument interpolation.
- [ ] Destructive commands call `WP_CLI::confirm()` unless `--yes` is provided.
- [ ] The command does not rely on `current_user_can()` without an explicit `--user`.
- [ ] Secrets, tokens, and API keys are never printed or logged in plaintext.
- [ ] `--allow-root` usage is documented and justified.
- [ ] Output uses `WP_CLI::log()` / `success()` / `error()` instead of `echo`.
- [ ] Command docblocks define options and examples.

## Official references

- [WP-CLI Commands — Handbook](https://make.wordpress.org/cli/handbook/commands-cookbook/)
- [`WP_CLI::add_command()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp_cli-add_command/)
- [`WP_CLI::error()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp_cli-error/)
- [`WP_CLI::success()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp_cli-success/)
- [`WP_CLI::log()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp_cli-log/)
- [`WP_CLI::confirm()`](https://make.wordpress.org/cli/handbook/references/internal-api/wp_cli-confirm/)
- [Config — WP-CLI](https://make.wordpress.org/cli/handbook/references/config/)
- [OWASP — Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
