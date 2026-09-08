---
name: secure-plugin-development
description: >
  Use when starting a new WordPress plugin or theme, scaffolding a plugin file,
  wiring hooks, or adding any feature that handles requests, options, or output.
  Establishes the secure-by-default baseline — ABSPATH guard, the
  capability + nonce + sanitize + escape flow, prepared queries, and safe defaults —
  and routes to the focused security skills for each concern. Apply proactively at
  the start of any WordPress build.
license: MIT
metadata:
  tags: [wordpress, security, php, plugin, theme, baseline]
---

# Secure plugin & theme development (baseline)

## When to use this skill

Use this skill at the **start** of any WordPress development work and whenever you add
a feature that crosses a trust boundary:

- Creating a new plugin main file or theme `functions.php` addition.
- Registering hooks (`add_action` / `add_filter`) that handle input or render output.
- Adding admin pages, settings, shortcodes, blocks, widgets, or REST routes.
- Reviewing an existing plugin to bring it up to a secure baseline.

This is the **router** skill. It gives the end-to-end secure flow, then points to the
focused skills for each step:

- Input handling: `input-sanitization-validation`.
- Output / XSS: `output-escaping`.
- CSRF: `nonces-csrf-protection`.
- Authorization: `capability-permission-checks`.
- Database: `sql-injection-prevention`.
- Uploads: `file-upload-security`.
- REST: `rest-api-security`.
- Hard config: `wp-hardening-best-practices`.
- Auditing: `security-auditing-code-review`.
- Privacy: `user-data-protection-privacy`.
- AJAX: `ajax-security`.
- Settings/options: `settings-options-security`.
- Outbound HTTP / SSRF: `http-api-ssrf-prevention`.
- Shortcodes & dynamic blocks: `shortcode-block-security`.
- Serialization: `object-injection-deserialization`.
- Filesystem: `filesystem-security`.
- Secrets: `secrets-credentials-management`.
- Cron: `cron-background-job-security`.
- Multisite: `multisite-security`.
- Block editor: `gutenberg-block-editor-security`.
- WP-CLI: `wp-cli-security`.
- WooCommerce: `woocommerce-security`.
- Dependencies & supply chain: `dependency-supply-chain-security`.
- Authentication & sessions: `authentication-session-security`.
- Security headers / CSP: `security-headers-csp`.

Related: see the `object-injection-deserialization` skill whenever you store or read
serialized PHP, and the `secrets-credentials-management` skill for API keys and tokens.

## Core principles (and why they matter)

1. **Never trust input; always escape output.** Every value from `$_GET`, `$_POST`,
   `$_REQUEST`, `$_COOKIE`, the database, or a remote API is untrusted until sanitized,
   and untrusted again the moment it is echoed. These are two separate jobs.
2. **Block direct file access.** Plugin files are reachable by URL. Without an `ABSPATH`
   guard, an attacker can execute them outside WordPress, bypassing all your checks.
3. **Authenticate the request, then authorize the user.** Nonce (CSRF) + capability
   (`current_user_can`) on every state-changing action — neither replaces the other.
4. **Use core APIs, not hand-rolled code.** Core's sanitize/escape/DB/HTTP functions are
   audited and maintained. Reinventing them (manual SQL, `file_get_contents` for URLs,
   custom escaping) reintroduces solved bugs.
5. **Least privilege by default.** Default options to the safe value, scope capabilities
   tightly, and expose the minimum surface.
6. **Fail closed.** On any failed check, stop and return an error — never fall through.

## Step-by-step implementation

1. **Guard the file:** `defined( 'ABSPATH' ) || exit;` at the top of every PHP file.
2. **Namespace everything:** prefix functions, hooks, options, and globals (e.g.
   `my_plugin_*`) to avoid collisions and accidental overrides.
3. **For each request handler**, apply the flow in order:
   1. Verify nonce → see `nonces-csrf-protection`.
   2. Check capability → see `capability-permission-checks`.
   3. `wp_unslash()` + sanitize input → see `input-sanitization-validation`.
   4. Use `$wpdb->prepare()` for any custom query → see `sql-injection-prevention`.
   5. Escape on output → see `output-escaping`.
4. **Set safe defaults** for all options; validate on save and on read.
5. **Enqueue assets properly** (`wp_enqueue_script/style`) and pass data via
   `wp_localize_script()` rather than inline-echoing PHP into JS.
6. **Keep secrets out of the repo** and out of client-readable output.

## Common AI mistakes / anti-patterns

### Mistake 1 — No ABSPATH guard

```php
// ❌ Insecure: file executes if requested directly over HTTP.
<?php
function my_plugin_init() { /* ... */ }
```

```php
// ✅ Secure: bail unless loaded within WordPress.
<?php
defined( 'ABSPATH' ) || exit;

function my_plugin_init() { /* ... */ }
```

### Mistake 2 — Doing the work before the security checks

```php
// ❌ Insecure: option saved before anything is verified.
function my_plugin_save() {
    update_option( 'my_opt', $_POST['val'] );
    check_admin_referer( 'my_plugin_save' );
    current_user_can( 'manage_options' );
}
```

```php
// ✅ Secure: verify, authorize, sanitize, THEN act.
function my_plugin_save() {
    check_admin_referer( 'my_plugin_save', 'my_plugin_nonce' );
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'Forbidden', 'my-plugin' ), 403 );
    }
    $val = isset( $_POST['val'] ) ? sanitize_text_field( wp_unslash( $_POST['val'] ) ) : '';
    update_option( 'my_opt', $val );
}
```

### Mistake 3 — Rolling your own instead of using core APIs

```php
// ❌ Insecure: manual SQL, manual escaping, raw remote fetch.
$rows = $wpdb->get_results( "SELECT * FROM t WHERE id = " . $_GET['id'] );
echo "<a href=" . $_GET['url'] . ">x</a>";
$body = file_get_contents( $remote_url );
```

```php
// ✅ Secure: prepared query, escaped output, HTTP API.
$id   = absint( $_GET['id'] ?? 0 );
$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}t WHERE id = %d", $id ) );
echo '<a href="' . esc_url( wp_unslash( $_GET['url'] ?? '' ) ) . '">x</a>';
$response = wp_remote_get( $remote_url );
$body     = is_wp_error( $response ) ? '' : wp_remote_retrieve_body( $response );
```

### Mistake 4 — Unsafe defaults

```php
// ❌ Insecure: feature ships enabled, capability defaults wide open.
add_option( 'my_plugin_allow_uploads', true );
```

```php
// ✅ Secure: default to the safe value; opt-in to risk.
add_option( 'my_plugin_allow_uploads', false );
```

## Correct code examples

A minimal but complete secure plugin skeleton — ABSPATH guard, an admin page behind a
capability, and the full verify → authorize → sanitize → act → escape flow — lives in
[`references/secure-plugin-skeleton.php`](references/secure-plugin-skeleton.php).

## Checklist

- [ ] Every PHP file opens with `defined( 'ABSPATH' ) || exit;`.
- [ ] Functions, hooks, and options are uniquely prefixed.
- [ ] Each request handler verifies nonce, then capability, then sanitizes input.
- [ ] All custom DB access uses `$wpdb->prepare()`.
- [ ] All dynamic output is escaped at the point of echo.
- [ ] Options have safe defaults and are validated on save.
- [ ] Remote requests use the WP HTTP API (`wp_remote_*`), not `file_get_contents`/cURL.
- [ ] No secrets, keys, or credentials are hard-coded or sent to the browser.
- [ ] Scripts are enqueued and given data via `wp_localize_script()`.

## Official references

- [Security — Common APIs Handbook](https://developer.wordpress.org/apis/security/)
- [Plugin Security — Plugin Handbook](https://developer.wordpress.org/plugins/security/)
- [Checking User Capabilities](https://developer.wordpress.org/plugins/security/checking-user-capabilities/)
- [Data Validation](https://developer.wordpress.org/apis/security/data-validation/)
- [Escaping Data](https://developer.wordpress.org/apis/security/escaping/)
- [HTTP API](https://developer.wordpress.org/plugins/http-api/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
