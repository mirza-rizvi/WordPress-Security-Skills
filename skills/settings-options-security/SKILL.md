---
name: settings-options-security
description: >
  Use when building an options or settings page with the WordPress Settings API -
  register_setting, add_settings_field, settings_fields, an options.php form, or
  update_option / get_option on plugin data. Attaches a sanitize_callback to every
  setting, gates the page with manage_options, relies on Settings API nonce handling,
  and escapes options on output. Prevents stored XSS and unauthorized option writes.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, settings, options, admin, xss"
---

# Settings & options security

## When to use this skill

Use this skill whenever a plugin or theme stores configuration in WordPress options:

- Building a settings page with the Settings API (`register_setting`, `add_settings_section`,
  `add_settings_field`).
- A form that posts to `options.php`.
- Calling `update_option()` or `add_option()` from a custom handler.
- Reading options with `get_option()` and rendering them anywhere (admin, front-end, emails).

The Settings API gives you nonce handling, capability gating, and a structured
sanitization hook for free — but only if you actually wire it. Bypassing it for a
"quick" custom form is a common source of stored XSS and unauthorized writes.

Related: see the `input-sanitization-validation` skill for per-request sanitization
patterns and the `nonces-csrf-protection` skill for custom-form nonce handling.

## Core principles (and why they matter)

1. **Every registered setting needs a `sanitize_callback`.** This is the single most
   important line of defense against stored XSS and malformed data. Without it,
   `update_option()` saves raw `$_POST` values verbatim.
2. **The Settings API supplies the nonce only when you use `settings_fields()`.** If you
   build a custom form that calls `options.php`, include `settings_fields( $option_group )`
   or you lose CSRF protection.
3. **Options are untrusted on read.** Even if you sanitized on save, escape again on output.
   A compromised database, a bad import, or a future bug can reintroduce dangerous values.
4. **Gate the page with a capability, not just a menu position.** `add_options_page()`
   already requires `manage_options` by default; custom menus should too.
5. **Use typed defaults.** Pass a `default` value to `register_setting()` so `get_option()`
   returns a known shape instead of `false`.
6. **If you expose settings via REST (`show_in_rest`), provide a schema.** Untyped REST
   options are another stored-XSS vector.

## Step-by-step implementation

1. On `admin_init`, call `register_setting()` with:
   - `option_group` matching the page.
   - `option_name` for the stored option.
   - `sanitize_callback` pointing to a strict sanitizer.
   - `default` with a safe value.
2. Add sections and fields with `add_settings_section()` and `add_settings_field()`.
3. Render the form posting to `options.php` and call `settings_fields( $option_group )`.
4. In field callbacks, escape the current option value with `esc_attr()` / `esc_textarea()`.
5. For custom (non-`options.php`) handlers, add your own `wp_nonce_field()` and verify it with
   `check_admin_referer()`, plus `current_user_can( 'manage_options' )`.
6. When displaying saved options anywhere, escape for the output context.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Settings & options security checklist](references/checklist.md) | Before final verification of the settings & options security controls. |
| [Secure Settings API page](references/secure-settings-page.php) | Implementing a sanitized Settings API page with an options.php form and escaped output. |

## Common AI mistakes / anti-patterns

### Mistake 1 — `register_setting()` with no sanitize callback

```php
// ❌ Insecure: raw POST data is saved into the option.
register_setting( 'my_plugin_group', 'my_plugin_options' );
```

```php
// ✅ Secure: every setting has a sanitize_callback.
register_setting(
    'my_plugin_group',
    'my_plugin_options',
    array(
        'type'              => 'array',
        'sanitize_callback' => 'my_plugin_sanitize_options',
        'default'           => array( 'api_key' => '', 'enabled' => 0 ),
    )
);

function my_plugin_sanitize_options( $input ) {
    $clean = array();
    if ( isset( $input['api_key'] ) ) {
        $clean['api_key'] = sanitize_text_field( wp_unslash( $input['api_key'] ) );
    }
    $clean['enabled'] = ! empty( $input['enabled'] ) ? 1 : 0;
    return $clean;
}
```

### Mistake 2 — Custom settings form bypassing `settings_fields`

```php
// ❌ Insecure: no nonce, no capability gate, raw option write.
<form method="post" action="">
    <input type="text" name="my_plugin_api_key">
    <?php submit_button(); ?>
</form>
<?php
if ( isset( $_POST['my_plugin_api_key'] ) ) {
    update_option( 'my_plugin_api_key', $_POST['my_plugin_api_key'] );
}
```

```php
// ✅ Secure: post to options.php and use settings_fields.
<form method="post" action="options.php">
    <?php
    settings_fields( 'my_plugin_group' );
    do_settings_sections( 'my-plugin' );
    submit_button();
    ?>
</form>
```

### Mistake 3 — Echoing `get_option()` unescaped

```php
// ❌ Insecure: stored XSS if the option contains JavaScript.
echo '<div class="notice">' . get_option( 'my_plugin_notice' ) . '</div>';
```

```php
// ✅ Secure: escape on output for the context.
$notice = get_option( 'my_plugin_notice', '' );
echo '<div class="notice">' . esc_html( $notice ) . '</div>';
```

### Mistake 4 — Not recursively sanitizing array options

```php
// ❌ Insecure: only the top-level array is sanitized; nested strings remain raw.
function my_plugin_sanitize_array( $input ) {
    return array_map( 'sanitize_text_field', $input );
}
```

```php
// ✅ Secure: know the schema and sanitize each member.
function my_plugin_sanitize_array( $input ) {
    $clean = array();
    if ( isset( $input['api_key'] ) ) {
        $clean['api_key'] = sanitize_text_field( wp_unslash( $input['api_key'] ) );
    }
    if ( isset( $input['webhook_url'] ) ) {
        $clean['webhook_url'] = esc_url_raw( wp_unslash( $input['webhook_url'] ) );
    }
    $clean['debug'] = ! empty( $input['debug'] ) ? 1 : 0;
    return $clean;
}
```

### Mistake 5 — `show_in_rest => true` with no schema

```php
// ❌ Insecure: REST consumers can write arbitrary shapes to the option.
register_setting(
    'my_plugin_group',
    'my_plugin_options',
    array( 'show_in_rest' => true )
);
```

```php
// ✅ Secure: declare a REST schema so WordPress validates the shape.
register_setting(
    'my_plugin_group',
    'my_plugin_options',
    array(
        'type'              => 'object',
        'show_in_rest'      => array(
            'schema' => array(
                'type'       => 'object',
                'properties' => array(
                    'api_key' => array( 'type' => 'string' ),
                    'enabled' => array( 'type' => 'boolean' ),
                ),
            ),
        ),
        'sanitize_callback' => 'my_plugin_sanitize_options',
        'default'           => array( 'api_key' => '', 'enabled' => false ),
    )
);
```

## Correct code examples

A complete Settings API page (registration, section, field, form, sanitization) is in
[`references/secure-settings-page.php`](references/secure-settings-page.php).

## Checklist

- [ ] Every `register_setting()` call includes a `sanitize_callback`.
- [ ] Settings have safe `default` values of the correct type.
- [ ] The settings form posts to `options.php` and calls `settings_fields()`.
- [ ] The admin page is gated by `manage_options` (or a stricter custom capability).
- [ ] Custom non-Settings-API handlers add their own nonce + capability checks.
- [ ] Array/object options are recursively sanitized against a known schema.
- [ ] `get_option()` values are escaped at the point of output.
- [ ] REST-exposed settings (`show_in_rest`) include a schema.
- [ ] Secrets are stored encrypted or in wp-config constants, not plaintext in options.

## Official references

- [Settings API — Plugin Handbook](https://developer.wordpress.org/plugins/settings/)
- [`register_setting()`](https://developer.wordpress.org/reference/functions/register_setting/)
- [`add_settings_section()`](https://developer.wordpress.org/reference/functions/add_settings_section/)
- [`add_settings_field()`](https://developer.wordpress.org/reference/functions/add_settings_field/)
- [`settings_fields()`](https://developer.wordpress.org/reference/functions/settings_fields/)
- [`do_settings_sections()`](https://developer.wordpress.org/reference/functions/do_settings_sections/)
- [`get_option()`](https://developer.wordpress.org/reference/functions/get_option/)
- [`update_option()`](https://developer.wordpress.org/reference/functions/update_option/)
- [`esc_attr()`](https://developer.wordpress.org/reference/functions/esc_attr/)
- [`esc_textarea()`](https://developer.wordpress.org/reference/functions/esc_textarea/)
