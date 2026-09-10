---
name: object-injection-deserialization
description: >
  Use when code calls unserialize, maybe_unserialize, or stores serialized PHP in
  options, meta, or transients from untrusted input. Avoids unserialize on
  attacker-controlled data, prefers json_encode / json_decode, and when
  unserialize is unavoidable passes ['allowed_classes' => false]. Prevents PHP
  object injection and POP-chain remote code execution.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, deserialization, object-injection, rce"
---

# Object injection & deserialization security

## When to use this skill

Use this skill whenever code touches PHP serialization:

- Calling `unserialize()`, `maybe_unserialize()`, or `is_serialized()` on user input.
- Storing serialized arrays/objects in options, post meta, user meta, or transients.
- Importing data from files, feeds, or uploads that may contain serialized PHP.
- Migrating or caching objects by serializing them.

PHP object injection lets an attacker instantiate arbitrary objects and trigger
magic methods (`__wakeup()`, `__destruct()`, `__toString()`) that form POP
(property-oriented programming) chains, often leading to remote code execution.

## Core principles (and why they matter)

1. **Never `unserialize()` untrusted input.** Anything from `$_POST`, `$_GET`, files,
   remote APIs, or cookies is untrusted.
2. **Prefer JSON for interchange.** `wp_json_encode()` / `json_decode()` only produces
   arrays/stdClass and cannot instantiate PHP classes, breaking object-injection chains.
3. **`maybe_unserialize()` is still `unserialize()`.** It just checks `is_serialized()`
   first. Do not use it on attacker-controlled data.
4. **If forced to unserialize, disable classes.** Pass `array( 'allowed_classes' => false )`
   (PHP 7.0+) to `unserialize()` so no objects are instantiated.
5. **Do not trust `is_serialized()` as a safety check.** It only tells you the format;
   it does not make the payload safe.
6. **Keep serialized objects out of user-facing storage.** Options and meta that users
   can influence should store JSON or scalar values.

## Step-by-step implementation

1. Identify every `unserialize()`, `maybe_unserialize()`, and `is_serialized()` call.
2. Determine whether the data is attacker-controllable. If yes, replace with JSON.
3. For trusted internal serialization, use `allowed_classes => false` or a narrow
   allowlist of classes.
4. Validate the decoded shape (expected keys/types) before use.
5. Escape any values from the decoded data before output.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Object injection & deserialization checklist](references/checklist.md) | Before final verification of the object injection & deserialization controls. |
| [Secure deserialization and import](references/secure-deserialization.php) | Implementing validated JSON imports and disabling class instantiation where trusted deserialization is unavoidable. |

## Common AI mistakes / anti-patterns

### Mistake 1 — `unserialize()` on `$_POST`

```php
// ❌ Insecure: arbitrary object instantiation.
$data = unserialize( $_POST['config'] );
```

```php
// ✅ Secure: use JSON for user-supplied structured data.
$raw  = isset( $_POST['config'] ) ? wp_unslash( $_POST['config'] ) : '';
$data = json_decode( $raw, true );
if ( ! is_array( $data ) ) {
    wp_die( esc_html__( 'Invalid configuration.', 'my-plugin' ), 400 );
}
$api_key = isset( $data['api_key'] ) ? sanitize_text_field( $data['api_key'] ) : '';
```

### Mistake 2 — Treating `maybe_unserialize()` as safe

```php
// ❌ Insecure: maybe_unserialize is unserialize with a format check.
$config = maybe_unserialize( file_get_contents( $uploaded_file ) );
```

```php
// ✅ Secure: read and validate JSON instead.
$raw      = file_get_contents( $uploaded_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
$decoding = json_decode( $raw, true );
if ( null === $decoding && json_last_error() !== JSON_ERROR_NONE ) {
    wp_die( esc_html__( 'Invalid import file.', 'my-plugin' ), 400 );
}
```

### Mistake 3 — Trusting `is_serialized()`

```php
// ❌ Insecure: is_serialized only describes the format.
if ( is_serialized( $value ) ) {
    $value = unserialize( $value ); // still dangerous
}
```

```php
// ✅ Secure: if you must accept serialized data, disable class instantiation.
if ( is_serialized( $value ) ) {
    $value = @unserialize( $value, array( 'allowed_classes' => false ) );
}
```

### Mistake 4 — Storing user-supplied serialized blobs

```php
// ❌ Insecure: stores attacker-controlled serialized payload in meta.
update_post_meta( $post_id, '_my_plugin_data', $_POST['data'] );
```

```php
// ✅ Secure: store JSON; validate and sanitize on read.
$raw  = isset( $_POST['data'] ) ? wp_unslash( $_POST['data'] ) : '';
$data = json_decode( $raw, true );
if ( is_array( $data ) ) {
    update_post_meta( $post_id, '_my_plugin_data', wp_json_encode( $data ) );
}
```

### Mistake 5 — Serializing objects for cache/transients without class restrictions

```php
// ❌ Risky: transient value can instantiate arbitrary objects on read.
set_transient( 'my_plugin_state', serialize( $object ) );
```

```php
// ✅ Safer: store JSON or, if objects are required, a known shape with allowed_classes false.
set_transient( 'my_plugin_state', wp_json_encode( $object ) );
```

## Correct code examples

A safe importer that rejects serialized PHP and parses JSON is in
[`references/secure-deserialization.php`](references/secure-deserialization.php).

## Checklist

- [ ] No `unserialize()` / `maybe_unserialize()` runs on user input, uploads, or remote data.
- [ ] JSON is used for structured data interchange.
- [ ] Where `unserialize()` is unavoidable, `allowed_classes => false` is set.
- [ ] `is_serialized()` is not treated as a security check.
- [ ] Serialized blobs are not stored from user-controlled sources.
- [ ] Decoded JSON is validated for expected shape before use.
- [ ] Values from decoded data are sanitized/escaped before output.

## Official references

- [PHP `unserialize()`](https://www.php.net/manual/en/function.unserialize.php)
- [`maybe_unserialize()`](https://developer.wordpress.org/reference/functions/maybe_unserialize/)
- [`is_serialized()`](https://developer.wordpress.org/reference/functions/is_serialized/)
- [`maybe_serialize()`](https://developer.wordpress.org/reference/functions/maybe_serialize/)
- [`wp_json_encode()`](https://developer.wordpress.org/reference/functions/wp_json_encode/)
- [`json_decode()`](https://www.php.net/manual/en/function.json-decode.php)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheetsheets/Deserialization_Cheat_Sheet.html)
