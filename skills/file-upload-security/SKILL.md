---
name: file-upload-security
description: >
  Use when a WordPress plugin or theme accepts file uploads, processes $_FILES, saves
  user-provided files, or generates file paths from input. Uses wp_handle_upload and
  wp_check_filetype_and_ext with a MIME/extension allowlist, blocks executable types,
  and prevents path traversal. Prevents arbitrary file upload and RCE. Apply proactively
  to any upload or file-writing code path.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, upload, files, rce, path-traversal"
---

# File upload security

## When to use this skill

Use this skill whenever code touches user-provided files or paths:

- Handling `$_FILES` from a form (front-end or admin).
- Saving uploads, avatars, imports, attachments, CSV/JSON imports.
- Building a filesystem path from user input (download handlers, `include`, `readfile`).
- Serving or deleting files based on a request parameter.

Arbitrary file upload is one of the highest-severity WordPress bugs — an uploaded `.php`
in a web-served directory is remote code execution.

## Core principles (and why they matter)

1. **Use `wp_handle_upload()`, not manual `move_uploaded_file()`.** Core validates the
   upload, applies the site's MIME rules, sanitizes the filename, and places the file in
   the uploads directory with a unique name.
2. **Allowlist types; never blocklist.** Decide which extensions/MIME types you accept and
   reject everything else. Blocklists miss variants (`.phtml`, `.php5`, `.pht`, double
   extensions).
3. **Verify the real type, not the claimed one.** The browser-supplied MIME and the
   extension can lie. `wp_check_filetype_and_ext()` checks extension vs. actual content.
4. **Never trust the client filename for a path.** Use `sanitize_file_name()` and let core
   assign the final name; never concatenate `$_FILES[...]['name']` into a path.
5. **Block executables from web-served upload dirs.** Don't allow `.php`/`.phtml`/`.htaccess`
   uploads; harden the uploads directory (see `wp-hardening-best-practices`).
6. **Prevent path traversal.** Validate any path built from input with `realpath()` and
   confirm it stays within an allowed base directory; reject `..` sequences.

## Step-by-step implementation

1. Verify nonce + capability (`upload_files` or stricter) before processing.
2. Require `wp_handle_upload()` with `array( 'test_form' => false )` (or set the action).
3. Validate the result with `wp_check_filetype_and_ext()` against an explicit allowlist.
4. Reject anything not on the allowlist; surface a clear error.
5. For path operations, resolve with `realpath()` and assert the prefix matches an
   allowed base; never `include`/`readfile` raw input.
6. Store the returned URL/path; escape on output.

### Supporting references

| Reference | Load when |
| --- | --- |
| [File upload security checklist](references/checklist.md) | Before final verification of the file upload security controls. |
| [Secure file upload handler](references/secure-file-upload.php) | Implementing the nonce-to-capability-to-validated-upload flow and optional media-library attachment. |

## Common AI mistakes / anti-patterns

### Mistake 1 — `move_uploaded_file()` straight from `$_FILES`

```php
// ❌ Insecure: no type/extension validation, attacker-controlled filename → RCE.
$name = $_FILES['file']['name'];
move_uploaded_file( $_FILES['file']['tmp_name'], WP_CONTENT_DIR . '/uploads/' . $name );
```

```php
// ✅ Secure: let core validate, sanitize, and place the file.
if ( ! current_user_can( 'upload_files' ) ) {
    wp_die( esc_html__( 'Forbidden', 'my-plugin' ), 403 );
}
require_once ABSPATH . 'wp-admin/includes/file.php';
$upload = wp_handle_upload( $_FILES['file'], array( 'test_form' => false ) );
if ( isset( $upload['error'] ) ) {
    wp_die( esc_html( $upload['error'] ) );
}
$file_url = $upload['url'];
```

### Mistake 2 — Trusting the client-provided MIME type

```php
// ❌ Insecure: $_FILES['file']['type'] is set by the browser and forgeable.
if ( 'image/png' === $_FILES['file']['type'] ) {
    save_it();
}
```

```php
// ✅ Secure: check actual extension/type and allowlist.
$check   = wp_check_filetype_and_ext( $_FILES['file']['tmp_name'], $_FILES['file']['name'] );
$allowed = array( 'png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg' );
if ( empty( $check['ext'] ) || ! isset( $allowed[ $check['ext'] ] ) ) {
    wp_die( esc_html__( 'File type not allowed.', 'my-plugin' ), 400 );
}
```

### Mistake 3 — Blocklisting dangerous extensions

```php
// ❌ Insecure: misses .phtml, .php5, .pht, .phar, case variants, double extensions.
$ext = pathinfo( $name, PATHINFO_EXTENSION );
if ( 'php' === $ext ) {
    wp_die( 'No PHP files' );
}
```

```php
// ✅ Secure: allowlist exactly what you accept; reject everything else.
$allowed_ext = array( 'png', 'jpg', 'jpeg', 'gif', 'pdf' );
$ext         = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
if ( ! in_array( $ext, $allowed_ext, true ) ) {
    wp_die( esc_html__( 'File type not allowed.', 'my-plugin' ), 400 );
}
```

### Mistake 4 — Path traversal in a download/read handler

```php
// ❌ Insecure: ../../wp-config.php is reachable.
$file = $_GET['file'];
readfile( '/var/www/uploads/' . $file );
```

```php
// ✅ Secure: sanitize, resolve, and confine to the base directory.
$base    = realpath( wp_upload_dir()['basedir'] );
$request = sanitize_file_name( wp_unslash( $_GET['file'] ?? '' ) );
$target  = realpath( $base . '/' . $request );
if ( false === $target || strpos( $target, $base . DIRECTORY_SEPARATOR ) !== 0 ) {
    wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}
readfile( $target );
```

### Mistake 5 — Widening allowed MIME types globally and forgetting it

```php
// ❌ Risky: opens SVG (script-bearing) site-wide with no sanitization.
add_filter( 'upload_mimes', function ( $m ) {
    $m['svg'] = 'image/svg+xml';
    return $m;
} );
```

```php
// ✅ Safer: only if truly needed, sanitize SVGs and restrict to high-trust roles.
// Prefer not allowing SVG. If required, sanitize markup server-side and gate by capability.
add_filter( 'upload_mimes', function ( $m ) {
    if ( current_user_can( 'manage_options' ) ) {
        $m['svg'] = 'image/svg+xml'; // plus server-side SVG sanitization before storage
    }
    return $m;
} );
```

### Mistake 6 — Trusting extension alone and missing double extensions

```php
// ❌ Insecure: pathinfo can be fooled by file.php.jpg or .phtml variants.
$ext = pathinfo( $name, PATHINFO_EXTENSION );
if ( 'jpg' === $ext ) {
    accept_upload();
}
```

```php
// ✅ Secure: use wp_check_filetype_and_ext() which inspects real MIME type and extension.
$check = wp_check_filetype_and_ext( $tmp_name, $name, $allowed );
if ( empty( $check['ext'] ) || empty( $check['type'] ) ) {
    wp_die( esc_html__( 'Invalid file type.', 'my-plugin' ), 400 );
}
```

### Mistake 7 — Serving uploaded files without path containment

```php
// ❌ Insecure: download handler may escape the uploads directory.
readfile( wp_upload_dir()['basedir'] . '/' . $_GET['file'] );
```

```php
// ✅ Secure: resolve and confine to the uploads base directory.
$base    = realpath( wp_upload_dir()['basedir'] );
$request = sanitize_file_name( wp_unslash( $_GET['file'] ?? '' ) );
$target  = realpath( $base . '/' . $request );
if ( false === $target || strpos( $target, $base . DIRECTORY_SEPARATOR ) !== 0 ) {
    wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}
readfile( $target );
```

Related: see the `filesystem-security` skill for post-upload path handling and deletion.

## Correct code examples

A complete secure upload handler (nonce + capability + `wp_handle_upload` +
`wp_check_filetype_and_ext` allowlist + safe path handling) is in
[`references/secure-file-upload.php`](references/secure-file-upload.php).

## Checklist

- [ ] Upload handler checks nonce and the `upload_files` capability first.
- [ ] Uses `wp_handle_upload()` (not raw `move_uploaded_file`).
- [ ] Validates with `wp_check_filetype_and_ext()` against an explicit allowlist.
- [ ] Accepts via allowlist; never relies on a blocklist of extensions.
- [ ] Does not trust the client-supplied MIME type (`$_FILES[...]['type']`).
- [ ] Filenames pass through `sanitize_file_name()` / are assigned by core.
- [ ] Any path built from input is resolved with `realpath()` and confined to a base dir.
- [ ] Executable types are not accepted into web-served directories.
- [ ] SVG and other script-bearing types are sanitized or disallowed.

## Official references

- [`wp_handle_upload()`](https://developer.wordpress.org/reference/functions/wp_handle_upload/)
- [`wp_check_filetype_and_ext()`](https://developer.wordpress.org/reference/functions/wp_check_filetype_and_ext/)
- [`sanitize_file_name()`](https://developer.wordpress.org/reference/functions/sanitize_file_name/)
- [`wp_upload_dir()`](https://developer.wordpress.org/reference/functions/wp_upload_dir/)
- [`upload_mimes` filter](https://developer.wordpress.org/reference/hooks/upload_mimes/)
- [`media_handle_upload()`](https://developer.wordpress.org/reference/functions/media_handle_upload/)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
