---
name: filesystem-security
description: >
  Use when reading, writing, including, or deleting files from paths that include
  user input - include / require, readfile, unlink, file_get_contents, or the
  WP_Filesystem API. Validates paths with validate_file, normalizes with
  wp_normalize_path, confines operations to an allowed base directory, and uses
  wp_delete_file / WP_Filesystem. Prevents path traversal, local file inclusion,
  and arbitrary file deletion.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, filesystem, path-traversal, lfi, rce"
---

# Filesystem security

## When to use this skill

Use this skill whenever code touches the filesystem with paths derived from input:

- Building a file path from `$_GET` / `$_POST` / `$_REQUEST`.
- `include`, `require`, `readfile`, `file_get_contents`, or `unlink` of a dynamic file.
- Serving downloads, exports, or logs based on a request parameter.
- Deleting files selected by the user.
- Using `WP_Filesystem` for writes, deletes, or directory creation.

Path traversal and local file inclusion are high-impact WordPress vulnerabilities —
`../../wp-config.php` or a malicious uploaded `.php` can expose secrets or achieve RCE.

Related: see the `file-upload-security` skill for `$_FILES` handling and the
`object-injection-deserialization` skill for uploaded data formats.

## Core principles (and why they matter)

1. **Never `include` / `require` a user-controlled path.** That is remote/local code
   execution. Keep templates and includes hardcoded.
2. **Constrain every file operation to a known base directory.** Resolve with `realpath()`
   and assert the result starts with the allowed base path.
3. **`validate_file()` catches traversal, drive letters, and `:` characters.** A non-zero
   return value means the path is suspect.
4. **Use `sanitize_file_name()` and `wp_normalize_path()`.** Normalize separators and strip
   dangerous characters before building paths.
5. **Use WordPress deletion helpers.** `wp_delete_file()` and `wp_delete_file_from_directory()`
   are safer than raw `unlink()`.
6. **Use `WP_Filesystem` for writes.** It handles permissions, credentials, and stream
   wrappers consistently across hosts.

## Step-by-step implementation

1. Reject any request that wants to `include`/`require` a file based on input; use a hardcoded
   allowlist of template files instead.
2. For read/delete handlers:
   - Verify nonce + capability.
   - Sanitize the filename with `sanitize_file_name()`.
   - Optionally run `validate_file()`.
   - Build the target path under a known base directory.
   - Resolve with `realpath()` and confirm it stays under the base.
3. For writes/deletes, prefer `WP_Filesystem` with `request_filesystem_credentials()`.
4. Never expose the full server path in errors or URLs.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Filesystem security checklist](references/checklist.md) | Before final verification of the filesystem security controls. |
| [Secure filesystem operations](references/secure-filesystem-operations.php) | Implementing confined file reads and deletion, and writes through WP_Filesystem. |

## Common AI mistakes / anti-patterns

### Mistake 1 — `include $_GET['page']`

```php
// ❌ Insecure: local/remote code execution.
include 'templates/' . $_GET['page'] . '.php';
```

```php
// ✅ Secure: hardcoded allowlist of template files.
$allowed = array( 'dashboard', 'settings', 'logs' );
$page    = isset( $_GET['page'] ) ? sanitize_key( $_GET['page'] ) : 'dashboard';
if ( ! in_array( $page, $allowed, true ) ) {
    wp_die( esc_html__( 'Invalid page.', 'my-plugin' ), 400 );
}
include __DIR__ . '/templates/' . $page . '.php';
```

### Mistake 2 — `unlink()` of a user-named file

```php
// ❌ Insecure: arbitrary file deletion via traversal.
unlink( WP_CONTENT_DIR . '/exports/' . $_POST['file'] );
```

```php
// ✅ Secure: sanitize, resolve, and confine to the base directory.
$base    = realpath( WP_CONTENT_DIR . '/exports' );
$request = sanitize_file_name( wp_unslash( $_POST['file'] ?? '' ) );
$target  = realpath( $base . '/' . $request );

if ( false === $target || strpos( $target, $base . DIRECTORY_SEPARATOR ) !== 0 ) {
    wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}

if ( ! current_user_can( 'manage_options' ) ) {
    wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
}

wp_delete_file( $target );
```

### Mistake 3 — `readfile()` without base-directory containment

```php
// ❌ Insecure: ../../wp-config.php is reachable.
readfile( '/var/www/uploads/' . $_GET['file'] );
```

```php
// ✅ Secure: resolve and confine.
$base    = realpath( wp_upload_dir()['basedir'] );
$request = sanitize_file_name( wp_unslash( $_GET['file'] ?? '' ) );
$target  = realpath( $base . '/' . $request );

if ( false === $target || strpos( $target, $base . DIRECTORY_SEPARATOR ) !== 0 ) {
    wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}

readfile( $target );
```

### Mistake 4 — Trusting `basename()` alone

```php
// ❌ Insecure: basename does not prevent traversal to siblings.
$file = basename( $_GET['file'] );
readfile( '/var/www/uploads/' . $file );
```

```php
// ✅ Secure: basename plus realpath containment.
$base    = realpath( '/var/www/uploads' );
$file    = basename( sanitize_file_name( wp_unslash( $_GET['file'] ?? '' ) ) );
$target  = realpath( $base . '/' . $file );
if ( false === $target || strpos( $target, $base . DIRECTORY_SEPARATOR ) !== 0 ) {
    wp_die( esc_html__( 'Invalid file.', 'my-plugin' ), 400 );
}
readfile( $target );
```

### Mistake 5 — Writing files with raw PHP functions

```php
// ❌ Insecure: no permission/credential handling, may fail on restrictive hosts.
file_put_contents( $path, $data );
```

```php
// ✅ Secure: use WP_Filesystem after requesting credentials.
function my_plugin_write_file( $path, $data ) {
    global $wp_filesystem;

    if ( ! function_exists( 'request_filesystem_credentials' ) ) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }

    $url   = admin_url( 'admin-post.php?action=my_plugin_save' );
    $creds = request_filesystem_credentials( $url );
    if ( false === $creds || ! WP_Filesystem( $creds ) ) {
        return new WP_Error( 'filesystem', __( 'Could not initialize filesystem.', 'my-plugin' ) );
    }

    return $wp_filesystem->put_contents( $path, $data, FS_CHMOD_FILE );
}
```

## Correct code examples

A complete safe file download/delete helper using base-directory containment is in
[`references/secure-filesystem-operations.php`](references/secure-filesystem-operations.php).

## Checklist

- [ ] No `include` / `require` uses user input; templates are selected from a hardcoded allowlist.
- [ ] File paths are built under a known base directory.
- [ ] `realpath()` resolves the final path and containment is verified.
- [ ] Filenames pass through `sanitize_file_name()` and `wp_normalize_path()`.
- [ ] `validate_file()` returns `0` for paths that include user input.
- [ ] File delete operations use `wp_delete_file()` or `wp_delete_file_from_directory()`.
- [ ] File writes use `WP_Filesystem` with `request_filesystem_credentials()`.
- [ ] State-changing handlers verify nonce + capability first.
- [ ] Full server paths are not exposed in errors or URLs.

## Official references

- [`validate_file()`](https://developer.wordpress.org/reference/functions/validate_file/)
- [`wp_normalize_path()`](https://developer.wordpress.org/reference/functions/wp_normalize_path/)
- [`sanitize_file_name()`](https://developer.wordpress.org/reference/functions/sanitize_file_name/)
- [`wp_delete_file()`](https://developer.wordpress.org/reference/functions/wp_delete_file/)
- [`wp_delete_file_from_directory()`](https://developer.wordpress.org/reference/functions/wp_delete_file_from_directory/)
- [`WP_Filesystem`](https://developer.wordpress.org/reference/classes/wp_filesystem/)
- [`request_filesystem_credentials()`](https://developer.wordpress.org/reference/functions/request_filesystem_credentials/)
- [`wp_mkdir_p()`](https://developer.wordpress.org/reference/functions/wp_mkdir_p/)
- [`realpath()`](https://www.php.net/manual/en/function.realpath.php)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
