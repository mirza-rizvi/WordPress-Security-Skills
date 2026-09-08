# Filesystem security checklist

Use this checklist before any filesystem operation that touches user input.

- [ ] No `include` / `require` uses user input; templates use a hardcoded allowlist.
- [ ] File paths are resolved under a known base directory.
- [ ] `realpath()` resolves the final path and containment is verified.
- [ ] Filenames pass through `sanitize_file_name()`.
- [ ] `validate_file()` returns `0` for paths that include user input.
- [ ] Deletion uses `wp_delete_file()` or `wp_delete_file_from_directory()`.
- [ ] Writes use `WP_Filesystem` with `request_filesystem_credentials()`.
- [ ] State-changing handlers verify nonce + capability first.
- [ ] Full server paths are not exposed in errors or URLs.
