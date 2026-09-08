# File upload security checklist

- [ ] Handler verifies nonce and `upload_files` (or stricter) capability first.
- [ ] Uses `wp_handle_upload()` / `media_handle_upload()`, not raw `move_uploaded_file()`.
- [ ] Validates real type with `wp_check_filetype_and_ext()` against an allowlist.
- [ ] Accepts via allowlist of extensions/MIME types; no blocklist logic.
- [ ] Does not trust `$_FILES[...]['type']` (client-supplied).
- [ ] Filename sanitized with `sanitize_file_name()` or assigned by core.
- [ ] Executable types (`.php`, `.phtml`, `.phar`, `.htaccess`) are never accepted.
- [ ] SVG/HTML uploads are disallowed or sanitized server-side before storage.
- [ ] Paths built from input resolved with `realpath()` and confined to a base dir.
- [ ] No raw user input passed to `include`/`require`/`readfile`/`unlink`.
- [ ] Uploads directory hardened against PHP execution (see wp-hardening skill).
