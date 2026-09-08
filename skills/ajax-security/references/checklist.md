# AJAX security checklist

Use this checklist before finishing any `admin-ajax.php` handler.

- [ ] Privileged actions use `wp_ajax_*`, not `wp_ajax_nopriv_*`.
- [ ] Public actions on `wp_ajax_nopriv_*` are truly anonymous and rate-limited.
- [ ] The handler calls `check_ajax_referer()` before reading input or acting.
- [ ] `current_user_can()` runs right after nonce verification.
- [ ] Every `$_POST` / `$_GET` value is `wp_unslash()`-ed and sanitized to type.
- [ ] The handler exits through `wp_send_json_success()` or `wp_send_json_error()`.
- [ ] Values inside the JSON response are escaped (`esc_html`, `esc_attr`, `esc_url`).
- [ ] The nonce action is specific and scoped to the operation.
- [ ] Secrets are not returned, logged, or exposed to JavaScript.
