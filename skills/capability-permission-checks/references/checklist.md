# Capability / authorization checklist

- [ ] Every privileged handler calls `current_user_can()` and branches on it.
- [ ] Capabilities are tested — never roles (`administrator`, `editor`).
- [ ] The most specific capability is used (`manage_options`, `edit_posts`, `upload_files`…).
- [ ] Per-object actions pass the object ID: `current_user_can( 'edit_post', $id )`.
- [ ] The check is paired with nonce verification on state-changing requests.
- [ ] Admin pages re-check the capability on render, not just at menu registration.
- [ ] REST routes define a real `permission_callback` (never `__return_true` for writes).
- [ ] AJAX handlers check capability after `check_ajax_referer`.
- [ ] Hidden menus/buttons are treated as UX only, never as the security boundary.
- [ ] Denied requests fail closed: `wp_die(...,403)`, `wp_send_json_error(...,403)`, or `WP_Error` 403.
