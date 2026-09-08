# Nonce / CSRF verification checklist

Run through this before shipping any request-handling code.

## Generation (request origin)
- [ ] Form includes `wp_nonce_field( 'specific_action', 'field_name' )`.
- [ ] Action links use `wp_nonce_url( $url, 'specific_action', 'arg' )`.
- [ ] JS gets its nonce via `wp_create_nonce()` passed through
      `wp_localize_script()` / `wp_add_inline_script()` — not hard-coded.
- [ ] The action string is specific (e.g. `delete_widget_42`), not generic (`nonce`).

## Verification (server)
- [ ] Nonce is verified **before** any input is read or any action runs.
- [ ] Forms use `check_admin_referer( 'action', 'field' )`.
- [ ] AJAX uses `check_ajax_referer( 'action', 'field' )` (pass `false` as 3rd arg
      to return JSON errors instead of dying).
- [ ] Manual checks branch on `wp_verify_nonce()` and fail closed on `false`.
- [ ] The result of `wp_verify_nonce()` is never computed and discarded.

## Authorization (always paired)
- [ ] `current_user_can( $capability )` runs alongside the nonce check.
- [ ] Per-object actions use the object form, e.g. `current_user_can( 'edit_post', $id )`.

## Wiring
- [ ] Privileged AJAX uses `wp_ajax_*` only — never `wp_ajax_nopriv_*`.
- [ ] `wp_ajax_nopriv_*` is used only for genuinely public, low-risk actions.

## Failure & I/O
- [ ] Failure path is explicit: `wp_die( ..., 403 )` or `wp_send_json_error( ..., 403 )`.
- [ ] Input is `wp_unslash()`-ed then sanitized after verification.
- [ ] Any nonce or value echoed to the page is escaped (or produced by core helpers).
