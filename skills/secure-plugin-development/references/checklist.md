# Secure plugin baseline checklist

## File & structure
- [ ] `defined( 'ABSPATH' ) || exit;` at the top of every PHP file.
- [ ] Functions, classes, hooks, options, and globals are uniquely prefixed.
- [ ] Plugin header declares `Requires PHP` and `Requires at least`.
- [ ] A text domain is set and used in all translation functions.

## Request handling (every state-changing action)
- [ ] Nonce verified first (`check_admin_referer` / `check_ajax_referer`).
- [ ] Capability verified (`current_user_can`) — re-checked on admin page render.
- [ ] Input `wp_unslash()`-ed and sanitized to the right type.
- [ ] Custom queries use `$wpdb->prepare()`.
- [ ] Output escaped at the point of echo.
- [ ] Failure path is explicit and fails closed.

## Data & defaults
- [ ] Options default to the safe value (features off, permissions narrow).
- [ ] Settings validated on save and defensively on read.
- [ ] No secrets/credentials hard-coded or exposed to the browser.

## Integrations
- [ ] Remote calls use `wp_remote_*`, results checked with `is_wp_error()`.
- [ ] Scripts/styles enqueued; data passed via `wp_localize_script()`.
- [ ] File operations use core helpers (`wp_handle_upload`, `WP_Filesystem`).
