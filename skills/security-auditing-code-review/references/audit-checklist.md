# WordPress security audit checklist

Work top-down. For each entry point, verify all four controls, then sweep the sinks.

## Trust-boundary inventory
- [ ] All `wp_ajax_*` / `wp_ajax_nopriv_*` handlers listed.
- [ ] All `register_rest_route` routes listed.
- [ ] All `admin_post_*` handlers and action links listed.
- [ ] All shortcodes, widgets, blocks accepting attributes listed.
- [ ] All direct superglobal reads located.

## Per entry point — the four controls
- [ ] **CSRF**: nonce generated and verified (`check_admin_referer`/`check_ajax_referer`/`wp_verify_nonce`).
- [ ] **AuthZ**: `current_user_can()` with the correct (often per-object) capability.
- [ ] **Input**: `wp_unslash()` + type-appropriate sanitize; validated against allowlists.
- [ ] **Output/DB**: escaping at output; `$wpdb->prepare()` for queries.
- [ ] `wp_ajax_nopriv_*` usage is justified (public, low-risk).

## SQL
- [ ] No input concatenated into queries.
- [ ] `prepare()` used with correct placeholders; `esc_like()` for LIKE.
- [ ] Identifiers allowlisted (or `%i`).

## XSS / output
- [ ] Every echoed variable escaped in the right context.
- [ ] `add_query_arg`/`remove_query_arg` results escaped with `esc_url`.
- [ ] Intentional HTML via `wp_kses*` allowlist.

## Files / RCE
- [ ] Uploads via `wp_handle_upload` + `wp_check_filetype_and_ext` allowlist.
- [ ] No input-driven `include`/`require`/`readfile`/`unlink` without confinement.
- [ ] No `eval`/`create_function`/`assert`/`/e` regex.
- [ ] `unserialize()` not fed untrusted input (object injection).
- [ ] No `extract()` on request data.

## Configuration / data exposure
- [ ] Remote calls use `wp_remote_*`, not `file_get_contents`/cURL on URLs.
- [ ] No hard-coded secrets/API keys/credentials.
- [ ] No sensitive data leaked to under-privileged users (REST/AJAX responses).
- [ ] Errors/debug output disabled in production.

## Reporting
- [ ] Each finding: file:line, category, severity (impact × reachability), description, fix.
- [ ] Severities not inflated; real exploitability confirmed.
- [ ] Fixes re-verified; no control bypassed elsewhere.
