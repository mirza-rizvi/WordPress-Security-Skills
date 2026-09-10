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
- [ ] Review context records target, immutable revision, reviewer/date, scope/exclusions,
  methods/tool versions, testing authorization, and limitations; unknowns are explicit.
- [ ] Each confirmed finding includes file:line, category, evidence/data flow, exploit
  prerequisites, impact, concrete remediation, verification, and official references.
- [ ] Severity follows demonstrated impact and reachability; only confirmed vulnerabilities
  enter totals. Scanner hits/incomplete traces are unverified leads; optional controls
  without demonstrated vulnerabilities are separate hardening recommendations.
- [ ] Executed verification and actual results are separate from proposed checks; fixes
  and alternate in-scope paths are re-verified or explicitly marked unverified.
- [ ] Secrets/PII are redacted; residual limitations and excluded paths are explicit.
- [ ] Incomplete scope receives no security certification or blanket release sign-off.
- [ ] No secure score, remediation-hour estimates, or response-time promises; CVSS/CWE
  values appear only with the actual vector/mapping and recorded source.
- [ ] The report follows the full [report template](report-template.md).
