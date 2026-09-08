---
name: security-auditing-code-review
description: >
  Use when auditing or code-reviewing an existing WordPress plugin or theme for security
  issues, triaging a vulnerability report, or hardening inherited code. Provides a
  systematic methodology — locate trust boundaries, grep for missing nonces, capability
  checks, escaping, and unprepared queries, then triage by severity and report with fixes.
  Apply proactively before shipping or when reviewing third-party code.
license: MIT
metadata:
  tags: [wordpress, security, audit, code-review, vulnerability, hardening]
---

# Security auditing & code review

## When to use this skill

Use this skill when the task is to **evaluate** code rather than write a feature:

- Reviewing a PR/plugin/theme for security defects.
- Auditing inherited or third-party code before deploying it.
- Triaging a reported vulnerability or suspicious behavior.
- Producing a security findings report with severities and fixes.

This skill is the audit counterpart to the secure-coding skills. When you find an issue,
fix it using the relevant skill (`nonces-csrf-protection`, `output-escaping`,
`sql-injection-prevention`, etc.).

## Core principles (and why they matter)

1. **Follow the data, not the file order.** Trace untrusted input from its entry point
   (`$_GET`/`$_POST`/`$_FILES`/REST) to where it is used (DB, output, filesystem). Bugs
   live on those paths.
2. **Map trust boundaries first.** Every AJAX action, REST route, form handler, and
   shortcode is a boundary that needs nonce + capability + sanitize + escape. Enumerate
   them before reading line by line.
3. **Absence is the bug.** Most WordPress vulns are *missing* controls — no
   `current_user_can`, no `wp_verify_nonce`, no `esc_*`, no `prepare()`. Grep for the
   sinks, then check each for the missing guard.
4. **Confirm exploitability, then rate severity.** Distinguish a real, reachable issue
   from a theoretical one. Rate by impact × reachability (auth required? privilege level?).
5. **Report with a concrete fix.** Each finding = location, what's wrong, why it matters,
   and the corrected code. A finding without a fix is half-done.
6. **Don't trust comments or names.** Verify what the code does, not what it claims.

## Step-by-step implementation

1. **Inventory entry points:** grep for `wp_ajax_`, `register_rest_route`, `admin_post_`,
   `add_shortcode`, `$_GET`/`$_POST`/`$_REQUEST`/`$_FILES`, form handlers.
2. **For each, check the four controls:** nonce verified? capability checked? input
   sanitized (after unslash)? output escaped / queries prepared?
3. **Grep the sinks:** `$wpdb->query`/`get_results` without `prepare`; `echo`/`print` of
   variables without `esc_*`; `include`/`require`/`readfile`/`unlink` with input;
   `move_uploaded_file`; `eval`/`create_function`/`unserialize` of input;
   `extract()`; `add_query_arg`/`remove_query_arg` echoed unescaped.
4. **Triage:** assign Critical / High / Medium / Low / Info by impact and reachability.
5. **Report:** file:line, category, severity, description, PoC (if safe), and the fix.
6. **Re-verify** after fixes; confirm no control was bypassed elsewhere.

See [`references/grep-patterns.md`](references/grep-patterns.md) for ready-to-run searches
and [`references/audit-checklist.md`](references/audit-checklist.md) for the full review pass.

## Common AI mistakes / anti-patterns

### Mistake 1 — Reviewing for style, missing the security sink

```php
// Reviewer comment: "rename $q to $query for clarity" ← misses the actual bug:
$rows = $wpdb->get_results( "SELECT * FROM t WHERE id = " . $_GET['id'] ); // SQL injection
```

Flag the **injection** first. Cosmetic notes never outrank a Critical finding.

### Mistake 2 — Assuming a nonce implies authorization (or vice versa)

```php
// A nonce check is present, so the reviewer marks it "secure" —
check_admin_referer( 'act' );
delete_user( absint( $_POST['id'] ) ); // ❌ still missing current_user_can()
```

Verify **both** controls independently on every state-changing path.

### Mistake 3 — Trusting `sanitize_*` as if it were escaping (or the reverse)

```php
// Input was sanitized on save, so output is assumed safe — but context differs:
echo '<a href="' . get_option( 'my_url' ) . '">'; // ❌ needs esc_url on output
```

Sanitize-on-input and escape-on-output are separate; check both ends.

### Mistake 4 — Marking everything Critical (or burying real issues)

Inflated severity destroys signal. Rate by impact × reachability: an unauthenticated RCE
is Critical; a self-XSS reachable only by an admin editing their own profile is Low/Info.

### Mistake 5 — Reporting the problem without the fix

```text
❌ "Line 42 is vulnerable to XSS."
✅ "Line 42: $name echoed unescaped into HTML (stored XSS, High).
    Fix: echo esc_html( $name );"
```

## Correct code examples

Apply this review template to each finding:

```text
[SEVERITY] Category — short title
Location:    path/to/file.php:42
Description: What the code does and why it is unsafe.
Impact:      Who can do what (auth level, data exposed, action performed).
Fix:         The corrected code, using the relevant secure-coding skill.
```

Worked example:

```text
[CRITICAL] SQL Injection — unprepared query in order lookup
Location:    includes/orders.php:88
Description: $_GET['id'] is concatenated directly into a SELECT.
Impact:      Unauthenticated; full DB read via UNION; potential auth bypass.
Fix:         $id = absint( $_GET['id'] ?? 0 );
             $wpdb->get_row( $wpdb->prepare(
                 "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $id ) );
```

## Checklist

- [ ] All entry points (AJAX, REST, admin-post, shortcodes, superglobals) inventoried.
- [ ] Each state-changing path checked for nonce AND capability.
- [ ] Each output checked for context-correct escaping.
- [ ] Each custom query checked for `$wpdb->prepare()`.
- [ ] File/path operations checked for allowlisting and traversal.
- [ ] Dangerous sinks (`eval`, `unserialize`, `extract`, raw includes) flagged.
- [ ] Findings rated by impact × reachability, not inflated.
- [ ] Every finding includes file:line and a concrete fix.
- [ ] Fixes re-verified; no control bypassed elsewhere.

## Official references

- [Plugin Security — Plugin Handbook](https://developer.wordpress.org/plugins/security/)
- [Common Vulnerabilities — Plugin Handbook](https://developer.wordpress.org/plugins/security/common-vulnerabilities/)
- [Data Validation](https://developer.wordpress.org/apis/security/data-validation/)
- [Escaping Data](https://developer.wordpress.org/apis/security/escaping/)
- [WPCS — WordPress Coding Standards (security sniffs)](https://github.com/WordPress/WordPress-Coding-Standards)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
