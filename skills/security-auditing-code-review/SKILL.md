---
name: security-auditing-code-review
description: >
  Use when auditing or code-reviewing an existing WordPress plugin or theme for security
  issues, triaging a vulnerability report, or hardening inherited code. Provides a
  systematic methodology — locate trust boundaries, inventory sensitive sinks, trace
  their controls and data flows, then triage confirmed issues and report with fixes.
  Apply proactively before shipping or when reviewing third-party code.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, audit, code-review, vulnerability, hardening"
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
2. **Map trust boundaries first.** Enumerate AJAX actions, REST routes, forms,
   shortcodes, cron jobs, and CLI commands. Decide which need authentication,
   authorization, CSRF protection, validation, and output escaping for their context.
3. **Trace controls, not proximity.** A nearby nonce, capability check, escaper, or
   `prepare()` call does not establish protection. Verify it governs the reachable
   operation; absence from the same line/file does not establish a vulnerability.
4. **Confirm exploitability, then rate severity.** Distinguish a real, reachable issue
   from a theoretical one. Rate by impact × reachability (auth required? privilege level?).
5. **Report with a concrete fix.** Each finding = location, what's wrong, why it matters,
   and the corrected code. A finding without a fix is half-done.
6. **Don't trust comments or names.** Verify what the code does, not what it claims.

## Step-by-step implementation

1. **Record review context before inventory/scanning:** target, immutable revision
   (commit/tag resolved to commit/checksum), reviewer, date, scope, exclusions,
   methods/tool versions, active-testing authorization, and limitations. Keep
   unavailable values explicitly Unknown; never infer them. Use the full
   [report template](references/report-template.md) throughout the review.
2. **Inventory entry points:** grep for `wp_ajax_`, `register_rest_route`, `admin_post_`,
   `add_shortcode`, `$_GET`/`$_POST`/`$_REQUEST`/`$_FILES`, form handlers.
3. **Check applicable controls on each path:** transport-appropriate authentication
   and CSRF protection, resource-level authorization, shape/type validation,
   sanitization, output escaping, and safe query construction.
4. **Inventory sinks**, including safely guarded ones: database calls, output,
   filesystem operations, uploads, code execution, deserialization, redirects,
   and outbound requests. Follow the input and controls before labeling any hit.
5. **Classify before rating:** confirmed vulnerabilities alone receive severity
   counts based on impact and reachability. Put scanner hits and incomplete traces
   under Unverified leads, and defense-in-depth advice under Hardening recommendations.
6. **Report:** evidence/data flow, exploit prerequisites, impact, concrete remediation,
   verification, and references. Redact secrets/PII. Do not invent CVSS/CWE values,
   remediation hours, response promises, or an overall secure score.
7. **Re-verify** fixes across in-scope paths; distinguish executed checks from proposed
   checks. Record residual limitations and refuse blanket release sign-off or security
   certification for incomplete scope.

After recording context, use the read-only [sink inventory helper](scripts/scan-security-sinks.sh)
if Bash and ripgrep (`rg`) are available. From this skill directory:

```bash
bash scripts/scan-security-sinks.sh /path/to/plugin-or-theme
```

This is a **heuristic text search, not a security audit or vulnerability detector**.
It includes safe calls, comments, and strings; it does not prove missing controls.
No hits is not proof of safety. It searches PHP/PHTML/INC files using ripgrep
ignore rules, skipping hidden/binary files and symlinks. Dynamic/multiline calls
and other file types require separate review. Source lines can contain secrets;
keep the output local and redact before sharing. `--help` explains scope and
exit codes (0: completed, with or without hits; 2: usage/search error).

See [`references/grep-patterns.md`](references/grep-patterns.md) for additional searches
and [`references/audit-checklist.md`](references/audit-checklist.md) for the full review pass.

### Supporting references

| Reference | Load when |
| --- | --- |
| [WordPress security audit checklist](references/audit-checklist.md) | Performing the full manual audit pass across entry points, controls, and sinks. |
| [Audit grep patterns](references/grep-patterns.md) | Expanding the entry-point and sink inventory with additional heuristic searches. |
| [WordPress security review report template](references/report-template.md) | Recording review context before inventory and reporting evidence, classification, verification, and limitations. |

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

Use the full [report template](references/report-template.md) for the review.
Keep this compact skeleton for each **confirmed** finding:

```text
[SEVERITY] Category — title
Location: Exact file:line at the reviewed revision.
Evidence/data flow: Reachable source, governing controls, and sensitive sink.
Exploit prerequisites: Required identity, nonce access, object restrictions, configuration.
Impact: Demonstrated consequences and evidence-based severity rationale.
Remediation: Concrete corrected code/configuration with fail-closed controls.
Verification: Executed checks and results; proposed checks explicitly unexecuted.
References: Relevant official API/security sources.
```

## Checklist

- [ ] Review context records scope, immutable revision, reviewer/date, methods/versions,
  testing authorization, exclusions, and limitations; unavailable values remain Unknown.
- [ ] All in-scope entry points inventoried; no claim extends beyond reviewed paths.
- [ ] State-changing paths checked independently for applicable CSRF and authorization controls.
- [ ] Each output checked for context-correct escaping.
- [ ] Each custom query checked for `$wpdb->prepare()`.
- [ ] File/path operations checked for allowlisting and traversal.
- [ ] Dangerous sink hits traced before classifying them as vulnerabilities.
- [ ] Confirmed findings alone enter severity totals; unverified leads and hardening stay separate.
- [ ] Each finding records location, evidence/data flow, exploit prerequisites, impact,
  concrete remediation, verification, and references.
- [ ] Executed checks and results distinguished from proposed checks and unverified fixes.
- [ ] Secrets/PII redacted; residual scope limitations explicit; no blanket sign-off or certification.

## Official references

- [Plugin Security — Plugin Handbook](https://developer.wordpress.org/plugins/security/)
- [Data Validation](https://developer.wordpress.org/apis/security/data-validation/)
- [Escaping Data](https://developer.wordpress.org/apis/security/escaping/)
- [WPCS — WordPress Coding Standards (security sniffs)](https://github.com/WordPress/WordPress-Coding-Standards)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
