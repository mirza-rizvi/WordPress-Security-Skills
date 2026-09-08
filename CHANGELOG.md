# Changelog

All notable changes to this repository will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning once
tagged releases begin.

## Unreleased

### Added

- 3 new skills closing the last core coverage gaps: `authentication-session-security`,
  `security-headers-csp`, and `dependency-supply-chain-security`.
- 12 core skills:
  `ajax-security`, `settings-options-security`, `http-api-ssrf-prevention`,
  `shortcode-block-security`, `object-injection-deserialization`, `filesystem-security`,
  `secrets-credentials-management`, `cron-background-job-security`, `multisite-security`,
  `gutenberg-block-editor-security`, `wp-cli-security`, `woocommerce-security`.
- Targeted enhancements to the first 11 skills (open redirects, header/JSON nonces,
  privilege-escalation patterns, `%i` identifier examples, SVG/double-extension handling,
  REST schema/field permissions, extended audit grep patterns, XML-RPC/REST enumeration
  hardening, WooCommerce/privacy cross-links).
- Extended `scripts/validate-skills.sh` with line-count guard, "Use when" description check,
  nonce+capability heuristic, and optional PHPCS/WPCS integration.
- Extended `.github/workflows/validate.yml` with external link checking, README-sync
  reminder, and pinned PHPCS + WordPress Coding Standards step.
- Coverage matrix and README table updates for all new skills.

### Added (initial)

- 11 core skills: `secure-plugin-development`, `input-sanitization-validation`,
  `output-escaping`, `nonces-csrf-protection`, `capability-permission-checks`,
  `sql-injection-prevention`, `file-upload-security`, `rest-api-security`,
  `security-auditing-code-review`, `wp-hardening-best-practices`,
  `user-data-protection-privacy`.
- Public security policy.
- GitHub issue and pull request templates.
- Coverage matrix for current and candidate WordPress security skills.
- Local skill validation script and GitHub Actions workflow.
- Root `.gitignore` for local, cache, and generated artifacts.
