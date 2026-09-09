# Changelog

All notable changes to this repository will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning once
tagged releases begin.

## Unreleased

### Added

- Eval scenario contracts: one JSON per skill under `eval/scenarios/` (task prompt +
  expected review steps + acceptance criteria), a documented evaluation protocol with
  stated limits, and structural schema/coverage validation. Scenarios are prompts and
  rubrics, not executed behavior tests.
- Frontmatter hardening: every skill now declares `compatibility` (accurate PHP 7.4
  syntax baseline; per-example version requirements stay in context) and
  spec-compatible scalar `metadata.tags`; both enforced by validators and CI.
- Validation tooling: `scripts/validate-content.py` (strict metadata + scenario
  validation, refuses incomplete drafts), `scripts/add-skill.py` scaffolding generator,
  `scripts/smoke-install.py` install/discovery smoke, and the official `skills-ref`
  validator wired into CI alongside the existing structural checks.
- `security-auditing-code-review`: `scripts/scan-security-sinks.sh`, a read-only
  heuristic sink/entry-point inventory (documented limits; not an audit).
- `secure-plugin-development`: `references/decision-tree.md` — route by entry path and
  data/policy branches instead of loading every skill.
- `docs/ai-authorship.md`: what AI assistance and automated validation do and do not
  establish; no human-review claim is made.
- Content additions: git secret-leak response procedure, mass-assignment allowlist
  pattern, per-route rate-limit caveats, REST response minimization, consent-manager
  tracker gating, bot/abuse controls, and a consolidated `go-live-checklist.md`.
- CI installs ripgrep/PyYAML/skills-ref, runs official per-skill validation and an
  isolated install smoke before the existing structural checks.
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
- README: scoped security/verification claims (examples are integration examples,
  validation limits, PHP 7.4 end-of-life note) and a "Get better results" usage guide.
- Authentication skill: corrected revocation guidance — core auth cookies embed a
  fragment of the stored password hash, so password changes already invalidate old
  cookies; session destruction is defense in depth for stored tokens.
- AJAX, dependency, and cron references relabeled as integration examples with exact
  prerequisites; the dependency reference ships a real computed SRI hash and fails
  closed on CDN source mismatches instead of passing unverified scripts through.
- SECURITY.md: documents what validation does not prove and the pre-publication
  secret/history review.

### Fixed

- CI: installs ripgrep (GitHub runners do not ship it); the reference link check now
  verifies URL values, hard-fails on 404/410 references, and scans the checkout plus
  reachable Git history for secrets (checksum-verified Gitleaks) using a committed
  `.gitleaks.toml` whose single allowlist entry covers one documented fictional
  credential example. Dead developer.wordpress.org links fixed.
- PHPCS details in reference files (missing `@package`, explicit enqueue args).
- README: repository URL updated to the canonical `wpultimatesecurity/WordPress-Security-Skills`
  location after the GitHub transfer (old links redirect, but the prompt and docs now point
  at the new org directly).
 
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
