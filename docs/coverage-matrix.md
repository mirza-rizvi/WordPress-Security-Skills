# WordPress Security Coverage Matrix

This matrix tracks public skill coverage and helps contributors propose focused additions.

| Domain | Current status | Skill |
| --- | --- | --- |
| Secure plugin baseline | Covered | `secure-plugin-development` |
| Input sanitization and validation | Covered | `input-sanitization-validation` |
| Output escaping and XSS prevention | Covered | `output-escaping` |
| Nonces and CSRF protection | Covered | `nonces-csrf-protection` |
| Capabilities and permissions | Covered | `capability-permission-checks` |
| SQL injection prevention | Covered | `sql-injection-prevention` |
| File upload security | Covered | `file-upload-security` |
| REST API security | Covered | `rest-api-security` |
| Security auditing and code review | Covered | `security-auditing-code-review` |
| WordPress hardening | Covered | `wp-hardening-best-practices` |
| User data protection and privacy | Covered | `user-data-protection-privacy` |
| AJAX security | Covered | `ajax-security` |
| Settings and options security | Covered | `settings-options-security` |
| HTTP API and SSRF prevention | Covered | `http-api-ssrf-prevention` |
| Shortcode and block security | Covered | `shortcode-block-security` |
| Object injection / deserialization | Covered | `object-injection-deserialization` |
| Filesystem API security | Covered | `filesystem-security` |
| Secrets and credentials management | Covered | `secrets-credentials-management` |
| Cron and background job security | Covered | `cron-background-job-security` |
| Multisite security | Covered | `multisite-security` |
| Gutenberg block editor security | Covered | `gutenberg-block-editor-security` |
| WP-CLI security | Covered | `wp-cli-security` |
| WooCommerce security | Covered | `woocommerce-security` |
| Dependency and supply-chain security | Covered | `dependency-supply-chain-security` |
| Authentication and session management | Covered | `authentication-session-security` |
| HTTP security headers, CSP, and CORS | Covered | `security-headers-csp` |

All rows above are covered. Future candidates (propose via the issue template before
starting work):

1. `custom-fields-meta-security`: ACF and custom meta sanitization/authorization on read
   and write.
2. `page-builder-output-security`: escaping rules for popular page builders' custom HTML
   widgets and dynamic tags.
3. `headless-jwt-rest-auth`: headless setups authenticating REST with JWT/OIDC instead of
   cookies.
4. `logging-monitoring-security`: what to log, log injection, and keeping secrets out of
   logs.
