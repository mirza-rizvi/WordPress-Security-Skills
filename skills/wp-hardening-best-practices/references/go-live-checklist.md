# Pre-launch (go-live) checklist

The final sweep before a site ships. Each section points at the skill whose checklist
holds the detailed rows — this file is the launch gate, not a replacement.

## Configuration

- [ ] Hardening checklist fully ticked (wp-config, server rules, filesystem): [checklist.md](checklist.md)
- [ ] Security headers verified with `curl -sI` on `/` and `/wp-login.php` — see the
      `security-headers-csp` skill checklist.
- [ ] Plain-HTTP requests redirect to HTTPS; HSTS sent only if the site is HTTPS-only.

## Code

- [ ] A security audit pass ran over all custom code — entry points, trust boundaries,
      sinks: `security-auditing-code-review`.
- [ ] No secrets hard-coded, echoed, or logged; service keys in `wp-config.php`
      constants or encrypted options: `secrets-credentials-management`.
- [ ] Dependencies audited (`composer audit` / `npm audit`); CDN assets version-pinned
      with SRI: `dependency-supply-chain-security`.
- [ ] Bulk writes use field allowlists (no mass assignment); inputs sanitized,
      outputs escaped — `input-sanitization-validation`, `output-escaping`.

## Accounts and access

- [ ] Login throttling active on every login path; uniform login errors:
      `authentication-session-security`.
- [ ] No unused or default-named admin accounts; roles least-privilege.
- [ ] Application Passwords limited to users who need machine access; XML-RPC off if unused.
- [ ] Public abuse controls active: comment moderation on, pingbacks off if unused,
      CAPTCHA/Turnstile on login/registration via an established plugin for bot-heavy sites.

## Data and privacy

- [ ] Exporter + eraser registered; privacy policy content declared:
      `user-data-protection-privacy`.
- [ ] Tracking/analytics scripts load only after consent (server-side gate); cookies
      disclosed in the policy content.
- [ ] Logs exclude PII and secrets; IPs anonymized where identity is not needed.

## Verification

- [ ] Fresh incognito visit shows no debug output, notices, or stack traces.
- [ ] `curl -sI https://site/` shows the expected headers; error pages (404, search)
      render the theme without warnings.
- [ ] A backup restore has been tested on staging within the last week.
- [ ] Post-launch monitoring exists: uptime check, error log review cadence.
