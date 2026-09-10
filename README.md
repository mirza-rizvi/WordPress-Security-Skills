# WordPress Security Skills

Modular [Agent Skills](https://agentskills.io) that teach AI coding agents — Claude Code,
Cursor, Codex, OpenCode, Gemini CLI — to write **secure-by-default WordPress code** and to
**audit and harden** existing plugins and themes.

## Confused? Just ask your agent 💡

You do not need to understand skills, frontmatter, or per-agent install paths.
Open your AI coding agent **in the WordPress project you want to work on**, then
copy and paste this prompt:

```text
Set up the WordPress security skills from
https://github.com/wpultimatesecurity/WordPress-Security-Skills for this project.

Read the repository's README and inspect my agent's existing configuration.
Use the install location supported by this agent and its current version;
prefer project-scoped installation unless I ask for a global installation.
Copy the skill directories together with their references. Preserve existing
skills and settings; ask before replacing anything with the same name.

Install instructions only. Do not activate the PHP examples, change my
WordPress site, access production credentials, commit, or push anything.
Report the source revision, installed skill names, destination, and any
reload needed. Verify discovery using the agent's available skill listing;
if you cannot verify it, say so rather than assuming installation worked.
```

ℹ️ **What you are installing** — Markdown instructions with PHP and configuration
reference examples. This is **not a WordPress plugin**, a scanner, or automatic
protection for your website. Review examples before adapting them to your project.

💡 **Every future project** — Add: “Install these globally for all my projects.”
Use one scope where possible to avoid duplicate or conflicting skill copies.

⚠️ **No skills support?** — Ask the agent to read the relevant `SKILL.md` and
its linked references before working. If it cannot open links, provide the local
files. Pasting a URL alone does not prove the instructions were loaded.

❓ **Verify it worked** — Ask: “Which WordPress security skills can you discover,
and where were they loaded from?” Restart or reload the tool if required.

Prefer doing it yourself? Jump to [manual installation](#install).

[Browse the skills](#the-skills) · [Get better results](#get-better-results) ·
[Report a security issue](SECURITY.md) · [Contribute](CONTRIBUTING.md)


Scope is deliberately **security only**. These skills guide development and review;
they do not automatically enforce controls or prove that a website is secure.

## Why this exists

AI-generated WordPress code can omit nonce checks, authorization, escaping, or
prepared queries. These skills describe those failure modes and show defensive
patterns for reviewers and developers to adapt.

Guidance links to the [official WordPress reference](https://developer.wordpress.org/reference/).
Check API behavior against your supported WordPress/PHP versions. Automated
validation checks structure, PHP syntax, and coding standards where available;
it is not an independent security audit or proof that every example is correct.

## Who it's for

WordPress plugin and theme developers who use AI coding agents and want the generated code
to be secure without hand-holding — plus reviewers auditing AI-written or third-party code.

## What these skills solve

Each skill targets a documented failure mode in AI-generated WordPress code:

| Skill | The mistake it prevents |
| --- | --- |
| **secure-plugin-development** | Scaffolds without an ABSPATH guard; does work before checks; rolls its own SQL/HTTP instead of core APIs. |
| **input-sanitization-validation** | Sanitizes without `wp_unslash`, uses the wrong sanitizer, treats `strip_tags` as XSS-safe, never validates. |
| **output-escaping** | Echoes variables unescaped, or escapes for the wrong context (HTML escaper inside an attribute / URL). |
| **nonces-csrf-protection** | Acts on requests with no nonce, or verifies a nonce but skips the capability check. |
| **capability-permission-checks** | Checks roles instead of capabilities, hides UI instead of authorizing, skips per-object checks. |
| **sql-injection-prevention** | Concatenates input into `$wpdb` queries, mis-quotes `prepare()`, builds `IN()`/`ORDER BY` from input. |
| **file-upload-security** | Uses raw `move_uploaded_file`, trusts the client MIME type, blocklists extensions, allows path traversal. |
| **rest-api-security** | Ships `permission_callback => '__return_true'` on writes, skips `args` sanitize/validate. |
| **security-auditing-code-review** | Reviews for style and misses the security sink; inflates severity; reports without a fix. |
| **wp-hardening-best-practices** | Leaves debug on, allows the file editor, `chmod 777`, lets uploads execute PHP. |
| **user-data-protection-privacy** | Stores PII with no export/erase integration; keeps full IPs; exposes PII to low-privilege users. |
| **ajax-security** | Registers AJAX actions with no nonce, uses `wp_ajax_nopriv_*` for privileged flows, or echoes raw `$_POST`. |
| **settings-options-security** | Registers settings with no `sanitize_callback`, bypasses `settings_fields`, or echoes `get_option` unescaped. |
| **http-api-ssrf-prevention** | Calls `wp_remote_get` on user input without host allowlists or `wp_safe_remote_*`. |
| **shortcode-block-security** | Echoes shortcode/block attributes unescaped or trusts `shortcode_atts()` to sanitize. |
| **object-injection-deserialization** | Calls `unserialize` / `maybe_unserialize` on attacker-controlled data. |
| **filesystem-security** | Builds file paths from input without containment checks, or `include`s user-controlled files. |
| **secrets-credentials-management** | Hardcodes API keys, stores passwords reversibly, or logs tokens. |
| **cron-background-job-security** | Uses `current_user_can` inside cron callbacks or puts secrets in cron URLs/args. |
| **multisite-security** | Confuses site/network capabilities, trusts `blog_id` input, or forgets `restore_current_blog`. |
| **gutenberg-block-editor-security** | Renders block attributes unescaped or registers REST fields with no permission check. |
| **wp-cli-security** | Interpolates CLI args into SQL, assumes admin context, or prints secrets. |
| **woocommerce-security** | Exposes orders without `edit_shop_orders`, stores payment data, or leaks customer PII. |
| **dependency-supply-chain-security** | Vendors outdated libraries, enqueues unversioned CDN scripts with no integrity, or loads remotely fetched code. |
| **authentication-session-security** | Bypasses core authentication or mishandles session revocation, password changes, and login throttling. |
| **security-headers-csp** | Sends no security headers, ships a blanket CSP that permits everything, or reflects arbitrary `Origin` values into CORS. |

## The skills

| Skill | One-liner |
| --- | --- |
| [`secure-plugin-development`](skills/secure-plugin-development/) | Secure-by-default baseline + router to the focused skills. |
| [`input-sanitization-validation`](skills/input-sanitization-validation/) | Unslash, sanitize to type, validate against allowlists. |
| [`output-escaping`](skills/output-escaping/) | Context-correct escaping at the point of output (XSS). |
| [`nonces-csrf-protection`](skills/nonces-csrf-protection/) | Generate/verify nonces, paired with capability checks. |
| [`capability-permission-checks`](skills/capability-permission-checks/) | `current_user_can` with the right (often per-object) capability. |
| [`sql-injection-prevention`](skills/sql-injection-prevention/) | `$wpdb->prepare()`, `esc_like`, allowlisted identifiers. |
| [`file-upload-security`](skills/file-upload-security/) | `wp_handle_upload` + type allowlist; block exec & traversal. |
| [`rest-api-security`](skills/rest-api-security/) | Real `permission_callback`, `args` sanitize/validate. |
| [`security-auditing-code-review`](skills/security-auditing-code-review/) | Systematic audit: find boundaries, grep sinks, triage, fix. |
| [`wp-hardening-best-practices`](skills/wp-hardening-best-practices/) | wp-config, `.htaccess`/nginx, permissions, file editor. |
| [`user-data-protection-privacy`](skills/user-data-protection-privacy/) | GDPR export/erase hooks, IP anonymization, data minimization. |
| [`ajax-security`](skills/ajax-security/) | Nonce + capability on `admin-ajax.php` handlers; safe JSON responses. |
| [`settings-options-security`](skills/settings-options-security/) | `register_setting` sanitize_callback, `settings_fields`, escaped options output. |
| [`http-api-ssrf-prevention`](skills/http-api-ssrf-prevention/) | `wp_safe_remote_*`, host allowlists, and response validation. |
| [`shortcode-block-security`](skills/shortcode-block-security/) | Sanitized shortcode/block attributes and escaped render output. |
| [`object-injection-deserialization`](skills/object-injection-deserialization/) | Avoid `unserialize` on untrusted data; prefer JSON. |
| [`filesystem-security`](skills/filesystem-security/) | Base-directory containment, `validate_file`, safe file delete/write. |
| [`secrets-credentials-management`](skills/secrets-credentials-management/) | Hashed passwords, encrypted options, Application Passwords. |
| [`cron-background-job-security`](skills/cron-background-job-security/) | Cron callbacks with no `current_user_can`; validated stored context. |
| [`multisite-security`](skills/multisite-security/) | Network capabilities, validated `blog_id`, `restore_current_blog`. |
| [`gutenberg-block-editor-security`](skills/gutenberg-block-editor-security/) | Escaped `render_callback`, REST field permissions, `wp_kses` rich text. |
| [`wp-cli-security`](skills/wp-cli-security/) | Sanitized CLI args, prepared queries, confirmed destructive ops. |
| [`woocommerce-security`](skills/woocommerce-security/) | WooCommerce capabilities, order/customer PII handling, tokenized payments. |
| [`dependency-supply-chain-security`](skills/dependency-supply-chain-security/) | Vetted dependencies, `composer audit`, pinned + SRI-checked CDN assets, no runtime code loading. |
| [`authentication-session-security`](skills/authentication-session-security/) | Core `wp_signon` flows, cookie/session lifecycle, login throttling, uniform login errors. |
| [`security-headers-csp`](skills/security-headers-csp/) | `nosniff`, frame protection, Referrer-Policy, real CSP nonces, CORS allowlists, cookie flags. |

Every skill follows the same structure: **When to use · Core principles · Step-by-step ·
Common AI mistakes (wrong→right) · Correct code examples · Checklist · Official references**,
with integration examples under each skill's `references/` directory. A **Supporting
references** table in Step-by-step explicitly routes every artifact by load condition. These are
not a plugin bundle: adapt prefixes, permissions, storage, and any documented
asset/template dependencies before running them in a local WordPress environment.

## Compatibility

Examples generally use a **PHP 7.4 syntax baseline**, with newer WordPress/PHP
requirements noted where relevant. PHP 7.4 is end-of-life: use a supported PHP
release and maintained WordPress version for production. Syntax compatibility
does not imply that an older runtime is secure or supported.

These skills conform to the open [Agent Skills specification](https://agentskills.io/specification),
so any compatible agent can load them. Each is a directory with a `SKILL.md`
(`name` + `description` frontmatter) plus a `references/` folder for progressive disclosure.

## Install

Skills are plain directories — install by copying the ones you want (or the whole `skills/`
folder) into your agent's skills directory.

### One command (skills CLI)

With Node.js installed, the [skills CLI](https://agentskills.io) can install directly from
this repository:

```bash
# Interactive (pick skills and scope):
npx skills add wpultimatesecurity/WordPress-Security-Skills

# Non-interactive, all skills:
npx --yes skills add wpultimatesecurity/WordPress-Security-Skills
```


### Claude Code

```bash
# Personal (all your projects):
mkdir -p ~/.claude/skills && cp -r skills/* ~/.claude/skills/

# Project-scoped (commit with the repo):
mkdir -p .claude/skills && cp -r skills/* .claude/skills/
```

Claude Code reads skills from `~/.claude/skills/<name>/SKILL.md` (personal) and
`.claude/skills/<name>/SKILL.md` (project). It loads each skill's `description` at startup and
the body on demand. See the [Claude Code skills docs](https://code.claude.com/docs/en/skills).

### Cursor

```bash
# Project-scoped:
mkdir -p .cursor/skills && cp -r skills/* .cursor/skills/
```

Cursor discovers skills in `.cursor/skills/<name>/SKILL.md` (also `.agents/skills/`) anywhere
in the repo. See the [Cursor skills docs](https://cursor.com/docs/skills).

### OpenCode

```bash
# Project-scoped:
mkdir -p .opencode/skills && cp -r skills/* .opencode/skills/

# Global:
mkdir -p ~/.config/opencode/skills && cp -r skills/* ~/.config/opencode/skills/
```

OpenCode loads from `.opencode/skills/` (project) and `~/.config/opencode/skills/` (global),
and also reads `~/.claude/skills/` and `.claude/skills/`. See the
[OpenCode skills docs](https://opencode.ai/docs/skills).

### Other agents (Codex, Gemini CLI, etc.)

Any agent implementing the Agent Skills standard can point at this `skills/` directory. Where
an agent reads `.claude/skills/` or `.agents/skills/` (several do), the Claude Code paths above
work as-is.

## Get better results

1. **Give the agent context.** State your WordPress and PHP versions, whether
   this is a plugin or theme, multisite/WooCommerce usage, relevant user roles,
   and whether it is working locally or on staging. Never paste production secrets.
2. **Load the relevant guidance.** Start new code with
   [secure-plugin-development](skills/secure-plugin-development/SKILL.md).
   For existing code, start with
   [security-auditing-code-review](skills/security-auditing-code-review/SKILL.md)
   and load focused skills as the review identifies trust boundaries.
3. **Ask for evidence, not a security score.** Require file locations,
   affected roles, exploit prerequisites, and a concrete verification for each
   finding. Separate confirmed vulnerabilities from hardening recommendations.
4. **Keep changes reversible.** Review the diff, verify the changed behavior
   on local/staging data, and maintain a tested backup before deployment.
   Skill installation is not authorization to modify a live site.

For an existing project, try:

```text
Use the installed WordPress security skills to review this project.
Start read-only: identify entry points, authorization boundaries, and risky
inputs and outputs. Report confirmed findings with file/line references,
exploit prerequisites, impact, and recommended fixes. Separate assumptions
and hardening suggestions from confirmed bugs. Propose a prioritized plan
before editing; do not access production or publish changes.
```

Skills improve the instructions available to an agent; they do not guarantee
secure output or replace updates, backups, monitoring, or a qualified review.
For reproducibility, record the installed revision. Review upstream changes
before updating your local copies, then repeat discovery and behavior checks.


## Contributing

New skills and fixes are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the SKILL.md
contract, description-writing rules, and the WordPress-correctness requirement (verify every
API against developer.wordpress.org; never invent functions).

Content in this repository is developed with AI assistance under human direction; see
[docs/ai-authorship.md](docs/ai-authorship.md) for what our validation does and does not
establish.

## Official WordPress security references

- [Security — Common APIs Handbook](https://developer.wordpress.org/apis/security/)
- [Plugin Security — Plugin Handbook](https://developer.wordpress.org/plugins/security/)
- [Data Validation](https://developer.wordpress.org/apis/security/data-validation/) ·
  [Sanitizing](https://developer.wordpress.org/apis/security/sanitizing/) ·
  [Escaping](https://developer.wordpress.org/apis/security/escaping/) ·
  [Nonces](https://developer.wordpress.org/apis/security/nonces/)
- [Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [WordPress Coding Standards](https://github.com/WordPress/WordPress-Coding-Standards)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/) ·
  [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

## License

[MIT](LICENSE).
