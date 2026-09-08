# Dependency & supply-chain checklist

## Before adding a dependency

- [ ] WordPress core does not already provide the functionality (default script handles, bundled PHP libraries such as PHPMailer via `wp_mail()`).
- [ ] The project shipped a tagged release within the last ~12 months.
- [ ] Advisory history is clean or understood: `composer audit` after the first install, `roave/security-advisories` in `require-dev`.
- [ ] For front-end libraries without Composer coverage, advisories were checked with OWASP Dependency-Check or the vendor's security page.
- [ ] The license is compatible with the plugin's distribution (GPL-compatible for WordPress.org hosting).
- [ ] The version constraint is bounded (`^1.4`, `~2.0`), `minimum-stability` is `stable`, and nothing depends on `dev-main`.
- [ ] The dependency is actually needed; the best dependency is the one you did not add.

## Before shipping

- [ ] `composer.lock` is committed and reviewed; the build ran `composer install --no-dev --optimize-autoloader`, not `composer update`.
- [ ] `composer audit` reports no known vulnerabilities for the locked set.
- [ ] `.gitattributes` `export-ignore` lines keep `tests/`, `.github/`, CI configs, and demo data out of the distributable zip.
- [ ] No `eval(`, string `assert(`, `create_function(`, preg `/e` modifier, or `include`/`require` of anything fetched with `wp_remote_get()` remains in shipped code.
- [ ] No `phar://` stream usage on paths influenced by input.
- [ ] CDN assets are self-hosted, or pinned to an exact version with `integrity` + `crossorigin` attributes added via `script_loader_tag` / `style_loader_tag`.
- [ ] No enqueued URL resolves to changeable content such as `latest.js`.
- [ ] Shipped code contains no `auto_update_plugin` / `auto_update_theme` / `AUTOMATIC_UPDATER_DISABLED` blockers.
- [ ] PHP and WordPress minimums are enforced with `version_compare()` before the plugin loads.
- [ ] Pasted snippets were rewritten against current WordPress/PHP APIs before merging.
- [ ] The release diff for `composer.lock` was reviewed like code: every version bump is deliberate.
