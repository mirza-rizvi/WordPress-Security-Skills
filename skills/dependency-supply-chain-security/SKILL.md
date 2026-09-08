---
name: dependency-supply-chain-security
description: >
  Use when a plugin or theme bundles a third-party PHP or JavaScript library,
  enqueues an asset from a CDN, fetches or executes code at runtime, manages
  dependencies with Composer, or prepares the distributable zip. Covers
  core-handle-first enqueuing, dependency vetting with composer audit,
  lockfile pinning, export-ignore artifact hygiene, Subresource Integrity for
  CDN assets via script_loader_tag, and refusal of eval() and remote include
  patterns. Prevents supply-chain compromise through stale, unvetted, or
  remotely loaded third-party code.
license: MIT
metadata:
  tags: [wordpress, security, php, composer, supply-chain, dependencies, sri]
---

# Dependency & supply-chain security

## When to use this skill

Use this skill whenever code consumes third-party code or assets:

- Adding a Composer package, or vendoring a library copy into `vendor/` or `assets/lib/`.
- Enqueueing a script or stylesheet whose `src` is a full `https://` CDN URL.
- Loading PHP at runtime from the network, including "remote updater" patterns.
- Preparing the distributable zip and deciding what ships inside `vendor/`.
- Merging a snippet taken from Stack Overflow, a blog post, or an AI answer.

Do not reach for this skill for flaws in first-party code: use the
`output-escaping` skill for XSS in your own markup, the
`capability-permission-checks` skill for authorization, and the
`cron-background-job-security` skill for cron callbacks.

A plugin is only as secure as the oldest library inside it. A large share of
WordPress plugin CVEs are vulnerable bundled dependencies or compromised
third-party code loaded at runtime, not bugs in the plugin's own logic.

Related: see the `http-api-ssrf-prevention` skill for validating URLs you fetch
data from, the `filesystem-security` skill for confining local includes, and
the `secure-plugin-development` skill for overall plugin hardening.

## Core principles (and why they matter)

1. **Prefer core over bundling.** WordPress registers jQuery, Underscore,
   Backbone, media libraries, and the block-editor React build under documented
   handles. `wp_enqueue_script()` the core handle instead of shipping your own
   copy: bundled duplicates drift out of date and conflict with other plugins
   and themes that use the core version. Core patches its bundled libraries;
   your vendored copy of the same library gets no patches.
2. **Vet before adding.** Confirm the project shipped a release in the last
   ~12 months, scan its CVE history, and check the license is compatible with
   GPL where required. `composer audit` (Composer 2.4+) checks installed
   packages against the Packagist advisory database; the
   `roave/security-advisories` dev dependency refuses installs of
   known-vulnerable versions outright.
3. **Lock and pin.** Commit `composer.lock` and build with `composer install`,
   never `composer update`. Avoid `minimum-stability: dev` and unbounded
   constraints like `dev-main`: they make builds unreproducible and
   unauditable, so a compromise upstream is indistinguishable from your own
   release.
4. **Ship a minimal artifact.** Distributable zips must not contain dev
   dependencies, tests, CI configs, or demo data. `.gitattributes`
   `export-ignore` lines keep them out of `git archive` / `composer archive`
   builds, so attackers cannot read your tests to map untested code paths.
5. **Never load code from the network at runtime.** `eval()`, string
   `assert()`, `create_function()` (removed in PHP 8), the preg `/e` modifier
   (removed in PHP 7), or `include`/`require` of a fetched file, including
   `wp_remote_get()` bodies and `phar://` deserialization tricks, is RCE by
   design. Updates ship through an update channel; fetched payloads are not an
   update channel.
6. **Integrity-check front-end assets you do not host.** Self-host when
   possible. If a CDN is required, pin an exact version URL and add Subresource
   Integrity (`integrity` + `crossorigin` attributes) via the
   `script_loader_tag` / `style_loader_tag` filters. Never enqueue a URL whose
   content can change, such as `latest.js`.
7. **Keep update latency low for what you ship.** Do not ship code that blocks
   the auto-updates users rely on (`auto_update_plugin`, `auto_update_theme`,
   `WP_AUTO_UPDATE_CORE`, `AUTOMATIC_UPDATER_DISABLED`). Guard your own PHP and
   WordPress minimums with `version_compare()` and release patched builds fast
   when a bundled dependency announces a CVE.
8. **Treat pasted snippets as untrusted dependencies.** Rewrite them against
   current WordPress APIs and check for removed functions (`mysql_*`,
   `create_function()`) before merging. A snippet copied from 2011 carries the
   threat model of 2011.

## Step-by-step implementation

1. Before vendoring, check whether WordPress core already registers the asset.
   The `wp_register_script()` documentation lists the default handles
   (`jquery`, `jquery-ui-*`, `underscore`, `backbone`, `wp-api`, and more).
   Enqueue the handle; do not print your own copy of the same file.
2. Vet each new dependency before the first `composer require`:
   - Last tagged release within roughly the last 12 months.
   - No open high-severity advisories: run `composer audit` after adding.
   - License compatible with the plugin's distribution (GPL-compatible for
     WordPress.org hosting).
   - For non-Composer front-end libraries, check advisories with OWASP
     Dependency-Check or the vendor's security page.
3. Configure Composer for reproducible builds and commit the lock file:

   ```json
   {
       "name": "acme/my-plugin",
       "minimum-stability": "stable",
       "require": {
           "php": ">=7.4"
       },
       "require-dev": {
           "roave/security-advisories": "dev-latest"
       },
       "config": {
           "sort-packages": true
       }
   }
   ```

   Build with `composer install --no-dev --optimize-autoloader`. Only
   `composer update` intentionally bumps the lock file, and the diff gets
   reviewed like any other code change.
4. Keep tests, CI configs, and demo data out of the shipped zip via
   `.gitattributes`:

   ```
   /.github            export-ignore
   /tests              export-ignore
   /demo               export-ignore
   /phpcs.xml.dist     export-ignore
   /phpunit.xml.dist   export-ignore
   ```

5. Enforce your minimums at load time with `version_compare()` and refuse to
   run on stacks below them (see the reference file for the guard).
6. For CDN assets: self-host if possible. Otherwise pin an exact version URL,
   store an integrity hash per asset, and add `integrity` + `crossorigin`
   through the `script_loader_tag` / `style_loader_tag` filters (full example
   in the reference file).
7. Ship no auto-update blockers. Never distribute
   `add_filter( 'auto_update_plugin', '__return_false' );` or a
   `define( 'AUTOMATIC_UPDATER_DISABLED', true );` inside plugin code. If you
   must influence updates, filter only your own plugin:

   ```php
   // Keep this plugin on the auto-update train; never silence the whole site.
   add_filter( 'auto_update_plugin', 'my_plugin_auto_update_self', 10, 2 );
   function my_plugin_auto_update_self( $update, $item ) {
       if ( isset( $item->slug ) && 'my-plugin' === $item->slug ) {
           return true;
       }
       return $update;
   }
   ```

8. Grep the codebase before every release for runtime code loading:
   `eval(`, `assert(`, `create_function(`, `preg_replace(` with `/e`,
   `include`/`require` fed by `wp_remote_get()`, and `phar://` stream usage.
9. Rewrite pasted snippets against current APIs before merging. Anything
   calling `mysql_*` or `create_function()` was written for PHP that no longer
   runs your code.

## Common AI mistakes / anti-patterns

### Mistake 1 - Vendoring a stale copy of a library core already ships

```php
// ❌ Insecure: bundles an old PHPMailer 5.x copy "because it worked".
// Old 5.x releases carry known remote-command-execution CVEs, and this copy
// never receives patches. Core's copy does.
require_once __DIR__ . '/vendor/phpmailer/phpmailer/PHPMailerAutoload.php';
```

```php
// ✅ Secure: wp_mail() uses the PHPMailer version core ships and patches.
wp_mail( $to, $subject, $message, $headers );
```

### Mistake 2 - CDN script with no version pin and no integrity

```php
// ❌ Insecure: "chart.js" can change content at any time; the CDN operator
// (or anyone compromising it) controls the code that runs on every site.
wp_enqueue_script( 'my-charts', 'https://cdn.example.com/chart.js', array(), null );
```

```php
// ✅ Secure: exact version URL + Subresource Integrity, or self-host the file.
wp_enqueue_script(
    'my-charts',
    'https://cdn.jsdelivr.net/npm/chart.js@4.1.2/dist/chart.umd.min.js',
    array(),
    null // The URL path pins the version; no cache-busting query needed.
);
// integrity/crossorigin attributes are added in the script_loader_tag filter.
```

### Mistake 3 - Runtime updater that fetches and executes code

```php
// ❌ Insecure: RCE by design, and the plugin bricks itself when the host dies.
// $response = wp_remote_get( 'https://example.com/updater.php' );
// $body     = wp_remote_retrieve_body( $response );
// eval( $body );        // executes whatever the remote server returns
// include $tmp_path;    // same result if $tmp_path holds the fetched payload
```

```php
// ✅ Secure: updates arrive through the WordPress.org update channel, or a
// signed self-hosted channel. Metadata travels over the network; code does not.
// Plugins on WordPress.org need no custom updater code at all.
```

### Mistake 4 - Committing `vendor/` with dev dependencies and CI configs

```php
// ❌ Insecure: the distributable zip ships phpunit, phpcs configs, and test
// fixtures. Attackers read tests to map code paths nothing verifies.
// Built with: composer update (whatever was newest that Tuesday).
```

```php
// ✅ Secure: export-ignore keeps dev trees out of archives; builds are pinned.
// .gitattributes:
//   /tests          export-ignore
//   /.github        export-ignore
// Build command:
//   composer install --no-dev --optimize-autoloader
```

### Mistake 5 - `minimum-stability: dev` plus unbounded constraints

```json
// ❌ Insecure: every build resolves differently; you cannot audit what ships.
{
    "minimum-stability": "dev",
    "require": { "monolog/monolog": "dev-main" }
}
```

```json
// ✅ Secure: stable channel, bounded constraints, committed lock file.
{
    "minimum-stability": "stable",
    "require": { "monolog/monolog": "^3.0" }
}
```

### Mistake 6 - Shipping removed dynamic-code constructs

```php
// ❌ Insecure: fatals on PHP 8 (create_function removed) and on PHP 7 (/e
// modifier removed). Both execute strings as code, which is the point.
// $double  = create_function( '$a', 'return $a * 2;' );
// $bold    = preg_replace( '/<b>(.*?)<\/b>/e', 'strtoupper("$1")', $html );
```

```php
// ✅ Secure: closures and callbacks; no string-as-code anywhere.
$double = function ( $a ) {
    return $a * 2;
};
$bold = preg_replace_callback(
    '/<b>(.*?)<\/b>/',
    function ( $m ) {
        return strtoupper( $m[1] );
    },
    $html
);
```

## Correct code examples

A complete reference module covering core-handle-first enqueuing, pinned CDN
assets with Subresource Integrity via the `script_loader_tag` filter, a
`version_compare()` minimum-version gate, and a guarded local include confined
to the plugin directory is in
[`references/secure-dependency-management.php`](references/secure-dependency-management.php).

A before-adding / before-shipping checklist is in
[`references/checklist.md`](references/checklist.md), and a
situation-to-practice lookup table is in
[`references/cheatsheet.md`](references/cheatsheet.md).

## Checklist

- [ ] Core handles are used for assets WordPress registers (`jquery`, `underscore`, editor builds).
- [ ] Every bundled dependency is maintained (release within ~12 months) and audited (`composer audit`).
- [ ] `roave/security-advisories` is in `require-dev` for Composer projects.
- [ ] `composer.lock` is committed; builds run `composer install --no-dev`.
- [ ] `minimum-stability` is `stable`; no unbounded `dev-*` constraints.
- [ ] `.gitattributes` `export-ignore` keeps tests, CI configs, and demo data out of the zip.
- [ ] No `eval()`, string `assert()`, `create_function()`, preg `/e`, or remote `include`/`require` anywhere in shipped code.
- [ ] CDN assets are self-hosted, or pinned to an exact version with `integrity` + `crossorigin` attributes.
- [ ] No enqueued URL resolves to changeable content such as `latest.js`.
- [ ] Shipped code contains no `auto_update_plugin` / `auto_update_theme` / `AUTOMATIC_UPDATER_DISABLED` blockers.
- [ ] PHP and WordPress minimums are enforced with `version_compare()` before the plugin loads.
- [ ] Pasted snippets were rewritten against current APIs before merging.

## Official references

- [`wp_enqueue_script()`](https://developer.wordpress.org/reference/functions/wp_enqueue_script/)
- [`wp_enqueue_style()`](https://developer.wordpress.org/reference/functions/wp_enqueue_style/)
- [`wp_register_script()`](https://developer.wordpress.org/reference/functions/wp_register_script/) (default handle list)
- [`wp_script_add_data()`](https://developer.wordpress.org/reference/functions/wp_script_add_data/)
- [`script_loader_tag` filter](https://developer.wordpress.org/reference/hooks/script_loader_tag/)
- [`style_loader_tag` filter](https://developer.wordpress.org/reference/hooks/style_loader_tag/)
- [`WP_HTML_Tag_Processor` class](https://developer.wordpress.org/reference/classes/wp_html_tag_processor/)
- [`wp_remote_get()`](https://developer.wordpress.org/reference/functions/wp_remote_get/)
- [`wp_is_auto_update_enabled_for_type()`](https://developer.wordpress.org/reference/functions/wp_is_auto_update_enabled_for_type/)
- [`auto_update_{$type}` filter](https://developer.wordpress.org/reference/hooks/auto_update_type/) (`auto_update_plugin`, `auto_update_theme`)
- [`AUTOMATIC_UPDATER_DISABLED` constant](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#disable-wordpress-auto-updates)
- [`WP_AUTO_UPDATE_CORE` constant](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/#disable-wordpress-core-updates)
- [`validate_file()`](https://developer.wordpress.org/reference/functions/validate_file/)
- [Composer `audit` command](https://getcomposer.org/doc/03-cli.md#audit)
- [Composer `composer.lock`](https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control)
- [Composer `minimum-stability`](https://getcomposer.org/doc/04-schema.md#minimum-stability)
- [Roave SecurityAdvisories](https://github.com/Roave/SecurityAdvisories)
- [MDN: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [OWASP Third-Party JavaScript Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
- [`version_compare()`](https://www.php.net/manual/en/function.version-compare.php)
- [`create_function()` (removed)](https://www.php.net/manual/en/function.create-function.php)
- [PCRE pattern modifiers (`/e` removed)](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php)
- [`export-ignore` in `.gitattributes`](https://git-scm.com/docs/gitattributes)
