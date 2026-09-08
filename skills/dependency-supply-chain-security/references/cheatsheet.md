# Dependency & supply-chain cheatsheet

Situation -> correct practice. Wrong->right pairs live in the SKILL.md; this is the lookup table.

| Situation | Correct practice |
| --- | --- |
| Asset that core registers (`jquery`, `underscore`, editor builds) | `wp_enqueue_script()` the core handle; never bundle your own copy. |
| Must ship a PHP library core does not bundle | Vet (release < ~12 months old, advisory scan, license), pin a bounded constraint, commit `composer.lock`, build with `composer install --no-dev`. |
| Chart/analytics library from a CDN | Self-host. Otherwise exact version URL + `integrity`/`crossorigin` via the `script_loader_tag` / `style_loader_tag` filters. |
| Styling from a CDN (`style_loader_tag`) | Same rule: exact version + SRI; mirror the script allowlist pattern. |
| Core asset (jQuery, admin bar scripts) | Core handle. Bundled duplicates drift and conflict. |
| Runtime updater / "auto-update my plugin" feature | WordPress.org update channel, or a signed self-hosted channel. Never fetch-and-`eval`/`include` code. |
| Pasted snippet from Stack Overflow or an AI answer | Rewrite against current APIs; reject `mysql_*`, `create_function()`, preg `/e`; audit before merge. |
| Composer project build | `composer install --no-dev --optimize-autoloader` from a committed lock file; `composer update` only as a reviewed change. |
| Distributable zip | `.gitattributes` `export-ignore` for `tests/`, `.github/`, demo data; `composer audit` clean. |
| Old PHP / old WordPress hosts | `version_compare()` gate before load; refuse to run below declared minimums. |
| Site-wide auto-update behavior | Leave it alone. No `auto_update_plugin` / `auto_update_theme` / `AUTOMATIC_UPDATER_DISABLED` blockers in shipped code. |

## Fast greps before a release

- `eval(`, `assert(`, `create_function(`, `/e` preg modifier
- `include`/`require` fed by `wp_remote_get()` or a temp file from the network
- `phar://`
- `latest.js` or any enqueued URL without a version in its path
- `auto_update_plugin`, `auto_update_theme`, `AUTOMATIC_UPDATER_DISABLED`, `WP_AUTO_UPDATE_CORE` in plugin code
