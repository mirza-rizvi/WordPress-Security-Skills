# WP-CLI security checklist

Use this checklist before shipping any WP-CLI command.

- [ ] Every CLI argument is sanitized to its expected type.
- [ ] Database queries use `$wpdb->prepare()`; no argument interpolation.
- [ ] Destructive commands call `WP_CLI::confirm()` unless `--yes` is provided.
- [ ] The command does not rely on `current_user_can()` without an explicit `--user`.
- [ ] Secrets, tokens, and API keys are never printed or logged in plaintext.
- [ ] `--allow-root` usage is documented and justified.
- [ ] Output uses `WP_CLI::log()` / `success()` / `error()` instead of `echo`.
- [ ] Command docblocks define options and examples.
