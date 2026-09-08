# Secrets & credentials management checklist

Use this checklist before handling passwords, API keys, or tokens.

- [ ] No secrets are hard-coded in source files.
- [ ] User passwords are hashed with `wp_hash_password()` and verified with `wp_check_password()`.
- [ ] Service/API keys live in `wp-config.php` constants or are encrypted at rest.
- [ ] Machine-to-machine auth uses Application Passwords where possible.
- [ ] Tokens are generated with `wp_generate_password()` (not nonces) and stored as hashes.
- [ ] Secrets are never echoed, logged, exported, or sent to the browser.
- [ ] Settings forms that collect secrets use nonce + capability checks.
