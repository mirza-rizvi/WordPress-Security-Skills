---
name: secrets-credentials-management
description: >
  Use when handling passwords, API keys, tokens, or third-party credentials in a
  WordPress plugin or theme. Hashes passwords with wp_hash_password /
  wp_check_password, generates tokens with wp_generate_password, keeps secrets
  out of code and the database in plaintext, and uses Application Passwords for
  API auth. Prevents credential leakage and insecure storage.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, secrets, credentials, tokens, passwords"
---

# Secrets & credentials management

## When to use this skill

Use this skill whenever code handles sensitive credentials:

- Storing an API key, webhook secret, or service token from a settings form.
- Building a custom login or token-verification flow.
- Generating reset tokens, API keys, or one-time nonces that must stay secret.
- Logging or exporting data that might accidentally include secrets.
- Deciding whether to use the user's account password or an application-specific
  password for API/integration access.

Secrets in source code, reversible password storage, and plaintext API keys in
options are common sources of credential leaks.

Related: see the `nonces-csrf-protection` skill for CSRF tokens and the
`settings-options-security` skill for sanitizing option values.

## Core principles (and why they matter)

1. **Never hardcode secrets.** API keys and passwords committed to source control leak to
   anyone with repo access and often end up in public repositories.
2. **Never store user passwords reversibly.** WordPress stores passwords as salted hashes
   via `wp_hash_password()`; use `wp_check_password()` to verify. Do not roll your own hash.
3. **Prefer wp-config constants or encrypted option storage for service keys.** Put keys in
   `wp-config.php` constants or encrypt them at rest with libsodium so the database alone
   is not enough to recover them.
4. **Use Application Passwords for API auth.** WordPress 5.6+ provides `WP_Application_Passwords`
   for machine-to-machine auth without exposing the user's account password.
5. **Never echo or log secrets.** Tokens and keys should never appear in HTML, logs, error
   messages, shell history, or exported backups.
6. **Generate tokens with `wp_generate_password()` or `wp_create_nonce()`.** They are designed
   for cryptographic strength (nonces are short-lived; passwords/tokens can be longer).

## Step-by-step implementation

1. For user passwords: hash with `wp_hash_password()` on save, verify with `wp_check_password()`.
2. For service/API keys:
   - Accept via a secure settings form (nonce + capability + sanitize).
   - Store in a `wp-config.php` constant if possible, or encrypt with `sodium_crypto_secretbox()`
     using a key derived from `wp_salt()` (or a dedicated constant) before `update_option()`.
3. For machine auth: use `WP_Application_Passwords::create_new_application_password()`.
4. For tokens: generate with `wp_generate_password( $length, false )`; store only a hash if you
   need to verify it later.
5. Sanitize any log/export output to redact known secret keys.
6. **If a secret leaks, respond in this order:**
   1. **Rotate first.** Assume compromise the moment the secret left your control — once
      pushed to a remote, treat it as captured (clones, forks, and scrapers may already
      hold it). Issue a new key at the provider, then update the `wp-config` constant or
      re-save the encrypted option, and revoke the old key; issuing a replacement alone
      may leave the leaked key usable. For active abuse, revoke immediately.
   2. **Revoke what rotation cannot cover.** Delete leaked Application Passwords
      (Users → Profile → Application Passwords) and destroy sessions for affected users
      with `WP_Session_Tokens::get_instance( $affected_user_id )->destroy_all()` for
      each trusted, verified affected user ID. `wp_destroy_all_sessions()` targets
      only the current user, not an arbitrary affected user. Session revocation does
      not revoke Application Passwords. If `wp-config.php` leaked, rotate all eight
      keys/salts and exposed database/service credentials. If an encryption key
      changes, re-encrypt retained secrets before discarding it; salt-derived keys
      also change when salts rotate. See `wp-hardening-best-practices`.
   3. **Consider history cleanup after revocation, never instead.** If needed, plan a
      `git filter-repo` rewrite with repository owners and collaborators. Do not
      automatically rewrite history or force-push: publishing rewritten history is
      destructive and requires explicit approval and coordinated protection of
      others' work. Old clones still contain the secret and can reintroduce it;
      arrange re-cloning or careful cleanup. Forks and cached views need separate
      coordination; consult GitHub Support's removal criteria where applicable.
   4. **Add push protection** to block supported secrets when pushing to GitHub, not
      when making local commits. Use local secret scanning/pre-commit checks for
      earlier feedback; neither catches every secret or replaces safe handling.

## Common AI mistakes / anti-patterns

### Mistake 1 — API key as a string literal

```php
// ❌ Insecure: key is in source control and readable by anyone with file access.
$api_key = 'sk-live-abc123';
```

```php
// ✅ Secure: read from a wp-config constant or an encrypted option.
if ( ! defined( 'MY_PLUGIN_API_KEY' ) ) {
    wp_die( esc_html__( 'API key is not configured.', 'my-plugin' ) );
}
$api_key = MY_PLUGIN_API_KEY;
```

### Mistake 2 — Storing user passwords in plaintext or with a weak hash

```php
// ❌ Insecure: reversible or weak storage.
update_option( 'my_plugin_user_password', $_POST['password'] );
update_option( 'my_plugin_user_password', md5( $_POST['password'] ) );
```

```php
// ✅ Secure: use WordPress password hashing.
$hash = wp_hash_password( $_POST['password'] );
update_option( 'my_plugin_user_password_hash', $hash );

// Verify later:
if ( wp_check_password( $submitted, $stored_hash ) ) { /* ... */ }
```

### Mistake 3 — Logging tokens or API keys

```php
// ❌ Insecure: secret lands in error_log / shell history.
error_log( 'Request failed with token: ' . $api_key );
```

```php
// ✅ Secure: log an identifier or redacted value.
error_log( 'Request failed for token ending in: ' . substr( $api_key, -4 ) );
```

### Mistake 4 — Reusing nonces as long-lived secrets

```php
// ❌ Insecure: nonces expire and are not designed for persistent auth.
$token = wp_create_nonce( 'my_api' );
update_user_meta( $user_id, 'my_api_token', $token );
```

```php
// ✅ Secure: generate a dedicated token and hash it for storage.
$token      = wp_generate_password( 32, false );
$token_hash = wp_hash_password( $token );
update_user_meta( $user_id, 'my_api_token_hash', $token_hash );
// Hand the plaintext token to the user once, then verify with wp_check_password().
```

### Mistake 5 — Storing service keys in plaintext options

```php
// ❌ Insecure: database dump exposes the key.
update_option( 'my_plugin_stripe_key', $_POST['stripe_key'] );
```

```php
// ✅ Secure: encrypt at rest with libsodium (PHP 7.2+).
function my_plugin_encrypt_secret( $plaintext ) {
    $key    = sodium_base642bin( MY_PLUGIN_ENCRYPTION_KEY, SODIUM_BASE64_VARIANT_ORIGINAL );
    $nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
    $cipher = sodium_crypto_secretbox( $plaintext, $nonce, $key );
    return base64_encode( $nonce . $cipher );
}

function my_plugin_decrypt_secret( $encoded ) {
    $raw   = base64_decode( $encoded );
    $nonce = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
    $cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
    $key    = sodium_base642bin( MY_PLUGIN_ENCRYPTION_KEY, SODIUM_BASE64_VARIANT_ORIGINAL );
    return sodium_crypto_secretbox_open( $cipher, $nonce, $key );
}
```

## Correct code examples

A complete settings-page snippet that stores an API key either as a wp-config constant or
encrypted in options is in [`references/secure-secret-storage.php`](references/secure-secret-storage.php).

## Checklist

- [ ] No secrets, API keys, or passwords are hard-coded in source files.
- [ ] User passwords are hashed with `wp_hash_password()` and verified with `wp_check_password()`.
- [ ] Service/API keys are stored in `wp-config.php` constants or encrypted at rest.
- [ ] Machine-to-machine auth uses Application Passwords where possible.
- [ ] Tokens are generated with `wp_generate_password()` (or `wp_create_nonce()` for short-lived CSRF).
- [ ] Stored tokens are verified against a hash, not compared in plaintext.
- [ ] Secrets are never echoed, logged, exported, or sent to the browser.
- [ ] Leaked credentials are revoked/rotated; affected users' sessions are revoked when warranted.
- [ ] Any history rewrite/publication has explicit approval and coordinated clone/fork cleanup.
- [ ] Settings forms that collect secrets use nonce + capability + HTTPS.

## Official references

- [`wp_destroy_all_sessions()` — current user only](https://developer.wordpress.org/reference/functions/wp_destroy_all_sessions/)
- [`WP_Session_Tokens::get_instance()`](https://developer.wordpress.org/reference/classes/wp_session_tokens/get_instance/)
- [GitHub — removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [GitHub — push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)

- [`wp_hash_password()`](https://developer.wordpress.org/reference/functions/wp_hash_password/)
- [`wp_check_password()`](https://developer.wordpress.org/reference/functions/wp_check_password/)
- [`wp_generate_password()`](https://developer.wordpress.org/reference/functions/wp_generate_password/)
- [`wp_salt()`](https://developer.wordpress.org/reference/functions/wp_salt/)
- [`WP_Application_Passwords`](https://developer.wordpress.org/reference/classes/wp_application_passwords/)
- [`wp_authenticate_application_password()`](https://developer.wordpress.org/reference/functions/wp_authenticate_application_password/)
- [`sodium_crypto_secretbox()`](https://www.php.net/manual/en/function.sodium-crypto-secretbox.php)
- [Application Passwords — WordPress.org](https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/)
- [OWASP — Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
