---
name: wp-hardening-best-practices
description: >
  Use when configuring or hardening a WordPress site, editing wp-config.php, writing
  .htaccess or nginx rules, setting file permissions, or advising on deployment security.
  Covers security keys, DISALLOW_FILE_EDIT, FORCE_SSL_ADMIN, disabling debug output,
  blocking PHP execution in uploads, protecting sensitive files, and least-privilege file
  permissions. Apply proactively when setting up or reviewing a site's configuration.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, hardening, wp-config, htaccess, permissions, deployment"
---

# WordPress hardening best practices

## When to use this skill

Use this skill for **site/environment configuration**, as opposed to plugin code:

- Editing `wp-config.php` (keys, constants, debug).
- Writing/reviewing `.htaccess` (Apache) or server-block (nginx) rules.
- Setting filesystem permissions and ownership.
- Locking down `wp-admin`, XML-RPC, REST user enumeration, and the uploads dir.
- Pre-launch hardening checklists and deployment review.

This complements the secure-coding skills: even perfect code runs on a host that must be
configured to fail safely.

## Core principles (and why they matter)

1. **Disable in-dashboard file editing in production.** `DISALLOW_FILE_EDIT` removes the
   plugin/theme editor — a single compromised admin session otherwise becomes code
   execution.
2. **Force TLS for admin and logins.** `FORCE_SSL_ADMIN` stops credentials and cookies
   traveling in cleartext.
3. **Never display errors in production.** Stack traces leak paths, queries, and secrets.
   `WP_DEBUG` off, `display_errors` off; log to a non-web-readable file if needed.
4. **Block PHP execution where only data should live.** An attacker who slips a PHP file
   into `wp-content/uploads` gets RCE unless the server refuses to execute it there.
5. **Protect sensitive files.** `wp-config.php`, `.htaccess`, `readme.html`, `debug.log`,
   and dotfiles should not be web-readable.
6. **Least privilege on the filesystem.** Files `644`, directories `755`, `wp-config.php`
   `640`/`600`; web server should not own files it doesn't need to write.
7. **Unique, strong security keys/salts.** They invalidate stolen cookies; regenerate if
   leaked.
8. **Reduce attack surface.** Disable XML-RPC if unused, block user enumeration, keep core/
   plugins/themes updated, remove unused plugins.

## Step-by-step implementation

1. In `wp-config.php`: set unique salts, `DISALLOW_FILE_EDIT`, `FORCE_SSL_ADMIN`, disable
   debug display; optionally `WP_AUTO_UPDATE_CORE`, `DISALLOW_FILE_MODS` for locked builds.
2. Place `wp-config.php` permissions at `640`/`600`; ensure it is above or protected from
   the web root.
3. Add server rules to deny PHP in `uploads`, protect sensitive files, and (optionally)
   restrict `wp-admin`/`xmlrpc.php`.
4. Set file/dir permissions to least privilege.
5. Keep everything updated; remove what you don't use.
6. Add abuse controls for public surfaces: comment moderation on, pingbacks off if
   unused, and — for bot-heavy sites — CAPTCHA/Turnstile on login and registration via
   an established plugin (hand-rolled CAPTCHAs fail in both directions). Pair with the
   login throttle from `authentication-session-security`; XML-RPC stays off unless needed.

## Common AI mistakes / anti-patterns

### Mistake 1 — Leaving debug output on in production

```php
// ❌ Insecure: errors rendered to visitors leak paths, SQL, secrets.
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_DISPLAY', true );
```

```php
// ✅ Secure: log privately, never display, in production.
define( 'WP_DEBUG', false );
// If you must debug on a live box, at least never display:
@ini_set( 'display_errors', '0' );
define( 'WP_DEBUG_DISPLAY', false );
define( 'WP_DEBUG_LOG', true ); // writes to wp-content/debug.log — block it from the web
```

### Mistake 2 — Allowing the dashboard file editor

```php
// ❌ Risky: compromised admin = arbitrary PHP via Appearance/Plugins editor.
// (default: editor enabled)
```

```php
// ✅ Secure: disable file editing (and optionally all file mods).
define( 'DISALLOW_FILE_EDIT', true );
// Fully locked deploy (no plugin/theme install/update via UI):
define( 'DISALLOW_FILE_MODS', true );
```

### Mistake 3 — `777` permissions "to make it work"

```bash
# ❌ Insecure: world-writable lets any local process modify your site.
chmod -R 777 wp-content
```

```bash
# ✅ Secure: least privilege.
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;
chmod 640 wp-config.php
```

### Mistake 4 — Uploads directory that executes PHP

```apache
# ❌ Insecure: a smuggled shell.php in uploads runs.
# (no restriction)
```

```apache
# ✅ Secure: deny PHP execution in uploads (Apache). Place in wp-content/uploads/.htaccess
<FilesMatch "\.(?i:php|php\d|phtml|phar)$">
    Require all denied
</FilesMatch>
```

### Mistake 5 — Default/duplicated security keys

```php
// ❌ Insecure: placeholder salts (or copied between sites).
define( 'AUTH_KEY', 'put your unique phrase here' );
```

```php
// ✅ Secure: generate unique values from the official salt API and rotate if leaked.
// https://api.wordpress.org/secret-key/1.1/salt/
define( 'AUTH_KEY', '...64 random chars...' );
// (all eight: AUTH_KEY/SALT, SECURE_AUTH_KEY/SALT, LOGGED_IN_KEY/SALT, NONCE_KEY/SALT)
```

### Mistake 6 — Leaving XML-RPC enabled when unused

```php
// ❌ Risky: XML-RPC is a brute-force and pingback amplification vector if not needed.
// (default: enabled)
```

```php
// ✅ Secure: disable XML-RPC entirely if the site does not need it.
add_filter( 'xmlrpc_enabled', '__return_false' );
// Or block at the server level (see htaccess-hardening.conf).
```

### Mistake 7 — Allowing REST user enumeration

```bash
# ❌ Risky: /wp-json/wp/v2/users/ reveals usernames to unauthenticated visitors.
curl https://example.com/wp-json/wp/v2/users/
```

```php
// ✅ Safer: require authentication for the users endpoint.
add_filter( 'rest_endpoints', function ( $endpoints ) {
    if ( isset( $endpoints['/wp/v2/users'] ) ) {
        $endpoints['/wp/v2/users'][0]['permission_callback'] = static function () {
            return is_user_logged_in();
        };
    }
    return $endpoints;
} );
```

### Mistake 8 — Application Passwords enabled without review

Application Passwords (WordPress 5.6+) are powerful for integrations but create a
long-lived credential surface. Disable them if unused, or restrict them to users who
actually need machine access.

```php
// ✅ Secure: disable Application Passwords if the site does not use them.
add_filter( 'wp_is_application_passwords_available', '__return_false' );
```

Related: see the `secrets-credentials-management` skill for storing and handling API
keys and tokens safely. See the `security-headers-csp` skill for application-level
security headers (HSTS belongs in this skill's server config; the rest is code-level), and
the `dependency-supply-chain-security` skill for keeping bundled libraries and CDN assets
from rotting.

## Correct code examples

Hardened `wp-config.php` constants are in
[`references/wp-config-hardening.php`](references/wp-config-hardening.php); Apache and
nginx rules (deny PHP in uploads, protect `wp-config.php`/`.htaccess`/`debug.log`, limit
`xmlrpc.php`) are in [`references/htaccess-hardening.conf`](references/htaccess-hardening.conf);
the consolidated pre-launch sweep is [`references/go-live-checklist.md`](references/go-live-checklist.md).

## Checklist

- [ ] Unique, strong security keys/salts set (all eight).
- [ ] `DISALLOW_FILE_EDIT` enabled in production.
- [ ] `FORCE_SSL_ADMIN` enabled; site served over HTTPS.
- [ ] `WP_DEBUG`/`WP_DEBUG_DISPLAY` off in production; logs not web-readable.
- [ ] PHP execution denied in `wp-content/uploads`.
- [ ] `wp-config.php`, `.htaccess`, `debug.log`, dotfiles not web-accessible.
- [ ] Permissions least-privilege: dirs `755`, files `644`, `wp-config.php` `640`/`600`.
- [ ] XML-RPC disabled/limited if unused; user enumeration limited.
- [ ] Core, plugins, themes kept updated; unused extensions removed.
- [ ] Admin accounts use strong passwords + 2FA where possible.

## Official references

- [Hardening WordPress — Documentation](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [Editing wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/)
- [Security keys & salts API](https://api.wordpress.org/secret-key/1.1/salt/)
- [Changing File Permissions](https://developer.wordpress.org/advanced-administration/server/file-permissions/)
- [`DISALLOW_FILE_EDIT` / `DISALLOW_FILE_MODS`](https://developer.wordpress.org/apis/wp-config-php/#disable-the-plugin-and-theme-file-editor)
- [`FORCE_SSL_ADMIN`](https://developer.wordpress.org/advanced-administration/security/https/)
- [Debugging in WordPress (`WP_DEBUG`)](https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/)
- [OWASP — Secure Configuration](https://owasp.org/www-project-top-ten/)
