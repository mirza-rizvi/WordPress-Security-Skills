# WordPress hardening checklist

## wp-config.php
- [ ] All eight security keys/salts set, unique per site, rotated if leaked.
- [ ] `DISALLOW_FILE_EDIT` = true (production).
- [ ] `FORCE_SSL_ADMIN` = true; whole site over HTTPS.
- [ ] `WP_DEBUG` / `WP_DEBUG_DISPLAY` = false in production.
- [ ] `WP_DEBUG_LOG` only with the log blocked from the web.
- [ ] (Locked builds) `DISALLOW_FILE_MODS` = true.
- [ ] `WP_AUTO_UPDATE_CORE` set for minor security updates.

## Server config
- [ ] `wp-config.php`, `.htaccess`, dotfiles, `debug.log` denied to the web.
- [ ] PHP execution denied in `wp-content/uploads`.
- [ ] `xmlrpc.php` denied/limited if unused.
- [ ] `wp-admin` IP-restricted where feasible.
- [ ] Author/user enumeration limited.

## Filesystem
- [ ] Directories `755`, files `644`.
- [ ] `wp-config.php` `640` or `600`.
- [ ] No `777`; web server owns only what it must write.

## Operational
- [ ] Core, plugins, themes updated; unused ones removed.
- [ ] Admin accounts: strong passwords + 2FA.
- [ ] Backups configured and tested.
- [ ] Default `admin` username avoided.
