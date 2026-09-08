<?php
/**
 * Hardened wp-config.php constants (reference excerpt).
 *
 * Add/merge these into your real wp-config.php. Do NOT commit real salts or DB
 * credentials to version control. Generate salts at:
 *   https://api.wordpress.org/secret-key/1.1/salt/
 *
 * @package WordPress
 */

/* -- Security keys & salts: unique per site, rotate if leaked ---------------- */
define( 'AUTH_KEY', 'replace-with-64-random-chars' );
define( 'SECURE_AUTH_KEY', 'replace-with-64-random-chars' );
define( 'LOGGED_IN_KEY', 'replace-with-64-random-chars' );
define( 'NONCE_KEY', 'replace-with-64-random-chars' );
define( 'AUTH_SALT', 'replace-with-64-random-chars' );
define( 'SECURE_AUTH_SALT', 'replace-with-64-random-chars' );
define( 'LOGGED_IN_SALT', 'replace-with-64-random-chars' );
define( 'NONCE_SALT', 'replace-with-64-random-chars' );

/* -- Block in-dashboard code editing ----------------------------------------- */
define( 'DISALLOW_FILE_EDIT', true );   // remove Appearance/Plugins file editor
// For fully locked deployments (no UI install/update of plugins/themes):
// define( 'DISALLOW_FILE_MODS', true );

/* -- Force TLS for the admin and login --------------------------------------- */
define( 'FORCE_SSL_ADMIN', true );

/* -- Debugging: log privately, never display, in production ------------------ */
define( 'WP_DEBUG', false );
define( 'WP_DEBUG_DISPLAY', false );    // never render errors to visitors
@ini_set( 'display_errors', '0' );      // phpcs:ignore WordPress.PHP.IniSet
define( 'WP_DEBUG_LOG', false );        // set true only with debug.log blocked from web

/* -- Limit post revisions & autosave (reduces surface/noise; optional) ------- */
define( 'WP_POST_REVISIONS', 10 );

/* -- Automatic background updates for core security releases ----------------- */
define( 'WP_AUTO_UPDATE_CORE', 'minor' );

/*
-- Disable XML-RPC at the app layer if unused (also block at server) ------- */
// add_filter( 'xmlrpc_enabled', '__return_false' );  // place in a mu-plugin, not here

/*
-- Move wp-config.php out of the web root where the host allows ------------ */
// Keeping it one directory above the docroot, or denying it at the server, is recommended.
