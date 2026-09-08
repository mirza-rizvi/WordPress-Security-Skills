---
name: user-data-protection-privacy
description: >
  Use when a WordPress plugin or theme stores, processes, or exposes personal data —
  emails, names, IP addresses, user content, or analytics. Registers data exporters and
  erasers via wp_privacy_personal_data_exporters / _erasers, declares privacy policy
  content, anonymizes IPs, and minimizes/secures PII. Helps meet GDPR/CCPA obligations.
  Apply proactively whenever code touches personally identifiable information.
license: MIT
metadata:
  tags: [wordpress, security, privacy, gdpr, pii, personal-data]
---

# User data protection & privacy

## When to use this skill

Use this skill whenever code handles **personal data**:

- Storing emails, names, addresses, phone numbers, IPs, or user-generated content.
- Logging requests/analytics that capture IPs or identifiers.
- Building forms, CRMs, comment features, membership/e-commerce data.
- Integrating third-party services that receive user data.

WordPress ships privacy tooling (export/erase requests, policy content) since 4.9.6.
Plugins that store PII are expected to integrate with it. This is both a legal obligation
(GDPR/CCPA) and a security concern — the safest data is the data you don't keep.

## Core principles (and why they matter)

1. **Data minimization.** Collect and retain only what the feature needs. Less stored PII
   means less to leak, export, or erase.
2. **Integrate with WordPress privacy tools.** Register an **exporter** and an **eraser** so
   the admin's Export/Erase Personal Data screens include your plugin's data — users have a
   right to access and deletion.
3. **Declare what you collect.** Use `wp_add_privacy_policy_content()` so the suggested
   privacy policy reflects your plugin's data practices.
4. **Anonymize where identity isn't needed.** Store anonymized IPs
   (`wp_privacy_anonymize_ip()`) and use `wp_privacy_anonymize_data()` for other types.
5. **Secure PII at rest and in transit.** Restrict who can read it (capabilities), don't
   expose it in REST/AJAX to under-privileged users, and never log secrets.
6. **Honor consent and retention.** Gate optional collection behind consent; delete data on
   schedule and on erasure requests.

## Step-by-step implementation

1. Map what PII you store and where (tables, options, meta).
2. Register an exporter on `wp_privacy_personal_data_exporters` returning the user's data in
   the expected paginated structure.
3. Register an eraser on `wp_privacy_personal_data_erasers` that deletes/anonymizes that data
   and reports what it did.
4. Add policy text via `admin_init` → `wp_add_privacy_policy_content()`.
5. Anonymize IPs at capture; minimize fields; set retention.
6. Gate any display/export of PII behind capability checks.

## Common AI mistakes / anti-patterns

### Mistake 1 — Storing PII with no export/erase integration

```php
// ❌ Non-compliant: data is invisible to WordPress' privacy tools.
add_option( 'my_newsletter_subscribers', array() ); // emails with no exporter/eraser
```

```php
// ✅ Compliant: register exporter + eraser so requests cover this data.
add_filter( 'wp_privacy_personal_data_exporters', 'my_plugin_register_exporter' );
add_filter( 'wp_privacy_personal_data_erasers',  'my_plugin_register_eraser' );
```

### Mistake 2 — Storing full IP addresses unnecessarily

```php
// ❌ Excessive: full IP retained for basic analytics/anti-spam.
$ip = $_SERVER['REMOTE_ADDR'];
$wpdb->insert( $table, array( 'ip' => $ip ) );
```

```php
// ✅ Minimized: anonymize the IP before storing.
$raw = isset( $_SERVER['REMOTE_ADDR'] )
    ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
    : '';
$ip  = wp_privacy_anonymize_ip( $raw );
$wpdb->insert(
    $wpdb->prefix . 'my_log',
    array( 'ip' => $ip ),
    array( '%s' )
);
```

### Mistake 3 — Exposing PII to under-privileged users

```php
// ❌ Insecure: any subscriber can read everyone's emails via the endpoint.
'permission_callback' => '__return_true',
'callback'            => fn() => get_option( 'my_newsletter_subscribers' ),
```

```php
// ✅ Secure: gate PII behind a capability.
'permission_callback' => static fn() => current_user_can( 'list_users' ),
```

### Mistake 4 — Eraser that doesn't report or doesn't actually erase

```php
// ❌ Broken: returns nothing; admin tool can't confirm erasure.
function my_eraser( $email, $page ) {
    delete_metadata( /* ... */ );
}
```

```php
// ✅ Correct: delete/anonymize AND return the documented status array.
function my_eraser( $email, $page = 1 ) {
    $removed = my_plugin_delete_subscriber( $email );
    return array(
        'items_removed'  => $removed,
        'items_retained' => false,
        'messages'       => array(),
        'done'           => true,
    );
}
```

### Mistake 5 — Collecting consent-optional data without consent

```php
// ❌ Risky: marketing opt-in assumed.
$wpdb->insert( $table, array( 'email' => $email, 'marketing' => 1 ) );
```

```php
// ✅ Respect explicit consent.
$consent = ! empty( $_POST['marketing_consent'] ) ? 1 : 0; // verified by nonce upstream
$wpdb->insert(
    $wpdb->prefix . 'my_subs',
    array( 'email' => sanitize_email( wp_unslash( $_POST['email'] ?? '' ) ), 'marketing' => $consent ),
    array( '%s', '%d' )
);
```

## Correct code examples

A complete exporter + eraser registration and a privacy-policy-content example are in
[`references/privacy-data-handlers.php`](references/privacy-data-handlers.php).

Related: see the `woocommerce-security` skill for order and customer PII handling, and
the `cron-background-job-security` and `http-api-ssrf-prevention` skills — IP
anonymization and retention limits apply to logs written by cron jobs and outbound HTTP
helpers too.

## Checklist

- [ ] All stored PII is inventoried (tables, options, meta).
- [ ] An exporter is registered on `wp_privacy_personal_data_exporters`.
- [ ] An eraser is registered on `wp_privacy_personal_data_erasers` and returns the status array.
- [ ] Privacy policy content declared via `wp_add_privacy_policy_content()`.
- [ ] IPs anonymized with `wp_privacy_anonymize_ip()` unless full IPs are required.
- [ ] Only necessary fields collected; retention/cleanup defined.
- [ ] PII display/export gated behind capability checks.
- [ ] Consent-optional data gated behind explicit consent.
- [ ] PII not leaked in REST/AJAX responses to under-privileged users.
- [ ] No PII or secrets written to logs.

## Official references

- [Personal Data Exporters — Plugin Handbook](https://developer.wordpress.org/plugins/privacy/adding-the-personal-data-exporter-to-your-plugin/)
- [Personal Data Erasers — Plugin Handbook](https://developer.wordpress.org/plugins/privacy/adding-the-personal-data-eraser-to-your-plugin/)
- [Suggesting Privacy Policy Content](https://developer.wordpress.org/plugins/privacy/suggesting-text-for-the-site-privacy-policy/)
- [`wp_add_privacy_policy_content()`](https://developer.wordpress.org/reference/functions/wp_add_privacy_policy_content/)
- [`wp_privacy_anonymize_ip()`](https://developer.wordpress.org/reference/functions/wp_privacy_anonymize_ip/)
- [`wp_privacy_anonymize_data()`](https://developer.wordpress.org/reference/functions/wp_privacy_anonymize_data/)
- [`wp_privacy_personal_data_exporters` filter](https://developer.wordpress.org/reference/hooks/wp_privacy_personal_data_exporters/)
- [`wp_privacy_personal_data_erasers` filter](https://developer.wordpress.org/reference/hooks/wp_privacy_personal_data_erasers/)
