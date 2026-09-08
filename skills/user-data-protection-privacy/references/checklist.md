# User data protection & privacy checklist

- [ ] All stored PII inventoried (tables, options, meta, logs).
- [ ] Only necessary fields collected (data minimization).
- [ ] Exporter registered on `wp_privacy_personal_data_exporters`.
- [ ] Eraser registered on `wp_privacy_personal_data_erasers`, returns the status array
      (`items_removed`, `items_retained`, `messages`, `done`).
- [ ] Privacy policy content declared via `wp_add_privacy_policy_content()`.
- [ ] IPs anonymized with `wp_privacy_anonymize_ip()` unless full IPs are essential.
- [ ] Retention/cleanup schedule defined for stored PII.
- [ ] PII display/export gated by capability checks.
- [ ] Consent-optional data gated behind explicit consent.
- [ ] No PII leaked in REST/AJAX responses to under-privileged users.
- [ ] No PII or secrets written to logs.
