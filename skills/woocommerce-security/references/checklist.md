# WooCommerce security checklist

Use this checklist before any WooCommerce extension code.

- [ ] Order/customer actions use WooCommerce capabilities (`edit_shop_orders`, `manage_woocommerce`).
- [ ] Order ids are cast to integers and validated with `wc_get_order()`.
- [ ] Input is sanitized with `wc_clean()` / `sanitize_text_field()` / `absint()`.
- [ ] CRUD objects (`WC_Order`, `WC_Product`, `WC_Customer`) are used instead of raw meta.
- [ ] No full card numbers, CVV, or magnetic-stripe data are stored.
- [ ] Customer PII is escaped on output.
- [ ] Custom WooCommerce REST/Store API routes have real `permission_callback` handlers.
- [ ] GDPR export/erase hooks are wired for custom customer data.
- [ ] Logs and exports anonymize or redact PII.
