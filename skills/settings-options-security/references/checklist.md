# Settings & options security checklist

Use this checklist before shipping any options/settings page.

- [ ] Every `register_setting()` call has a `sanitize_callback`.
- [ ] The option has a safe, typed `default` value.
- [ ] The form posts to `options.php` and calls `settings_fields()`.
- [ ] The admin page requires `manage_options` or a stricter capability.
- [ ] Field callbacks escape option values with `esc_attr()` / `esc_textarea()`.
- [ ] Array/object options are recursively sanitized against a known schema.
- [ ] `get_option()` output is escaped at the point of use.
- [ ] REST-exposed settings include a schema in `show_in_rest`.
- [ ] Secrets are not stored in plaintext options or returned to the browser.
