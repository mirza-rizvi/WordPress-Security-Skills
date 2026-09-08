# Input sanitization & validation checklist

- [ ] Every read of `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` is guarded with `isset()` + default.
- [ ] `wp_unslash()` applied before sanitizing superglobal data.
- [ ] Sanitizer matches the data type (text/email/int/key/url/html — see cheatsheet).
- [ ] Rich HTML uses `wp_kses` / `wp_kses_post`, not `strip_tags`.
- [ ] Values validated against allowlists / ranges after sanitizing (`in_array(..., true)`).
- [ ] Arrays sanitized element-by-element via `array_map`.
- [ ] URLs stored with `esc_url_raw()`; displayed with `esc_url()`.
- [ ] `register_setting()` calls pass a `sanitize_callback`.
- [ ] REST args define `sanitize_callback` and `validate_callback`.
- [ ] Invalid input fails closed (reject / default), never silently trusted.
