# Output escaping checklist

- [ ] Every echoed/printed dynamic value is escaped at the point of output.
- [ ] Function matches context: `esc_html` (text), `esc_attr` (attribute),
      `esc_url` (URL), `esc_js`/`wp_json_encode` (JS), `esc_textarea` (textarea).
- [ ] Database/option values are escaped on output too (not assumed safe).
- [ ] Intentional HTML uses `wp_kses_post` / `wp_kses` with an allowlist.
- [ ] Translatable strings use `esc_html__`, `esc_attr_e`, etc.
- [ ] `esc_url()` used for display; `esc_url_raw()` only for storage/redirects.
- [ ] No concatenation that mixes escaped and unescaped fragments.
- [ ] Inline `<script>` never interpolates raw PHP values.
- [ ] REST/AJAX HTML responses escape values before embedding in markup.
