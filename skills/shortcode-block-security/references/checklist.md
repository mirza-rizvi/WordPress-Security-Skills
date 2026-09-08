# Shortcode & dynamic block security checklist

Use this checklist before shipping any shortcode or dynamic block.

- [ ] `shortcode_atts()` provides defaults for every supported attribute.
- [ ] Shortcode attributes are sanitized to type after normalization.
- [ ] Block attributes are sanitized inside `render_callback`.
- [ ] All rendered output is escaped for its context.
- [ ] CSS classes pass through `sanitize_html_class()`.
- [ ] Hex colors pass through `sanitize_hex_color()`.
- [ ] Rich markup is constrained with `wp_kses_post()` or a custom allowlist.
- [ ] The callback returns a string instead of echoing.
- [ ] `do_shortcode()` is not run on untrusted input.
