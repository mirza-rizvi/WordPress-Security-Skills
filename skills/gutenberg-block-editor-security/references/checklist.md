# Gutenberg block editor security checklist

Use this checklist before shipping any dynamic block or editor REST integration.

- [ ] Block attributes are declared in `block.json` with types and defaults.
- [ ] `render_callback` sanitizes every attribute before use.
- [ ] Server-rendered output is escaped for its context.
- [ ] `register_rest_field()` has schema + sanitize/validate callbacks.
- [ ] `register_rest_field()` `update_callback` checks the appropriate capability.
- [ ] `RichText` and rich markup are constrained with `wp_kses_post()` or a custom allowlist.
- [ ] `ServerSideRender` blocks enforce the same permissions as the front-end render.
- [ ] Editor JS uses `apiFetch` (or sends `X-WP-Nonce`) for same-site REST calls.
- [ ] No secrets are returned to the block editor for low-privilege users.
