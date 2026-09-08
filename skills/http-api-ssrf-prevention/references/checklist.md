# HTTP API & SSRF prevention checklist

Use this checklist before any outbound HTTP request handler.

- [ ] Untrusted URLs use `wp_safe_remote_get()` / `wp_safe_remote_post()`.
- [ ] The destination host is in an explicit allowlist.
- [ ] `wp_http_validate_url()` guards the URL before the request.
- [ ] Only `http`/`https` schemes are accepted.
- [ ] `is_wp_error()` is checked before reading the response.
- [ ] The HTTP response code is validated.
- [ ] Response body is sanitized or escaped before output/storage.
- [ ] Errors are logged without exposing secrets or internal network details.
- [ ] The caller verifies nonce + capability before invoking the request helper.
