# HTTP headers cheat sheet

Lookup table: header, recommended value, the attack class it stops, and the
caveat that usually bites. WordPress wiring: front-end via the `wp_headers`
filter, wp-login.php via `login_init`, wp-admin via `admin_init`.

| Header | Recommended value | Stops | Caveat |
| --- | --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing: browser reinterpreting a response as executable script or style | Only effective when content types are correct upstream; do not serve user uploads as `text/html` |
| `X-Frame-Options` | `SAMEORIGIN` | Clickjacking by third-party framing | `DENY` breaks the Customizer preview and oEmbed previews (same-origin iframes). `SAMEORIGIN` still blocks foreign sites |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'nonce-...'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'` | Inline script injection, remote script loads, plug-in content (Flash/PDF), framing | Never ship `unsafe-inline` or `*` in `script-src`; run as Report-Only first; a full-page cache freezes the nonce into cached HTML |
| `Content-Security-Policy-Report-Only` | Same policy value | Nothing yet: observes violations without blocking | Temporary by design; enforcement means renaming the header. Budget time to triage the console/report stream |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Leaking full URLs (with tokens, query strings, user ids) to third-party sites via the Referer header | `no-referrer` breaks some analytics and deep-linked logins; `strict-origin-when-cross-origin` is the balanced default |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` (trim to what you actually deny) | Abused browser features in embedded or injected frames | Denying a feature the theme or a plugin uses breaks it; audit before denying |
| `Strict-Transport-Security` | `max-age=31536000` on HTTPS-only sites | SSL-stripping and downgrade attacks | Domain commitment cached by browsers: a broken certificate makes the site unreachable until expiry. Better placed in nginx/.htaccess; see `wp-hardening-best-practices` |
| `Set-Cookie` (flags) | `Secure; HttpOnly; SameSite=Lax` (PHP 7.3+ options array) | Session theft over plaintext (Secure), JS reads (HttpOnly), CSRF (SameSite) | `SameSite=None` requires `Secure` or the browser rejects the cookie. Core auth cookies already send `HttpOnly`; tune `Secure` via `secure_auth_cookie` / `secure_logged_in_cookie` |
| `Access-Control-Allow-Origin` | The allowed origin, from core's allowlist only | Nothing on its own; wrong values create cross-origin data exposure | Core's `rest_send_cors_headers()` already reflects the request `Origin` with `Access-Control-Allow-Credentials: true`; restrict via the `http_origin` filter. `*` plus credentials is always wrong |
| `Access-Control-Allow-Credentials` | `true` only for origins you have allowlisted (core sends `true` on REST) | Turns reflected CORS into full credentialed cross-origin reads | With credentials, every allowed origin can read logged-in responses; keep the allowlist minimal |
| `Cache-Control` / `Pragma` (via `nocache_headers()`) | `no-cache, no-store, must-revalidate` on per-user pages | One user's authenticated page served to another from a cache | Applies to custom member pages; core sends these on authenticated views already |

## CSP Report-Only to enforced migration

1. Ship the exact policy under `Content-Security-Policy-Report-Only` on all
   three surfaces (front-end, wp-login.php via `login_init`, wp-admin via
   `admin_init`).
2. Generate the nonce once per response (`random_bytes()` + `bin2hex()`), attach
   it to your enqueued scripts via `script_loader_tag` and to all inline scripts
   via `wp_inline_script_attributes`.
3. Collect violations: browser devtools console for manual passes, or a
   reporting endpoint you control for real traffic. Include logged-in views,
   search pages, and any third-party embeds.
4. For each violation, fix the cause (move inline JS into an enqueued file) or
   make a conscious allowlist entry (hash or host). Never reach for
   `unsafe-inline` to silence noise.
5. When the log is quiet for a full traffic cycle, rename the header to
   `Content-Security-Policy`. Keep Report-Only running alongside during the
   rollout if your cache layer allows two CSP headers.
6. Re-verify after any new plugin or theme update: enforcement is only as good
   as the last audit.

Escaping output (see the `output-escaping` skill) remains the primary XSS
defense. CSP contains what slips through; it does not excuse skipping `esc_html`
and friends.
