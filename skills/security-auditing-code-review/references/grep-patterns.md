# Audit grep patterns

Ready-to-run searches to locate trust boundaries and risky sinks. Run from the
plugin/theme root. Each hit is a *candidate* — confirm the missing control by reading it.

> These find where to look. Absence of a guard near a hit is usually the bug.

## 1. Entry points (trust boundaries)
```bash
grep -rn "wp_ajax_\|wp_ajax_nopriv_" .          # AJAX actions (nopriv = public!)
grep -rn "register_rest_route"        .          # REST routes — check permission_callback
grep -rn "admin_post_\|admin_post_nopriv_" .     # form/link handlers
grep -rn "add_shortcode\|add_action( *'init'" .  # shortcodes / init handlers
grep -rn "\$_GET\|\$_POST\|\$_REQUEST\|\$_COOKIE\|\$_FILES\|\$_SERVER" .
```

## 2. Missing CSRF / authorization
```bash
# State-changing handlers that never verify a nonce:
grep -rn "wp_ajax_" . | sed 's/:.*//' | sort -u   # then inspect each for check_ajax_referer
grep -rn "check_admin_referer\|check_ajax_referer\|wp_verify_nonce" .   # where present
grep -rn "current_user_can" .                                          # where present
grep -rn "permission_callback'[^,]*__return_true" .                    # open REST writes
```
Cross-reference: an entry point present in (1) but absent from the nonce/capability lists
above is a likely missing-control bug.

## 3. SQL injection sinks
```bash
grep -rn "\$wpdb->\(query\|get_results\|get_var\|get_row\|get_col\)" .
grep -rn "\$wpdb->prepare" .                      # confirm prepare wraps dynamic values
grep -rn "\. *\$_\(GET\|POST\|REQUEST\)" .        # concatenation of input
```

## 4. XSS / output sinks
```bash
grep -rn "echo \|print \|printf(" . | grep -v "esc_\|wp_kses\|esc_url\|wp_json_encode"
grep -rn "the_\|get_the_" . | grep -v "esc_"      # template output review
grep -rn "add_query_arg\|remove_query_arg" .      # must be esc_url() on output
```

## 5. File / path & RCE sinks
```bash
grep -rn "move_uploaded_file\|file_put_contents\|fopen\|fwrite" .
grep -rn "include\|include_once\|require\|require_once\|readfile\|unlink\|fopen" . \
  | grep "\$_"                                     # input-driven file ops = traversal risk
grep -rn "eval(\|create_function(\|assert(\|preg_replace(.*/e" .
grep -rn "unserialize(\|maybe_unserialize(" .       # object injection if fed input
grep -rn "extract(" .                              # variable injection
grep -rn "switch_to_blog" .                        # multisite context switching
grep -rn "wp_remote_get\|wp_remote_post\|wp_remote_request" .  # outbound HTTP / SSRF
```

## 6. Dangerous configuration / secrets
```bash
grep -rn "file_get_contents( *['\"]http\|curl_exec" .   # use wp_remote_* instead
grep -rn "DISABLE_WP_CRON\|WP_DEBUG\|define( *'" .       # config review
grep -rni "api_key\|secret\|password\|token" .          # hard-coded secrets
```

## 7. Advanced sinks to triage
```bash
grep -rn "add_shortcode\|register_block_type" .     # shortcode / block render callbacks
grep -rn "register_rest_field" .                     # custom REST fields
grep -rn "wp_schedule_event\|wp_schedule_single_event" .  # cron jobs
grep -rn "WP_Filesystem\|request_filesystem_credentials" .  # filesystem writes
grep -rn "wp_hash_password\|wp_check_password\|wp_generate_password" .  # credential handling
grep -rn "sodium_crypto_secretbox\|openssl_encrypt" .  # custom encryption
grep -rn "wc_get_order\|WC_Order" .                 # WooCommerce order access

## 8. Auth/session, headers & supply-chain sinks
```bash
grep -rn "wp_signon\|wp_set_auth_cookie\|setcookie(" .   # custom auth flows / cookies
grep -rn "wp_destroy_all_sessions\|wp_destroy_other_sessions" .  # session destruction
grep -rn "wp_authenticate_user\|wp_login_failed" .       # login throttling hooks
grep -rn "X-Frame-Options\|X-Content-Type-Options\|Content-Security-Policy" .
grep -rn "Access-Control-Allow-Origin" .                 # CORS — check for Origin reflection
grep -rn "wp_enqueue_script\|wp_enqueue_style" . | grep "http"  # CDN assets — pin + SRI
grep -rn "phar:" .                                       # phar stream wrapper
```

## Notes
- `wp_ajax_nopriv_*` exposes an action to logged-out users — always justify it.
- `__return_true` as a `permission_callback` on a write is broken access control.
- A `$wpdb->...` call with no nearby `prepare()` and a `$_` value is injection until proven otherwise.
- `echo` of a variable with no `esc_*` is XSS until proven otherwise.
- `unserialize()` / `maybe_unserialize()` on user-supplied data is object injection.
- `switch_to_blog()` without `restore_current_blog()` or validation is multisite data leakage.
- Outbound HTTP with user-controlled URLs is an SSRF sink.
- `setcookie()` for login/session state instead of core auth cookies is an auth-bypass pattern.
- A custom `/login` REST route or `wp_ajax_nopriv_` handler with no throttling invites brute force.
- `Access-Control-Allow-Origin` echoing `$_SERVER['HTTP_ORIGIN']` (with credentials) is a CORS hole.
- CDN-enqueued scripts with no version pin or `integrity` attribute are a supply-chain sink.
