# Choose the security review path

Use this tree before implementing a feature. Follow **one entry path**, then apply
**every relevant data/risk branch**. A feature can require several skills; stopping
at its transport (for example, REST) misses its database, output, and privacy risks.
Read the selected skill and its linked references, not just its name.

## 1. Are you evaluating existing code or building a feature?

- **Evaluating, triaging, or preparing a release:** start with
  [security-auditing-code-review](../../security-auditing-code-review/SKILL.md).
  Inventory entry points, trace attacker-controlled data to sinks, establish
  reachability and impact, then use the branches below to choose remediation.
  Text-search hits alone are not findings.
- **Building or changing behavior:** use the baseline in
  [secure-plugin-development](../SKILL.md), then identify who invokes it below.
- **Only changing deployment configuration:** go to
  [wp-hardening-best-practices](../../wp-hardening-best-practices/SKILL.md).
  If the change also affects HTTP response policy, follow the headers branch in §4.
  Do not treat server hardening as a substitute for fixing vulnerable application code.

## 2. Who invokes the behavior?

### A browser or API client

1. **Does the feature authenticate users, issue credentials, or manage sessions?**
   Start with [authentication-session-security](../../authentication-session-security/SKILL.md),
   then continue to the appropriate transport below. Login is not an ordinary
   privileged endpoint: it needs a deliberately public authentication flow, not
   an administrator capability requirement that would prevent login.
2. **Which transport reaches the handler?**
   - `admin-ajax.php` action → [ajax-security](../../ajax-security/SKILL.md).
     Is it privileged? Do not expose it through `wp_ajax_nopriv_*`. If genuinely
     public, define abuse controls and exactly what anonymous callers may do.
   - REST route or REST field → [rest-api-security](../../rest-api-security/SKILL.md).
     Is it public read-only data or protected data/a mutation? Set the permission
     policy accordingly; do not copy `__return_true` onto protected operations.
     Distinguish cookie authentication with REST nonce from non-cookie API authentication.
   - Options/settings page → [settings-options-security](../../settings-options-security/SKILL.md).
     Is it a standard Settings API submission or a custom handler? Follow the
     correct nonce and capability flow for that path.
   - Other form, action link, or request hook →
     [nonces-csrf-protection](../../nonces-csrf-protection/SKILL.md) for cookie-authenticated
     mutations, plus [capability-permission-checks](../../capability-permission-checks/SKILL.md)
     for privileged operations and protected reads. A nonce never grants permission.
3. **Which resource is affected?** For an existing post, user, order, or other object,
   check authority over that specific object, not only a broad role or menu permission.
   Use [capability-permission-checks](../../capability-permission-checks/SKILL.md).

### A renderer, not a request handler

- **Shortcode or server-rendered block output?** Use
  [shortcode-block-security](../../shortcode-block-security/SKILL.md). Public rendering
  does not automatically require a nonce, but private data still needs access control.
- **Block editor attributes, editor REST fields, or editor/server interaction?** Use
  [gutenberg-block-editor-security](../../gutenberg-block-editor-security/SKILL.md).
  If it also renders frontend HTML, apply the shortcode/block branch too.
- In either case, render without side effects; move mutations to an authorized
  request handler. Apply the output branch in §3 even to values saved earlier.

### A scheduler or command-line operator

- **WP-Cron/background worker?** Use
  [cron-background-job-security](../../cron-background-job-security/SKILL.md).
  Is an HTTP request scheduling privileged work? Authorize that request at enqueue
  time, validate stored job context, and enforce the worker's resource policy at
  execution. Do not rely on a browser nonce or logged-in user inside cron.
- **WP-CLI command?** Use [wp-cli-security](../../wp-cli-security/SKILL.md).
  Define the operator trust model and destructive-operation confirmation. Do not
  assume a WordPress administrator session exists or bolt on a browser nonce.

## 3. Where does the data go?

Apply all matching branches to the selected entry path:

- **Input crosses a trust boundary?** Use
  [input-sanitization-validation](../../input-sanitization-validation/SKILL.md).
  Check shape/type and allowed values. Unslash WordPress-slashed request data;
  do not blindly unslash REST JSON or other already-unslashed input.
- **Custom SQL?** Use [sql-injection-prevention](../../sql-injection-prevention/SKILL.md).
  Separate query structure from values; choose any identifier APIs only after
  checking the target WordPress version. Authorization is still required.
- **HTML, attributes, URLs, JavaScript, or redirects?** Use
  [output-escaping](../../output-escaping/SKILL.md). Decide the output context first,
  then escape at the sink; input sanitization does not settle this decision.
- **Incoming file upload?** Use [file-upload-security](../../file-upload-security/SKILL.md).
  If paths are also constructed, files extracted/read/deleted, or code included,
  add [filesystem-security](../../filesystem-security/SKILL.md). MIME validation
  alone does not prove path containment or prevent execution by the web server.
- **Other filesystem access?** Use [filesystem-security](../../filesystem-security/SKILL.md),
  even if the path came from a previously stored option rather than this request.
- **Outbound URL or remote download?** Use
  [http-api-ssrf-prevention](../../http-api-ssrf-prevention/SKILL.md).
  Is the destination user-controlled? Constrain destinations and redirects;
  escaping a URL for HTML is not SSRF protection.
- **Serialized or encoded data?** If PHP objects might be reconstructed, use
  [object-injection-deserialization](../../object-injection-deserialization/SKILL.md).
  Prefer an explicit JSON schema for external data; encoding is not validation.

## 4. Does the feature cross an additional policy boundary?

- **Personal data stored, displayed, exported, or erased?** Apply
  [user-data-protection-privacy](../../user-data-protection-privacy/SKILL.md).
  Decide collection, access, retention, export, and erasure policy before storage.
- **Keys, passwords, access tokens, or webhooks with shared secrets?** Apply
  [secrets-credentials-management](../../secrets-credentials-management/SKILL.md).
  Distinguish password hashing from credentials that must be retrieved to call a service.
- **Network/site switching or network-level settings?** Apply
  [multisite-security](../../multisite-security/SKILL.md). Decide which site/network
  owns the resource before authorizing or switching context.
- **WooCommerce orders, payments, or customer records?** Apply
  [woocommerce-security](../../woocommerce-security/SKILL.md), plus privacy for
  personal data. Use order-aware authorization, not just possession of an order ID.
- **HTTP headers, framing, CORS, cookies, or CSP?** Apply
  [security-headers-csp](../../security-headers-csp/SKILL.md). Decide the origin and
  embedding policy; a CSP nonce is not a WordPress CSRF nonce.
- **Bundled dependencies, CDN assets, or update/download mechanisms?** Apply
  [dependency-supply-chain-security](../../dependency-supply-chain-security/SKILL.md).
  If fetched content becomes executable, treat its integrity and update trust
  chain separately from the SSRF risk of fetching it.

## Worked route

**An administrator imports customer CSV data from a URL through a REST endpoint:**
choose baseline → REST → per-resource/capability authorization → input validation
→ SSRF → privacy. Add upload/filesystem if the import writes temporary files,
SQL injection prevention if it uses custom queries, and output escaping if an
admin screen displays imported values. Add cron if import processing is queued;
that worker must validate stored context rather than reuse the request nonce.

Before finishing, walk the chosen paths again using each skill's checklist and
exercise unauthorized, malformed, and allowed cases in a disposable environment.
