---
name: output-escaping
description: >
  Use when echoing or printing any dynamic value in WordPress PHP or templates —
  into HTML, attributes, URLs, inline JavaScript, or textareas. Escapes at the point
  of output with esc_html, esc_attr, esc_url, esc_js, esc_textarea, or wp_kses_post,
  including the i18n variants (esc_html__, esc_attr_e). Prevents stored and reflected
  XSS. Apply proactively to every echoed variable, even data from the database.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, escaping, xss, output"
---

# Output escaping (XSS prevention)

## When to use this skill

Use this skill whenever a **dynamic value is sent to the browser**:

- `echo` / `print` of any variable into HTML.
- Values placed into HTML attributes (`value`, `href`, `src`, `class`, `data-*`).
- URLs in `href` / `src` / redirects.
- Data injected into inline `<script>` or JS via `wp_localize_script`.
- Content rendered in templates, shortcodes, blocks, widgets, REST responses that
  return HTML.

Escape **as late as possible**, at the point of output, choosing the function that
matches the **context** the value lands in. This is separate from input sanitization —
do both.

## Core principles (and why they matter)

1. **Escape on output, every time.** XSS happens when untrusted data is interpreted as
   markup or script. Escaping at output neutralizes it regardless of how it got stored.
2. **Escape even "trusted" data.** Database values, option values, and your own earlier
   output can still contain markup. Escape at render anyway — it's cheap and consistent.
3. **Context determines the function.** HTML body → `esc_html`; attribute → `esc_attr`;
   URL → `esc_url`; inline JS → `esc_js` (or `wp_json_encode`); rich HTML → `wp_kses_post`.
   Using the wrong one (e.g. `esc_html` inside an attribute) can still be exploitable.
4. **Escape the whole value, late.** Don't concatenate escaped + unescaped fragments;
   escape the final value as it is echoed.
5. **Translations are output too.** Use `esc_html__()`, `esc_attr_e()`, etc. — never echo
   a raw `__()` result into a sensitive context.
6. **`wp_kses_post()` is for intentional HTML.** When a value must contain markup, allow a
   safe subset rather than escaping it all away.

## Step-by-step implementation

1. Identify the **context** at the echo site (HTML text, attribute, URL, JS, textarea).
2. Pick the matching escaping function.
3. Wrap the value at the moment of output.
4. For translatable strings, use the `esc_*__` / `esc_*_e` variant.
5. For values that legitimately contain HTML, use `wp_kses_post()` / `wp_kses()`.

## Common AI mistakes / anti-patterns

### Mistake 1 — Echoing a value with no escaping

```php
// ❌ Insecure: stored XSS if $name ever contains markup.
echo '<h2>' . $name . '</h2>';
```

```php
// ✅ Secure: escape for HTML context.
echo '<h2>' . esc_html( $name ) . '</h2>';
```

### Mistake 2 — Wrong context (HTML escaper inside an attribute)

```php
// ❌ Insecure: esc_html doesn't encode quotes the way attributes need.
echo '<input value="' . esc_html( $value ) . '">';
```

```php
// ✅ Secure: esc_attr for attribute context.
echo '<input value="' . esc_attr( $value ) . '">';
```

### Mistake 3 — Unescaped URLs (allows `javascript:` and injection)

```php
// ❌ Insecure: attacker controls the scheme/markup.
echo '<a href="' . $url . '">link</a>';
```

```php
// ✅ Secure: esc_url strips dangerous schemes and encodes the URL.
echo '<a href="' . esc_url( $url ) . '">link</a>';
```

### Mistake 4 — Injecting PHP into inline JS without `esc_js`/JSON

```php
// ❌ Insecure: breaks out of the string and into script.
echo '<script>var label = "' . $label . '";</script>';
```

```php
// ✅ Secure: esc_js for a single quoted string...
echo '<script>var label = "' . esc_js( $label ) . '";</script>';
// ...or, better, pass structured data as JSON:
echo '<script>var data = ' . wp_json_encode( $data ) . ';</script>';
```

### Mistake 5 — Using `wp_kses_post()` where escaping is required (and vice versa)

```php
// ❌ Wrong tool: kses lets markup through where you wanted plain text.
echo '<td>' . wp_kses_post( $plain_title ) . '</td>';
```

```php
// ✅ Plain text → esc_html; intentional rich HTML → wp_kses_post.
echo '<td>' . esc_html( $plain_title ) . '</td>';
echo '<div class="bio">' . wp_kses_post( $rich_bio ) . '</div>';
```

### Mistake 6 — Translated strings echoed unescaped

```php
// ❌ Insecure: translation files can contain markup; raw echo into a tag.
echo '<p>' . __( 'Welcome, %s', 'my-plugin' ) . '</p>';
```

```php
// ✅ Secure: escape the translated output.
printf( '<p>%s</p>', esc_html__( 'Welcome back', 'my-plugin' ) );
```

### Mistake 7 — Redirect target not validated

```php
// ❌ Insecure: open redirect to an attacker-controlled site.
$redirect = $_GET['redirect_to'];
wp_redirect( $redirect );
exit;
```

```php
// ✅ Secure: the "escape" for a Location target is validation + wp_safe_redirect.
$redirect = isset( $_GET['redirect_to'] ) ? esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) : '';
$redirect = wp_validate_redirect( $redirect, admin_url() );
wp_safe_redirect( $redirect );
exit;
```

### Mistake 8 — Using wp_kses_post where a tighter allowlist is needed

```php
// ❌ Risky: wp_kses_post allows many tags you may not want in a caption.
echo wp_kses_post( $caption );
```

```php
// ✅ Secure: define a custom allowlist when the context is narrower.
$allowed = array(
    'a'      => array( 'href' => array() ),
    'em'     => array(),
    'strong' => array(),
);
echo wp_kses( $caption, $allowed );
```

Related: see the `input-sanitization-validation` skill for validating redirect URLs on
input and the `filesystem-security` skill for path escaping.

## Correct code examples

A complete context → function reference (with `esc_url` vs `esc_url_raw`, the i18n
variants, and `wp_kses` allowlist usage) is in
[`references/escaping-cheatsheet.md`](references/escaping-cheatsheet.md).

```php
// A small template snippet that escapes every dynamic value in context.
?>
<article id="post-<?php echo esc_attr( $post_id ); ?>" class="<?php echo esc_attr( $css ); ?>">
    <h2><a href="<?php echo esc_url( $permalink ); ?>"><?php echo esc_html( $title ); ?></a></h2>
    <div class="content"><?php echo wp_kses_post( $content ); ?></div>
    <a class="more" href="<?php echo esc_url( $permalink ); ?>">
        <?php echo esc_html__( 'Read more', 'my-plugin' ); ?>
    </a>
</article>
<?php
```

## Checklist

- [ ] Every echoed variable is escaped at the point of output.
- [ ] HTML text uses `esc_html` / `esc_html__` / `esc_html_e`.
- [ ] Attribute values use `esc_attr` / `esc_attr__` / `esc_attr_e`.
- [ ] URLs in markup use `esc_url` (`esc_url_raw` only for storage/redirects).
- [ ] Inline JS uses `esc_js` or, preferably, `wp_json_encode`.
- [ ] Textarea contents use `esc_textarea`.
- [ ] Intentional HTML uses `wp_kses_post` / `wp_kses` with an allowlist.
- [ ] Translatable strings use the `esc_*` i18n variants.
- [ ] No escaped/unescaped string concatenation that defeats escaping.

## Official references

- [Escaping Data — Common APIs Handbook](https://developer.wordpress.org/apis/security/escaping/)
- [`esc_html()`](https://developer.wordpress.org/reference/functions/esc_html/)
- [`esc_attr()`](https://developer.wordpress.org/reference/functions/esc_attr/)
- [`esc_url()`](https://developer.wordpress.org/reference/functions/esc_url/)
- [`esc_js()`](https://developer.wordpress.org/reference/functions/esc_js/)
- [`esc_textarea()`](https://developer.wordpress.org/reference/functions/esc_textarea/)
- [`wp_kses_post()`](https://developer.wordpress.org/reference/functions/wp_kses_post/)
- [`wp_kses()`](https://developer.wordpress.org/reference/functions/wp_kses/)
- [Internationalization — escaping translations](https://developer.wordpress.org/plugins/internationalization/how-to-internationalize-your-plugin/)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
