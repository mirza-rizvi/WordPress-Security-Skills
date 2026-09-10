---
name: shortcode-block-security
description: >
  Use when registering a shortcode with add_shortcode or a dynamic block with a
  render_callback, or processing shortcode / block attributes. Normalizes
  attributes with shortcode_atts, validates against allowlists, and escapes all
  rendered output for its context with esc_html, esc_attr, esc_url, or
  wp_kses_post. Prevents stored and reflected XSS in rendered content.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, shortcode, block, xss, gutenberg"
---

# Shortcode & dynamic block security

## When to use this skill

Use this skill whenever code renders content from shortcodes or dynamic blocks:

- Registering a shortcode with `add_shortcode()`.
- Reading or outputting shortcode attributes (`$atts`) or enclosed content (`$content`).
- Registering a dynamic block with a `render_callback`.
- Reading block attributes in a server-side render.
- Building HTML, URLs, or classes from shortcode/block input.

Shortcodes and dynamic blocks are stored XSS sinks: a contributor enters `[my_card title="<script>..."]`
and the render callback echoes it unescaped. Every attribute must be sanitized and every output escaped.

Related: see the `output-escaping` skill for context-correct escaping and the
`gutenberg-block-editor-security` skill for broader block-editor surfaces.

## Core principles (and why they matter)

1. **`shortcode_atts()` sets defaults; it does NOT sanitize.** The returned array still holds
   raw user input. Sanitize each value before use.
2. **Block attributes are user input too.** Declaring `type: 'string'` in `block.json` does not
   escape HTML or JavaScript for you; sanitize on render.
3. **Escape at render for the exact context.** HTML body → `esc_html()`. HTML attribute →
   `esc_attr()`. URL → `esc_url()`. Rich HTML → `wp_kses_post()` with an allowlist.
4. **Do not store unescaped attribute values.** If you persist them, sanitize on save and escape
   on read.
5. **Never pass shortcode/block input to `do_shortcode()` or `eval()` uncontrolled.** Both can
   execute arbitrary shortcodes or code.
6. **Return, don't echo.** Shortcode and block render callbacks must return strings; echoing
   produces unexpected output placement.

## Step-by-step implementation

1. In the shortcode callback, call `shortcode_atts()` with a complete default map.
2. Sanitize each attribute to its expected type (`absint`, `sanitize_text_field`, `esc_url_raw`,
   `sanitize_key`).
3. In a block `render_callback`, read attributes from the `$attributes` array and sanitize them
   the same way.
4. Build the markup by concatenating escaped values.
5. Return the complete markup string.
6. For rich content, use `wp_kses_post()` or a tightly scoped `wp_kses()` allowlist.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Shortcode & dynamic block security checklist](references/checklist.md) | Before final verification of the shortcode & dynamic block security controls. |
| [Secure shortcode and dynamic block](references/secure-shortcode-block.php) | Implementing shortcode and dynamic-block render callbacks with validated attributes and escaped markup. |

## Common AI mistakes / anti-patterns

### Mistake 1 — Echoing `$atts` directly

```php
// ❌ Insecure: stored XSS through the title attribute.
function my_plugin_card_shortcode( $atts ) {
    return '<div class="card"><h3>' . $atts['title'] . '</h3></div>';
}
```

```php
// ✅ Secure: default, then sanitize, then escape.
function my_plugin_card_shortcode( $atts ) {
    $atts = shortcode_atts(
        array(
            'title' => '',
            'link'  => '',
        ),
        $atts,
        'my_plugin_card'
    );

    $title = sanitize_text_field( $atts['title'] );
    $link  = esc_url_raw( $atts['link'] );

    $output = '<div class="card">';
    if ( $link ) {
        $output .= '<h3><a href="' . esc_url( $link ) . '">' . esc_html( $title ) . '</a></h3>';
    } else {
        $output .= '<h3>' . esc_html( $title ) . '</h3>';
    }
    $output .= '</div>';

    return $output;
}
```

### Mistake 2 — Trusting `shortcode_atts()` to sanitize

```php
// ❌ Insecure: shortcode_atts only supplies defaults and filters unknown keys.
$atts = shortcode_atts( array( 'class' => '' ), $atts );
echo '<div class="' . $atts['class'] . '">...</div>';
```

```php
// ✅ Secure: sanitize the value after normalizing it.
$atts  = shortcode_atts( array( 'class' => '' ), $atts, 'my_plugin_box' );
$class = sanitize_html_class( $atts['class'] );
echo '<div class="' . esc_attr( $class ) . '">...</div>';
```

### Mistake 3 — Dynamic block render callback echoing attributes

```php
// ❌ Insecure: block attributes echoed raw.
function my_plugin_render_banner( $attributes ) {
    ?>
    <div class="banner" style="background: <?php echo $attributes['bgColor']; ?>">
        <?php echo $attributes['heading']; ?>
    </div>
    <?php
}
```

```php
// ✅ Secure: sanitize attributes and escape for the output context.
function my_plugin_render_banner( $attributes ) {
    $bg_color = isset( $attributes['bgColor'] ) ? sanitize_hex_color( $attributes['bgColor'] ) : '#ffffff';
    $heading  = isset( $attributes['heading'] ) ? sanitize_text_field( $attributes['heading'] ) : '';

    return sprintf(
        '<div class="banner" style="background: %s"><h2>%s</h2></div>',
        esc_attr( $bg_color ),
        esc_html( $heading )
    );
}
```

### Mistake 4 — Allowing arbitrary HTML through attributes

```php
// ❌ Insecure: an attacker can inject script/event handlers.
function my_plugin_render_note( $attributes ) {
    return '<div>' . $attributes['content'] . '</div>';
}
```

```php
// ✅ Secure: constrain rich markup with wp_kses_post.
function my_plugin_render_note( $attributes ) {
    $content = isset( $attributes['content'] ) ? $attributes['content'] : '';
    return '<div>' . wp_kses_post( $content ) . '</div>';
}
```

### Mistake 5 — Running `do_shortcode()` on untrusted input

```php
// ❌ Insecure: executes arbitrary shortcodes supplied by a visitor.
echo do_shortcode( $_POST['content'] );
```

```php
// ✅ Secure: do not run do_shortcode on user input; if required, sanitize first.
$content = wp_kses_post( wp_unslash( $_POST['content'] ?? '' ) );
```

## Correct code examples

A complete secure shortcode and dynamic-block render callback is in
[`references/secure-shortcode-block.php`](references/secure-shortcode-block.php).

## Checklist

- [ ] `shortcode_atts()` provides defaults for every supported attribute.
- [ ] Each shortcode attribute is sanitized to its expected type after normalization.
- [ ] Block attributes are sanitized inside `render_callback`, not trusted from `block.json` types.
- [ ] All rendered output is escaped for its context (`esc_html`, `esc_attr`, `esc_url`, `wp_kses_post`).
- [ ] CSS classes use `sanitize_html_class()` (or `esc_attr()` with an allowlist).
- [ ] Colors use `sanitize_hex_color()` where appropriate.
- [ ] The callback returns a string; it does not echo directly.
- [ ] `do_shortcode()` is never run on untrusted input.

## Official references

- [`add_shortcode()`](https://developer.wordpress.org/reference/functions/add_shortcode/)
- [`shortcode_atts()`](https://developer.wordpress.org/reference/functions/shortcode_atts/)
- [`register_block_type()`](https://developer.wordpress.org/reference/functions/register_block_type/)
- [`get_block_wrapper_attributes()`](https://developer.wordpress.org/reference/functions/get_block_wrapper_attributes/)
- [`esc_html()`](https://developer.wordpress.org/reference/functions/esc_html/)
- [`esc_attr()`](https://developer.wordpress.org/reference/functions/esc_attr/)
- [`esc_url()`](https://developer.wordpress.org/reference/functions/esc_url/)
- [`wp_kses_post()`](https://developer.wordpress.org/reference/functions/wp_kses_post/)
- [`sanitize_html_class()`](https://developer.wordpress.org/reference/functions/sanitize_html_class/)
- [`sanitize_hex_color()`](https://developer.wordpress.org/reference/functions/sanitize_hex_color/)
- [Shortcode API — Plugin Handbook](https://developer.wordpress.org/plugins/shortcodes/)
- [Block Editor Handbook](https://developer.wordpress.org/block-editor/)
