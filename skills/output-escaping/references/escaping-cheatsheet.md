# Output escaping cheatsheet

Escape at the point of output, matched to the **context** the value lands in.
Escaping is separate from input sanitization — do both.

## Context → function

| Output context                | Escape with                         | i18n variants                          |
| ----------------------------- | ----------------------------------- | -------------------------------------- |
| HTML text / element body      | `esc_html()`                        | `esc_html__()`, `esc_html_e()`         |
| HTML attribute value          | `esc_attr()`                        | `esc_attr__()`, `esc_attr_e()`         |
| URL in `href`/`src` (display) | `esc_url()`                         | —                                      |
| URL for storage / redirect    | `esc_url_raw()`                     | —                                      |
| Inline JS string              | `esc_js()`                          | —                                      |
| Structured data into JS       | `wp_json_encode()`                  | —                                      |
| `<textarea>` contents         | `esc_textarea()`                    | —                                      |
| Intentional rich HTML (posts) | `wp_kses_post()`                    | —                                      |
| Intentional HTML (custom set) | `wp_kses( $html, $allowed )`        | —                                      |
| XML/feed node                 | `esc_xml()`                         | —                                      |
| CSS value (limited)           | `esc_attr()` + validate             | —                                      |

## Examples

```php
echo esc_html( $title );
echo '<input value="' . esc_attr( $value ) . '">';
echo '<a href="' . esc_url( $url ) . '">' . esc_html( $text ) . '</a>';
echo '<textarea>' . esc_textarea( $note ) . '</textarea>';
printf( '<button>%s</button>', esc_html__( 'Save', 'my-plugin' ) );

// JS: prefer JSON over string interpolation.
wp_add_inline_script( 'my-plugin', 'var myData = ' . wp_json_encode( $data ) . ';', 'before' );

// Intentional HTML with a tight allowlist.
$allowed = array(
    'a'      => array( 'href' => array(), 'rel' => array() ),
    'strong' => array(),
    'br'     => array(),
);
echo wp_kses( $html, $allowed );
```

## `esc_url()` vs `esc_url_raw()`
- `esc_url()` — display in HTML; entity-encodes for markup.
- `esc_url_raw()` — database storage, redirects, HTTP requests; no display encoding.

## Pitfalls
- `esc_html` inside an attribute is wrong — use `esc_attr`.
- Never echo a raw `__()` into HTML; use `esc_html__()` / `esc_attr_e()`.
- `wp_kses_post` allows markup — don't use it where plain text is expected.
- Don't pre-escape then concatenate more unescaped text; escape the final value.
- Escaping is not a substitute for input sanitization.
