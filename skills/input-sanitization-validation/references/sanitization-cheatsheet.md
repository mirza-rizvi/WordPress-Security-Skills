# Sanitization & validation cheatsheet

Always `wp_unslash()` superglobal data **before** sanitizing. Sanitize on input;
escape on output (see the `output-escaping` skill).

## Input type → sanitizer

| Input type            | Sanitize with                          | Then validate with                          |
| --------------------- | -------------------------------------- | ------------------------------------------- |
| Single-line text      | `sanitize_text_field()`                | length / pattern checks                     |
| Multi-line plain text | `sanitize_textarea_field()`            | length checks                               |
| Email                 | `sanitize_email()`                     | `is_email()`                                |
| Integer (>= 0)        | `absint()`                             | range check                                 |
| Signed integer        | `intval()`                             | range check                                 |
| Float                 | `floatval()` / `(float)`               | range check                                 |
| Boolean / checkbox    | `! empty( $v ) ? 1 : 0` / `rest_sanitize_boolean()` | —                              |
| Key (lowercase a-z0-9_-) | `sanitize_key()`                    | `in_array( $v, $allowed, true )`            |
| Slug                  | `sanitize_title()`                     | —                                           |
| HTML class            | `sanitize_html_class()`                | —                                           |
| File name             | `sanitize_file_name()`                 | extension allowlist                         |
| URL (for storage)     | `esc_url_raw()`                        | scheme allowlist (`http`, `https`)          |
| URL (for output)      | `esc_url()`                            | —                                           |
| Rich HTML (post-like) | `wp_kses_post()`                       | —                                           |
| Rich HTML (custom)    | `wp_kses( $v, $allowed_html )`         | —                                           |
| Hex color             | `sanitize_hex_color()`                 | —                                           |
| Option name / meta key | `sanitize_key()`                      | allowlist                                   |
| Array of ints         | `array_map( 'absint', (array) $v )`    | —                                           |
| Array of text         | `array_map( 'sanitize_text_field', wp_unslash( (array) $v ) )` | —                |
| JSON string           | `json_decode()` then sanitize fields   | structure check after decode                |

## Common patterns

```php
// Guarded scalar read.
$qty = isset( $_POST['qty'] ) ? absint( wp_unslash( $_POST['qty'] ) ) : 0;

// Allowlisted choice.
$view    = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : 'list';
$view    = in_array( $view, array( 'list', 'grid' ), true ) ? $view : 'list';

// Email with validation.
$email = sanitize_email( wp_unslash( $_POST['email'] ?? '' ) );
if ( ! is_email( $email ) ) {
    wp_die( esc_html__( 'Invalid email.', 'my-plugin' ), 400 );
}

// Restricted HTML allowlist.
$allowed = array(
    'a'      => array( 'href' => array(), 'title' => array() ),
    'strong' => array(),
    'em'     => array(),
);
$html = wp_kses( wp_unslash( $_POST['content'] ?? '' ), $allowed );
```

## Pitfalls
- `strip_tags()` is **not** an XSS defense — use `wp_kses*`.
- Scalar sanitizers return `''` when handed an array — map instead.
- `esc_url_raw()` for DB storage; `esc_url()` for display. Don't swap them.
- Sanitizing does not validate — always check allowed values/ranges too.
