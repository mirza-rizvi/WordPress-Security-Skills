---
name: woocommerce-security
description: >
  Use when a plugin extends WooCommerce - reading or writing orders, customer
  data, or hooking checkout, REST, or the Store API. Sanitizes input with wc_clean,
  gates shop actions with WooCommerce capabilities like edit_shop_orders,
  minimizes stored payment data, and escapes customer PII on output. Prevents
  broken access control and PII / order data exposure.
compatibility: "Examples generally use PHP 7.4 syntax; check each API against target WordPress/PHP versions. Use maintained WordPress and supported PHP in production. Shell examples require their named tools."
license: MIT
metadata:
  tags: "wordpress, security, php, woocommerce, ecommerce, pii, rest"
---

# WooCommerce security

## When to use this skill

Use this skill whenever a plugin or theme extends WooCommerce:

- Reading or writing orders, products, customers, or coupons via `wc_get_order()`,
  `WC_Order`, `WC_Product`, or `WC_Customer`.
- Hooking checkout, cart, or order-status actions (`woocommerce_checkout_*`,
  `woocommerce_order_status_*`).
- Adding custom WooCommerce REST or Store API endpoints.
- Storing or displaying customer PII (names, emails, addresses, phone numbers).
- Building admin order-meta boxes or custom reports.

WooCommerce has its own capabilities and data objects. Re-using generic WordPress
capabilities like `edit_posts` for orders often grants too much or too little access,
and raw customer data is PII that must be handled carefully.

Related: see the `user-data-protection-privacy` skill for GDPR export/erase hooks and
IP anonymization, and the `rest-api-security` skill for endpoint patterns.

## Core principles (and why they matter)

1. **Use WooCommerce capabilities.** Orders need `edit_shop_orders` / `edit_others_shop_orders`;
   shop settings need `manage_woocommerce`. Do not rely on `edit_posts` or `manage_options`.
2. **Use WooCommerce CRUD objects and sanitizers.** `wc_get_order()`, `wc_clean()`,
   `wc_sanitize_textarea()`, and `WC_Order` getters/setters apply WooCommerce-specific validation.
3. **Never store full payment data.** PAN, CVV, and raw magnetic-stripe data violate PCI DSS.
   Use the gateway/token system; store only tokens and last-four digits if required.
4. **Treat customer data as PII.** Escape names, emails, addresses, and phones on output;
   minimize retention; provide export/erase integration.
5. **Validate order ids before acting.** A user-supplied order id must correspond to a real
   order and the current user must be allowed to view/edit it.
6. **REST/Store API endpoints need real permission callbacks.** `edit_shop_orders` or
   `read` depending on the operation; never `__return_true`.

## Step-by-step implementation

1. Load the order/customer with `wc_get_order()` / `wc_get_product()` / `new WC_Customer()`.
2. Verify the user may act on it with `current_user_can( 'edit_shop_order', $order_id )` or
   `wc_current_user_has_role( 'shop_manager' )` as appropriate.
3. Sanitize input with `wc_clean()`, `sanitize_text_field()`, `absint()`, etc.
4. Use CRUD setters (`$order->set_billing_email(...)`) rather than raw `update_post_meta()`.
5. Save with `$order->save()`.
6. Escape output with `esc_html()`, `esc_attr()`, or `wp_kses_post()`.

### Supporting references

| Reference | Load when |
| --- | --- |
| [WooCommerce security checklist](references/checklist.md) | Before final verification of the woocommerce security controls. |
| [Secure WooCommerce order handler](references/secure-woocommerce-order.php) | Implementing authorized order updates through WooCommerce CRUD with sanitized input and escaped customer data. |

## Common AI mistakes / anti-patterns

### Mistake 1 — Exposing orders without `edit_shop_orders`

```php
// ❌ Insecure: subscribers can read any order by id.
$order = wc_get_order( $_GET['order_id'] );
echo $order->get_formatted_billing_full_name();
```

```php
// ✅ Secure: verify the user may edit shop orders (or own the order).
$order_id = isset( $_GET['order_id'] ) ? absint( wp_unslash( $_GET['order_id'] ) ) : 0;
$order    = $order_id ? wc_get_order( $order_id ) : false;

if ( ! $order || ! current_user_can( 'edit_shop_order', $order_id ) ) {
    wp_die( esc_html__( 'Invalid order.', 'my-plugin' ), 403 );
}

echo esc_html( $order->get_formatted_billing_full_name() );
```

### Mistake 2 — Trusting `$_POST` order ids

```php
// ❌ Insecure: any order can be updated by guessing the id.
$order = wc_get_order( $_POST['order_id'] );
$order->set_status( 'completed' );
$order->save();
```

```php
// ✅ Secure: sanitize, load, verify capability, then act.
$order_id = isset( $_POST['order_id'] ) ? absint( wp_unslash( $_POST['order_id'] ) ) : 0;
$order    = $order_id ? wc_get_order( $order_id ) : false;

if ( ! $order || ! current_user_can( 'edit_shop_order', $order_id ) ) {
    wp_die( esc_html__( 'Forbidden.', 'my-plugin' ), 403 );
}

$order->set_status( 'completed' );
$order->save();
```

### Mistake 3 — Storing PAN/CVV in post meta

```php
// ❌ Insecure: violates PCI DSS and creates a massive breach risk.
update_post_meta( $order_id, '_card_number', $_POST['card_number'] );
update_post_meta( $order_id, '_card_cvv', $_POST['card_cvv'] );
```

```php
// ✅ Secure: never store full card data; use gateway tokens.
// The gateway handles tokenization; your code stores only a token reference.
$order->update_meta_data( '_my_plugin_token_ref', sanitize_text_field( $token_ref ) );
$order->save();
```

### Mistake 4 — Echoing customer PII unescaped

```php
// ❌ Insecure: XSS if the customer name or address contains JavaScript.
echo '<p>' . $order->get_billing_email() . '</p>';
```

```php
// ✅ Secure: escape on output.
echo '<p>' . esc_html( $order->get_billing_email() ) . '</p>';
```

### Mistake 5 — Custom Store API route with open permissions

```php
// ❌ Insecure: anyone can read order data.
register_rest_route( 'wc/store/v1', '/my-orders', array(
    'methods'  => 'GET',
    'callback' => 'my_plugin_store_orders',
    'permission_callback' => '__return_true',
) );
```

```php
// ✅ Secure: require a real capability.
register_rest_route(
    'wc/store/v1',
    '/my-orders',
    array(
        'methods'             => 'GET',
        'callback'            => 'my_plugin_store_orders',
        'permission_callback' => function () {
            return current_user_can( 'edit_shop_orders' );
        },
    )
);
```

## Correct code examples

A complete secure WooCommerce order-meta update handler is in
[`references/secure-woocommerce-order.php`](references/secure-woocommerce-order.php).

## Checklist

- [ ] Order/customer actions use WooCommerce capabilities (`edit_shop_orders`, `manage_woocommerce`).
- [ ] Order ids are cast to integers and validated with `wc_get_order()`.
- [ ] Input is sanitized with `wc_clean()` / `sanitize_text_field()` / `absint()`.
- [ ] CRUD objects (`WC_Order`, `WC_Product`, `WC_Customer`) are used instead of raw meta.
- [ ] No full card numbers, CVV, or magnetic-stripe data are stored.
- [ ] Customer PII is escaped on output.
- [ ] Custom WooCommerce REST/Store API routes have real `permission_callback` handlers.
- [ ] GDPR export/erase hooks are wired for custom customer data.
- [ ] Logs and exports anonymize or redact PII.

## Official references

- [WooCommerce Code Reference](https://woocommerce.github.io/code-reference/)
- [WooCommerce Developer Docs](https://developer.woocommerce.com/)
- [`wc_get_order()`](https://woocommerce.github.io/code-reference/files/woocommerce_includes_wc-order-functions.html#source-view.47)
- [`WC_Order`](https://woocommerce.github.io/code-reference/classes/WC_Order.html)
- [`wc_clean()`](https://woocommerce.github.io/code-reference/files/woocommerce_includes_wc-formatting-functions.html)
- [`wc_sanitize_textarea()`](https://woocommerce.github.io/code-reference/files/woocommerce_includes_wc-formatting-functions.html)
- [WooCommerce REST API](https://woocommerce.github.io/woocommerce-rest-api-docs/)
- [WordPress capabilities](https://developer.wordpress.org/reference/functions/current_user_can/)
- [PCI DSS](https://www.pcisecuritystandards.org/)
