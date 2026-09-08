---
name: sql-injection-prevention
description: >
  Use when writing any custom database query in WordPress with $wpdb — get_results,
  get_var, get_row, query, or building WHERE/IN/LIKE/ORDER BY clauses. Uses
  $wpdb->prepare() with correct placeholders (%d, %s, %f, %i), $wpdb->esc_like() for
  LIKE, and allowlists for identifiers that cannot be parameterized. Prevents SQL
  injection. Apply proactively to every query containing a dynamic value.
license: MIT
metadata:
  tags: [wordpress, security, php, sql, wpdb, injection, database]
---

# SQL injection prevention with `$wpdb`

## When to use this skill

Use this skill for **any custom SQL** that includes a dynamic value:

- `$wpdb->get_results()`, `get_var()`, `get_row()`, `get_col()`, `query()`.
- `WHERE`, `IN (...)`, `LIKE`, `LIMIT`, `ORDER BY`, table/column names.
- Custom tables, custom meta queries, reporting/analytics queries.

Prefer the high-level APIs (`WP_Query`, `get_posts`, `get_users`, `$wpdb->insert/update/
delete`) when they fit — they parameterize for you. Drop to raw SQL only when necessary,
and then always via `$wpdb->prepare()`.

## Core principles (and why they matter)

1. **Never concatenate user input into SQL.** String interpolation is the root cause of
   injection. `prepare()` separates the query template from the data.
2. **Use the right placeholder.** `%d` (integer), `%f` (float), `%s` (string), `%i`
   (identifier — table/column, **WordPress 6.2+**). The wrong placeholder can break
   quoting and reopen injection.
3. **`prepare()` quotes strings for you — don't add your own quotes.** Writing
   `'%s'` (with surrounding quotes) double-quotes the value and breaks the query.
4. **`esc_like()` before `prepare()` for `LIKE`.** Otherwise `%` and `_` in user input act
   as wildcards (and can be abused). Escape, then pass through `%s`.
5. **Identifiers can't be parameterized as data.** Column/table names and `ORDER BY`
   direction must be validated against an allowlist (or use `%i` for identifiers in 6.2+).
6. **Prefer the table prefix property**: `$wpdb->prefix`, `$wpdb->posts`, etc., never a
   hard-coded `wp_`.

## Step-by-step implementation

1. Can a core API do it (`WP_Query`, `$wpdb->insert`)? If yes, use it.
2. If raw SQL is needed, write the query with placeholders, not variables.
3. Call `$wpdb->prepare( $sql, $args... )` and run the prepared string.
4. For `LIKE`, wrap the term: `'%' . $wpdb->esc_like( $term ) . '%'`, passed via `%s`.
5. For `IN()` lists, build a placeholder string and spread the values.
6. For identifiers/sort columns, allowlist them (or use `%i` on 6.2+).

## Common AI mistakes / anti-patterns

### Mistake 1 — Interpolating input directly

```php
// ❌ Insecure: classic SQL injection.
$id   = $_GET['id'];
$row  = $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}orders WHERE id = $id" );
```

```php
// ✅ Secure: prepared statement with a typed placeholder.
$id  = absint( $_GET['id'] ?? 0 );
$row = $wpdb->get_row(
    $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}orders WHERE id = %d", $id )
);
```

### Mistake 2 — Quoting the placeholder yourself

```php
// ❌ Broken/insecure: prepare already quotes %s — this double-quotes.
$wpdb->prepare( "SELECT * FROM t WHERE name = '%s'", $name );
```

```php
// ✅ Correct: no surrounding quotes; prepare handles it.
$wpdb->prepare( "SELECT * FROM t WHERE name = %s", $name );
```

### Mistake 3 — `LIKE` without `esc_like()`

```php
// ❌ Insecure: user-supplied % / _ become wildcards.
$wpdb->prepare( "SELECT * FROM t WHERE title LIKE %s", '%' . $term . '%' );
```

```php
// ✅ Secure: escape LIKE wildcards first, then prepare.
$like = '%' . $wpdb->esc_like( $term ) . '%';
$wpdb->prepare( "SELECT * FROM t WHERE title LIKE %s", $like );
```

### Mistake 4 — Building an `IN()` list by joining input

```php
// ❌ Insecure: raw join of user values into IN().
$ids = implode( ',', $_POST['ids'] );
$wpdb->query( "DELETE FROM t WHERE id IN ($ids)" );
```

```php
// ✅ Secure: one placeholder per value, spread into prepare.
$ids          = array_map( 'absint', (array) ( $_POST['ids'] ?? array() ) );
$ids          = array_filter( $ids );
if ( $ids ) {
    $placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
    $wpdb->query(
        $wpdb->prepare( "DELETE FROM {$wpdb->prefix}t WHERE id IN ($placeholders)", $ids )
    );
}
```

### Mistake 5 — Dynamic `ORDER BY` / column name from input

```php
// ❌ Insecure: identifiers can't be safely parameterized as %s.
$orderby = $_GET['orderby'];
$wpdb->get_results( "SELECT * FROM t ORDER BY $orderby" );
```

```php
// ✅ Secure: allowlist the column and direction, or use %i on WP 6.2+.
$orderby = sanitize_key( $_GET['orderby'] ?? 'created' );
$order   = strtoupper( $_GET['order'] ?? 'DESC' );
$columns = array( 'created', 'name', 'total' );
$orderby = in_array( $orderby, $columns, true ) ? $orderby : 'created';
$order   = ( 'ASC' === $order ) ? 'ASC' : 'DESC';

if ( version_compare( $GLOBALS['wp_version'], '6.2', '>=' ) ) {
    $wpdb->get_results(
        $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}t ORDER BY %i $order", $orderby )
    );
} else {
    $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}t ORDER BY {$orderby} {$order}" );
}
```

### Mistake 6 — Hand-rolled insert instead of `$wpdb->insert()`

```php
// ❌ Insecure: manual INSERT with interpolation.
$wpdb->query( "INSERT INTO t (name) VALUES ('{$_POST['name']}')" );
```

```php
// ✅ Secure: $wpdb->insert() with format specifiers handles escaping.
$wpdb->insert(
    $wpdb->prefix . 't',
    array( 'name' => sanitize_text_field( wp_unslash( $_POST['name'] ?? '' ) ) ),
    array( '%s' )
);
```

## Correct code examples

Full prepared-query patterns — single value, `IN()`, `LIKE`, `insert/update/delete`, and
allowlisted `ORDER BY` — are in
[`references/secure-wpdb-queries.php`](references/secure-wpdb-queries.php).

## Checklist

- [ ] No user input is concatenated/interpolated into SQL.
- [ ] Every dynamic value goes through `$wpdb->prepare()` with the right placeholder.
- [ ] `%d`/`%f`/`%s` chosen by type; placeholders are **not** wrapped in extra quotes.
- [ ] `LIKE` terms are wrapped with `$wpdb->esc_like()` then passed via `%s`.
- [ ] `IN()` lists use one placeholder per value, spread into `prepare()`.
- [ ] Identifiers / `ORDER BY` columns are allowlisted (or use `%i` on WP 6.2+).
- [ ] Table names use `$wpdb->prefix` / `$wpdb->posts`, not hard-coded `wp_`.
- [ ] `insert`/`update`/`delete` use `$wpdb` helpers with format specifiers where possible.

## Official references

- [`wpdb::prepare()`](https://developer.wordpress.org/reference/classes/wpdb/prepare/)
- [`wpdb::esc_like()`](https://developer.wordpress.org/reference/classes/wpdb/esc_like/)
- [`wpdb` class (insert/update/delete/get_*)](https://developer.wordpress.org/reference/classes/wpdb/)
- [Protecting Queries Against SQL Injection — Common APIs](https://developer.wordpress.org/apis/security/data-validation/#database)
- [Escaping table and field names with `%i` in `wpdb::prepare()` (introduced WP 6.2)](https://make.wordpress.org/core/2022/10/08/escaping-table-and-field-names-with-wpdbprepare-in-wordpress-6-1/)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
