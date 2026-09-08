# SQL injection prevention checklist

- [ ] A core API (`WP_Query`, `get_posts`, `$wpdb->insert/update/delete`) was preferred where it fit.
- [ ] No user input is concatenated/interpolated into a SQL string.
- [ ] Every dynamic value passes through `$wpdb->prepare()`.
- [ ] Placeholder matches type: `%d` int, `%f` float, `%s` string, `%i` identifier (WP 6.2+).
- [ ] Placeholders are NOT wrapped in extra quotes (`'%s'` is wrong).
- [ ] `LIKE` terms wrapped with `$wpdb->esc_like()` then bound via `%s`.
- [ ] `IN()` lists use one placeholder per value, spread into `prepare()`.
- [ ] `ORDER BY` / column / table identifiers are allowlisted (or `%i` on 6.2+).
- [ ] Table names use `$wpdb->prefix` / `$wpdb->posts`, never hard-coded `wp_`.
- [ ] `insert`/`update`/`delete` supply format specifier arrays.
