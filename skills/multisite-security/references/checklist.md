# Multisite security checklist

Use this checklist before any multisite-aware code.

- [ ] Multisite-specific code checks `is_multisite()` first.
- [ ] Network admin actions use `manage_network` / `manage_network_options`.
- [ ] `blog_id` values from input are cast to integers and validated.
- [ ] The user is confirmed to be a member of / allowed on the target site before switching.
- [ ] Every `switch_to_blog()` has a matching `restore_current_blog()`.
- [ ] Capabilities are re-checked after switching sites if the action is privileged.
- [ ] Per-site data is not leaked into another site's context.
- [ ] `is_super_admin()` is used only where the super-admin list is the correct gate.
