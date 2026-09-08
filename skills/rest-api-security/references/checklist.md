# REST API security checklist

- [ ] Every `register_rest_route` defines a `permission_callback`.
- [ ] Writes/deletes enforce a capability; `__return_true` only for genuinely public reads.
- [ ] Per-object routes verify the user can act on that object (via request args).
- [ ] Authorization varies by HTTP method where appropriate.
- [ ] All params declared under `args` with `sanitize_callback` + `validate_callback`.
- [ ] Required params marked `required => true`; `type` declared.
- [ ] Callback treats params as sanitized but still escapes HTML on output.
- [ ] Failures return `WP_Error` with an explicit `status`.
- [ ] Namespace is plugin-specific and versioned (`my-plugin/v1`).
- [ ] Sensitive data is not leaked in responses to under-privileged users.
