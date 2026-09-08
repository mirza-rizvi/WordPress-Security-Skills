# Cron & background job security checklist

Use this checklist before any cron event or background job.

- [ ] Cron callbacks do not rely on `current_user_can()`.
- [ ] Per-object jobs capture the acting user/context at schedule time and re-verify it in the callback.
- [ ] Secrets are not passed as cron arguments or embedded in cron URLs.
- [ ] Stored cron args are sanitized and validated before use.
- [ ] `wp_next_scheduled()` prevents duplicate scheduled events.
- [ ] Custom recurrence intervals are registered via the `cron_schedules` filter before scheduling.
- [ ] Scheduled hooks are cleared on plugin deactivation.
- [ ] Failures are logged without exposing secrets or internal paths.
