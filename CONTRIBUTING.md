# Contributing

Thanks for helping make AI-generated WordPress code safer. This repo is **security only** —
proposals that aren't about WordPress security (general features, performance, styling) are
out of scope. New skills, sharper "common mistakes", and corrections to APIs are all welcome.

## The one hard rule: WordPress APIs must be real and current

Every WordPress function, hook, or constant you cite **must exist** and be current per the
[official reference](https://developer.wordpress.org/reference/). Verify before you write.
A wrong API in a security guide is worse than no guide — never invent or guess a function,
and don't use deprecated ones. When in doubt, link the reference page you checked.

## Repository layout

```
skills/<skill-name>/
├── SKILL.md          # required
└── references/       # copy-paste artifacts (example file, checklist, cheatsheet)
```

`<skill-name>` must be lowercase letters, numbers, and single hyphens, and **must match the
`name:` in the frontmatter** (Agent Skills spec).

## SKILL.md contract

### Frontmatter (YAML)

```yaml
---
name: skill-name                 # required; matches the directory name
description: >                   # required; the trigger that decides activation
  Use when ... names concrete triggers (form, AJAX, REST route, query, upload) and
  says what the skill does, in third person.
license: MIT
metadata:
  tags: [wordpress, security, ...]
---
```

Required fields are exactly `name` and `description` (spec). `tags` is **not** a top-level
spec field — nest it under `metadata`. Keep `description` ≤ 1024 characters.

#### Writing the `description`

It is the single most important field — agents load only `name` + `description` at startup
and use it to decide whether to pull in the skill. Make it:

- **Third person**, leading with **"Use when…"**.
- Concrete about **triggers** (a form, an AJAX call, a REST route, a `$wpdb` query, a file
  upload) — not vague ("helps with security").
- Clear about **what the skill does**.
- Narrow enough not to fire on everything, broad enough to catch the real cases.

**Sanity-check every description** against 3 should-trigger and 2 should-not-trigger example
queries. If it misfires either way, tighten it.

### Body — identical H2 section order in every skill

1. `## When to use this skill`
2. `## Core principles (and why they matter)`
3. `## Step-by-step implementation`
4. `## Common AI mistakes / anti-patterns` — the most valuable section; show **wrong → right**
   pairs (`// ❌ Insecure` then `// ✅ Secure`). Use *real* mistakes specific to the topic.
5. `## Correct code examples` — complete, copy-paste-ready, WPCS-compliant (no pseudo-code).
6. `## Checklist` — tickable items an agent verifies before finishing.
7. `## Official references` — developer.wordpress.org pages, Plugin Handbook security section,
   and OWASP where it fits.

Keep `SKILL.md` scannable (aim < 500 lines); move long copy-paste material into `references/`.

### `references/`

Include at least one complete, copy-paste-ready artifact: a secure example file
(`secure-*.php`), a `checklist.md`, and/or a `cheatsheet.md`. Reference them from `SKILL.md`
with relative links (`references/secure-ajax-handler.php`).

## Code style

- WordPress Coding Standards conventions; `defined( 'ABSPATH' ) || exit;` atop PHP files.
- Pair nonce + capability on every state-changing example.
- `wp_unslash()` before sanitizing; escape on output; `$wpdb->prepare()` for queries.
- Secure but simple — no enterprise over-engineering.
- "✅ Secure" examples must themselves pass the `security-auditing-code-review` checklist.

Scaffold a new skill draft with `python3 scripts/add-skill.py <skill-name>` — it creates an
explicitly incomplete skill plus scenario that validators refuse until real content lands.
Never cite an API that the official `skills-ref` validator or your own verification cannot
confirm.

## Submitting

1. Fork, branch, add or edit a skill following the contract above.
2. Verify every cited API on developer.wordpress.org.
3. Run `./scripts/validate-skills.sh` (needs `rg`, `python3` + PyYAML) and fix what it flags.
4. Add or update the skill's eval scenario under `eval/scenarios/` (see
   [eval/scenarios/README.md](eval/scenarios/README.md)); every skill needs at least one.
5. Check internal links and `references/` paths resolve.
6. Open a PR describing the AI mistake the change addresses, and disclose AI assistance
   per [docs/ai-authorship.md](docs/ai-authorship.md).

By contributing you agree your work is licensed under the [MIT License](LICENSE).
