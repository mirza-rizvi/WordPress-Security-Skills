# Security Policy

## Supported scope

This repository publishes WordPress security Agent Skills and reference examples. Security
reports should focus on:

- insecure guidance in a skill;
- insecure PHP or configuration reference artifacts;
- incorrect or deprecated WordPress APIs used in security examples;
- instructions that could cause agents to produce vulnerable WordPress code.

General WordPress support questions, feature requests, and non-security docs feedback should
use the normal issue templates.

## Reporting a security issue

If a report includes exploit details, a working proof of concept, or a vulnerability pattern
that could immediately put users at risk, do not open a public issue. Use GitHub private
vulnerability reporting if it is enabled for this repository. If private reporting is not
enabled, contact the maintainers privately before publishing details.

For lower-risk corrections, such as a wrong function reference or an example that is
defensive but incomplete, use the API correction or insecure example issue template.

## What to include

- affected skill or reference file;
- the insecure behavior or incorrect API;
- the official WordPress reference or handbook page that supports the correction;
- a suggested secure replacement, if known;
- whether the issue affects copy-paste reference code or only explanatory guidance.

## Maintainer expectations

Maintainers should verify every reported WordPress API against official documentation before
merging a fix. If a report affects secure examples, maintainers should also review the
example against `security-auditing-code-review`.
