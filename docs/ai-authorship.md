# AI assistance and verification

AI coding assistants have been used to draft and revise security guidance,
reference examples, evaluation scenarios, repository tooling, and documentation
in this project. This disclosure records that assistance; it does not attribute
every historical line to an AI or establish the authorship of earlier revisions.

AI-generated security advice can contain incorrect APIs, incomplete threat models,
and examples that are unsafe in a different context. Treat the skills as guidance
to check against official documentation and your application's trust boundaries,
not as a security certification.

## What validation means

- Metadata/specification checks verify format and packaging, not security behavior.
- PHP syntax and coding-standard checks catch a limited class of defects; they do
  not execute examples inside WordPress or establish that authorization is correct.
- Scenario validation checks fixture structure and skill coverage. It does not run
  an AI agent, score its responses, or demonstrate that the scenarios pass.
- Installation smoke checks validate a disposable copy and reference discovery;
  a successful copy does not prove a particular coding agent loaded a skill.
- The audit helper is a heuristic sink inventory, not a security audit. Matches
  require data-flow and control-flow review; an empty inventory is not assurance.

This document makes **no claim of human review or an independent security audit**.
Such a claim needs a documented reviewer, scope, revision, and result; AI assistance
or an automated check cannot supply that evidence.

## Contributing with AI

Follow [CONTRIBUTING.md](../CONTRIBUTING.md) regardless of how a change was authored:
verify cited APIs, document prerequisites, exercise changed behavior in a disposable
environment, and report the exact checks performed and their limits. In a pull
request, disclose relevant AI assistance and distinguish observed results from
assumptions. Do not present generated content or a passing linter as human approval.

Report vulnerabilities through the [security policy](../SECURITY.md), without
publishing production credentials or sensitive scanner output.
