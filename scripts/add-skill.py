#!/usr/bin/env python3
"""Create an explicitly incomplete skill and scenario without overwriting content."""

import argparse
import json
from pathlib import Path
import re
import shutil
import sys


SECTIONS = (
    ("When to use this skill", "Describe concrete security triggers and exclusions; check three should-trigger and two should-not-trigger queries."),
    ("Core principles (and why they matter)", "Explain the trust boundaries, attacker capabilities, and controls specific to this topic."),
    ("Step-by-step implementation", """Write actionable implementation steps, including failure paths and authorization before privileged effects.

Add a row with a load condition for every new reference artifact before removing draft status.

### Supporting references

| Reference | Load when |
| --- | --- |
| [Draft checklist](references/checklist.md) | Replacing the draft with topic-specific checks and verifying the finished skill. |"""),
    ("Common AI mistakes / anti-patterns", "Show real insecure patterns and their secure replacements; explain why each correction works."),
    ("Correct code examples", "Author a complete, verified reference artifact and link it here. Do not present unfinished code as secure."),
    ("Checklist", "Replace the authoring notes in [the draft checklist](references/checklist.md) with observable security checks."),
    ("Official references", "Link the official documentation for every cited API and verify requirements for the target versions."),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="lowercase letters/digits separated by single hyphens, at most 64 characters")
    parser.add_argument("--title", help="human-readable title (defaults to the name in title case)")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help="repository root")
    args = parser.parse_args()
    if len(args.name) > 64 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", args.name):
        parser.error("invalid skill name")
    title = args.title if args.title is not None else args.name.replace("-", " ").title()
    if not title.strip() or "\n" in title or "\r" in title:
        parser.error("title must be a nonempty single line")
    skill = args.root / "skills" / args.name
    scenario = args.root / "eval" / "scenarios" / f"{args.name}-scenario.json"
    if skill.exists() or skill.is_symlink() or scenario.exists() or scenario.is_symlink():
        parser.error("refusing to overwrite an existing skill directory or scenario")
    if not (args.root / "skills").is_dir():
        parser.error("root must contain a skills directory")

    content = f'''---
name: {args.name}
description: >
  Use when authoring this incomplete skill; replace this description with concrete security triggers before release.
compatibility: "INCOMPLETE: establish the actual WordPress/PHP API and tooling requirements for the authored examples."
license: MIT
metadata:
  tags: wordpress, security
  status: incomplete
---

# {title}

> INCOMPLETE AUTHORING DRAFT — not security guidance. Finish every section and
> scenario, verify the examples, and only then remove the incomplete statuses.
'''
    for heading, guidance in SECTIONS:
        content += f"\n## {heading}\n\n{guidance}\n"
    fixture = {
        "status": "incomplete",
        "name": f"{title} authoring draft",
        "skills": [args.name],
        "query": "INCOMPLETE: write a realistic user request demonstrating the concrete security failure.",
        "expected_behavior": ["INCOMPLETE: describe the secure behavior the agent should produce, including denied and invalid requests."],
        "success_criteria": ["INCOMPLETE: define observable pass/fail criteria, not wording or implementation trivia."],
    }
    created_skill = False
    created_scenario = False
    try:
        scenario.parent.mkdir(parents=True, exist_ok=True)
        skill.mkdir()
        created_skill = True
        (skill / "references").mkdir()
        (skill / "SKILL.md").write_text(content, encoding="utf-8")
        (skill / "references" / "checklist.md").write_text(
            "# Incomplete authoring checklist\n\n"
            "This is an authoring draft, not a verified security checklist.\n\n"
            "- [ ] Identify the trust boundary and realistic failure mode.\n"
            "- [ ] Verify all APIs and compatibility requirements against official sources.\n"
            "- [ ] Supply complete examples and exercise success, denied, and invalid-input paths.\n"
            "- [ ] Write an evaluation scenario with observable success criteria.\n"
            "- [ ] Replace these authoring notes with topic-specific security checks.\n",
            encoding="utf-8",
        )
        with scenario.open("x", encoding="utf-8") as stream:
            created_scenario = True
            json.dump(fixture, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    except OSError as exc:
        if created_scenario:
            scenario.unlink()
        if created_skill:
            shutil.rmtree(skill)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Created incomplete draft: {skill}")
    print(f"Created incomplete scenario: {scenario}")
    print("Validation intentionally fails until the content is authored and both incomplete statuses are removed or set to ready.")
    print("Update README.md and docs/coverage-matrix.md when the skill is ready for inclusion.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
