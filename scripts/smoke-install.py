#!/usr/bin/env python3
"""Smoke a disposable skill copy and skills-ref discovery, not a live agent install."""

from pathlib import Path
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET

from skills_ref import read_properties, to_prompt, validate


def main():
    source = Path(__file__).resolve().parents[1] / "skills"
    directories = sorted(path for path in source.iterdir() if path.is_dir())
    if not directories:
        raise ValueError("no skills to install")
    with tempfile.TemporaryDirectory(prefix="wp-skills-install-") as temporary:
        destination = Path(temporary) / ".agents" / "skills"
        destination.mkdir(parents=True)
        installed = []
        for directory in directories:
            target = destination / directory.name
            shutil.copytree(directory, target)
            problems = validate(target)
            if problems:
                raise ValueError(f"{target}: {'; '.join(problems)}")
            properties = read_properties(target)
            if properties.name != directory.name:
                raise ValueError(f"installed name mismatch: {directory.name}")
            content = (target / "SKILL.md").read_text(encoding="utf-8")
            for link in re.findall(r"\]\((references/[^)]+)\)", content):
                reference = (target / link).resolve()
                if not reference.is_relative_to(target.resolve()):
                    raise ValueError(f"reference escapes installed skill: {link}")
                reference.read_bytes()
            installed.append(target)
        prompt = ET.fromstring(to_prompt(installed))
        discovered = {
            node.findtext("name", "").strip(): node.findtext("location", "").strip()
            for node in prompt.findall("skill")
        }
        expected = {target.name: str((target / "SKILL.md").resolve()) for target in installed}
        if discovered != expected:
            raise ValueError("skills-ref prompt did not discover every copied skill at its installed path")
        print(f"Install smoke passed: copied {len(installed)} skills, validated metadata, read linked references, and resolved skills-ref prompt locations.")
        print("This verifies filesystem packaging and reference discovery, not discovery by a particular coding agent.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
