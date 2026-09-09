#!/usr/bin/env python3
"""Validate repository metadata and evaluation fixtures, not security correctness."""

import argparse
import json
from pathlib import Path
import re
import sys


NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
SCENARIO_FIELDS = {"name", "skills", "query", "expected_behavior", "success_criteria"}


def unique_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key!r}")
        result[key] = value
    return result


def nonempty_string(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a nonempty array")
    normalized = [nonempty_string(item, label).strip() for item in value]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{label} contains duplicate entries")
    return value


def validate_metadata(path):
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("PyYAML is required: python3 -m pip install PyYAML==6.0.3") from exc

    class UniqueLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node):
        return unique_mapping(
            (loader.construct_object(key), loader.construct_object(value))
            for key, value in node.value
        )

    UniqueLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
    )
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("must start with YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError("missing closing frontmatter delimiter") from exc
    try:
        data = yaml.load("\n".join(lines[1:end]), Loader=UniqueLoader)
    except (yaml.YAMLError, TypeError) as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("frontmatter must be a mapping")
    allowed = {"name", "description", "compatibility", "license", "metadata", "allowed-tools"}
    if set(data) - allowed:
        raise ValueError(f"unsupported frontmatter fields: {set(data) - allowed}")
    name = nonempty_string(data.get("name"), "name")
    if not NAME.fullmatch(name) or len(name) > 64 or name != path.parent.name:
        raise ValueError("name must match directory and use at most 64 lowercase letters/digits/single hyphens")
    description = nonempty_string(data.get("description"), "description")
    if not description.startswith("Use when") or len(description) > 1024:
        raise ValueError("description must start with 'Use when' and be at most 1024 characters")
    compatibility = nonempty_string(data.get("compatibility"), "compatibility")
    if len(compatibility) > 500:
        raise ValueError("compatibility must be at most 500 characters")
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in metadata.items()
    ):
        raise ValueError("metadata must map strings to strings")
    if "status" in metadata and metadata["status"] != "ready":
        raise ValueError("authored content is incomplete; finish it before removing metadata.status or setting it to ready")


def validate_scenarios(root, skill_names):
    paths = sorted((root / "eval" / "scenarios").glob("*.json"))
    if not paths:
        raise ValueError("no scenarios found at eval/scenarios/*.json")
    covered = set()
    names = set()
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_mapping)
            if not isinstance(data, dict):
                raise ValueError("scenario must be an object")
            if not SCENARIO_FIELDS <= data.keys() or data.keys() - SCENARIO_FIELDS - {"status"}:
                raise ValueError(f"required fields: {', '.join(sorted(SCENARIO_FIELDS))}; only optional field: status")
            if "status" in data and data["status"] != "ready":
                raise ValueError("scenario is incomplete; author it before removing status or setting it to ready")
            name = nonempty_string(data["name"], "name").strip()
            if name in names:
                raise ValueError(f"duplicate scenario name: {name}")
            names.add(name)
            nonempty_string(data["query"], "query")
            skills = string_list(data["skills"], "skills")
            unknown = set(skills) - skill_names
            if unknown:
                raise ValueError(f"unknown skills: {', '.join(sorted(unknown))}")
            string_list(data["expected_behavior"], "expected_behavior")
            string_list(data["success_criteria"], "success_criteria")
            covered.update(skills)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError(f"{path}: {exc}") from exc
    missing = skill_names - covered
    if missing:
        raise ValueError(f"skills without an evaluation scenario: {', '.join(sorted(missing))}")
    print(f"Scenario validation passed: {len(paths)} scenarios cover {len(covered)} skills (structural coverage only).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--metadata-only", action="store_true")
    mode.add_argument("--scenarios-only", action="store_true")
    args = parser.parse_args()
    try:
        directories = sorted(path for path in (args.root / "skills").iterdir() if path.is_dir())
        if not directories:
            raise ValueError("no skill directories found")
        for directory in directories:
            path = directory / "SKILL.md"
            if not path.is_file():
                raise ValueError(f"{path}: missing SKILL.md")
            if not args.scenarios_only:
                try:
                    validate_metadata(path)
                except ValueError as exc:
                    raise ValueError(f"{path}: {exc}") from exc
        if not args.scenarios_only:
            print(f"Metadata validation passed: {len(directories)} skills.")
        if not args.metadata_only:
            validate_scenarios(args.root, {path.name for path in directories})
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
