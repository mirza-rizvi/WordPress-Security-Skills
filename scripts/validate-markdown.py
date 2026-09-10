#!/usr/bin/env python3
"""Check public Markdown fences and pipe tables without modifying files."""

import argparse
import os
from pathlib import Path
import re
import sys


FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
SEPARATOR = re.compile(r":?-+:?\Z")


def cells(line):
    """Split only unescaped pipes, including pipes inside inline code (GFM)."""
    parts = []
    start = 0
    slashes = 0
    for index, char in enumerate(line):
        if char == "|" and slashes % 2 == 0:
            parts.append(line[start:index].strip())
            start = index + 1
        slashes = slashes + 1 if char == "\\" else 0
    if not parts:
        return None
    parts.append(line[start:].strip())
    if not parts[0]:
        parts.pop(0)
    if parts and not parts[-1]:
        parts.pop()
    return parts or None


def check(text):
    lines = text.splitlines()
    fence = None
    width = None
    issues = []
    for index, line in enumerate(lines):
        number = index + 1
        match = FENCE.match(line)
        if fence:
            if match and match[1][0] == fence[0] and len(match[1]) >= fence[1] and not match[2].strip():
                fence = None
            continue
        if match and not (match[1][0] == "`" and "`" in match[2]):
            fence = (match[1][0], len(match[1]), number)
            width = None
            continue
        row = cells(line)
        if not row or line.startswith("    ") or line.startswith("\t"):
            width = None
            continue
        following = cells(lines[index + 1]) if index + 1 < len(lines) else None
        separator = following and all(SEPARATOR.fullmatch(cell) for cell in following)
        # A delimiter row establishes a table; a leading pipe also signals an
        # intended table header. Ordinary prose containing a pipe is not a table.
        if width is not None:
            if len(row) != width:
                issues.append((number, "table-column-count", f"expected {width} columns, found {len(row)}"))
            continue
        if separator:
            width = len(row)
        elif line.lstrip().startswith("|"):
            issues.append((number, "table-missing-separator", "table header must be followed by a separator row"))
            width = len(row)
    if fence:
        issues.append((fence[2], "unclosed-code-fence", "code fence has no matching closing fence"))
    return sorted(issues)


def files_in(directory):
    def unreadable(error):
        raise error
    for root, _, filenames in os.walk(directory, onerror=unreadable):
        for name in filenames:
            if name.endswith(".md"):
                yield Path(root) / name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="files or directories (recursive Markdown scan)")
    args = parser.parse_args()
    try:
        paths = set()
        if args.paths:
            for path in args.paths:
                if path.is_file():
                    paths.add(path)
                elif path.is_dir():
                    paths.update(files_in(path))
                else:
                    parser.error(f"missing or unreadable path: {path}")
        else:
            paths.update(Path(name) for name in ("README.md", "CONTRIBUTING.md", "CHANGELOG.md", "SECURITY.md"))
            for directory in ("docs", ".github"):
                paths.update(Path(directory).glob("*.md"))
            for directory in ("eval", "skills"):
                paths.update(files_in(Path(directory)))
        defects = False
        for path in sorted(paths):
            for line, code, message in check(path.read_text(encoding="utf-8")):
                print(f"{path}:{line}: [{code}] {message}")
                defects = True
    except (OSError, UnicodeError) as exc:
        parser.error(str(exc))
    if defects:
        return 1
    print(f"Markdown validation passed: {len(paths)} files checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
