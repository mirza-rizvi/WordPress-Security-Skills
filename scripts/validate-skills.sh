#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

required_headings=(
  "## When to use this skill"
  "## Core principles (and why they matter)"
  "## Step-by-step implementation"
  "## Common AI mistakes / anti-patterns"
  "## Correct code examples"
  "## Checklist"
  "## Official references"
)

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

warn() {
  printf 'WARNING: %s\n' "$1" >&2
}

command -v rg >/dev/null 2>&1 || fail "rg is required."
command -v python3 >/dev/null 2>&1 || fail "python3 is required."
python3 scripts/validate-content.py
python3 scripts/validate-markdown.py

for skill_file in skills/*/SKILL.md; do
  line_count="$(wc -l < "$skill_file")"
  [ "$line_count" -le 500 ] || fail "$skill_file has ${line_count} lines (max 500)."

  heading_lines=()
  for heading in "${required_headings[@]}"; do
    line="$(rg -n -x -F "$heading" "$skill_file" | cut -d: -f1 || true)"
    [ -n "$line" ] || fail "$skill_file missing heading: $heading"
    [[ "$line" != *$'\n'* ]] || fail "$skill_file repeats heading: $heading"
    heading_lines+=("$line")
  done

  previous=0
  for line in "${heading_lines[@]}"; do
    [ "$line" -gt "$previous" ] || fail "$skill_file headings are out of order."
    previous="$line"
  done

  python3 - "$skill_file" "${heading_lines[2]}" "${heading_lines[3]}" <<'PY'
from pathlib import Path
import re
import sys

skill_file = Path(sys.argv[1])
lines = skill_file.read_text(encoding="utf-8").splitlines()
heading = "### Supporting references"
positions = [index for index, line in enumerate(lines) if line == heading]


def fail(message):
    sys.exit(f"ERROR: {skill_file} {message}")


if len(positions) != 1:
    fail(f"must contain exactly one {heading} subsection (found {len(positions)}).")
start = positions[0]
if not int(sys.argv[2]) < start + 1 < int(sys.argv[3]):
    fail(f"must place {heading} between the step-by-step and anti-pattern headings.")
end = next(
    (index for index in range(start + 1, len(lines)) if re.match(r"^#{2,3}(?:\s|$)", lines[index])),
    len(lines),
)
subsection = lines[start + 1:end]


def cells(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


has_table = any(
    cells(header) == ["Reference", "Load when"]
    and len(cells(separator)) == 2
    and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells(separator))
    for header, separator in zip(subsection, subsection[1:])
)
if not has_table:
    fail(f"{heading} must contain a table with columns Reference and Load when.")

section_text = "\n".join(subsection)
for reference in sorted((skill_file.parent / "references").rglob("*")):
    if reference.is_file():
        relative_path = reference.relative_to(skill_file.parent).as_posix()
        if f"]({relative_path})" not in section_text:
            fail(f"{heading} is missing reference: {relative_path}")
PY

  while IFS= read -r reference_path; do
    [ -f "$(dirname "$skill_file")/$reference_path" ] || fail "$skill_file links missing reference: $reference_path"
  done < <(rg -o '\]\(references/[^)]+' "$skill_file" | sed 's/^](//' || true)
done

if compgen -G "skills/*/references/*.php" >/dev/null; then
  command -v php >/dev/null 2>&1 || fail "php is required for reference syntax validation."
  while IFS= read -r php_file; do
    php -l "$php_file" >/dev/null || fail "$php_file failed PHP syntax validation."
    if [ "$(basename "$php_file")" = "wp-config-hardening.php" ]; then
      continue
    fi
    rg -q "defined\\( 'ABSPATH' \\) \\|\\| exit;" "$php_file" || fail "$php_file missing ABSPATH guard."

    # Heuristic: state-changing PHP examples should pair a nonce check with a capability check.
    # Suppress with a comment containing: validate-skills:ignore-state-change-checks
    if ! rg -q 'validate-skills:ignore-state-change-checks' "$php_file" && \
       rg -q '\$wpdb->(insert|update|delete|query)|update_option|wp_handle_upload|unlink' "$php_file"; then
      has_capability="$(rg -q 'current_user_can' "$php_file" && echo 1 || echo 0)"
      has_nonce="$(rg -q 'check_admin_referer|check_ajax_referer|wp_verify_nonce' "$php_file" && echo 1 || echo 0)"
      if [ "$has_capability" -eq 0 ] || [ "$has_nonce" -eq 0 ]; then
        warn "$php_file performs a state-changing operation but is missing a nonce or capability check. Add one, or suppress with a comment explaining why this data-layer example is exempt."
      fi
    fi
  done < <(find skills -path '*/references/*.php' -type f | sort)
fi

# Optional PHPCS/WPCS check. Uses a locally installed phpcs or phpcs.phar; CI downloads the PHAR + deps.
phpcs_bin=""
if command -v phpcs >/dev/null 2>&1; then
  phpcs_bin="phpcs"
elif [ -x "./phpcs.phar" ]; then
  phpcs_bin="./phpcs.phar"
fi

if [ -n "$phpcs_bin" ] && [ -f "phpcs.xml.dist" ]; then
  "$phpcs_bin" --standard=phpcs.xml.dist skills/*/references/*.php || fail "PHPCS found violations."
else
  warn "PHPCS not found or phpcs.xml.dist missing (run without it). CI installs the pinned PHAR + WPCS."
fi

printf 'Skill validation passed.\n'
