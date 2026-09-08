#!/usr/bin/env bash
set -euo pipefail

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

if ! compgen -G "skills/*/SKILL.md" >/dev/null; then
  fail "No skill files found at skills/*/SKILL.md."
fi

for skill_file in skills/*/SKILL.md; do
  skill_dir="$(basename "$(dirname "$skill_file")")"

  first_line="$(sed -n '1p' "$skill_file")"
  [ "$first_line" = "---" ] || fail "$skill_file must start with YAML frontmatter."

  frontmatter_end="$(awk 'NR > 1 && $0 == "---" { print NR; exit }' "$skill_file")"
  [ -n "$frontmatter_end" ] || fail "$skill_file has no closing frontmatter delimiter."

  frontmatter="$(sed -n "1,${frontmatter_end}p" "$skill_file")"
  name="$(printf '%s\n' "$frontmatter" | awk -F': *' '$1 == "name" { print $2; exit }')"
  [ -n "$name" ] || fail "$skill_file frontmatter is missing name."
  [ "$name" = "$skill_dir" ] || fail "$skill_file name '$name' does not match directory '$skill_dir'."

  printf '%s\n' "$frontmatter" | rg -q '^description:' || fail "$skill_file frontmatter is missing description."

  description_value="$(printf '%s\n' "$frontmatter" | awk '
    /^description:/ {
      in_desc = 1
      sub(/^description:[[:space:]]*>?[[:space:]]*/, "")
      text = text $0
      next
    }
    in_desc && /^[a-zA-Z0-9_-]+:/ { in_desc = 0 }
    in_desc {
      sub(/^[[:space:]]+/, "")
      text = text $0
    }
    END { print text }
  ')"

  description_length="${#description_value}"
  [ "$description_length" -le 1024 ] || fail "$skill_file description is ${description_length} characters."

  case "$description_value" in
    "Use when"*) ;;
    *) fail "$skill_file description must start with 'Use when'." ;;
  esac

  line_count="$(wc -l < "$skill_file")"
  [ "$line_count" -le 500 ] || fail "$skill_file has ${line_count} lines (max 500)."

  heading_lines=()
  for heading in "${required_headings[@]}"; do
    line="$(rg -n -F "$heading" "$skill_file" | cut -d: -f1 | head -n 1 || true)"
    [ -n "$line" ] || fail "$skill_file missing heading: $heading"
    heading_lines+=("$line")
  done

  previous=0
  for line in "${heading_lines[@]}"; do
    [ "$line" -gt "$previous" ] || fail "$skill_file headings are out of order."
    previous="$line"
  done

  while IFS= read -r reference_path; do
    [ -f "$(dirname "$skill_file")/$reference_path" ] || fail "$skill_file links missing reference: $reference_path"
  done < <(rg -o '\]\(references/[^)]+' "$skill_file" | sed 's/^](//' || true)
done

if compgen -G "skills/*/references/*.php" >/dev/null; then
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
  $phpcs_bin --standard=phpcs.xml.dist skills/*/references/*.php || fail "PHPCS found violations."
else
  warn "PHPCS not found or phpcs.xml.dist missing (run without it). CI installs the pinned PHAR + WPCS."
fi

printf 'Skill validation passed.\n'
