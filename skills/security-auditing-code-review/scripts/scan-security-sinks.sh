#!/usr/bin/env bash
# Read-only review inventory; requires Bash and ripgrep (rg).
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash scan-security-sinks.sh [DIRECTORY]

Inventory PHP entry points, security controls, and potentially sensitive sinks.
DIRECTORY defaults to the current directory. Requires Bash and ripgrep (rg).

This is a heuristic text search, NOT a security audit or vulnerability detector.
Hits include safe code, comments, and strings. No hits does not mean secure.
No parsing, data-flow analysis, authorization checks, or code execution occurs.
Only *.php, *.phtml, and *.inc files are searched, case-insensitively by extension.
Ripgrep ignore rules apply; hidden files, binary files, and symlinks are skipped.
Dynamic calls, multiline constructs, other extensions and ignored code need review.
Output includes source lines: keep it local and redact secrets before sharing.

Exit status: 0 = inventory completed (with or without hits), 2 = usage/search error.
HELP
}

if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi
root=${1:-.}
if [[ ! -d $root ]]; then
  printf 'ERROR: not a directory: %s\n' "$root" >&2
  exit 2
fi
if ! command -v rg >/dev/null 2>&1; then
  printf 'ERROR: ripgrep (rg) is required.\n' >&2
  exit 2
fi
# Enter the root so leading hyphens in its name cannot become rg options.
cd -- "$root" || exit 2
printf '%s\n' \
  'HEURISTIC INVENTORY ONLY — not an audit; hits are not findings; no hits is not proof of safety.' \
  'Scope: PHP/PHTML/INC; rg ignore rules apply; no hidden/binary files or symlink traversal.' \
  'Source lines may contain secrets. Review locally before sharing.'

inventory() {
  local label=$1 pattern=$2 status=0
  printf '\n## %s\n' "$label"
  rg --no-config --glob '!.*' --line-number --with-filename --no-heading --color never \
    --type-add 'inventory:*.[pP][hH][pP]' --type-add 'inventory:*.[pP][hH][tT][mM][lL]' \
    --type-add 'inventory:*.[iI][nN][cC]' --type inventory \
    -- "$pattern" . || status=$?
  if [[ $status -eq 1 ]]; then
    printf '(no textual matches in this scope)\n'
  elif [[ $status -ne 0 ]]; then
    printf 'ERROR: inventory incomplete while searching %s.\n' "$label" >&2
    exit 2
  fi
}

inventory 'Entry points and untrusted input' \
  'wp_ajax_|admin_post_|\b(register_rest_route|register_rest_field|add_shortcode|register_block_type|wp_schedule_event|wp_schedule_single_event)\s*\(|\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b'
inventory 'Authorization and CSRF controls (presence does not prove correct use)' \
  '\b(current_user_can|user_can|check_admin_referer|check_ajax_referer|wp_verify_nonce)\s*\(|permission_callback'
inventory 'Database operations (including safely prepared calls)' \
  '\$wpdb\s*->\s*(query|get_results|get_row|get_col|get_var|insert|update|delete|replace|prepare)\s*\('
inventory 'Output, redirects, headers and cookies (including escaped output)' \
  '\b(echo|print)\b|\b(printf|vprintf|header|setcookie|wp_redirect|wp_safe_redirect|wp_send_json|wp_send_json_success|wp_send_json_error|add_query_arg|remove_query_arg)\s*\(|<\?='
inventory 'Filesystem, upload, deserialization and code execution' \
  '\b(include|include_once|require|require_once)\b|\b(eval|assert|create_function|unserialize|maybe_unserialize|extract|readfile|unlink|fopen|fwrite|file_get_contents|file_put_contents|move_uploaded_file|wp_handle_upload|wp_handle_sideload|WP_Filesystem|exec|system|shell_exec|passthru|popen|proc_open)\s*\(|phar://'
inventory 'Outbound HTTP and remote assets' \
  '\b(wp_remote_get|wp_remote_post|wp_remote_request|wp_safe_remote_get|wp_safe_remote_post|wp_safe_remote_request|curl_exec|wp_enqueue_script|wp_enqueue_style)\s*\('
inventory 'Authentication, persistence and multisite boundaries' \
  '\b(wp_signon|wp_set_auth_cookie|wp_set_password|wp_insert_user|wp_update_user|update_option|update_site_option|update_user_meta|switch_to_blog|restore_current_blog|wc_get_order)\s*\('

printf '\nInventory completed. Trace each reachable path and its controls before reporting findings.\n'
