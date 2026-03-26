#!/usr/bin/env bash
# shellcheck disable=SC2310  # functions in if/! conditions are intentional
# ============================================================================
# .githooks/check-hygiene.sh
# ============================================================================
#
# Server-side enforcement of repository hygiene.  Run in CI on every push
# and pull request so violations CANNOT be merged, even if a contributor
# bypasses the pre-commit hook with --no-verify.
#
# Checks all three invariants:
#   RULE 1 -- LINE ENDINGS:  No CR (\r) bytes in any text file.
#   RULE 2 -- PERMISSIONS:   Every file is mode 100644 (no executable bit).
#   RULE 3 -- ENCODING:      ASCII only (bytes 10, 32-126) outside exempt paths.
#
# Usage:
#   bash .githooks/check-hygiene.sh           # check ALL tracked files
#   bash .githooks/check-hygiene.sh --diff    # check only files changed vs base
#                                      # (reads GITHUB_BASE_REF; falls back
#                                      #  to origin/main)
#
# GitHub Actions integration:
#   Violations emit ::error annotations so they appear inline on the PR diff.
#
# Exit codes:
#   0 = all checks pass
#   1 = one or more violations
#
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CONFIGURATION -- keep in sync with .githooks/pre-commit
# ---------------------------------------------------------------------------

# Files allowed to have the executable bit (mode 100755).
EXEC_ALLOWLIST=(
  ".githooks/check-hygiene.sh"
  ".githooks/pre-commit"
)

# Paths exempt from the ASCII-only encoding check (Rule 3).
ASCII_EXEMPT_PATTERNS=(
  "^docs/"
  "^README\.md$"
)

# Files allowed to contain CR (\r) bytes (CRLF line endings).
# Keep in sync with the eol=crlf declarations in .gitattributes.
CRLF_ALLOWLIST=(
  "docs/make.bat"
)

# Extensions treated as binary (skipped for encoding and line-ending checks).
# Keep in sync with the "binary" declarations in .gitattributes.
BINARY_EXTENSIONS="png|jpg|jpeg|gif|ico|bmp|tiff|webp|pdf|woff|woff2|ttf|eot|otf"

# ---------------------------------------------------------------------------
# Determine which files to check
# ---------------------------------------------------------------------------

if [[ "${1:-}" == "--diff" ]]; then
  base="${GITHUB_BASE_REF:-main}"

  # Make sure the base ref is available (shallow clones in CI may not have it).
  git fetch origin "${base}" --depth=1 2> /dev/null || true

  mapfile -t files < <(
    git diff --name-only --diff-filter=ACMR "origin/${base}...HEAD" 2> /dev/null || true
  )

  echo "Mode: diff against origin/${base}"
else
  mapfile -t files < <(git ls-files || true)

  echo "Mode: all tracked files"
fi

echo "Files to check: ${#files[@]}"
echo ""

if [[ ${#files[@]} -eq 0 ]]; then
  echo "Nothing to check."
  exit 0
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

fail=0
perm_count=0
encoding_count=0
cr_count=0

is_exec_allowed() {
  local file="${1}"
  for allowed in "${EXEC_ALLOWLIST[@]+"${EXEC_ALLOWLIST[@]}"}"; do
    [[ "${file}" == "${allowed}" ]] && return 0
  done
  return 1
}

is_ascii_exempt() {
  local file="${1}"
  for pattern in "${ASCII_EXEMPT_PATTERNS[@]}"; do
    if [[ "${file}" =~ ${pattern} ]]; then
      return 0
    fi
  done
  return 1
}

is_binary() {
  local file="${1}"
  [[ "${file}" =~ \.(${BINARY_EXTENSIONS})$ ]]
}

is_crlf_allowed() {
  local file="${1}"
  for allowed in "${CRLF_ALLOWLIST[@]+"${CRLF_ALLOWLIST[@]}"}"; do
    [[ "${file}" == "${allowed}" ]] && return 0
  done
  return 1
}

# Emit a GitHub Actions annotation if running in CI, otherwise plain text.
# Usage: annotate "error" "file.py" "Message"
annotate() {
  local level="${1}" file="${2}" msg="${3}"
  if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    echo "::${level} file=${file}::${msg}"
  else
    echo "[${level^^}] ${file}: ${msg}"
  fi
}

# ---------------------------------------------------------------------------
# RULE 2 -- Permissions
# ---------------------------------------------------------------------------

for file in "${files[@]}"; do
  mode=$(git ls-files -s -- "${file}" 2> /dev/null | awk '{print $1}')

  if [[ "${mode}" == "100755" ]]; then
    if ! is_exec_allowed "${file}"; then
      annotate "error" "${file}" \
        "File has executable bit (mode 100755). Expected 100644. Fix: git update-index --chmod=-x \"${file}\""
      ((perm_count++))
      fail=1
    fi
  fi
done

# ---------------------------------------------------------------------------
# RULE 3 -- Encoding
# ---------------------------------------------------------------------------

for file in "${files[@]}"; do
  if is_ascii_exempt "${file}"; then continue; fi
  if is_binary "${file}"; then continue; fi

  # Read from HEAD for full-repo mode, from the file for diff mode
  # (the file on disk in CI is the checked-out version of the PR head).
  bad_count=$(git show "HEAD:${file}" 2> /dev/null \
    | LC_ALL=C grep -Pc '[^\x0a\x20-\x7e]' 2> /dev/null || true)

  if [[ -n "${bad_count}" ]] && [[ "${bad_count}" -gt 0 ]]; then
    # Grab the first offending line for diagnostic context.
    first_bad=$(git show "HEAD:${file}" 2> /dev/null \
      | LC_ALL=C grep -Pn '[^\x0a\x20-\x7e]' 2> /dev/null \
      | head -1)
    annotate "error" "${file}" \
      "File contains ${bad_count} line(s) with non-ASCII bytes. First: ${first_bad}"
    ((encoding_count++))
    fail=1
  fi
done

# ---------------------------------------------------------------------------
# RULE 1 -- Line endings (CR bytes)
# ---------------------------------------------------------------------------

for file in "${files[@]}"; do
  if is_binary "${file}"; then continue; fi
  if is_crlf_allowed "${file}"; then continue; fi

  if git show "HEAD:${file}" 2> /dev/null | LC_ALL=C grep -Pq '\r' 2> /dev/null; then
    annotate "error" "${file}" \
      "File contains CR (\\r) bytes. Line endings must be LF only."
    ((cr_count++))
    fail=1
  fi
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

echo ""
echo "======================================"
echo "  Repository hygiene report"
echo "======================================"
echo "  Files checked:          ${#files[@]}"
echo "  Permission violations:  ${perm_count}"
echo "  Encoding violations:    ${encoding_count}"
echo "  Line-ending violations: ${cr_count}"
echo "======================================"

if [[ "${fail}" -ne 0 ]]; then
  echo ""
  echo "FAILED -- fix the errors above."
  echo ""
  echo "Quick reference:"
  [[ ${perm_count} -gt 0 ]] && echo "  Permissions:  git update-index --chmod=-x <file>"
  [[ ${encoding_count} -gt 0 ]] && echo "  Encoding:     replace non-ASCII bytes with ASCII equivalents"
  [[ ${cr_count} -gt 0 ]] && printf '  Line endings: sed -i '\''s/\\r//g'\'' <file>\n'
  exit 1
fi

echo ""
echo "All checks passed."
exit 0
