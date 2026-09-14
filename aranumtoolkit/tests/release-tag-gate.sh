#!/usr/bin/env bash
# Release consistency policy shared by smoke.sh and focused policy fixtures.

set -uo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CHANGELOG_FILE="$REPO_ROOT/CHANGELOG.md"
VERSION_FILE="$REPO_ROOT/VERSION"

latest_ver=$(grep -oE '^## \[v[0-9]+\.[0-9]+\.[0-9]+\]' "$CHANGELOG_FILE" 2>/dev/null \
    | head -1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' || true)
if [ -z "$latest_ver" ]; then
    printf 'git: could not derive latest released version from CHANGELOG.md\n'
    exit 2
fi

if [ ! -f "$VERSION_FILE" ]; then
    printf 'version: VERSION file is missing\n'
    exit 1
fi

vfile=$(tr -d '[:space:]' < "$VERSION_FILE")
if [ "v$vfile" != "$latest_ver" ]; then
    printf 'version: VERSION (%s) != CHANGELOG latest release (%s)\n' "$vfile" "$latest_ver"
    exit 1
fi

if git -C "$REPO_ROOT" tag --list "$latest_ver" | grep -Fqx "$latest_ver"; then
    printf 'version: VERSION (%s) matches CHANGELOG; released tag %s is present\n' \
        "$vfile" "$latest_ver"
    exit 0
fi

if [ "${GITHUB_ACTIONS:-}" = "true" ] && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
    printf 'version: VERSION (%s) matches CHANGELOG; tag %s may be created after this release PR merges\n' \
        "$vfile" "$latest_ver"
    exit 0
fi

printf 'git: latest released tag %s MISSING — allowed only in GitHub pull_request CI\n' "$latest_ver"
exit 1
