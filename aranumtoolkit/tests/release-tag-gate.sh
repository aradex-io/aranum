#!/usr/bin/env bash
# Release consistency policy shared by smoke.sh and focused policy fixtures.

set -uo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
CHANGELOG_FILE="$REPO_ROOT/CHANGELOG.md"
VERSION_FILE="$REPO_ROOT/VERSION"

parse_version_file() {
    local path="$1"
    [ -r "$path" ] || return 1
    python3 - "$path" <<'PY'
import pathlib
import re
import sys

try:
    raw = pathlib.Path(sys.argv[1]).read_bytes()
except OSError:
    raise SystemExit(1)
match = re.fullmatch(rb"([0-9]+\.[0-9]+\.[0-9]+)\n?", raw)
if match is None:
    raise SystemExit(1)
print(match.group(1).decode("ascii"))
PY
}

parse_changelog_file() {
    local path="$1" content first_h2 release_line heading_re release_version release_date
    [ -r "$path" ] || return 2
    content=$(< "$path") || return 2
    first_h2=$(printf '%s\n' "$content" | grep -m1 '^## ' 2>/dev/null || true)
    if [ "$first_h2" != "## [Unreleased]" ]; then
        return 2
    fi
    release_line=$(printf '%s\n' "$content" | awk '
        seen_unreleased && /^## / { print; exit }
        $0 == "## [Unreleased]" { seen_unreleased=1 }
    ')
    heading_re='^## \[v([0-9]+\.[0-9]+\.[0-9]+)\] — ([0-9]{4}-[0-9]{2}-[0-9]{2})$'
    if [[ ! "$release_line" =~ $heading_re ]]; then
        return 2
    fi
    release_version="${BASH_REMATCH[1]}"
    release_date="${BASH_REMATCH[2]}"
    if ! python3 - "$release_date" <<'PY' >/dev/null 2>&1
import datetime
import sys

try:
    parsed = datetime.date.fromisoformat(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if parsed.isoformat() == sys.argv[1] else 1)
PY
    then
        return 2
    fi
    printf '%s\t%s\n' "$release_version" "$release_date"
}

if [ ! -f "$CHANGELOG_FILE" ]; then
    printf 'git: CHANGELOG.md is missing\n'
    exit 2
fi
if ! release_metadata=$(parse_changelog_file "$CHANGELOG_FILE"); then
    printf 'git: CHANGELOG.md must begin with ## [Unreleased] followed by a complete dated release heading\n'
    exit 2
fi
IFS=$'\t' read -r latest_version latest_date <<< "$release_metadata"
latest_ver="v$latest_version"

if [ ! -f "$VERSION_FILE" ]; then
    printf 'version: VERSION file is missing\n'
    exit 1
fi

if ! vfile=$(parse_version_file "$VERSION_FILE"); then
    printf 'version: VERSION must contain exactly one X.Y.Z version line\n'
    exit 1
fi
if [ "$vfile" != "$latest_version" ]; then
    printf 'version: VERSION (%s) != CHANGELOG latest release (%s)\n' "$vfile" "$latest_ver"
    exit 1
fi

if git -C "$REPO_ROOT" tag --list "$latest_ver" | grep -Fqx "$latest_ver"; then
    if ! tag_commit=$(git -C "$REPO_ROOT" rev-parse -q --verify "$latest_ver^{commit}"); then
        printf 'git: released tag %s does not peel to a commit\n' "$latest_ver"
        exit 1
    fi
    if ! git -C "$REPO_ROOT" cat-file -e "$tag_commit:VERSION" 2>/dev/null; then
        printf 'git: released tag %s does not contain VERSION\n' "$latest_ver"
        exit 1
    fi
    if ! tag_version=$(parse_version_file <(git -C "$REPO_ROOT" show "$tag_commit:VERSION")); then
        printf 'git: released tag %s contains malformed VERSION\n' "$latest_ver"
        exit 1
    fi
    if [ "$tag_version" != "$latest_version" ]; then
        printf 'git: released tag %s contains VERSION %s, expected %s\n' \
            "$latest_ver" "$tag_version" "$latest_version"
        exit 1
    fi
    if ! git -C "$REPO_ROOT" cat-file -e "$tag_commit:CHANGELOG.md" 2>/dev/null; then
        printf 'git: released tag %s does not contain CHANGELOG.md\n' "$latest_ver"
        exit 1
    fi
    if ! tag_metadata=$(parse_changelog_file \
        <(git -C "$REPO_ROOT" show "$tag_commit:CHANGELOG.md")); then
        printf 'git: released tag %s contains malformed CHANGELOG.md\n' "$latest_ver"
        exit 1
    fi
    IFS=$'\t' read -r tag_version tag_date <<< "$tag_metadata"
    if [ "$tag_version" != "$latest_version" ] || [ "$tag_date" != "$latest_date" ]; then
        printf 'git: released tag %s CHANGELOG release heading does not match %s / %s\n' \
            "$latest_ver" "$latest_version" "$latest_date"
        exit 1
    fi
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
