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
    local path="$1"
    [ -r "$path" ] || return 2
    python3 - "$path" <<'PY'
import datetime
import pathlib
import re
import sys

try:
    content = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
except (OSError, UnicodeError):
    raise SystemExit(2)

headings = [line for line in content.split("\n") if line.startswith("## ")]
if len(headings) < 2 or headings[0] != "## [Unreleased]":
    raise SystemExit(2)

match = re.fullmatch(
    r"## \[v([0-9]+\.[0-9]+\.[0-9]+)\] — ([0-9]{4}-[0-9]{2}-[0-9]{2})",
    headings[1],
)
if match is None:
    raise SystemExit(2)

release_version, release_date = match.groups()
try:
    parsed_date = datetime.date.fromisoformat(release_date)
except ValueError:
    raise SystemExit(2)
if parsed_date.isoformat() != release_date:
    raise SystemExit(2)

print(f"{release_version}\t{release_date}")
PY
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

if ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    printf 'git: repository context is unavailable; release tag state is indeterminate\n'
    exit 1
fi
if ! matching_tags=$(git -C "$REPO_ROOT" tag --list "$latest_ver" 2>/dev/null); then
    printf 'git: could not query release tag %s; tag state is indeterminate\n' "$latest_ver"
    exit 1
fi

if printf '%s\n' "$matching_tags" | grep -Fqx "$latest_ver"; then
    if ! tag_commit=$(git -C "$REPO_ROOT" rev-parse -q --verify "$latest_ver^{commit}"); then
        printf 'git: released tag %s does not peel to a commit\n' "$latest_ver"
        exit 1
    fi
    git -C "$REPO_ROOT" merge-base --is-ancestor "$tag_commit" HEAD >/dev/null 2>&1
    ancestry_rc=$?
    case "$ancestry_rc" in
        0) ;;
        1)
            printf 'git: released tag %s is not an ancestor of the current HEAD\n' "$latest_ver"
            exit 1
            ;;
        *)
            printf 'git: could not verify released tag %s ancestry; tag state is indeterminate\n' \
                "$latest_ver"
            exit 1
            ;;
    esac
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
