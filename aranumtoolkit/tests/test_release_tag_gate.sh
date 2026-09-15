#!/usr/bin/env bash
# Focused fixtures for the untagged release-PR exception.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$REPO_ROOT/aranumtoolkit/tests/release-tag-gate.sh"
FIXTURE=$(mktemp -d "${TMPDIR:-/tmp}/aranum-release-gate.XXXXXX")
trap 'rm -rf "$FIXTURE"' EXIT

git -C "$FIXTURE" init -q
git -C "$FIXTURE" config user.name 'aranum test'
git -C "$FIXTURE" config user.email 'test@invalid'
git -C "$FIXTURE" commit -q --allow-empty -m fixture
EMPTY_COMMIT=$(git -C "$FIXTURE" rev-parse HEAD)

write_valid_metadata() {
    printf '0.34.0\n' > "$FIXTURE/VERSION"
    printf '# Changelog\n\n## [Unreleased]\n\n## [v0.34.0] — 2026-09-14\n' \
        > "$FIXTURE/CHANGELOG.md"
}

write_valid_metadata

fail=0

if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    :
else
    printf 'FAIL: untagged GitHub pull_request release candidate was rejected\n' >&2
    fail=1
fi

if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=push bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: untagged GitHub push was accepted\n' >&2
    fail=1
fi

if env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: untagged local run was accepted\n' >&2
    fail=1
fi

printf '0.34.1\n' > "$FIXTURE/VERSION"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: mismatched VERSION/CHANGELOG was accepted in pull_request CI\n' >&2
    fail=1
fi
printf '0.34.0\n' > "$FIXTURE/VERSION"

mv "$FIXTURE/CHANGELOG.md" "$FIXTURE/CHANGELOG.valid"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: missing CHANGELOG was accepted in pull_request CI\n' >&2
    fail=1
fi

printf '# Changelog\n\n## [Unreleased]\n\n## malformed release heading\n' \
    > "$FIXTURE/CHANGELOG.md"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: malformed CHANGELOG was accepted in pull_request CI\n' >&2
    fail=1
fi
mv "$FIXTURE/CHANGELOG.valid" "$FIXTURE/CHANGELOG.md"

printf '# Changelog\n\n## [Unreleased]\n\n## [v0.34.0] — 2026-09-14 trailing-junk\n' \
    > "$FIXTURE/CHANGELOG.md"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: release heading with a valid prefix and trailing junk was accepted\n' >&2
    fail=1
fi

printf '# Changelog\n\n## [Unreleased]\n\n## [v0.34.0] — 2026-99-99\n' \
    > "$FIXTURE/CHANGELOG.md"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: release heading with an invalid calendar date was accepted\n' >&2
    fail=1
fi

printf '# Changelog\n\n## [v0.34.0] — 2026-09-14\n\n## [Unreleased]\n' \
    > "$FIXTURE/CHANGELOG.md"
if GITHUB_ACTIONS=true GITHUB_EVENT_NAME=pull_request bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: release heading before Unreleased was accepted\n' >&2
    fail=1
fi

write_valid_metadata
git -C "$FIXTURE" tag v0.34.0 "$EMPTY_COMMIT"
if env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME bash "$GATE" "$FIXTURE" >/dev/null; then
    printf 'FAIL: tag whose commit omits VERSION and CHANGELOG was accepted\n' >&2
    fail=1
fi
git -C "$FIXTURE" tag -d v0.34.0 >/dev/null

git -C "$FIXTURE" add VERSION CHANGELOG.md
git -C "$FIXTURE" commit -q -m 'release fixture'
git -C "$FIXTURE" tag v0.34.0
git -C "$FIXTURE" commit -q --allow-empty -m 'post-release fixture'
if env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME bash "$GATE" "$FIXTURE" >/dev/null; then
    :
else
    printf 'FAIL: valid tagged release was rejected after a later commit\n' >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    printf 'release tag gate fixtures passed\n'
fi
exit "$fail"
