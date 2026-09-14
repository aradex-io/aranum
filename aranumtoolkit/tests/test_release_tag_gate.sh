#!/usr/bin/env bash
# Focused fixtures for the untagged release-PR exception.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATE="$REPO_ROOT/aranumtoolkit/tests/release-tag-gate.sh"
FIXTURE=$(mktemp -d "${TMPDIR:-/tmp}/aranum-release-gate.XXXXXX")
trap 'rm -rf "$FIXTURE"' EXIT

git -C "$FIXTURE" init -q
git -C "$FIXTURE" -c user.name='aranum test' -c user.email='test@invalid' \
    commit -q --allow-empty -m fixture
printf '0.34.0\n' > "$FIXTURE/VERSION"
printf '# Changelog\n\n## [Unreleased]\n\n## [v0.34.0] — 2026-09-14\n' \
    > "$FIXTURE/CHANGELOG.md"

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

git -C "$FIXTURE" tag v0.34.0
if env -u GITHUB_ACTIONS -u GITHUB_EVENT_NAME bash "$GATE" "$FIXTURE" >/dev/null; then
    :
else
    printf 'FAIL: tagged local release was rejected\n' >&2
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    printf 'release tag gate fixtures passed\n'
fi
exit "$fail"
