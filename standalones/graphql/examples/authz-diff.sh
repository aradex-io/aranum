#!/usr/bin/env bash
# Example: GitLab authorization differential testing.
# Runs the same query as three identities, flags fields that leak to lower-priv.
#
# Setup:
#   export GQL_URL='https://gitlab.example.com/api/graphql'
#   ADMIN=glpat-AAA   REGULAR=glpat-BBB
#
# Target: a private project. Walk the high-value resolvers and diff.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GQL="$SCRIPT_DIR/gql.py"

: "${GQL_URL:?set GQL_URL}"
: "${ADMIN:?set ADMIN token}"
: "${REGULAR:?set REGULAR token (lower-privileged)}"
: "${TARGET_PATH:?set TARGET_PATH, e.g. mygroup/private-proj}"
: "${TARGET_USER_GID:?set TARGET_USER_GID, e.g. gid://gitlab/User/5}"
: "${TARGET_MR_GID:?set TARGET_MR_GID, e.g. gid://gitlab/MergeRequest/42}"

echo "=== diff: project ==="
"$GQL" diff project --arg "fullPath=$TARGET_PATH" \
        --as "admin:PRIVATE-TOKEN=$ADMIN" \
        --as "regular:PRIVATE-TOKEN=$REGULAR" \
        --as "anon:"

echo "=== diff: user (private email exposure check) ==="
"$GQL" diff user --arg "id=$TARGET_USER_GID" \
        --select "id username name publicEmail commitEmail" \
        --as "admin:PRIVATE-TOKEN=$ADMIN" \
        --as "regular:PRIVATE-TOKEN=$REGULAR" \
        --as "anon:"

echo "=== diff: mergeRequest (internal-note disclosure check) ==="
"$GQL" diff mergeRequest --arg "id=$TARGET_MR_GID" \
        --select '{ id title state confidential notes(first: 50) { nodes { internal body author { username } } } }' \
        --as "admin:PRIVATE-TOKEN=$ADMIN" \
        --as "regular:PRIVATE-TOKEN=$REGULAR" \
        --as "anon:"
