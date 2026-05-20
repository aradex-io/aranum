#!/usr/bin/env bash
# Example: IDOR sweep across User/Project/Runner GIDs.
# Anomaly signatures from the summary output are your candidates.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GQL="$SCRIPT_DIR/gql.py"

: "${GQL_URL:?set GQL_URL}"
: "${GQL_TOKEN:?set GQL_TOKEN (use a low-privilege account)}"

mkdir -p out

echo "--- User enumeration (1..500) ---"
"$GQL" loop user --vary id --gid-range 'gid://gitlab/User/1-500' \
        --select "id username name publicEmail webUrl" \
        --delay 0.05 | tee out/users.txt

echo
echo "--- Project enumeration by ID (1..500) — looking for private leakage ---"
"$GQL" loop project --vary fullPath --values-file out/probable_paths.txt \
        --select "id name visibility description" \
        --delay 0.05 | tee out/projects.txt 2>/dev/null || \
        echo "  (no out/probable_paths.txt — populate with one path/line; then re-run)"

echo
echo "--- Runner enumeration ---"
"$GQL" loop runner --vary id --gid-range 'gid://gitlab/Ci::Runner/1-1000' \
        --select "id runnerType description ipAddress accessLevel" \
        --delay 0.05 | tee out/runners.txt

echo
echo "Look at the bottom 'response-signature summary' of each — outliers (×1, ×2) are anomalies."
