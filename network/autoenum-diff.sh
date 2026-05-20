#!/usr/bin/env bash
# autoenum-diff.sh — diff two auto-enum.sh output trees by their findings.json.
#
# Usage:
#   ./autoenum-diff.sh <prev-out-dir> <curr-out-dir>
#
# Compares the findings.json files (produced by network/report.py) in both
# trees and surfaces:
#   * NEW hosts that appear in curr but not prev
#   * NEW (host, service) pairs
#   * NEW findings (by host+service+line)
#   * DROPPED findings (gone in curr — usually means the host was patched
#     or the service was taken down)
#
# Exit 0 iff there are zero new findings. Exit 1 otherwise so a wrapper can
# alert. Run report.py against each output dir first if you haven't.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

R="\033[1;31m"; G="\033[1;32m"; Y="\033[1;33m"; C="\033[1;36m"; N="\033[0m"
[ -t 1 ] || { R=""; G=""; Y=""; C=""; N=""; }

if [ $# -ne 2 ]; then
    echo "usage: $0 <prev-out-dir> <curr-out-dir>"
    exit 2
fi
PREV="$1"; CURR="$2"

for d in "$PREV" "$CURR"; do
    [ -d "$d" ] || { echo "${R}[!]${N} not a directory: $d"; exit 2; }
    [ -f "$d/findings.json" ] || {
        echo "${Y}[?]${N} $d/findings.json missing — running report.py to materialize it"
        python3 "$SCRIPT_DIR/report.py" "$d" --findings-only >/dev/null || {
            echo "${R}[!]${N} report.py failed for $d"; exit 2
        }
    }
done

python3 - "$PREV/findings.json" "$CURR/findings.json" <<'PY'
import json, sys

prev = json.load(open(sys.argv[1]))
curr = json.load(open(sys.argv[2]))

def key_set(d, level):
    """level='host', 'host_svc', or 'finding' — what tuple to dedupe on."""
    s = set()
    for f in d["findings"]:
        if level == "host":
            s.add(f["host"])
        elif level == "host_svc":
            s.add((f["host"], f["service"]))
        else:
            s.add((f["host"], f["service"], f["severity"], f["line"][:120]))
    return s

print(f"=== diff: {prev['label']} -> {curr['label']} ===\n")

# Host-level
prev_hosts = set(prev["summary"]["hosts"])
curr_hosts = set(curr["summary"]["hosts"])
new_hosts = curr_hosts - prev_hosts
dropped_hosts = prev_hosts - curr_hosts

print(f"hosts:    prev={len(prev_hosts):4d}  curr={len(curr_hosts):4d}  "
      f"new={len(new_hosts):4d}  dropped={len(dropped_hosts):4d}")

# Service-level
prev_pairs = key_set(prev, "host_svc")
curr_pairs = key_set(curr, "host_svc")
new_pairs = curr_pairs - prev_pairs
dropped_pairs = prev_pairs - curr_pairs
print(f"host x service pairs: new={len(new_pairs):4d}  dropped={len(dropped_pairs):4d}")

# Finding-level
prev_findings = key_set(prev, "finding")
curr_findings = key_set(curr, "finding")
new_findings = curr_findings - prev_findings
dropped_findings = prev_findings - curr_findings

# Group by severity
sev_buckets = {"critical": [], "high": [], "medium": [], "low": []}
for f in new_findings:
    sev = f[2]
    sev_buckets.setdefault(sev, []).append(f)

print()
print("=== NEW FINDINGS ===")
for sev in ("critical", "high", "medium", "low"):
    items = sev_buckets.get(sev, [])
    if not items: continue
    print(f"\n--- {sev.upper()} ({len(items)}) ---")
    for host, svc, _, line in sorted(items):
        print(f"  [{svc:12s}] {host:20s}  {line[:120]}")

if dropped_findings:
    print(f"\n=== DROPPED ({len(dropped_findings)}) ===")
    for host, svc, sev, line in sorted(dropped_findings)[:30]:
        print(f"  [{svc:12s}] {host:20s}  {sev:8s}  {line[:100]}")
    if len(dropped_findings) > 30:
        print(f"  ... and {len(dropped_findings) - 30} more")

# Exit 1 iff there are new findings; useful for CI alerting
sys.exit(1 if new_findings else 0)
PY
PY_RC=$?
exit $PY_RC
