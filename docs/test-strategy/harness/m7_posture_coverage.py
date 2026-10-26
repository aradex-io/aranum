#!/usr/bin/env python3
"""M7 harness (PLAN-001 S3): posture checks per OS that carry a KB test+fix.

Counts distinct check ids statically emitted by each collector
(`POSTURE|<ID>|` literals) and how many of them have a KB check entry in
network/finding-kb.json `checks` with >=1 test and >=1 fix. Frozen: re-run
unchanged at the S3 base and head.
"""
import json, re, sys
from pathlib import Path

repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
collectors = {
    "linux": repo / "standalones/linux/host-posture.sh",
    "windows": repo / "standalones/windows/Invoke-HostPosture.ps1",
}
ID = re.compile(r"POSTURE\|([A-Z0-9][A-Z0-9-]*)\|")
kb_path = repo / "aranumtoolkit/network/finding-kb.json"
checks = {}
if kb_path.exists():
    checks = json.loads(kb_path.read_text()).get("checks", {}) or {}
for os_name, path in collectors.items():
    ids = sorted(set(ID.findall(path.read_text(errors="replace")))) if path.exists() else []
    covered = [i for i in ids if isinstance(checks.get(i), dict)
               and checks[i].get("test") and checks[i].get("fix")]
    print(f"{os_name}: collector_present={path.exists()} ids={len(ids)} kb_covered={len(covered)}")
