#!/usr/bin/env python3
"""M7 harness (PLAN-001 S3): posture checks per OS that carry a KB test+fix.

Counts distinct check ids statically present in each collector as quoted
string literals ('LIN-…' / "WIN-…" / 'AD-…') and how many of them have a KB
check entry in network/finding-kb.json `checks` with >=1 test and >=1 fix.

Harness v2 (S3 Phase 6): v1 matched `POSTURE|<ID>|` literals, but the
collectors emit through helpers (`_p_emit LIN-X …`, `Write-PostureLine 'WIN-X'`),
so v1 would undercount to ~0. v2 was re-run at the S3 base 7e62404 (still 0/0 —
collectors absent) before head was measured; the delta is measured on v2 only.
Linux ids are bare words in shell (`_p_emit LIN-X`), so linux also accepts an
unquoted `_p_emit <ID>` call.
"""
import json, re, sys
from pathlib import Path

repo = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
collectors = {
    "linux": repo / "standalones/linux/host-posture.sh",
    "windows": repo / "standalones/windows/Invoke-HostPosture.ps1",
}
ID = re.compile(r"['\"]((?:LIN|WIN|AD)-[A-Z0-9][A-Z0-9-]*)['\"]")
EMIT = re.compile(r"_p_emit\s+['\"]?((?:LIN|AD)-[A-Z0-9][A-Z0-9-]*)")
kb_path = repo / "aranumtoolkit/network/finding-kb.json"
checks = {}
if kb_path.exists():
    checks = json.loads(kb_path.read_text()).get("checks", {}) or {}
for os_name, path in collectors.items():
    text = path.read_text(errors="replace") if path.exists() else ""
    ids = sorted(set(ID.findall(text)) | set(EMIT.findall(text)))
    covered = [i for i in ids if isinstance(checks.get(i), dict)
               and checks[i].get("test") and checks[i].get("fix")]
    print(f"{os_name}: collector_present={path.exists()} ids={len(ids)} kb_covered={len(covered)}")
