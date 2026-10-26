#!/usr/bin/env python3
"""build_kb.py (S3) — fold the host/domain posture checks into finding-kb.json.

Adds a `checks` section keyed by POSTURE check id (LIN-*/WIN-*/AD-*). Each check
carries the catalog metadata (os, scope, group, category, title, sev_fail,
sev_warn, semantics) from catalog.json plus the peer-drafted, validated guidance
(why/test/fix/refs) from batches/P{1,2}-*.out.json (REVIEW-010 Part A).
Existing `classes` are left untouched. Run from the repo root.
"""
import json
import sys
from pathlib import Path

HERE = Path("docs/review/s3-posture-kb")
KB = Path("aranumtoolkit/network/finding-kb.json")
BATCHES = ["P1-linux", "P2-windows-ad"]

# Hand-authored additions made after the peer batches (REVIEW-010 R2: the check
# now grades channel binding too, so its guidance must cover it). Appended to the
# batch guidance, never replacing it.
ADDITIONS = {
    "AD-LDAP-SIGNING": {
        "why": (" Signing alone does not stop relay to LDAPS: without channel binding"
                " (LdapEnforceChannelBinding=2) a relayed NTLM bind over TLS is still accepted."),
        "test": [{"label": "Read LDAP channel-binding enforcement on each domain controller",
                  "cmd": "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LdapEnforceChannelBinding"}],
        "fix": [{"label": "Always enforce LDAP channel binding (after auditing clients with event 3039)",
                 "cmd": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters\" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f"}],
        "refs": ["https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server",
                 "https://support.microsoft.com/help/4520412"],
    },
}


def main() -> int:
    catalog = json.loads((HERE / "catalog.json").read_text())
    guidance: dict = {}
    for b in BATCHES:
        guidance.update(json.loads((HERE / "batches" / f"{b}.out.json").read_text()))
    kb = json.loads(KB.read_text())
    checks = {}
    missing = []
    for row in catalog:
        g = guidance.get(row["id"])
        if not g:
            missing.append(row["id"])
            continue
        if row["category"] not in kb["categories"]:
            print(f"unknown category {row['category']} for {row['id']}", file=sys.stderr)
            return 1
        checks[row["id"]] = {
            "os": row["os"], "scope": row["scope"], "group": row["group"],
            "category": row["category"], "title": row["title"],
            "sev_fail": row["sev_fail"], "sev_warn": row["sev_warn"],
            "semantics": row["semantics"],
            "why": g["why"], "test": g["test"], "fix": g["fix"], "refs": g["refs"],
        }
        add = ADDITIONS.get(row["id"])
        if add:
            c = checks[row["id"]]
            c["why"] = c["why"] + add["why"]
            c["test"] = c["test"] + add["test"]
            c["fix"] = c["fix"] + add["fix"]
            c["refs"] = c["refs"] + [r for r in add["refs"] if r not in c["refs"]]
    if missing:
        print(f"no guidance for: {missing}", file=sys.stderr)
        return 1
    kb["checks"] = checks
    KB.write_text(json.dumps(kb, indent=2) + "\n")
    by = {}
    for c in checks.values():
        by[c["os"]] = by.get(c["os"], 0) + 1
    print(f"wrote {KB} — {len(checks)} checks {by}, {len(kb['classes'])} classes unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
