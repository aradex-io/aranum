#!/usr/bin/env python3
"""Frozen M4/M5 benefit counter for the example fixture (PLAN-001-25OCT2026).

Independent of report.py's own attribution/dedup code so the benefit number is
not measured by the thing it grades. Reads a findings.json and reports:
  M4  unattributed findings  = scope=="run" OR host=="(dispatcher)"
  M5  duplicate findings      = redundant "same fact twice" findings

A "fact" is a cluster of findings on the same (host, service) whose evidence
lines are the same statement — normalized (markers/timestamps/host/port stripped,
lowercased, whitespace-collapsed) and judged identical, substring, or token
Jaccard >= 0.7. Severity is ignored (a high echo of a critical is still a dup).
M5 counts the redundant members: sum(cluster_size - 1).

Usage: dup_audit.py <findings.json>
"""
import json, re, sys
from pathlib import Path

MARK = re.compile(r"^\s*(?:\[[0-9:]+\]\s*)?(?:\[[-+!*]{1,2}\]\s*)+")
TS = re.compile(r"\[[0-9]{1,2}:[0-9]{2}:[0-9]{2}\]")
IPPORT = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
WS = re.compile(r"\s+")


def norm(line: str) -> str:
    s = TS.sub("", line)
    s = MARK.sub("", s)
    s = IPPORT.sub("", s)
    return WS.sub(" ", s).strip().lower()


def toks(s: str):
    return set(w for w in re.findall(r"[a-z0-9]{2,}", s))


def same_fact(a: str, b: str) -> bool:
    if a == b:
        return True
    if a and b and (a in b or b in a):
        return True
    ta, tb = toks(a), toks(b)
    if not ta or not tb:
        return False
    j = len(ta & tb) / len(ta | tb)
    return j >= 0.7


def main() -> int:
    data = json.loads(Path(sys.argv[1]).read_text())
    fs = data["findings"] if isinstance(data, dict) else data
    m4 = sum(1 for f in fs if f.get("scope") == "run" or f.get("host") == "(dispatcher)")
    groups: dict = {}
    for f in fs:
        groups.setdefault((f.get("host", ""), f.get("service", "")), []).append(norm(f.get("line", "")))
    m5 = 0
    for _, lines in groups.items():
        clusters: list[list[str]] = []
        for ln in lines:
            for cl in clusters:
                if any(same_fact(ln, x) for x in cl):
                    cl.append(ln); break
            else:
                clusters.append([ln])
        m5 += sum(len(cl) - 1 for cl in clusters)
    print(json.dumps({"total_findings": len(fs), "M4_unattributed": m4, "M5_duplicates": m5}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
