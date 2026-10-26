#!/usr/bin/env python3
"""Build a per-test identity->status manifest from a raw test-output dir.
Usage: manifest.py <dir>  (expects pytest.log, unittest.log, smoke*.log)"""
import json, re, sys, glob, os
from collections import Counter
B = sys.argv[1]
m = {}
ansi = re.compile(r"\x1b\[[0-9;]*m")
for l in open(os.path.join(B, "pytest.log")):
    r = re.match(r"^(aranumtoolkit/\S+::\S+) (PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)", l)
    if r: m["pytest::" + r[1]] = r[2]
for l in open(os.path.join(B, "unittest.log")):
    r = re.match(r"^(\S+) \((\S+)\) \.\.\. (ok|FAIL|ERROR|skipped.*)$", l.strip())
    if r: m["unittest::" + r[2]] = r[3].split()[0]
smoke = sorted(glob.glob(os.path.join(B, "smoke*.log")))[-1]
for l in open(smoke):
    l = ansi.sub("", l).rstrip()
    r = re.match(r"^\s*\[(\+|-|!|SKIP|PASS|FAIL)\]\s+(.*)$", l)
    if r: m["smoke::" + r[2]] = r[1]
json.dump(m, open(os.path.join(B, "manifest.json"), "w"), indent=0, sort_keys=True)
print(len(m), dict(Counter(k.split("::")[0] + ":" + v for k, v in m.items())))
