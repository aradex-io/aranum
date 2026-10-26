#!/usr/bin/env python3
"""Pinned method for BRAINSTORM-001 §1/§6.1 baselines (answers Mythos A-1/A-2).

Read-only. Imports report.py, reads only repo source + shipped fixtures.
Usage: python3 fixture_ungraded.py <aranum-repo-root>

Prints:
  1. static-emission grading under BOTH rule sets:
     - "harness" = _DEFAULT_RULES + _AD_DEPTH_RULES (what emission_audit.py uses; no generic fallbacks)
     - "runtime" = _compose_rules(_load_rules(None), _AD_DEPTH_RULES) (what report.main uses; +4 generic fallbacks)
  2. ungraded non-blank line ratios per fixture set, with the exact file filter and rule set used.
"""
import importlib.util
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "aranumtoolkit" / "tests"))
from _emission_corpus import extract_emissions  # noqa: E402

spec = importlib.util.spec_from_file_location("rep", root / "aranumtoolkit/network/report.py")
rep = importlib.util.module_from_spec(spec)
sys.modules["rep"] = rep
spec.loader.exec_module(rep)

RULESETS = {
    "harness": list(rep._DEFAULT_RULES) + list(rep._AD_DEPTH_RULES),
    "runtime": rep._compose_rules(rep._load_rules(None), rep._AD_DEPTH_RULES),
}
rows = extract_emissions(root)
for name, rules in RULESETS.items():
    c = Counter((r["kind"], rep._classify_line(r["text"], rules) is not None) for r in rows)
    print(f"[emissions/{name}] rules={len(rules)} " +
          " ".join(f"{k}:{'g' if g else 'u'}={v}" for (k, g), v in sorted(c.items())))

net = RULESETS["runtime"]
bulk_l = rep._compose_rules(rep._BULK_RULES, rep._AD_DEPTH_RULES)
bulk_w = rep._compose_rules(rep._BULK_RULES_WIN, rep._AD_DEPTH_RULES)
fx = root / "aranumtoolkit/docs/examples/dashboard/fixture"
tf = root / "aranumtoolkit/tests/fixtures"
SETS = [
    # (label, file list, rule set, filter description)
    ("dashboard-fixture (per-host *.txt under service dirs + _dispatcher.log; excludes run.log, _targets_*.txt)",
     [p for p in fx.glob("*/*/*.txt")] + list(fx.glob("*/_dispatcher.log")), net),
    ("bulk linenum.txt (tests/fixtures/bulk-enum/*/linenum.txt, bulk Linux rules)",
     list(tf.glob("bulk-enum/*/linenum.txt")), bulk_l),
    ("bulk winenum.txt (tests/fixtures/bulk-enum/*/winenum.txt, bulk Windows rules)",
     list(tf.glob("bulk-enum/*/winenum.txt")), bulk_w),
    ("ad-signals (tests/fixtures/ad-signals/*/*.txt, runtime network rules)",
     list(tf.glob("ad-signals/*/*.txt")), net),
]
for label, files, rules in SETS:
    tot = graded = 0
    for p in sorted(files):
        for ln in p.read_text(errors="replace").splitlines():
            if not ln.strip():
                continue
            tot += 1
            graded += rep._classify_line(ln, rules) is not None
    print(f"[fixture] {label}: files={len(files)} nonblank={tot} ungraded={tot - graded}")

# A-4 / H-2: how many fixture findings carry a non-vocabulary rule_id (crit-*/custom-*) or no KB class
kb = rep._load_finding_kb()
nonvocab = total = 0
for label, files, rules in SETS:
    for p in files:
        for ln in p.read_text(errors="replace").splitlines():
            m = rep._classify_line(ln, rules)
            if m is None:
                continue
            total += 1
            if m.rule_id not in kb["classes"]:
                nonvocab += 1
print(f"[vocab] graded fixture lines={total} rule_id-not-a-KB-class={nonvocab}")
