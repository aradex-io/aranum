#!/usr/bin/env python3
"""Benefit harness: static dispatcher-emission corpus -> classifier FP/FN audit.

Extracts every literal hit/miss/err/crit/log "..." call from
aranumtoolkit/network/enum-*.sh, renders it the way _lib.sh prints it
([+] / [-] / [!] / [!!] / [HH:MM:SS]), substitutes shell vars with plausible
tokens, and runs report.py's classifier (default + AD-depth rules) over each.

Metrics (pre-registered, see the plan doc):
  neg_graded   miss/log lines that the classifier grades as a finding (FP)
  crit_ungraded crit/err "CRITICAL" lines the classifier does not grade (FN)
Usage: emission_audit.py <repo-root> [--json OUT]
"""
import importlib.util, json, re, sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("rep", root / "aranumtoolkit/network/report.py")
rep = importlib.util.module_from_spec(spec); sys.modules["rep"] = rep; spec.loader.exec_module(rep)
rules = rep._DEFAULT_RULES + rep._AD_DEPTH_RULES
classify = getattr(rep, "_classify_line", None) or rep._classify

MARK = {"hit": "[+] ", "miss": "[-] ", "err": "[!] ", "crit": "[!!] ", "log": "[10:00:00] "}
call = re.compile(r'(?<![\w-])(hit|miss|err|crit|log)\s+"((?:[^"\\]|\\.)*)"')
VARS = {"ip": "10.0.0.9", "port": "8080", "host": "10.0.0.9", "url": "http://10.0.0.9:8080"}
def render(s):
    s = re.sub(r"\$\(([^()]*)\)", "3", s)
    s = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)[^}\s]*\}?", lambda m: VARS.get(m[1].lower(), "x"), s)
    return s.replace('\\"', '"')

rows = []
for f in sorted((root / "aranumtoolkit/network").glob("enum-*.sh")):
    for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for m in call.finditer(line):
            kind, text = m[1], render(m[2])
            out = MARK[kind] + text
            rows.append({"file": f.name, "line": n, "kind": kind, "text": out,
                         "sev": classify(out, rules)})

c = Counter((r["kind"], r["sev"] is not None) for r in rows)
neg = [r for r in rows if r["kind"] in ("miss", "log") and r["sev"]]
critu = [r for r in rows if (r["kind"] == "crit" or (r["kind"] == "err" and "CRITICAL" in r["text"])) and not r["sev"]]
summary = {"emissions": len(rows), "by_kind_graded": {f"{k}:{g}": v for (k, g), v in sorted(c.items())},
           "neg_graded": len(neg), "crit_ungraded": len(critu)}
print(json.dumps(summary, indent=1))
if "--json" in sys.argv:
    out = Path(sys.argv[sys.argv.index("--json") + 1])
    out.write_text(json.dumps({"summary": summary, "neg_graded": neg, "crit_ungraded": critu}, indent=1))

# ---- M4: labeled true-positive recall + severity accuracy (tp_labels.json)
lab = json.loads((Path(__file__).parent / "tp_labels.json").read_text())["labels"]
hit_rows = [r for r in rows if r["kind"] in ("hit", "err", "crit")]
recall = acc = present = 0
miss_list = []
for sub, want in lab:
    rs = [r for r in hit_rows if sub in r["text"]]
    if not rs:
        miss_list.append(("ABSENT", sub)); continue
    present += 1
    if all(r["sev"] for r in rs): recall += 1
    else: miss_list.append(("UNGRADED", sub))
    if all(r["sev"] == want for r in rs): acc += 1
print(json.dumps({"tp_labels": len(lab), "tp_present": present, "tp_recall": recall, "tp_sev_exact": acc}))
for m in miss_list: print(" ", *m)
