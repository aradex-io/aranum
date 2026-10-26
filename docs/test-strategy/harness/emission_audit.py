#!/usr/bin/env python3
"""Benefit harness: static dispatcher-emission corpus -> classifier FP/FN audit.

Uses the shared extractor (aranumtoolkit/tests/_emission_corpus.py) so the
corpus this benefit number is measured on is byte-for-byte the corpus the S1
gates assert on — they cannot drift. Each rendered emission is run through
report.py's classifier guard (_classify_line, default + AD-depth rules).

Metrics (pre-registered, see PLAN-001-25OCT2026):
  neg_graded     miss/log lines the classifier grades as a finding (FP)   -> M1
  crit_ungraded  crit/err "CRITICAL" lines the classifier does not grade  -> M2
  tp_recall      labeled true positives that still grade                  -> M3
  tp_sev_exact   labeled true positives that grade at the exact severity  -> M3b

Usage: emission_audit.py <repo-root> [--json OUT]
"""
import importlib.util, json, sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "aranumtoolkit" / "tests"))
from _emission_corpus import extract_emissions  # noqa: E402

spec = importlib.util.spec_from_file_location("rep", root / "aranumtoolkit/network/report.py")
rep = importlib.util.module_from_spec(spec); sys.modules["rep"] = rep; spec.loader.exec_module(rep)
rules = list(rep._DEFAULT_RULES) + list(rep._AD_DEPTH_RULES)
classify = getattr(rep, "_classify_line", None) or rep._classify


def _sev(text):
    """Severity string for a rendered line, or None. Normalizes the D1.0 Rule
    return (classify now returns a Rule namedtuple, not a bare severity)."""
    m = classify(text, rules)
    if m is None:
        return None
    return getattr(m, "severity", m)  # tolerate either return shape


rows = extract_emissions(root)
for r in rows:
    r["sev"] = _sev(r["text"])

c = Counter((r["kind"], r["sev"] is not None) for r in rows)
neg = [r for r in rows if r["kind"] in ("miss", "log") and r["sev"]]
critu = [r for r in rows if (r["kind"] == "crit" or (r["kind"] == "err" and "CRITICAL" in r["text"])) and not r["sev"]]
summary = {"emissions": len(rows), "by_kind_graded": {f"{k}:{g}": v for (k, g), v in sorted(c.items())},
           "neg_graded": len(neg), "crit_ungraded": len(critu)}
print(json.dumps(summary, indent=1))
if "--json" in sys.argv:
    out = Path(sys.argv[sys.argv.index("--json") + 1])
    out.write_text(json.dumps({"summary": summary, "neg_graded": neg, "crit_ungraded": critu}, indent=1))

# ---- labeled true-positive recall + severity accuracy (tp_labels.json)
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
