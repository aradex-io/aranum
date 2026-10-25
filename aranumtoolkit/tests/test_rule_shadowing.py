#!/usr/bin/env python3
"""test_rule_shadowing.py — S1/D1.2 gate: expected rule id + severity per sample.

A frozen expectation table (fixtures/rule_expectations.json) names, for each
pre-registered sample, the severity it must grade at and a substring of the
SPECIFIC rule id that must win first-match. This catches rule shadowing — e.g.
the generic `EXPOSED` high rule stealing the critical Tomcat/Jenkins samples —
without using "longest literal" as a (bogus) specificity measure.

The NFS cross-list block asserts no_root_squash/no_all_squash/insecure grade
identically under the default walker order and the bulk walker order, so a
severity right in one rule list and wrong in another is caught.

RED proofs (Phase 7): moving the generic UNAUTH/EXPOSED rule back above the
Tomcat rule flips the Tomcat samples to the generic rule id (substring mismatch)
and to `high` (severity mismatch).

Run: python3 -m unittest tests.test_rule_shadowing
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
FIXTURE = REPO / "aranumtoolkit" / "tests" / "fixtures" / "rule_expectations.json"
sys.path.insert(0, str(REPO / "aranumtoolkit" / "tests"))
from _emission_corpus import extract_emissions  # noqa: E402


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_shadow", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()
_TABLE = json.loads(FIXTURE.read_text())
_CORPUS = extract_emissions(REPO)
_HIT = [r for r in _CORPUS if r["kind"] in ("hit", "err", "crit")]
_DEFAULT = list(R._DEFAULT_RULES) + list(R._AD_DEPTH_RULES)
_BULK = list(R._BULK_RULES) + list(R._AD_DEPTH_RULES)


def _emission_for(sample: str) -> str:
    """Return the real corpus emission text containing `sample` (so the audit
    runs on the bytes the dispatcher actually prints, not a synthetic line)."""
    for r in _HIT:
        if sample in r["text"]:
            return r["text"]
    raise AssertionError(f"sample not present in corpus: {sample!r}")


class TestCorpusIsReal(unittest.TestCase):
    def test_anti_vacuous(self):
        self.assertGreaterEqual(len(_CORPUS), 500, "extractor regressed")
        self.assertTrue(any("UNAUTH: Tomcat Manager exposed:" in r["text"] for r in _HIT),
                        "Tomcat Manager sample missing — extractor/dispatcher regressed")


class TestExpectedRuleAndSeverity(unittest.TestCase):
    """Every table entry: the default-walker first-match must be the expected
    severity AND the expected specific rule (by rule_id substring)."""

    def test_each_sample_matches_expectation(self):
        failures = []
        for e in _TABLE["expectations"]:
            text = _emission_for(e["sample"])
            g = R._classify_line(text, _DEFAULT)
            if g is None:
                failures.append(f"{e['sample']!r}: ungraded (want {e['severity']})")
                continue
            if g.severity != e["severity"]:
                failures.append(f"{e['sample']!r}: severity {g.severity} != {e['severity']}")
            if e["rule_id_substr"] not in g.rule_id:
                failures.append(f"{e['sample']!r}: rule_id {g.rule_id!r} lacks {e['rule_id_substr']!r} "
                                f"(shadowed by a different rule?)")
        self.assertEqual(failures, [], "shadow-audit expectation failures:\n  " + "\n  ".join(failures))

    def test_table_covers_every_tp_label(self):
        labels = {s for s, _ in json.loads(
            (REPO / "docs" / "test-strategy" / "harness" / "tp_labels.json").read_text())["labels"]}
        covered = {e["sample"] for e in _TABLE["expectations"]}
        self.assertEqual(labels - covered, set(),
                         f"tp_labels not covered by the expectation table: {labels - covered}")


class TestNfsCrossList(unittest.TestCase):
    """The no_root_squash divergence case: the NFS rules must grade identically
    under the default order and the bulk order."""

    def test_nfs_rules_consistent_across_lists(self):
        for e in _TABLE["cross_list_nfs"]:
            text = _emission_for(e["sample"])
            gd = R._classify_line(text, _DEFAULT)
            gb = R._classify_line(text, _BULK)
            self.assertIsNotNone(gd, f"{e['sample']}: ungraded under default rules")
            self.assertIsNotNone(gb, f"{e['sample']}: ungraded under bulk rules")
            self.assertEqual(gd.severity, e["severity"], f"{e['sample']}: default severity")
            self.assertEqual(gb.severity, e["severity"],
                             f"{e['sample']}: bulk severity {gb.severity} != default {e['severity']}")


if __name__ == "__main__":
    unittest.main()
