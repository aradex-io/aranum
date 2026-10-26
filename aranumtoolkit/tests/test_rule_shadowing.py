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
# Compose exactly as the walkers do, generic fallbacks LAST (REVIEW #1).
# Compose exactly as the walkers do (generic fallbacks LAST, REVIEW #1).
_DEFAULT = R._compose_rules(R._DEFAULT_RULES, R._AD_DEPTH_RULES)
_BULK = R._compose_rules(R._BULK_RULES, R._AD_DEPTH_RULES)


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
        gen_ids = R._GENERIC_FALLBACK_RULE_IDS
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
            # REVIEW #7a / ROUND2 #5: a substring check alone can pass when a
            # generic fallback's derived slug happens to contain the expected
            # substring, and checking only g.rule_id misses the case where the
            # specific rule was DELETED and the critical floor synthesised a
            # crit-* id from the generic CRITICAL pattern (that id is not in
            # gen_ids, so the gate would pass vacuously). Check PROVENANCE: the
            # matched rule's PATTERN must not be a generic fallback. For a floor
            # synthesis g.pattern is the generic CRITICAL marker, so removing the
            # specific rule turns this RED instead of silently passing.
            if R._derive_rule_id(g.pattern) in gen_ids:
                failures.append(f"{e['sample']!r}: graded via a GENERIC fallback pattern "
                                f"(id {g.rule_id!r}) — specific rule missing/shadowed")
        self.assertEqual(failures, [], "shadow-audit expectation failures:\n  " + "\n  ".join(failures))

    def test_expectation_table_is_not_vacuous(self):
        # REVIEW #7b: a shrunk/emptied table must not let the loop pass
        # vacuously. Pin a floor and total uniqueness of the samples.
        samples = [e["sample"] for e in _TABLE["expectations"]]
        self.assertGreaterEqual(len(samples), 25,
            f"expectation table shrank to {len(samples)} (floor is the 25 tp_labels)")
        self.assertEqual(len(samples), len(set(samples)),
            "duplicate samples in the expectation table")

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


class TestNoGenericShadowsSpecificAcrossCorpus(unittest.TestCase):
    """REVIEW #1 structural gate: across the composed walker rule list, on the
    whole real emission corpus, NO generic fallback rule (EXPOSED/UNAUTH/
    CRITICAL/[!!]) may win first-match over a specific rule — a generic can
    never steal a specific rule's id. The generic fallbacks are last by
    construction (report._compose_rules); this proves the invariant holds on
    actual dispatcher output, not just by rule order.

    RED proof (Phase 7c): put a generic back ahead of the specific rules
    (e.g. prepend _GENERIC_FALLBACK_RULES to _DEFAULT, or move \\bCRITICAL\\b to
    the front of _DEFAULT_RULES_RAW) and the offenders list becomes non-empty.
    """

    GEN_IDS = R._GENERIC_FALLBACK_RULE_IDS

    def _first_matches(self, clean):
        return [x for x in _DEFAULT if x.pattern.search(clean)]

    def test_corpus_has_lines_a_generic_could_shadow(self):
        # Anti-vacuous: the invariant is only meaningful if the corpus actually
        # contains lines that match BOTH a generic fallback and a specific rule
        # (so first-match order decides the id). If this collapses to ~0 the
        # gate proves nothing — fail loud.
        both = 0
        for r in _HIT:
            ms = self._first_matches(R._clean_line(r["text"]))
            if (any(x.rule_id in self.GEN_IDS for x in ms)
                    and any(x.rule_id not in self.GEN_IDS for x in ms)):
                both += 1
        self.assertGreaterEqual(both, 3,
            f"anti-vacuous: expected corpus lines a generic could shadow, found {both}")

    def test_no_generic_wins_first_match_over_a_specific_rule(self):
        offenders = []
        for r in _HIT:
            clean = R._clean_line(r["text"])
            ms = self._first_matches(clean)
            if len(ms) < 2:
                continue
            has_specific = any(x.rule_id not in self.GEN_IDS for x in ms)
            if has_specific and ms[0].rule_id in self.GEN_IDS:
                offenders.append((r["file"], r["line"], clean[:80], ms[0].rule_id))
        self.assertEqual(offenders, [],
            "a generic fallback won first-match over a specific rule:\n" +
            "\n".join(f"  {f}:{n} {t}  -> {rid}" for f, n, t, rid in offenders))


class TestFloorRuleId(unittest.TestCase):
    """ROUND2 #1: the line-derived KB key for a generic dispatcher critical with
    no specific rule keeps the URL PATH (distinct resources -> distinct keys)
    while collapsing volatile host/ip/port (same fact across hosts -> one key)."""

    def _fid(self, line):
        return R._floor_rule_id(R._clean_line(line))

    def test_distinct_url_paths_get_distinct_keys(self):
        a = self._fid("[!!] CRITICAL endpoint exposed: http://10.0.0.1/admin")
        b = self._fid("[!!] CRITICAL endpoint exposed: http://10.0.0.2/debug")
        self.assertNotEqual(a, b, "different resource paths must not collapse to one KB key")

    def test_same_fact_across_hosts_collapses(self):
        a = self._fid("[!!] CRITICAL endpoint exposed: http://10.0.0.1/admin")
        c = self._fid("[!!] CRITICAL endpoint exposed: http://10.0.0.9/admin")
        self.assertEqual(a, c, "the same critical fact on another host shares one KB key")


if __name__ == "__main__":
    unittest.main()
