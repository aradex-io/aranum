#!/usr/bin/env python3
"""test_findings_fidelity.py — S1/D1.1 gate: the marker-aware classifier guard.

Proves the dispatcher-marker guard (`report._classify_line`) drives miss/log
false positives to zero while preserving the true positives that are
legitimately emitted through Miss()/Log() (the `miss_ok` rules).

Gates here:
  * the emission corpus is real (>= 500 rows, Tomcat sample present) so a
    broken extractor cannot pass vacuously;
  * every known miss/log false positive the RAW classifier would surface is
    suppressed by the guard (goes RED if the guard is removed/broken);
  * the disabled-privilege true positive, emitted on a `[-]` marker with either
    a hyphen or an em-dash, is preserved (goes RED if its rule loses miss_ok).

Run: python3 -m unittest tests.test_findings_fidelity
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
sys.path.insert(0, str(REPO / "aranumtoolkit" / "tests"))
from _emission_corpus import extract_emissions  # noqa: E402


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_fidelity", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()
# The composed rule order the default (auto-enum) walker uses — including the
# generic fallbacks the walker appends LAST (REVIEW #1).
_RULES = list(R._DEFAULT_RULES) + list(R._AD_DEPTH_RULES) + list(R._GENERIC_FALLBACK_RULES)
_CORPUS = extract_emissions(REPO)
_MISSLOG = [r for r in _CORPUS if r["kind"] in ("miss", "log")]


class TestCorpusIsReal(unittest.TestCase):
    """Anti-vacuous guards: a regressed extractor must not let the sweep pass."""

    def test_corpus_is_large(self):
        self.assertGreaterEqual(len(_CORPUS), 500,
            f"emission corpus collapsed to {len(_CORPUS)} rows — extractor regressed")

    def test_corpus_has_tomcat_and_misslog(self):
        self.assertTrue(any("Tomcat Manager" in r["text"] for r in _CORPUS),
            "Tomcat Manager sample missing — extractor or dispatcher regressed")
        self.assertGreaterEqual(len(_MISSLOG), 100,
            "too few miss/log lines — extractor regressed")


class TestGuardSuppressesMissLogFalsePositives(unittest.TestCase):
    """D1.1 gate (G01/G02). The RAW classifier surfaces N miss/log lines through
    non-miss_ok rules; those are dispatcher negatives/progress, i.e. false
    positives. The guard must suppress every one of them. RED if the guard is
    removed (then guarded == raw and the suppressed list is non-empty)."""

    def test_raw_corpus_actually_contains_false_positives(self):
        raw_fp = [r for r in _MISSLOG
                  if (m := R._classify(r["text"], _RULES)) is not None and not m.miss_ok]
        # If this ever drops to ~0 the gate has nothing to prove — fail loud so
        # the gate is never silently vacuous (baseline neg_graded == 18).
        self.assertGreaterEqual(len(raw_fp), 15,
            f"expected the known miss/log false positives in the corpus, found {len(raw_fp)}")

    def test_guard_drives_misslog_false_positives_to_zero(self):
        raw_fp = [r for r in _MISSLOG
                  if (m := R._classify(r["text"], _RULES)) is not None and not m.miss_ok]
        still_surfacing = [(r["file"], r["line"], r["text"])
                           for r in raw_fp
                           if R._classify_line(r["text"], _RULES) is not None]
        self.assertEqual(still_surfacing, [],
            "guard failed to suppress miss/log false positives:\n" +
            "\n".join(f"  {f}:{n} {t[:80]}" for f, n, t in still_surfacing))

    def test_no_misslog_line_surfaces_through_a_non_missok_rule(self):
        # The invariant the guard enforces, stated directly: after the guard,
        # a surviving miss/log finding can only come from a miss_ok rule.
        offenders = []
        for r in _MISSLOG:
            g = R._classify_line(r["text"], _RULES)
            if g is not None and not g.miss_ok:
                offenders.append((r["file"], r["line"], r["text"]))
        self.assertEqual(offenders, [], f"non-miss_ok survivors: {offenders}")


class TestMissOkPreservesTruePositives(unittest.TestCase):
    """The miss_ok override keeps a true positive emitted on a `[-]` marker,
    dash-agnostic. RED if the disabled-privilege rule loses its miss_ok flag."""

    WIN_RULES = None

    def setUp(self):
        self.WIN_RULES = list(R._BULK_RULES_WIN) + list(R._AD_DEPTH_RULES)

    def test_disabled_privilege_miss_line_preserved_emdash(self):
        line = "[-] SeImpersonatePrivilege (disabled — can still be enabled)"
        g = R._classify_line(line, self.WIN_RULES)
        self.assertIsNotNone(g, "em-dash disabled-privilege TP was suppressed")
        self.assertTrue(g.miss_ok, "disabled-privilege rule must be miss_ok")
        self.assertEqual(g.severity, "medium")

    def test_disabled_privilege_miss_line_preserved_hyphen_ntadjust(self):
        # Exactly the Test-CoercedAuth.ps1 Miss() emission.
        line = "[-] SeImpersonatePrivilege (disabled - can still be enabled via NtAdjustToken)"
        g = R._classify_line(line, self.WIN_RULES)
        self.assertIsNotNone(g, "hyphen/NtAdjustToken disabled-privilege TP was suppressed")
        self.assertTrue(g.miss_ok)

    def test_exactly_one_rule_is_missok(self):
        # The sweep sized the override set to a single rule; pin it so a stray
        # miss_ok flag added later is noticed.
        missok = [r for name in ("_DEFAULT_RULES", "_BULK_RULES", "_BULK_RULES_WIN", "_AD_DEPTH_RULES")
                  for r in getattr(R, name) if r.miss_ok]
        self.assertEqual(len(missok), 1,
            f"expected exactly one built-in miss_ok rule, found {len(missok)}: "
            f"{[r.pattern.pattern for r in missok]}")
        self.assertIn("disabled", missok[0].pattern.pattern)


class TestOperatorCustomRulesNeverSuppressed(unittest.TestCase):
    """Override 1: an operator --severity-rules match is never suppressed even
    on a miss/log marker (custom rules are always miss_ok)."""

    def test_custom_rule_on_miss_marker_is_kept(self):
        import tempfile, json as _json
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
            tf.write(_json.dumps({"pattern": r"ACME-CUSTOM-SIGNAL", "severity": "high"}) + "\n")
            path = Path(tf.name)
        try:
            rules = R._load_rules(path)
            line = "[-] ACME-CUSTOM-SIGNAL present on host"
            g = R._classify_line(line, rules)
            self.assertIsNotNone(g, "operator custom rule was suppressed on a miss marker")
            self.assertTrue(g.miss_ok)
            self.assertEqual(g.severity, "high")
        finally:
            path.unlink()

    def test_custom_rule_cannot_downgrade_a_marked_critical(self):
        # ROUND2 #9: custom rules are all miss_ok, but miss_ok bypasses only
        # marker SUPPRESSION — a dispatcher [!!]/CRITICAL mark still floors the
        # severity to critical, so an operator low/medium custom rule can never
        # downgrade a dispatcher-marked critical in findings.json.
        import tempfile, json as _json
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
            tf.write(_json.dumps({"pattern": r"ACME-WIDGET", "severity": "low"}) + "\n")
            path = Path(tf.name)
        try:
            rules = R._load_rules(path)
            g = R._classify_line("[!!] ACME-WIDGET total compromise", rules)
            self.assertIsNotNone(g)
            self.assertEqual(g.severity, "critical",
                             "the [!!] critical floor must override a custom low rule")
            self.assertTrue(g.miss_ok)
            self.assertTrue(g.rule_id.startswith("custom-"), "operator rule keeps its own id")
            # a NON-critical-marked custom match keeps the operator-chosen severity.
            g2 = R._classify_line("[-] ACME-WIDGET present", rules)
            self.assertEqual(g2.severity, "low")
        finally:
            path.unlink()

    def test_custom_rule_id_is_stable_across_line_moves(self):
        # ROUND2 #6 (regression): the custom rule id derives from pattern+flags,
        # not the file line number, so inserting a comment above a rule does not
        # churn its KB key.
        import tempfile, json as _json

        def _cid(text):
            with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
                tf.write(text)
                p = Path(tf.name)
            try:
                return next(r.rule_id for r in R._load_rules(p)
                            if r.rule_id.startswith("custom-"))
            finally:
                p.unlink()

        rule = _json.dumps({"pattern": r"ACME-SIGNAL", "severity": "high"}) + "\n"
        self.assertEqual(_cid(rule), _cid("# leading comment\n\n" + rule),
                         "custom rule id must not depend on the file line number")


if __name__ == "__main__":
    unittest.main()
