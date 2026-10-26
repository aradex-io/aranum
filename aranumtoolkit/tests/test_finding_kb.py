#!/usr/bin/env python3
"""test_finding_kb.py — S2/D2.1 finding knowledge base.

Covers three things:
  * the KB **coverage gate** over every non-low built-in rule_id (and its RED
    proof, driven through the ARANUM_FINDING_KB env override);
  * KB schema validity (schema version, category references, test+fix blocks);
  * the additive ``category`` / ``kb_id`` / ``kb_match`` fields attached to
    findings at finalize time, plus the smb relay-vs-fileservice category split
    and the Top-risks markdown section.

The coverage denominator is enumerated *in this test*, straight from report.py's
rule lists, so the gate cannot be made to pass by editing one shared helper.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_kb", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _non_low_builtin_rule_ids(mod) -> "dict[str, str]":
    """The KB coverage denominator: non-low, non-generic-fallback built-in
    rule_ids across all four rule lists -> severity. Enumerated here (not from a
    report.py helper) so the gate is independent of the code it checks."""
    ids: "dict[str, str]" = {}
    for lst in (mod._DEFAULT_RULES, mod._BULK_RULES,
                mod._BULK_RULES_WIN, mod._AD_DEPTH_RULES):
        for r in lst:
            if r.severity == "low":
                continue
            if r.rule_id in mod._GENERIC_FALLBACK_RULE_IDS:
                continue
            ids.setdefault(r.rule_id, r.severity)
    return ids


def _fresh_kb(mod, path=None) -> dict:
    """Reload the KB uncached. With a path, point ARANUM_FINDING_KB at it; with
    None, clear the override and reload the shipped KB."""
    mod._FINDING_KB_CACHE = None
    mod._FINDING_KB_CACHE_PATH = None
    if path is None:
        os.environ.pop("ARANUM_FINDING_KB", None)
    else:
        os.environ["ARANUM_FINDING_KB"] = str(path)
    return mod._load_finding_kb()


def _uncovered(mod, kb) -> "list[str]":
    """The gate's decision function: non-low rule_ids with no KB class."""
    ids = _non_low_builtin_rule_ids(mod)
    classes = kb.get("classes", {})
    return sorted(k for k in ids if k not in classes)


class TestKBCoverageGate(unittest.TestCase):
    """The gate: every non-low built-in rule_id has a usable KB class."""

    def tearDown(self):
        _fresh_kb(R)  # always restore the shipped KB + cache

    def test_kb_covers_every_non_low_rule_id(self):
        kb = _fresh_kb(R)
        ids = _non_low_builtin_rule_ids(R)
        # Anti-vacuous: the denominator must be substantial. A rule-list rename
        # that empties it would otherwise make coverage pass trivially.
        self.assertGreaterEqual(
            len(ids), 150,
            f"only {len(ids)} non-low rule_ids enumerated — denominator collapsed")
        uncovered = _uncovered(R, kb)
        self.assertEqual(
            uncovered, [],
            f"{len(uncovered)} non-low rule_ids have no KB class: {uncovered[:20]}")
        # Every covered class must carry usable test AND fix guidance.
        classes = kb["classes"]
        thin = []
        for rid in ids:
            cls = classes.get(rid, {})
            tests, fixes = cls.get("test"), cls.get("fix")
            if not (isinstance(tests, list) and tests
                    and isinstance(fixes, list) and fixes):
                thin.append(rid)
        self.assertEqual(
            thin, [],
            f"{len(thin)} KB classes lack a test or fix block: {thin[:20]}")

    def test_coverage_gate_goes_red_when_a_class_is_removed(self):
        """RED proof. Drop one covered class into a temp KB via
        ARANUM_FINDING_KB; the gate's decision function must then name exactly
        that rule_id as uncovered. Proves the gate can fail (is not vacuous)."""
        ids = _non_low_builtin_rule_ids(R)
        victim = sorted(ids)[0]
        full = json.loads(R._FINDING_KB_DEFAULT.read_text())
        # Subject-exists guard: a missing victim would make this a silent no-op.
        self.assertIn(victim, full["classes"])
        del full["classes"][victim]
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "kb-minus-one.json"
            p.write_text(json.dumps(full))
            kb = _fresh_kb(R, p)
            uncovered = _uncovered(R, kb)
        self.assertIn(
            victim, uncovered,
            "gate did not flag the removed class — it is vacuous")


class TestKBSchema(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(R._FINDING_KB_DEFAULT.read_text())

    def test_schema_version_and_category_references(self):
        self.assertEqual(self.raw.get("schema"), 1)
        cats = self.raw["categories"]
        self.assertTrue(cats)
        bad = [rid for rid, c in self.raw["classes"].items()
               if c.get("category") not in cats]
        self.assertEqual(bad, [], f"classes with unknown category: {bad[:20]}")
        badsvc = [k for k, v in self.raw["service_categories"].items()
                  if v not in cats]
        self.assertEqual(badsvc, [],
                         f"service_categories -> unknown category: {badsvc}")

    def test_every_class_has_title_why_test_fix(self):
        missing = []
        for rid, c in self.raw["classes"].items():
            if not c.get("title") or not c.get("why"):
                missing.append(("meta", rid))
            if not (c.get("test") and isinstance(c["test"], list)):
                missing.append(("test", rid))
            if not (c.get("fix") and isinstance(c["fix"], list)):
                missing.append(("fix", rid))
        self.assertEqual(missing, [], f"incomplete classes: {missing[:20]}")


class TestServiceCategorySplit(unittest.TestCase):
    """_service_category — the smb relay-vs-fileservice split keys on the host's
    other open ports."""

    def setUp(self):
        self.kb = _fresh_kb(R)

    def tearDown(self):
        _fresh_kb(R)

    def test_smb_is_ad_on_a_domain_controller(self):
        self.assertEqual(R._service_category("smb", self.kb, {"445", "88"}), "ad")
        self.assertEqual(R._service_category("smb", self.kb, {"445", "389"}), "ad")

    def test_smb_is_network_without_kerberos_or_ldap(self):
        self.assertEqual(R._service_category("smb", self.kb, {"445"}), "network")

    def test_unknown_service_defaults_to_network(self):
        self.assertEqual(R._service_category("nosuchsvc", self.kb, set()), "network")


class TestAttachKBFields(unittest.TestCase):
    def setUp(self):
        self.kb = _fresh_kb(R)

    def tearDown(self):
        _fresh_kb(R)

    def test_rule_matched_finding_sets_kb_id_equal_to_rule_id(self):
        rid = sorted(_non_low_builtin_rule_ids(R))[0]
        f = {"rule_id": rid, "service": "smb", "host": "10.0.0.5"}
        R._attach_kb(f, self.kb, set())
        self.assertEqual(f["kb_match"], "rule")
        self.assertEqual(f["kb_id"], rid)
        self.assertEqual(f["category"], self.kb["classes"][rid]["category"])

    def test_service_default_when_rule_id_has_no_class(self):
        f = {"rule_id": "", "service": "smb", "host": "10.0.0.5"}
        R._attach_kb(f, self.kb, {"445"})
        self.assertEqual(f["kb_match"], "service-default")
        self.assertEqual(f["kb_id"], "")
        self.assertEqual(f["category"], "network")

    def test_collect_attaches_kb_to_every_finding(self):
        with tempfile.TemporaryDirectory() as d:
            scan = Path(d) / "scan"
            (scan / "redis" / "10.0.0.1_6379").mkdir(parents=True)
            (scan / "redis" / "10.0.0.1_6379" / "info.txt").write_text(
                "[!!] UNAUTH Redis 10.0.0.1:6379 — redis_version:7.0.15 role:master\n")
            rules = R._compose_rules(R._load_rules(None), R._AD_DEPTH_RULES)
            col = R.collect(scan, rules)
            self.assertTrue(col.findings, "fixture produced no findings")
            for f in col.findings:
                self.assertIn("category", f)
                self.assertIn("kb_id", f)
                self.assertIn("kb_match", f)
            matched = [f for f in col.findings if f["kb_match"] == "rule"]
            self.assertTrue(matched, "no finding resolved a KB class end-to-end")
            for f in matched:
                self.assertEqual(f["kb_id"], f["rule_id"])


class TestTopRisksMarkdown(unittest.TestCase):
    def test_report_md_has_top_risks_and_how_to_fix(self):
        _fresh_kb(R)
        with tempfile.TemporaryDirectory() as d:
            scan = Path(d) / "scan"
            (scan / "redis" / "10.0.0.1_6379").mkdir(parents=True)
            (scan / "redis" / "10.0.0.1_6379" / "info.txt").write_text(
                "[!!] UNAUTH Redis 10.0.0.1:6379 — redis_version:7.0.15 role:master\n")
            rules = R._compose_rules(R._load_rules(None), R._AD_DEPTH_RULES)
            col = R.collect(scan, rules)
            summary = R._summary(col.findings, scan)
            md = R.render_markdown(col.findings, summary, "test",
                                   R.Redactor(False), col.per_host)
        self.assertIn("## Top risks by category", md)
        self.assertIn("**How to fix:**", md)


if __name__ == "__main__":
    unittest.main()
