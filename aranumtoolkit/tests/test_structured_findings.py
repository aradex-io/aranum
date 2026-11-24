#!/usr/bin/env python3
"""test_structured_findings.py — structured finding fields in findings.json (v2).

The tests are intentionally narrow:
* walker output keeps legacy finding fields;
* default v2 fields are added when no metadata is present;
* optional `service-metadata.json` is loaded when present;
* CLI emits the same fields in findings.json and keeps `schema_version`.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import shutil
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"
FIXTURES = REPO / "aranumtoolkit" / "tests" / "fixtures" / "ad-signals" / "certipy-esc1"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_structured", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def _write_ldap_fixture(root: Path) -> None:
    (root / "ldap" / "10.0.0.10_389").mkdir(parents=True)
    fixture = FIXTURES / "certipy_20260520.txt"
    shutil.copy(fixture, root / "ldap" / "10.0.0.10_389" / "certipy.txt")


class TestStructuredFindingDefaults(unittest.TestCase):
    def test_walk_findings_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)

            findings = list(R.walk_findings(out, list(R._AD_DEPTH_RULES)))
            self.assertGreater(len(findings), 0)
            f = findings[0]

            for key in ("host", "port", "service", "severity", "line", "evidence_path"):
                self.assertIn(key, f, f"legacy key missing: {key}")

            for key in ("finding_id", "title", "confidence", "priority", "tags", "next_actions", "triage_status"):
                self.assertIn(key, f, f"structured key missing: {key}")
            self.assertTrue(f["finding_id"].startswith("AR-2-"))
            self.assertIsInstance(f["tags"], list)
            self.assertIsInstance(f["next_actions"], list)
            self.assertEqual(f["triage_status"], "new")

            findings_again = list(R.walk_findings(out, list(R._AD_DEPTH_RULES)))
            self.assertEqual({x["finding_id"] for x in findings}, {x["finding_id"] for x in findings_again},
                             "finding_id should be stable for the same input set")

    def test_walk_findings_ignores_generated_dashboard_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "http" / "10.0.0.5_80").mkdir(parents=True)
            (out / "http" / "10.0.0.5_80" / "probe.txt").write_text(
                "UNAUTH: Docker daemon exposed\n"
            )
            (out / "dashboard" / "assets").mkdir(parents=True)
            (out / "dashboard" / "index.html").write_text(
                "UNAUTH: stale generated dashboard content\n"
            )
            (out / "dashboard" / "assets" / "dashboard.css").write_text("/* generated */")
            (out / "dashboard" / "assets" / "dashboard.js").write_text("// generated")

            findings = list(R.walk_findings(out, R._load_rules(None)))
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["service"], "http")
            self.assertEqual(findings[0]["host"], "10.0.0.5")


class TestSarifExport(unittest.TestCase):
    def test_sarif_shape_and_levels(self):
        findings = [
            {"service": "redis", "severity": "critical", "title": "UNAUTH Redis",
             "host": "10.0.0.1", "port": "6379", "evidence_path": "redis/x.txt", "finding_id": "AR-2-a"},
            {"service": "http", "severity": "medium", "line": "CORS reflect", "host": "10.0.0.2", "port": "80"},
            {"service": "ssh", "severity": "low", "line": "banner", "host": "10.0.0.3", "port": "22"},
        ]
        s = R._to_sarif(findings, "test")
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "aranum")
        self.assertEqual([r["level"] for r in run["results"]], ["error", "warning", "note"])
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "redis/x.txt")


class TestClassifyPrefilter(unittest.TestCase):
    """The perf prefilter must never change a classification vs the brute loop."""

    def _brute(self, line, rules):
        # Mirrors _classify's new contract: return the matched Rule (D1.0), or
        # None. Rules are namedtuples compared by value, so the prefilter path
        # and this brute path return equal Rules for the same match.
        line = R._clean_line(line)[:4096]
        for r in rules:
            if r.pattern.search(line):
                return r
        return None

    def test_prefilter_matches_brute_force(self):
        rules = R._load_rules(None)
        samples = [
            "[!] CRITICAL: UNAUTH NATS monitoring http://x/varz",
            "UNAUTH etcd v2/keys", "OPEN PROXY: 1.2.3.4:3128 forwarded",
            "X11 OPEN DISPLAY: 1.2.3.4:6000", "polkit 0.105 < 0.120 — PwnKit candidate",
            "HARDENING: ptrace_scope=0 — unrestricted", "[+] WRITABLE PIPE: x",
            "EVAL scripting REACHABLE on h", "NTP AMPLIFICATION VECTOR (CVE-2013-5211 monlist): x",
            "some banner OpenSSH_9.6", "nothing interesting", "random 12345",
            "CVE-2024-6387 (regreSSHion) pre-auth RCE candidate",
        ]
        for s in samples:
            self.assertEqual(R._classify(s, rules), self._brute(s, rules), f"mismatch: {s!r}")


class TestWindowsBulkGrading(unittest.TestCase):
    """REVIEW-004 §5 — the winenum grader must actually classify AD-depth signals."""

    def test_writable_pipe_line_classifies(self):
        # Get-NamedPipes.ps1 emits via Hit() which prepends "[+] "; the old
        # "^WRITABLE PIPE:" rule never matched that prefix.
        rules = list(R._BULK_RULES_WIN) + list(R._AD_DEPTH_RULES)
        line = "[+] WRITABLE PIPE: \\\\.\\pipe\\spoolss — FullControl granted to Everyone"
        self.assertEqual(R._classify(line, rules).severity, "high")

    def test_bulk_winenum_grades_writable_pipe(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            host = out / "WIN-DC01"
            host.mkdir()
            (host / "_meta.json").write_text(json.dumps({"rc": 0, "os": "windows"}))
            (host / "winenum.txt").write_text(
                "[+] WRITABLE PIPE: \\\\.\\pipe\\spoolss — FullControl granted to Everyone\n"
            )
            findings = list(R.walk_findings_bulk(out, []))
            self.assertIn("high", {f["severity"] for f in findings})


class TestServiceMetadataIntegration(unittest.TestCase):
    def test_service_metadata_file_is_loaded_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)
            local_metadata = {
                "services": {
                    "ldap": {
                        "title": "LDAP service hardening finding",
                        "confidence": "very-high",
                        "priority": "P0",
                        "tags": ["ad", "critical"],
                        "next_actions": ["triage", "remove risk"],
                        "triage_status": "open",
                    }
                }
            }
            metadata_path = out / "service-metadata.json"
            metadata_path.write_text(json.dumps(local_metadata))
            cfg = R._load_service_metadata(out)
            self.assertIn("services", cfg)

            metadata = {
                "defaults": cfg.get("defaults", {}),
                "services": {**cfg.get("services", {}), **local_metadata["services"]},
            }

            finding = next(R.walk_findings(out, list(R._AD_DEPTH_RULES), metadata))
            self.assertEqual(finding["title"], "LDAP service hardening finding")
            self.assertEqual(finding["confidence"], "very-high")
            self.assertEqual(finding["priority"], "P0")
            self.assertEqual(finding["triage_status"], "open")
            self.assertIn("ad", finding["tags"])
            self.assertIn("triage", finding["next_actions"])


class TestCLIV2Output(unittest.TestCase):
    def test_findings_json_v2_schema_payload(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            _write_ldap_fixture(out)
            p = subprocess.run(
                [sys.executable, str(REPORT_PATH), str(out), "--findings-only"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(p.returncode, 0, f"report.py failed: {p.stderr}")
            payload = json.loads((out / "findings.json").read_text())

            self.assertEqual(payload["schema_version"], "2")
            self.assertIn("findings", payload)
            self.assertGreater(len(payload["findings"]), 0)
            f = payload["findings"][0]
            self.assertEqual(payload["label"], out.name)
            for key in ("finding_id", "title", "confidence", "priority", "tags", "next_actions", "triage_status", "schema_version"):
                self.assertIn(key, f)
            self.assertIn("line", f)
            self.assertIn("evidence_path", f)
            self.assertIn("host", f)


AD_FIX = REPO / "aranumtoolkit" / "tests" / "fixtures" / "ad-signals"


def _ad_rules():
    # Same composition the auto-enum CLI path uses (report.py main()).
    return R._compose_rules(R._load_rules(None), R._AD_DEPTH_RULES)


def _build_tree(td: str, files: dict) -> Path:
    """files maps a tree-relative path -> str content OR a Path to copy."""
    out = Path(td)
    for rel, content in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, Path):
            shutil.copy(content, p)
        else:
            p.write_text(content)
    return out


def _collect_findings(out: Path) -> list[dict]:
    return R.collect(out, _ad_rules(), R._load_service_metadata(out),
                     diagnostics=[]).findings


def _by_class(findings, cls):
    return [f for f in findings if R._promoted_class(f) == cls]


class TestAdSignalPromoters(unittest.TestCase):
    """S2 — structured per-entity AD promoters (ST-1..4, RC-1, coerce/QT-2) and
    the cross-source dedup (F4). Each promoter is exercised through the real
    walk_findings -> finalize_findings pipeline (collect), so a passing assertion
    on the typed finding is absent at base SHA 8cca59aa (no promoter) and present
    after — a non-vacuous RED proof per promoter."""

    # -------- ST-1 ADCS from certipy JSON --------
    def test_adcs_promotes_per_ca_and_template_from_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "ldap/dc01_389/certipy_Certipy.json":
                    AD_FIX / "certipy-esc-json" / "certipy_Certipy.json",
            })
            fs = _collect_findings(out)
            adcs = _by_class(fs, "adcs")
            # CA ESC7(high)+ESC8(critical) + template ESC1(critical) = 3
            self.assertEqual(len(adcs), 3, [f["line"] for f in adcs])
            for f in adcs:
                self.assertEqual(f["service"], "ldap")
            sev = {f["severity"] for f in adcs}
            self.assertEqual(sev, {"critical", "high"})
            esc8 = [f for f in adcs if "ESC8" in f["line"]][0]
            self.assertEqual(esc8["severity"], "critical")
            self.assertEqual(esc8["host"], "dc01.lab.local")  # real CA DNS name
            esc7 = [f for f in adcs if "ESC7" in f["line"]][0]
            self.assertEqual(esc7["severity"], "high")         # ESC7 not in crit set
            esc1 = [f for f in adcs if "ESC1" in f["line"]][0]
            self.assertEqual(esc1["severity"], "critical")
            self.assertEqual(esc1["host"], "dc01.lab.local")   # template host via CA
            self.assertIn("ESC1", esc1["title"])               # informative title

    def test_adcs_genuine_red_text_only_fixture_has_no_vulnerable(self):
        """F4 — the companion certipy .txt carries NO `(Vulnerable)` token, so the
        text rule emits nothing; ADCS recall is owned solely by the JSON promoter
        (the absent-at-base proof is genuine, not a reused Vulnerable fixture)."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "ldap/dc01_389/certipy.txt":
                    AD_FIX / "certipy-esc-json" / "certipy_novuln.txt",
            })
            # no JSON here: line-scan of the no-Vulnerable text must yield 0 ADCS.
            line_only = list(R.walk_findings(out, _ad_rules()))
            self.assertEqual(
                [f for f in line_only if "(Vulnerable)" in f["line"]], [],
                "no-Vulnerable certipy text must not fire the ESC text rule")

    def test_adcs_cross_source_dedup_text_and_json_collapse(self):
        """F4(A) — a tree with BOTH the text `ESC1 (Vulnerable)` rule and the JSON
        promoter yields ONE ADCS finding per (host, template, ESC): no double
        count, and the text finding's path is kept as secondary evidence."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                # certipy-esc1 text carries `ESC1 (Vulnerable)` (fires text rule)
                "ldap/dc01_389/certipy.txt":
                    FIXTURES / "certipy_20260520.txt",
                # JSON carries the same ESC1 (template) + ESC7/ESC8 (CA)
                "ldap/dc01_389/certipy_Certipy.json":
                    AD_FIX / "certipy-esc-json" / "certipy_Certipy.json",
            })
            fs = _collect_findings(out)
            esc1 = [f for f in fs if re.search(r"ESC1\b", f["line"])]
            self.assertEqual(len(esc1), 1,
                             f"ESC1 must not double-count: {[f['line'] for f in esc1]}")
            survivor = esc1[0]
            self.assertEqual(R._promoted_class(survivor), "adcs",
                             "the structured JSON finding is the survivor")
            # the subsumed text finding's path is retained as secondary evidence
            paths = " ".join(survivor.get("evidence_paths", []))
            self.assertIn("certipy.txt", paths)

    # -------- ST-2 relay per-host --------
    def test_relay_one_high_per_ip_with_real_host(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "smb/_relay_candidates.txt":
                    AD_FIX / "relay-candidates" / "_relay_candidates.txt",
            })
            relay = _by_class(_collect_findings(out), "relay")
            self.assertEqual({f["host"] for f in relay}, {"10.0.0.22", "10.0.0.23"})
            for f in relay:
                self.assertEqual(f["service"], "smb")
                self.assertEqual(f["severity"], "high")

    # -------- ST-3 kerberoast per-SPN (deduped across files) --------
    def test_kerberoast_per_account_deduped_across_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "kerberos/_kerberoast_hashcat.txt":
                    AD_FIX / "kerberoast-hash" / "_kerberoast_hashcat.txt",
                # same svc_sql hash also appears here -> must dedup by account
                "ldap/impacket_spns.txt":
                    AD_FIX / "kerberoast-hash" / "impacket_spns.txt",
            })
            kerb = _by_class(_collect_findings(out), "kerberoast")
            accts = sorted(
                re.search(r"account (\S+):", f["line"]).group(1) for f in kerb)
            self.assertEqual(accts, ["svc_sql", "svc_web"])  # 2, not 3
            for f in kerb:
                self.assertEqual(f["service"], "kerberos")
                self.assertEqual(f["severity"], "high")

    # -------- ST-4 asrep per-user + userlist-only --------
    def test_asrep_per_user_deduped_across_two_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "kerberos/_asrep_hashcat.txt":
                    AD_FIX / "asrep" / "_asrep_hashcat.txt",
                "kerberos/asrep_bulk.txt":
                    AD_FIX / "asrep" / "asrep_bulk.txt",
            })
            fs = [f for f in _collect_findings(out)
                  if str(f.get("rule_id", "")).startswith("promoted-asrep")]
            self.assertEqual(len(fs), 1, [f["line"] for f in fs])  # deduped user
            self.assertEqual(fs[0]["severity"], "high")
            self.assertIn("noPreAuthUser", fs[0]["line"])

    def test_asrep_userlist_only_is_info(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "kerberos/_asrep_userlist.txt":
                    AD_FIX / "asrep" / "_asrep_userlist.txt",
            })
            fs = R._promote_asrep(out, R._load_service_metadata(out))
            self.assertEqual(len(fs), 1)
            self.assertEqual(fs[0]["severity"], "info")
            self.assertEqual(fs[0]["rule_id"], "promoted-asrep-userlist")

    # -------- coerce (QT-2 / F5): severity keyed on the REAL result --------
    def test_coerce_access_denied_is_info_not_high(self):
        with tempfile.TemporaryDirectory() as td:
            # include the static hint boilerplate ("pipe") to prove it is NOT
            # read as a HIGH source (plan F5).
            out = _build_tree(td, {
                "smb/_petitpotam_signal.txt":
                    AD_FIX / "petitpotam-signal" / "_petitpotam_signal_negative.txt",
                "smb/_petitpotam_hint.txt":
                    AD_FIX / "petitpotam-signal" / "_petitpotam_hint.txt",
            })
            fs = R._promote_coerce(out, R._load_service_metadata(out))
            self.assertEqual(len(fs), 1, "coerce reads the signal file only")
            self.assertEqual(fs[0]["severity"], "info")  # ACCESS_DENIED -> INFO

    def test_coerce_positive_result_is_high(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "smb/_petitpotam_signal.txt":
                    AD_FIX / "petitpotam-signal" / "_petitpotam_signal_positive.txt",
            })
            fs = R._promote_coerce(out, R._load_service_metadata(out))
            self.assertEqual(len(fs), 1)
            self.assertEqual(fs[0]["severity"], "high")

    # -------- RC-1 shadow_creds (the only fully-missing class) --------
    def test_shadow_creds_info_with_non_comment_line(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "smb/_shadow_creds_hint.txt":
                    AD_FIX / "shadow-creds" / "_shadow_creds_hint.txt",
            })
            fs = [f for f in _collect_findings(out)
                  if str(f.get("rule_id", "")) == "promoted-shadow-creds"]
            self.assertEqual(len(fs), 1)
            self.assertEqual(fs[0]["severity"], "info")
            self.assertEqual(fs[0]["service"], "smb")
            # must pass a non-comment, non-empty line so S1's noise guard (which
            # the hint file would otherwise trip, being all `#`-comments) never
            # applies to a promoter finding.
            self.assertFalse(R._is_noise_line(fs[0]["line"]))

    # -------- F4(B)/F3 lossless class subsumption of coarse summaries --------
    # Rule (uniform across adcs/relay/kerberoast/asrep): a coarse `[!] CRITICAL:`
    # dispatcher summary is subsumed into the per-entity findings ONLY when a
    # survivor is already at least as severe; otherwise the summary is KEPT (never
    # downgrade CRITICAL -> the per-entity HIGH). Coarse phrasings below are the
    # verbatim dispatcher `err` strings (enum-smb.sh:144/193, enum-kerberos.sh:63/
    # 107). coerce is excluded from subsumption entirely (F2).

    def test_adcs_coarse_summary_subsumed_when_survivor_is_critical(self):
        """ADCS coarse CRITICAL + JSON survivors that INCLUDE a critical template
        -> subsumed, no loss, path retained as secondary evidence."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "ldap/dc01_389/certipy_Certipy.json":
                    AD_FIX / "certipy-esc-json" / "certipy_Certipy.json",
                "ldap/_dispatcher.log":
                    "[!] CRITICAL: Certipy found AD CS misconfiguration(s) — see "
                    "ldap/dc01_389/certipy_Certipy.json\n",
            })
            fs = _collect_findings(out)
            self.assertEqual(
                [f for f in fs if "Certipy found AD CS" in f["line"]], [],
                "ADCS coarse summary must be subsumed (survivors include critical)")
            adcs = _by_class(fs, "adcs")
            self.assertEqual(len(adcs), 3)
            self.assertTrue(
                any("_dispatcher.log" in p
                    for f in adcs for p in f.get("evidence_paths", [])),
                "subsumed ADCS summary path must be kept as secondary evidence")

    def test_relay_coarse_critical_kept_alongside_per_ip_highs(self):
        """F3 — relay coarse CRITICAL survives (survivors are HIGH); subsuming
        would downgrade, so BOTH are kept (lossless)."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "smb/_relay_candidates.txt":
                    AD_FIX / "relay-candidates" / "_relay_candidates.txt",
                "smb/_dispatcher.log":
                    "[!] CRITICAL: 2 SMB host(s) with signing disabled or "
                    "not-required — NTLM-relay candidates in _relay_candidates.txt\n",
            })
            fs = _collect_findings(out)
            coarse = [f for f in fs if "candidates in _relay_candidates" in f["line"]]
            self.assertEqual(len(coarse), 1, "coarse relay CRITICAL must be KEPT")
            self.assertEqual(coarse[0]["severity"], "critical")
            relay = _by_class(fs, "relay")
            self.assertEqual(len(relay), 2)
            self.assertTrue(all(f["severity"] == "high" for f in relay))

    def test_kerberoast_coarse_critical_kept_alongside_per_account_highs(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "kerberos/_kerberoast_hashcat.txt":
                    AD_FIX / "kerberoast-hash" / "_kerberoast_hashcat.txt",
                "kerberos/_dispatcher.log":
                    "[!] CRITICAL: 2 kerberoastable hash(es) captured to "
                    "_kerberoast_hashcat.txt (hashcat -m 13100)\n",
            })
            fs = _collect_findings(out)
            coarse = [f for f in fs if "kerberoastable hash(es) captured" in f["line"]]
            self.assertEqual(len(coarse), 1, "coarse kerberoast CRITICAL must be KEPT")
            self.assertEqual(coarse[0]["severity"], "critical")
            self.assertEqual(len(_by_class(fs, "kerberoast")), 2)

    def test_asrep_coarse_critical_kept_alongside_per_user_highs(self):
        """asrep is now handled consistently with relay/kerberoast (previously it
        was not subsumed at all = inconsistent): coarse CRITICAL kept, per-user
        HIGH present, no double-drop and no downgrade."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "kerberos/_asrep_hashcat.txt":
                    AD_FIX / "asrep" / "_asrep_hashcat.txt",
                "kerberos/_dispatcher.log":
                    "[!] CRITICAL: 1 AS-REP-roastable hash(es) captured to "
                    "_asrep_hashcat.txt (hashcat -m 18200)\n",
            })
            fs = _collect_findings(out)
            coarse = [f for f in fs if "AS-REP-roastable hash(es) captured" in f["line"]]
            self.assertEqual(len(coarse), 1, "coarse asrep CRITICAL must be KEPT")
            self.assertEqual(coarse[0]["severity"], "critical")
            per_user = [f for f in fs
                        if str(f.get("rule_id", "")) == "promoted-asrep-user"]
            self.assertEqual(len(per_user), 1)
            self.assertEqual(per_user[0]["severity"], "high")

    def test_coerce_chain_summary_and_probe_result_both_kept(self):
        """F2 — the coarse `[!] HIGH: PetitPotam coerce chain available`
        (enum-smb.sh:193, a chain-availability assessment) and the probe-RESULT
        promoter finding (enum-smb.sh:155-160) are DIFFERENT facts: keep both.
        coerce is excluded from subsumption."""
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "smb/_petitpotam_signal.txt":
                    AD_FIX / "petitpotam-signal" / "_petitpotam_signal_negative.txt",
                "smb/_dispatcher.log":
                    "[!] HIGH: PetitPotam coerce chain available — see "
                    "_petitpotam_hint.txt for the exact commands\n",
            })
            fs = _collect_findings(out)
            chain = [f for f in fs if "PetitPotam coerce chain available" in f["line"]]
            self.assertEqual(len(chain), 1, "coarse coerce-chain HIGH must survive")
            self.assertEqual(chain[0]["severity"], "high")
            probe = [f for f in fs
                     if str(f.get("rule_id", "")) == "promoted-coerce-signal"]
            self.assertEqual(len(probe), 1)
            self.assertEqual(probe[0]["severity"], "info")  # ACCESS_DENIED result

    # -------- robustness: malformed/empty artifact -> [] without raising --------
    def test_malformed_or_empty_artifacts_yield_no_findings_no_raise(self):
        with tempfile.TemporaryDirectory() as td:
            out = _build_tree(td, {
                "ldap/dc01_389/certipy_Certipy.json": "{ this is not json ",
                "smb/_relay_candidates.txt": "",
                "smb/_petitpotam_signal.txt": "",
                "smb/_shadow_creds_hint.txt": "",
                "kerberos/_kerberoast_hashcat.txt": "no hashes here at all\n",
                "kerberos/_asrep_hashcat.txt": "junk with no krb5 token\n",
            })
            meta = R._load_service_metadata(out)
            for fn in (R._promote_adcs, R._promote_relay, R._promote_coerce,
                       R._promote_shadow_creds, R._promote_kerberoast,
                       R._promote_asrep):
                with self.subTest(promoter=fn.__name__):
                    result = fn(out, meta)  # must not raise
                    self.assertEqual(result, [], fn.__name__)
            # and the whole report still collects cleanly (no crash)
            self.assertIsInstance(_collect_findings(out), list)


if __name__ == "__main__":
    unittest.main()
