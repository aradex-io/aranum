#!/usr/bin/env python3
"""test_echo_dedup.py — D1.4 token-safe echo dedup (G06).

A dispatcher summary line (``<svc>/_dispatcher.log``) that echoes a per-host
finding (``<svc>/<host>/<file>``) collapses into it — across that boundary
only. The merge is gated by EQUAL protected-token sets (addresses, ports,
paths, shares, secrets, credential pairs) plus a prose-Jaccard confirmation,
with one-to-one assignment. This proves the plan's named scenarios:

  * identical echo collapses to one;
  * same host / different port stays two;
  * same path / different secret stays two;
  * an SMB multi-share line is not collapsed into a single-share finding;
  * a cross-severity echo merges keeping the higher severity;
  * one-to-one (a second echo does not fan into the same per-host finding);
  * two per-host lines are never fuzzy-merged.

Ordinary unit tests (new-behaviour proof); D1.4 adds no acceptance *gate*.

Run with: python3 -m unittest tests.test_echo_dedup
"""
from __future__ import annotations

import hashlib
import importlib.util
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_d14", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()


def mk(host, port, service, severity, line, path, protocol=""):
    return {
        "host": host, "port": str(port), "protocol": protocol, "service": service,
        "severity": severity, "line": line, "evidence_path": path,
        "evidence_paths": [path],
        "evidence_identity": hashlib.sha256(line.encode()).hexdigest(),
        "finding_id": "AR-2-seed", "rule_id": "r",
    }


def _echo(service, *a, **k):
    return mk(a[0], a[1], service, a[2], a[3], f"{service}/_dispatcher.log", **k)


def _host(service, host, port, sev, line, fname="findings.txt", **k):
    return mk(host, port, service, sev, line, f"{service}/{host}/{fname}", **k)


class TestEchoDedup(unittest.TestCase):
    def test_identical_echo_collapses_to_one(self):
        out = R._dedup_echoes([
            _echo("smb", "10.0.0.5", 445, "medium", "[+] SMB signing disabled at 10.0.0.5"),
            _host("smb", "10.0.0.5", 445, "medium", "SMB signing disabled at 10.0.0.5"),
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(sorted(out[0]["evidence_paths"]),
                         ["smb/10.0.0.5/findings.txt", "smb/_dispatcher.log"])
        # The per-host file is the clickable primary.
        self.assertEqual(out[0]["evidence_path"], "smb/10.0.0.5/findings.txt")

    def test_cross_severity_echo_keeps_higher(self):
        out = R._dedup_echoes([
            _echo("http", "10.0.0.20", 8080, "critical",
                  "[+] UNAUTH: Jenkins API exposed: http://10.0.0.20:8080"),
            _host("http", "10.0.0.20", 8080, "high", "Jenkins API exposed", "jenkins.txt"),
        ])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "critical",
                         "the stronger grading must survive the merge")
        self.assertEqual(len(out[0]["evidence_paths"]), 2)

    def test_same_host_different_port_stays_two(self):
        out = R._dedup_echoes([
            _echo("redis", "10.0.0.5", 6379, "critical", "UNAUTH Redis at 10.0.0.5:6379"),
            _host("redis", "10.0.0.5", 6380, "critical", "UNAUTH Redis at 10.0.0.5:6380", "redis.txt"),
        ])
        self.assertEqual(len(out), 2, "different ports are different endpoints")

    def test_same_path_different_secret_stays_two(self):
        base = r"GPP cpassword at \\dc\SYSVOL\Policies\x.xml : "
        out = R._dedup_echoes([
            _echo("smb", "10.0.0.5", 445, "critical", "[+] " + base + "QWxhZGRpbjpvcGVuc2VzYW1l"),
            _host("smb", "10.0.0.5", 445, "critical", base + "Zm9vYmFyYmF6cXV4Y29ycA", "gpp.txt"),
        ])
        self.assertEqual(len(out), 2, "same path, different secret = different facts")

    def test_multi_share_not_collapsed_into_single(self):
        out = R._dedup_echoes([
            _echo("smb", "10.0.0.5", 445, "high",
                  "[+] UNAUTH SMB shares at 10.0.0.5 — IPC$, Users, Public, Backups"),
            _host("smb", "10.0.0.5", 445, "medium", "share Users readable at 10.0.0.5", "shares.txt"),
        ])
        self.assertEqual(len(out), 2, "a multi-share enumeration is not one share")

    def test_multi_word_enum_elements_not_collapsed(self):
        # ROUND2 #2: list elements with internal spaces ("Finance Team") must be
        # protected whole. Two distinct multi-WORD enumerations that happen to
        # share one element ("HR Team") must NOT merge and drop the other, even
        # though a single-token tokenizer would reduce both to {team, hr}.
        out = R._dedup_echoes([
            _echo("smb", "10.0.0.5", 445, "high",
                  "[+] UNAUTH SMB shares exposed: Finance Team, HR Team"),
            _host("smb", "10.0.0.5", 445, "high",
                  "UNAUTH SMB shares exposed: Legal Team, HR Team", "shares.txt"),
        ])
        self.assertEqual(len(out), 2,
                         "distinct multi-word enumerations are different facts, not an echo")

    def test_one_to_one_second_echo_does_not_fan_in(self):
        out = R._dedup_echoes([
            _echo("smb", "10.0.0.5", 445, "medium", "[+] SMB signing disabled at 10.0.0.5"),
            _echo("smb", "10.0.0.5", 445, "medium", "[+] SMB signing disabled at 10.0.0.5"),
            _host("smb", "10.0.0.5", 445, "medium", "SMB signing disabled at 10.0.0.5"),
        ])
        self.assertEqual(len(out), 2, "only one echo merges; the other survives as its own finding")
        merged = [f for f in out if len(f["evidence_paths"]) == 2]
        self.assertEqual(len(merged), 1)

    def test_two_per_host_lines_never_merged(self):
        out = R._dedup_echoes([
            _host("linux", "10.0.0.9", "", "high", "SUID /usr/bin/foo", "linpeas.txt"),
            _host("linux", "10.0.0.9", "", "high", "SUID /usr/bin/bar", "linpeas.txt"),
        ])
        self.assertEqual(len(out), 2, "per-host enumerations are never fuzzy-merged")

    def test_dispatcher_host_passthrough_untouched(self):
        run = mk("(dispatcher)", "", "http", "high", "something unattributed", "http/_dispatcher.log")
        out = R._dedup_echoes([run])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["host"], "(dispatcher)")


if __name__ == "__main__":
    unittest.main()
