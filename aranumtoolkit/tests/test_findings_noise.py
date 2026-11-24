#!/usr/bin/env python3
"""test_findings_noise.py — S1 (NR-1 / QT-1): comment-noise skip + title fidelity.

NR-1: the auto-enum walker line-scan must not emit a finding for a comment-only
line (`# filter: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)` echoed by
ldapsearch), a blank line, or a BARE dispatcher severity marker (`[!] CRITICAL`
with nothing after it). The skip lives at the walker CALL SITES, not inside
`_structured_finding`, so a later structured promoter may still build a finding
whose evidence is a `#`-comment hint file.

QT-1: when the colon-head of a fallback title is only a dispatcher marker
and/or a bare severity word, the title uses the informative text after the first
colon instead of the useless `[!] CRITICAL` head.

Run: python3 -m unittest aranumtoolkit.tests.test_findings_noise
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REPORT_PATH = REPO / "aranumtoolkit" / "network" / "report.py"


def _load_report():
    spec = importlib.util.spec_from_file_location("report_mod_noise", REPORT_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


R = _load_report()

_REAL_DELEGATION_LINE = (
    "msDS-AllowedToActOnBehalfOfOtherIdentity:: AQAEgBQAAAAAAAAAAAAAABQAAAAB"
)
_DELEGATION_FIXTURE = "\n".join([
    "# extended LDIF",
    "#",
    "# filter: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
    "# requesting: msDS-AllowedToActOnBehalfOfOtherIdentity sAMAccountName",
    "#",
    "",
    "dn: CN=WEB01,CN=Computers,DC=corp,DC=local",
    _REAL_DELEGATION_LINE,
    "",
    "# numResponses: 2",
    "",
])


def _rules():
    # Same composition the auto-enum CLI path uses (report.py main()).
    return R._compose_rules(R._load_rules(None), R._AD_DEPTH_RULES)


def _walk(root: Path) -> list[dict]:
    return list(R.walk_findings(root, _rules()))


class TestNoiseLinePredicate(unittest.TestCase):
    """(b) `_is_noise_line` matches exactly the three narrow shapes."""

    def test_matches_comment_blank_and_bare_marker(self):
        for line in (
            "# x",
            "#",
            "   # indented comment",
            "",
            "   ",
            "\t",
            "[!] CRITICAL",
            "[!] HIGH",
            "  [!] medium  ",
            "[!] INFO",
            "[!] LOW",
        ):
            with self.subTest(line=line):
                self.assertTrue(R._is_noise_line(line), repr(line))

    def test_does_not_match_real_content(self):
        for line in (
            "[!] CRITICAL: real content",
            "[!] HIGH: 10.0.0.10 has 3 account(s) with UNCONSTRAINED DELEGATION",
            "[!] CRITICAL:",          # colon present: not the bare shape
            "[!] CRITICAL foo",       # trailing content
            "[+] HIGH",               # only `[!]` is the bare-marker shape
            _REAL_DELEGATION_LINE,
            "dn: CN=WEB01,DC=corp,DC=local",
            "UNAUTH: Docker daemon exposed",
            "x # trailing hash is not a comment line",
        ):
            with self.subTest(line=line):
                self.assertFalse(R._is_noise_line(line), repr(line))


class TestWalkerSkipsNoise(unittest.TestCase):
    """(a) real delegation finding kept, `#`-comment findings absent."""

    def test_delegation_comment_lines_not_emitted(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            host_dir = out / "ldap" / "10.0.0.10"
            host_dir.mkdir(parents=True)
            (host_dir / "delegation_3268.txt").write_text(_DELEGATION_FIXTURE)

            findings = _walk(out)

            lines = [f["line"] for f in findings]
            # the two `#`-comment echoes must be gone (and nothing else leaks
            # a comment line through either).
            self.assertFalse(
                [ln for ln in lines if ln.lstrip().startswith("#")],
                f"comment-only line surfaced as a finding: {lines}",
            )
            # the real delegation result line is still a finding.
            real = [f for f in findings if f["line"] == _REAL_DELEGATION_LINE]
            self.assertEqual(len(real), 1, lines)
            self.assertEqual(real[0]["severity"], "high")

    def test_toplevel_underscore_file_skips_noise_too(self):
        """Second call site: top-level `_*` dispatcher/hint files."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            svc = out / "ldap"
            (svc / "10.0.0.10").mkdir(parents=True)
            (svc / "10.0.0.10" / "placeholder.txt").write_text("nothing here\n")
            (svc / "_hints.txt").write_text("\n".join([
                "# filter: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                "[!] CRITICAL",
                "",
                "[!] CRITICAL: Certipy found AD CS misconfiguration(s)",
                "",
            ]))

            findings = _walk(out)
            lines = [f["line"] for f in findings]

            self.assertNotIn(
                "# filter: (msDS-AllowedToActOnBehalfOfOtherIdentity=*)", lines)
            self.assertNotIn("[!] CRITICAL", lines)
            self.assertIn(
                "[!] CRITICAL: Certipy found AD CS misconfiguration(s)", lines)

    def test_real_marker_content_is_never_dropped(self):
        """The bare-marker anchor must not eat `[!] CRITICAL: real content`."""
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "smb" / "10.0.0.5").mkdir(parents=True)
            (out / "smb" / "10.0.0.5" / "enum.txt").write_text(
                "[!] CRITICAL: SMB signing disabled on 10.0.0.5\n")
            findings = _walk(out)
            self.assertEqual(
                [f["line"] for f in findings],
                ["[!] CRITICAL: SMB signing disabled on 10.0.0.5"],
            )
            self.assertEqual(findings[0]["severity"], "critical")


class TestTitleFidelity(unittest.TestCase):
    """(c) QT-1: title on the post-marker remainder, not `[!] CRITICAL`."""

    def test_certipy_critical_line_titles_on_content(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            host_dir = out / "ldap" / "10.0.0.10"
            host_dir.mkdir(parents=True)
            (host_dir / "enum.txt").write_text(
                "[!] CRITICAL: Certipy found AD CS misconfiguration(s)\n")

            findings = _walk(out)
            self.assertEqual(len(findings), 1, findings)
            title = findings[0]["title"]
            self.assertIn("Certipy", title)
            self.assertNotIn("[!] CRITICAL", title)

    def test_title_unit_cases(self):
        title = R._finding_title
        # marker + bare severity head -> remainder after first colon
        self.assertEqual(
            title("ldap", "critical",
                  "[!] CRITICAL: Certipy found AD CS misconfiguration(s)", {}),
            "LDAP: Certipy found AD CS misconfiguration(s)")
        # marker-only head
        self.assertEqual(
            title("smb", "high", "[+]: share is writable", {}),
            "SMB: share is writable")
        # bare severity-only head
        self.assertEqual(
            title("smb", "high", "HIGH: relay candidates present", {}),
            "SMB: relay candidates present")
        # remainder keeps later colons (only the FIRST colon splits)
        self.assertEqual(
            title("smb", "high", "[!] HIGH: 10.0.0.5: signing off", {}),
            "SMB: 10.0.0.5: signing off")
        # remainder truncated to the existing 90-char width
        long = "[!] CRITICAL: " + "A" * 200
        self.assertEqual(title("ldap", "critical", long, {}), "LDAP: " + "A" * 90)

    def test_non_marker_head_keeps_current_behavior(self):
        title = R._finding_title
        self.assertEqual(
            title("http", "high", "UNAUTH: Docker daemon exposed", {}),
            "HTTP: UNAUTH")
        self.assertEqual(
            title("smb", "high", "[*] Checking signing: disabled", {}),
            "SMB: [*] Checking signing")
        # no colon at all: whole line is the head (unchanged)
        self.assertEqual(
            title("smb", "high", "[!] CRITICAL", {}),
            "SMB: [!] CRITICAL")
        # marker head but empty remainder: falls back to the old head
        self.assertEqual(
            title("smb", "high", "[!] CRITICAL:   ", {}),
            "SMB: [!] CRITICAL")

    def test_cfg_title_path_untouched(self):
        title = R._finding_title
        self.assertEqual(
            title("ldap", "critical", "[!] CRITICAL: Certipy found x",
                  {"title": "Custom {service}/{severity}"}),
            "Custom ldap/critical")
        self.assertEqual(
            title("ldap", "critical", "[!] CRITICAL: Certipy found x",
                  {"title_template": "T: {line}"}),
            "T: [!] CRITICAL: Certipy found x")


if __name__ == "__main__":
    unittest.main()
