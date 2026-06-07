#!/usr/bin/env python3
"""test_gql_hardening.py — regression tests for BUG-1 through BUG-12 hardening.

Each test invokes gql.py as a subprocess (so exit code AND stderr are observable),
then asserts:
  - the expected exit code (2 for bad-input, 1 for probe-error, 0 for warn-only)
  - "Traceback" is absent from stderr (anti-vacuous bar)
  - a meaningful error keyword appears in the appropriate output stream

Run with:
    python3 -m unittest aranumtoolkit/tests/test_gql_hardening.py -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
GQL = REPO / "standalones" / "graphql" / "gql.py"


def _run(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Run gql.py with GQL_URL unset and a temp cache dir."""
    env = {**os.environ}
    env.pop("GQL_URL", None)
    env["GQL_CACHE_DIR"] = tempfile.mkdtemp(prefix="gqltest-cache-")
    return subprocess.run(
        [sys.executable, str(GQL), *args],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def _assert_clean_error(tc: unittest.TestCase, r: subprocess.CompletedProcess,
                        expect_rc: int, keyword: str, stream: str = "stderr") -> None:
    """Assert rc==expect_rc, no traceback, and keyword present in the named stream."""
    haystack = r.stderr if stream == "stderr" else r.stdout
    tc.assertNotIn("Traceback (most recent call last)", r.stderr,
                   f"traceback leaked to stderr:\n{r.stderr[:400]}")
    tc.assertEqual(r.returncode, expect_rc,
                   f"rc={r.returncode} (want {expect_rc})\nstdout={r.stdout[:200]}\nstderr={r.stderr[:200]}")
    tc.assertIn(keyword, haystack,
                f"keyword {keyword!r} missing from {stream}:\nstdout={r.stdout[:200]}\nstderr={r.stderr[:200]}")


# ---------------------------------------------------------------- BUG-1
class TestRawRequiresUrl(unittest.TestCase):
    """BUG-1: `raw` without --url must exit 2 with --url-required message."""

    def test_raw_no_url_exits_2(self):
        r = _run(["raw", "--query", "{__typename}"])
        _assert_clean_error(self, r, 2, "--url required")

    def test_raw_with_url_reaches_network_phase(self):
        # With --url it must NOT fail at the url-guard (may fail at network, that's fine).
        r = _run(["--url", "http://127.0.0.1:1/graphql", "raw", "--query", "{__typename}"])
        self.assertNotIn("--url required", r.stderr)
        self.assertNotIn("Traceback (most recent call last)", r.stderr)


# ---------------------------------------------------------------- BUG-2
class TestUaRotateMissingFile(unittest.TestCase):
    """BUG-2: --ua-rotate with a missing file must exit 2, not FileNotFoundError."""

    def test_missing_ua_file_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1/graphql",
                  "--ua-rotate", "/tmp/NOEXIST_ua_MISSING_SENTINEL.txt",
                  "csrf-probe"])
        _assert_clean_error(self, r, 2, "--ua-rotate")


# ---------------------------------------------------------------- BUG-3
class TestArgJsonMalformed(unittest.TestCase):
    """BUG-3: --arg name=@json:<bad> must exit 2, not JSONDecodeError."""

    def test_malformed_json_arg_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "text=@json:{bad",
                  "--show-query", "only"])
        _assert_clean_error(self, r, 2, "@json")


# ---------------------------------------------------------------- BUG-4
class TestArgFileMissing(unittest.TestCase):
    """BUG-4: --arg name=@file:<missing> must exit 2, not FileNotFoundError."""

    def test_missing_file_arg_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "text=@file:/tmp/NOEXIST_arg_MISSING_SENTINEL.txt",
                  "--show-query", "only"])
        _assert_clean_error(self, r, 2, "@file")


# ---------------------------------------------------------------- BUG-5
class TestRawVariablesMalformed(unittest.TestCase):
    """BUG-5: raw --variables '<bad json>' must exit 2, not JSONDecodeError."""

    def test_bad_variables_json_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "raw", "--query", "{x}", "--variables", "{bad json"])
        _assert_clean_error(self, r, 2, "--variables")


# ---------------------------------------------------------------- BUG-6
class TestRawQueryFileMissing(unittest.TestCase):
    """BUG-6: raw --query-file <missing> must exit 2, not FileNotFoundError."""

    def test_missing_query_file_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "raw", "--query-file", "/tmp/NOEXIST_query_MISSING_SENTINEL.graphql"])
        _assert_clean_error(self, r, 2, "--query-file")


# ---------------------------------------------------------------- BUG-7
class TestLoopValuesFileMissing(unittest.TestCase):
    """BUG-7: loop --values-file <missing> must exit 2, not FileNotFoundError."""

    def test_missing_values_file_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "loop", "echo", "--vary", "text",
                  "--values-file", "/tmp/NOEXIST_values_MISSING_SENTINEL.txt",
                  "--no-schema"])
        _assert_clean_error(self, r, 2, "--values-file")


# ---------------------------------------------------------------- BUG-8
class TestSuggestCorpusMissing(unittest.TestCase):
    """BUG-8: suggest --corpus <missing> must exit 2, not FileNotFoundError."""

    def test_missing_corpus_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "suggest", "--corpus", "/tmp/NOEXIST_corpus_MISSING_SENTINEL.txt"])
        _assert_clean_error(self, r, 2, "--corpus")


# ---------------------------------------------------------------- BUG-9 / BUG-10
class TestArgNameValidation(unittest.TestCase):
    """BUG-9/10: invalid GraphQL variable names must exit 2, never produce a
    malformed query at rc=0."""

    def test_empty_key_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "=5", "--show-query", "only"])
        _assert_clean_error(self, r, 2, "invalid GraphQL variable name")
        # Must NOT have emitted a malformed query
        self.assertNotIn("GqlPy($:", r.stdout)

    def test_space_in_name_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "a b=5", "--show-query", "only"])
        _assert_clean_error(self, r, 2, "invalid GraphQL variable name")

    def test_leading_digit_exits_2(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "1bad=5", "--show-query", "only"])
        _assert_clean_error(self, r, 2, "invalid GraphQL variable name")

    def test_valid_names_accepted(self):
        # Underscore prefix and mixed case are valid GQL identifiers.
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "_myVar=hello", "--show-query", "only"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertNotIn("invalid GraphQL variable name", r.stderr)


# ---------------------------------------------------------------- BUG-11
class TestDuplicateArgWarn(unittest.TestCase):
    """BUG-11: duplicate --arg names warn to stderr, last value wins, rc stays 0."""

    def test_duplicate_warns_and_keeps_last(self):
        r = _run(["--url", "http://127.0.0.1:1",
                  "call", "echo", "--no-schema",
                  "--arg", "text=first", "--arg", "text=second",
                  "--show-query", "only"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 0,
                         f"duplicate --arg must not cause non-zero exit: {r.stderr}")
        self.assertIn("duplicate", r.stderr.lower(),
                      f"expected duplicate warning in stderr: {r.stderr[:200]}")
        # Last value must win: variables block must contain "second"
        self.assertIn("second", r.stdout,
                      f"last-wins value missing from query output: {r.stdout[:300]}")


# ---------------------------------------------------------------- BUG-12
class TestApqProbeUnreachable(unittest.TestCase):
    """BUG-12: apq-probe on an unreachable host must NOT emit a false APQ verdict.
    It must exit 1 and report a connection error."""

    def test_unreachable_exits_1_no_false_verdict(self):
        r = _run(["--url", "http://127.0.0.1:1/graphql", "apq-probe"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 1,
                         f"expected rc=1 on unreachable host, got {r.returncode}\n"
                         f"stdout={r.stdout[:200]}\nstderr={r.stderr[:200]}")
        # Must NOT print the false-negative verdict
        self.assertNotIn("server does not implement APQ", r.stdout,
                         "false APQ verdict emitted on unreachable host")
        # Must emit a connection-error message
        combined = r.stdout + r.stderr
        self.assertIn("connection failed", combined,
                      f"connection-failed message missing: {combined[:300]}")


if __name__ == "__main__":
    unittest.main()
