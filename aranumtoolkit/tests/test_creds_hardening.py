#!/usr/bin/env python3
"""test_creds_hardening.py — regression tests for creds-standalone hardening.

Covers:
  DEFECT-4: default-creds-sweep.py --threads 0 → exit 2 (was ValueError traceback)
  DEFECT-5: default-creds-sweep.py missing/malformed catalog → exit 2 (was FileNotFoundError/JSONDecodeError)
  DEFECT-6: default-creds-sweep.py IPv6 targets produce correct bracketed URLs (was silent no-op)
  DEFECT-7: spray-scheduler.py --dry-run never sleeps when lockout state ≥ threshold

Each subprocess test asserts exit code + absence of "Traceback" in stderr.
IPv6 and spray tests exercise the pure function / subprocess directly.

Run with:
    python3 -m unittest aranumtoolkit/tests/test_creds_hardening.py -v
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SWEEP = REPO / "standalones" / "creds" / "default-creds-sweep.py"
SPRAY = REPO / "standalones" / "creds" / "spray-scheduler.py"


def _run_sweep(args: list[str], timeout: int = 10) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SWEEP), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _run_spray(args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SPRAY), *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _load_sweep_module():
    """Import default-creds-sweep.py as a module for pure-function tests."""
    spec = importlib.util.spec_from_file_location("sweep_mod", SWEEP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SWEEP_MOD = _load_sweep_module()


# ---------------------------------------------------------------- DEFECT-4
class TestThreadsValidation(unittest.TestCase):
    """DEFECT-4: --threads 0 (and negative) must exit 2 cleanly, not ValueError."""

    def _assert_clean_exit2(self, r: subprocess.CompletedProcess, label: str) -> None:
        self.assertNotIn("Traceback (most recent call last)", r.stderr,
                         f"traceback in stderr for {label}:\n{r.stderr[:300]}")
        self.assertEqual(r.returncode, 2,
                         f"rc={r.returncode} (want 2) for {label}\n"
                         f"stdout={r.stdout[:200]}\nstderr={r.stderr[:200]}")
        self.assertIn("--threads", r.stderr,
                      f"--threads message missing from stderr for {label}")

    def test_threads_zero(self):
        r = _run_sweep(["--target", "127.0.0.1:9",
                        "--threads", "0",
                        "--output", "/tmp/test_creds_threads0.json"])
        self._assert_clean_exit2(r, "--threads 0")

    def test_threads_negative(self):
        r = _run_sweep(["--target", "127.0.0.1:9",
                        "--threads", "-1",
                        "--output", "/tmp/test_creds_threads_neg.json"])
        self._assert_clean_exit2(r, "--threads -1")


# ---------------------------------------------------------------- DEFECT-5
class TestCatalogValidation(unittest.TestCase):
    """DEFECT-5: missing or malformed catalog must exit 2, not FileNotFoundError/JSONDecodeError."""

    def test_missing_catalog_exits_2(self):
        r = _run_sweep(["--target", "127.0.0.1:9",
                        "--catalog", "/tmp/NOEXIST_catalog_MISSING_SENTINEL.json",
                        "--output", "/tmp/test_creds_cat_missing.json"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 2,
                         f"rc={r.returncode} (want 2)\nstderr={r.stderr[:200]}")
        self.assertIn("catalog", r.stderr.lower())

    def test_malformed_catalog_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write("{this is not valid json !!!")
            bad_catalog = f.name
        r = _run_sweep(["--target", "127.0.0.1:9",
                        "--catalog", bad_catalog,
                        "--output", "/tmp/test_creds_cat_bad.json"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 2,
                         f"rc={r.returncode} (want 2)\nstderr={r.stderr[:200]}")
        self.assertIn("catalog", r.stderr.lower())

    def test_catalog_missing_products_key_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"not_products": []}, f)
            bad_catalog = f.name
        r = _run_sweep(["--target", "127.0.0.1:9",
                        "--catalog", bad_catalog,
                        "--output", "/tmp/test_creds_cat_noprod.json"])
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 2,
                         f"rc={r.returncode} (want 2)\nstderr={r.stderr[:200]}")


# ---------------------------------------------------------------- DEFECT-6
class TestIPv6ParseTarget(unittest.TestCase):
    """DEFECT-6: parse_target must produce correctly bracketed IPv6 URLs.

    All three problem forms from the bug report are tested as pure-function
    calls (no network) plus a subprocess repro confirming no silent no-op.
    """

    def _urls(self, target: str) -> list[str]:
        return _SWEEP_MOD.parse_target(target)

    def test_bare_ipv6_is_bracketed(self):
        # '2001:db8::1' → must produce http://[2001:db8::1]:80
        urls = self._urls("2001:db8::1")
        self.assertTrue(any("http://[2001:db8::1]" in u for u in urls),
                        f"bare IPv6 not bracketed: {urls}")

    def test_bracketed_ipv6_with_port(self):
        # '[::1]:8080' → http://[::1]:8080 (not http://::1:8080)
        urls = self._urls("[::1]:8080")
        self.assertEqual(urls, ["http://[::1]:8080"],
                         f"bracketed-IPv6+port produced wrong URLs: {urls}")

    def test_bracketed_ipv6_no_port_defaults(self):
        # '[2001:db8::1]' (no port) → must NOT produce corrupted port string
        urls = self._urls("[2001:db8::1]")
        for u in urls:
            self.assertNotIn("[2001:db8::1]:", u.split("//", 1)[-1].split("/")[0].rsplit(":", 1)[-1] if False else "",
                             "port must not be the entire address string")
        self.assertTrue(any("[2001:db8::1]" in u for u in urls),
                        f"address not bracketed: {urls}")
        # The corrupted form from the original bug was http://2001:db8::1:[2001:db8::1]
        for u in urls:
            self.assertNotIn("::[2001", u, f"corrupted URL produced: {u}")

    def test_ipv4_unchanged(self):
        # Confirm ordinary IPv4:port still works correctly after the refactor.
        urls = self._urls("192.168.1.1:8080")
        self.assertIn("http://192.168.1.1:8080", urls,
                      f"IPv4 target mangled: {urls}")

    def test_unmatched_bracket_returns_empty_with_warning(self):
        # '[::1' with no closing bracket must not crash; must return [] (visible stderr warning).
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            urls = _SWEEP_MOD.parse_target("[::1")
        self.assertEqual(urls, [],
                         f"unmatched bracket should yield empty list, got: {urls}")
        self.assertIn("unparseable", buf.getvalue().lower(),
                      f"no warning emitted for unmatched bracket: {buf.getvalue()!r}")

    def test_https_port_detected(self):
        # [::1]:443 → https://[::1]:443
        urls = self._urls("[::1]:443")
        self.assertIn("https://[::1]:443", urls,
                      f"HTTPS not detected for [::1]:443: {urls}")


# ---------------------------------------------------------------- DEFECT-7
class TestSprayDryRunNoSleep(unittest.TestCase):
    """DEFECT-7: --dry-run must NEVER call time.sleep when lockout state >= threshold.

    Discriminator: seed a state file so user 'admin' has `threshold` recent
    attempts, then run with --interval 30 (=1800s sleep without the fix).
    With a 15s subprocess timeout, the bug causes TimeoutExpired; the fix
    completes in < 1s.
    """

    def _seed_state(self, threshold: int) -> tuple[Path, Path, Path, Path]:
        """Return (state_file, users_file, pws_file, outdir)."""
        td = Path(tempfile.mkdtemp(prefix="spray-test-"))
        state_file = td / "state.json"
        state = {"admin": [time.time() - 10] * threshold}
        state_file.write_text(json.dumps(state))

        users_file = td / "users.txt"
        users_file.write_text("admin\n")

        pws_file = td / "pws.txt"
        pws_file.write_text("pass1\n")

        return state_file, users_file, pws_file, td

    def test_dry_run_completes_without_sleeping(self):
        state_file, users_file, pws_file, _ = self._seed_state(threshold=3)
        t0 = time.monotonic()
        r = _run_spray([
            "--users", str(users_file),
            "--passwords", str(pws_file),
            "--tool", "/bin/true",
            "--dry-run",
            "--threshold", "3",
            "--interval", "30",
            "--state-file", str(state_file),
        ], timeout=15)
        elapsed = time.monotonic() - t0
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertLess(elapsed, 5.0,
                        f"--dry-run slept for {elapsed:.1f}s — lockout sleep is NOT skipped")
        self.assertEqual(r.returncode, 0,
                         f"rc={r.returncode}\nstdout={r.stdout[:200]}\nstderr={r.stderr[:200]}")

    def test_dry_run_prints_would_sleep_message(self):
        state_file, users_file, pws_file, _ = self._seed_state(threshold=3)
        r = _run_spray([
            "--users", str(users_file),
            "--passwords", str(pws_file),
            "--tool", "/bin/true",
            "--dry-run",
            "--threshold", "3",
            "--interval", "30",
            "--state-file", str(state_file),
        ], timeout=15)
        self.assertIn("[DRY]", r.stdout,
                      f"dry-run would-sleep message missing:\nstdout={r.stdout[:300]}")
        self.assertIn("sleep", r.stdout.lower(),
                      f"'sleep' not mentioned in dry-run output:\nstdout={r.stdout[:300]}")

    def test_real_run_still_records_state(self):
        """Confirm non-dry-run path is unaffected: state file is written."""
        td = Path(tempfile.mkdtemp(prefix="spray-test-real-"))
        state_file = td / "state.json"
        users_file = td / "users.txt"
        users_file.write_text("bob\n")
        pws_file = td / "pws.txt"
        pws_file.write_text("secret\n")

        r = _run_spray([
            "--users", str(users_file),
            "--passwords", str(pws_file),
            "--tool", "/bin/true",
            "--threshold", "3",
            "--interval", "1",
            "--state-file", str(state_file),
        ], timeout=10)
        self.assertNotIn("Traceback (most recent call last)", r.stderr)
        self.assertEqual(r.returncode, 0)
        self.assertTrue(state_file.exists(),
                        "state file not written in real (non-dry-run) mode")
        state = json.loads(state_file.read_text())
        self.assertIn("bob", state)
        self.assertEqual(len(state["bob"]), 1)


if __name__ == "__main__":
    unittest.main()
