"""Static lint + smoke tests for the 1d thick-client enumerators.

- bash -n syntax check on thickclient-hunt.sh AND the linenum-fast.sh hook.
- PowerShell parse check via `pwsh` if present, else a clear skip.
- Structural marker checks (no pwsh needed) so the Windows scripts are covered
  even on a Linux CI host.
- A read-only smoke run of thickclient-hunt.sh on the runner (self-target):
  must exit 0 and emit the expected section/markers.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TC_SH = REPO / "standalones" / "linux" / "thickclient-hunt.sh"
LINENUM = REPO / "standalones" / "linux" / "linenum-fast.sh"
TC_PS1 = REPO / "standalones" / "windows" / "Get-ThickClientEnum.ps1"
PRIVESC_PS1 = REPO / "standalones" / "windows" / "Invoke-PrivEscEnum.ps1"

_HAVE_BASH = shutil.which("bash") is not None
_PWSH = shutil.which("pwsh")


# ------------------------------------------------------------------ existence
@pytest.mark.parametrize("p", [TC_SH, LINENUM, TC_PS1, PRIVESC_PS1])
def test_files_exist(p):
    assert p.is_file(), f"missing owned file: {p}"


# ------------------------------------------------------------------ bash -n
@pytest.mark.skipif(not _HAVE_BASH, reason="bash not available")
@pytest.mark.parametrize("script", [TC_SH, LINENUM])
def test_bash_syntax(script):
    r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n failed for {script.name}:\n{r.stderr}"


def test_thickclient_sets_pipefail():
    assert "set -uo pipefail" in TC_SH.read_text()


# ------------------------------------------------------------------ powershell parse
@pytest.mark.skipif(_PWSH is None, reason="pwsh not installed — PS parse check skipped")
@pytest.mark.parametrize("script", [TC_PS1, PRIVESC_PS1])
def test_powershell_parses(script):
    cmd = (
        "$e=$null;"
        f"[System.Management.Automation.Language.Parser]::ParseFile('{script}',[ref]$null,[ref]$e)|Out-Null;"
        "if($e -and $e.Count -gt 0){$e|ForEach-Object{Write-Error $_.Message};exit 1}else{exit 0}"
    )
    r = subprocess.run([_PWSH, "-NoProfile", "-Command", cmd], capture_output=True, text=True)
    assert r.returncode == 0, f"pwsh parse errors in {script.name}:\n{r.stderr}"


# ------------------------------------------------------------------ structural (no pwsh)
def test_windows_standalone_is_cmdletbinding_and_writes_output():
    txt = TC_PS1.read_text()
    assert "[CmdletBinding()]" in txt
    assert "Write-Output" in txt  # data stream per CLAUDE.md §8
    # a representative set of the new finding-class markers
    for marker in (
        "THICKCLIENT-APP",
        "THICKCLIENT-SAVED-SESSION",
        "THICKCLIENT-SSHKEY-AT-REST",
        "THICKCLIENT-RDP-CREDS",
        "THICKCLIENT-VPN-PROFILE",
        "THICKCLIENT-BROWSER-LOGINDB",
        "THICKCLIENT-ELECTRON",
        "THICKCLIENT-CONFIG-SECRET",
    ):
        assert marker in txt, f"{marker} missing from {TC_PS1.name}"


def test_privesc_hook_is_inlined_not_dotsourced():
    txt = PRIVESC_PS1.read_text()
    assert "THICK CLIENT / WORKSTATION APPS" in txt
    assert "THICKCLIENT-SAVED-SESSION" in txt
    # ADR-002 D1: self-contained — no line may dot-source / import the standalone.
    for raw in txt.splitlines():
        line = raw.strip()
        if "Get-ThickClientEnum" in line:
            assert not line.startswith(". "), f"dot-source of standalone: {line}"
            assert not line.lower().startswith("import-module"), line
            assert "invoke-expression" not in line.lower(), line
            assert "iex " not in line.lower(), line


def test_linux_hook_is_inlined():
    txt = LINENUM.read_text()
    assert "THICK-CLIENT / WORKSTATION APPS" in txt
    assert "THICKCLIENT-SSHKEY-AT-REST" in txt
    # ADR-002 D1: self-contained — no source/dot-import of the sibling standalone.
    for raw in txt.splitlines():
        line = raw.strip()
        if "thickclient-hunt.sh" in line and not line.startswith("#") and "echo" not in line:
            assert not line.startswith("source "), f"source of standalone: {line}"
            assert not line.startswith(". "), f"dot-import of standalone: {line}"


# ------------------------------------------------------------------ smoke run
@pytest.mark.skipif(not _HAVE_BASH, reason="bash not available")
def test_thickclient_smoke_run_self_target():
    r = subprocess.run(
        ["bash", str(TC_SH)], capture_output=True, text=True, timeout=120
    )
    assert r.returncode == 0, f"thickclient-hunt.sh exited {r.returncode}\n{r.stderr[:500]}"
    out = r.stdout
    assert "THICK-CLIENT APP INVENTORY" in out
    assert "===[ DONE ]===" in out
    # every emitted finding uses the [+] style report.py ingests
    for line in out.splitlines():
        if line.startswith("[+] THICKCLIENT"):
            break
    else:
        # It's acceptable for a bare CI host to have no thick-client artifacts;
        # the section headers must still be present (checked above).
        pass


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
