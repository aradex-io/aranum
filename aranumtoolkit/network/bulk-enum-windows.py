#!/usr/bin/env python3
"""bulk-enum-windows.py — run Invoke-PrivEscEnum.ps1 against many Windows
hosts in parallel over WinRM, Windows OpenSSH, or SMB/WMI. Per ADR-003 +
ADR-006 (Workstream 1c: multi-transport).

Mirrors the bulk-enum-linux.sh CLI shape so an operator who knows one
knows the other:

    --targets FILE         host or user@host per line; '#' comments OK
    --user USER            default username
    --pass PASSWORD        password (NTLM/Basic/CredSSP/ssh-password/SMB all use this)
    --key PATH             SSH private key (ssh transport only; KEY / KEY_THEN_PASS modes)
    --transport SPEC       {auto,winrm,ssh,smb}, comma-list or repeatable (default: auto)
    --auth {ntlm,basic,kerberos,credssp}   default: ntlm (winrm transport only)
    --port N               default 5985 (HTTP) or 5986 (HTTPS via --tls) — WinRM port
    --ssh-port N            default 22 — ssh transport port
    --tls                  use HTTPS:5986 for winrm (defaults to insecure cert mode)
    --script PATH          script to ship (default: standalones/windows/Invoke-PrivEscEnum.ps1)
    --use-smb-admin        REQUIRED explicit consent to use the smb transport at all
                           (admin-only; see ADR-003 D2 / ADR-006 SMB caveat below).
    -o, --output DIR       results dir
    -P, --parallel N       default 4, cap 16
    --throttle             gentle mode (-P 1 + inter-host delay)
    --dry-run              print plan + effective config, no connections
    --resume               skip hosts with .done from a prior run
    --connect-timeout SEC  default 10

Output layout matches ADR-002 D5 / bulk-enum-linux.sh's layout — only the
filename changes (winenum.txt vs linenum.txt). report.py auto-detects both
formats in the same $OUT dir. `_meta.json` now records which transport
actually succeeded (`"transport"`) and a `"status"` classification shared
with the Linux side: OK | AUTH_FAIL | UNREACHABLE | REMOTE_ERR.

TRANSPORTS
----------
winrm (existing, ADR-003 D1): pywinrm session, ntlm/basic/kerberos/credssp,
    5985/5986, --tls. `Invoke-Command`-equivalent keeps the script in the
    remote process's memory — no on-disk artifact on the target.

ssh (NEW, ADR-006 D1c-1): Windows OpenSSH Server (port 22, override with
    --ssh-port). The PowerShell script is piped over ssh stdin to
    `powershell -NoProfile -NonInteractive -Command -`, mirroring the
    Linux stdin-pipe transport exactly — no on-disk artifact either.
    The ssh argv is built by `build_ssh_argv()` below, which implements
    the ADR-006 "Post-review revisions" SSH-option-spec table verbatim
    (the same table `bulk-enum-linux.sh`'s `ssh_base_args()` implements) —
    this is the canonical cross-language spec that makes the 1a
    BatchMode-vs-sshpass bug (workstream 1a) impossible to re-ship here.
    `sshpass` wraps the ssh invocation whenever a password is required
    (PASS or KEY_THEN_PASS mode); if sshpass isn't installed, that
    specific host degrades to a clear AUTH_FAIL with an actionable
    message rather than a silent hang.

smb (NEW, formalizes the old --use-smb-admin fallback, ADR-003 D2 /
    ADR-006): impacket wmiexec-style exec of a base64 `-EncodedCommand`
    PS payload. Admin-only, opt-in ONLY via --use-smb-admin — this flag
    is required whenever "smb" appears in the resolved transport order,
    whether by explicit `--transport smb` or by inclusion in the `auto`
    default (auto never silently adds smb; the operator must ask for it).
    ****CAVEAT (ADR-006 post-review, resolves non-blocking rec #2):****
    Unlike winrm/ssh, this transport does NOT keep the no-on-disk-artifact
    guarantee from ADR-002 D1. impacket's wmiexec/smbexec family retrieve
    command output via a transient file written to the ADMIN$ share (and
    a temporary service/process is created via WMI/SCM) — this is visible
    to host-side EDR and leaves a forensic trace distinct from the
    WinRM/SSH stdin-pipe transports. Treat --use-smb-admin as accepting
    that trade-off, not as "same OPSEC property, different protocol."

WHAT THIS DOES NOT VALIDATE: see ADR-003's "What this ADR DOES NOT
validate" section. The WinRM transport is unverified pre-engagement on
this codebase's CI. This applies identically to the new ssh and smb
transports — there is no domain-joined Windows host, no Windows OpenSSH
server, and no real SMB/WMI target in CI. What CI *does* verify (mocked,
no live Windows/network calls):
  - target-spec parsing / IPv6 bracketing / output layout / --dry-run
  - --transport parsing, ordering, and auto fallthrough
  - dependency-absent degradation messaging (pywinrm / impacket / ssh)
  - the ssh transport's argv construction for all three auth modes
    (KEY / PASS / KEY_THEN_PASS), including the BatchMode/sshpass
    regression assertion
  - base64 PS-payload wrapping (smb transport)
  - status classification (OK/AUTH_FAIL/UNREACHABLE/REMOTE_ERR)
The operator's first real run against a known-good Windows VM (WinRM),
an OpenSSH-enabled Windows host (ssh), and an admin-reachable host (smb)
is the validation for each transport respectively. Treat that as
engagement prep, not the engagement.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# pywinrm is a hard dep at run-time but soft at import (so --help / --dry-run
# work on hosts without pywinrm installed).
try:
    import winrm                            # type: ignore
    from winrm.protocol import Protocol     # type: ignore
    HAS_PYWINRM = True
except ImportError:
    HAS_PYWINRM = False

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCRIPT = PROJECT_ROOT / "standalones" / "windows" / "Invoke-PrivEscEnum.ps1"
PARALLEL_CAP = 16
TRANSPORT_NAMES = ("winrm", "ssh", "smb")


# --------------------------------------------------------------------- colour helpers
def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    codes = {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m", "C": "\033[1;36m"}
    return f"{codes.get(code, '')}{s}\033[0m"


def err(msg: str) -> None:  print(_c(f"[!] {msg}", "R"), file=sys.stderr)
def warn(msg: str) -> None: print(_c(f"[?] {msg}", "Y"), file=sys.stderr)
def hit(msg: str) -> None:  print(_c(f"[+] {msg}", "G"))
def log(msg: str) -> None:  print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# --------------------------------------------------------------------- target parsing
@dataclass
class Target:
    user: str
    host: str
    port: int
    raw_spec: str   # original line, for logging


def parse_spec(spec: str, default_user: str, default_port: int) -> Optional[Target]:
    """Parse one targets-file line. Returns None for blanks / comments."""
    spec = spec.split("#", 1)[0].strip()
    if not spec:
        return None
    user = default_user
    rest = spec
    if "@" in spec:
        user, rest = spec.split("@", 1)
    # IPv6 bracketed: [::1]:port  OR  [::1]
    m = re.match(r"^\[([0-9a-fA-F:]+)\](?::(\d+))?$", rest)
    if m:
        host = m.group(1)
        port = int(m.group(2)) if m.group(2) else default_port
        return Target(user=user, host=host, port=port, raw_spec=spec)
    # host:port (but not bare IPv6 — IPv6 must be bracketed in target files)
    if rest.count(":") == 1:
        host, port_s = rest.split(":", 1)
        if port_s.isdigit():
            return Target(user=user, host=host, port=int(port_s), raw_spec=spec)
    return Target(user=user, host=rest, port=default_port, raw_spec=spec)


# --------------------------------------------------------------------- transport selection
def _flatten_transport_spec(raw: Optional[list[str]]) -> list[str]:
    """Turn argparse's `action="append"` accumulation (each item possibly a
    comma-list) into a de-duped, order-preserving list of lower-case names.
    Defaults to ["auto"] when nothing was given. Raises ValueError on an
    unrecognised transport name."""
    if not raw:
        return ["auto"]
    items: list[str] = []
    for chunk in raw:
        for piece in chunk.split(","):
            piece = piece.strip().lower()
            if piece:
                items.append(piece)
    if not items:
        return ["auto"]
    valid = {"auto", *TRANSPORT_NAMES}
    bad = [i for i in items if i not in valid]
    if bad:
        raise ValueError(f"unknown transport(s): {', '.join(bad)} "
                          f"(valid: auto, {', '.join(TRANSPORT_NAMES)})")
    seen: set = set()
    ordered = []
    for i in items:
        if i not in seen:
            seen.add(i)
            ordered.append(i)
    return ordered


def resolve_transport_order(raw: Optional[list[str]], use_smb_admin: bool) -> list[str]:
    """Resolve the final, ordered list of transports to try per host.

    `auto` (the default, alone or mixed with anything else) expands to
    winrm -> ssh, appending smb ONLY if the operator passed
    --use-smb-admin (ADR-003 D2's explicit-consent gate: smb never
    joins the party silently, even under `auto`).

    An explicit, non-auto list (e.g. `--transport ssh,smb`) is honored
    verbatim in the given order — but if it contains "smb" without
    --use-smb-admin, that is refused (ValueError) rather than silently
    dropped: the operator asked for smb explicitly, so a loud refusal is
    more honest than quietly skipping it.
    """
    items = _flatten_transport_spec(raw)
    if "auto" in items:
        order = ["winrm", "ssh"]
        if use_smb_admin:
            order.append("smb")
        return order
    if "smb" in items and not use_smb_admin:
        raise ValueError("transport 'smb' requires --use-smb-admin (explicit admin-creds "
                          "consent; ADR-003 D2 / ADR-006 — smb is never auto-selected)")
    return items


# --------------------------------------------------------------------- SSH argv builder
# ADR-006 "Post-review revisions" SSH-option-spec table — THE canonical,
# language-neutral source of truth. bulk-enum-linux.sh's ssh_base_args()
# implements the same table in bash; this is the Python side (also reused,
# conceptually, by ssh-key-triage.py in workstream 1d). The single rule
# that matters: BatchMode / PubkeyAuthentication / -i are gated on the
# explicit mode below, NEVER on the mere presence of a password — that is
# exactly the 1a bug (BatchMode=yes swallowing sshpass's prompt) re-shipped
# in a new language.
def _ssh_mode(key: Optional[str], password: Optional[str]) -> str:
    if key and password:
        return "KEY_THEN_PASS"
    if password:
        return "PASS"
    return "KEY"   # covers --key-only and the bare-agent default (no --key, no --pass)


def build_ssh_argv(target: Target, *, user: str, key: Optional[str], password: Optional[str],
                    ssh_port: int, connect_timeout: int, known_hosts: Path) -> tuple[list[str], str]:
    """Build the ssh argv per the ADR-006 SSH-option-spec table.
    Returns (argv, mode) where mode is one of KEY | PASS | KEY_THEN_PASS.

    | Mode          | -i key | Key opts                                   | Password opts |
    |---------------|--------|---------------------------------------------|---------------|
    | KEY           | if --key | BatchMode=yes, PreferredAuthentications=publickey, IdentitiesOnly=yes (if --key) | — |
    | PASS          | no     | PubkeyAuthentication=no                     | BatchMode=no, PreferredAuthentications=keyboard-interactive,password, NumberOfPasswordPrompts=1 |
    | KEY_THEN_PASS | yes    | IdentitiesOnly=yes (pubkey NOT disabled)    | BatchMode=no, PreferredAuthentications=publickey,keyboard-interactive,password, NumberOfPasswordPrompts=1 |
    """
    mode = _ssh_mode(key, password)
    argv: list[str] = ["ssh", "-p", str(ssh_port)]
    if mode == "KEY":
        if key:
            argv += ["-i", key, "-o", "IdentitiesOnly=yes"]
        argv += ["-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey"]
    elif mode == "PASS":
        # No BatchMode=yes: sshpass needs the interactive password prompt.
        argv += [
            "-o", "PubkeyAuthentication=no",
            "-o", "BatchMode=no",
            "-o", "PreferredAuthentications=keyboard-interactive,password",
            "-o", "NumberOfPasswordPrompts=1",
        ]
    elif mode == "KEY_THEN_PASS":
        # Pubkey stays ENABLED (key tried first); password is the fallback.
        # Only the one given key is offered (IdentitiesOnly). Do NOT set
        # PubkeyAuthentication=no here — that would kill the key attempt.
        argv += [
            "-i", key, "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=no",
            "-o", "PreferredAuthentications=publickey,keyboard-interactive,password",
            "-o", "NumberOfPasswordPrompts=1",
        ]
    argv += [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"ConnectTimeout={connect_timeout}",
        "-o", "LogLevel=ERROR",
        f"{user}@{target.host}",
        "powershell", "-NoProfile", "-NonInteractive", "-Command", "-",
    ]
    return argv, mode


def _classify_ssh_result(rc: int, stderr: str, *, password_used: bool) -> tuple[str, str]:
    """Map (ssh rc, stderr) -> (status, fail_reason). Mirrors
    bulk-enum-linux.sh's classify_status() (ADR-006 D1a-2), folded onto
    the 4-way status vocabulary this transport uses (TIMEOUT collapses
    into UNREACHABLE here)."""
    if rc == 0:
        return "OK", ""
    low = stderr.lower()
    if rc == 255:
        if re.search(r"permission denied|authentication failed|"
                     r"too many authentication failures", low):
            return "AUTH_FAIL", "permission denied"
        if re.search(r"connection refused|no route to host|network is unreachable|"
                     r"name or service not known|could not resolve|connection closed", low):
            return "UNREACHABLE", "host unreachable"
        if re.search(r"timed out|timeout", low):
            return "UNREACHABLE", "connection timed out"
        return "UNREACHABLE", "ssh transport error (rc=255)"
    if rc == 5 and password_used:
        # sshpass's own exit code for a detected incorrect-password re-prompt.
        return "AUTH_FAIL", "sshpass: incorrect password"
    return "REMOTE_ERR", f"remote command exited rc={rc}"


def _classify_winrm(rc: int, stderr: str) -> tuple[str, str]:
    """Classify a WinRM outcome. `_winrm_run` funnels any pywinrm/requests
    exception into rc=255 with stderr="ExceptionClassName: message" (see
    below) — everything else is a real WSMan status_code from a script
    that actually ran (auth succeeded)."""
    if rc == 0:
        return "OK", ""
    low = stderr.lower()
    exc_name = stderr.split(":", 1)[0].strip()
    if exc_name == "InvalidCredentialsError" or "unauthorized" in low or " 401" in low:
        return "AUTH_FAIL", "WinRM authentication rejected"
    if ("connection" in exc_name.lower() or "timeout" in exc_name.lower() or
            "winrmtransporterror" in exc_name.lower() or
            re.search(r"connection refused|no route to host|timed out|"
                      r"name or service not known", low)):
        return "UNREACHABLE", "WinRM endpoint unreachable"
    if rc == 127:
        return "UNREACHABLE", stderr or "pywinrm not installed"
    return "REMOTE_ERR", stderr or f"remote script exited rc={rc}"


def _classify_smb(rc: int, stderr: str) -> tuple[str, str]:
    if rc == 0:
        return "OK", ""
    if rc == 127:
        # impacket-wmiexec/wmiexec.py missing — shouldn't normally reach here
        # since the orchestrator gates on SMBTransport.available() first, but
        # keep this honest if _smb_admin_run is ever called directly.
        return "UNREACHABLE", stderr or "impacket-wmiexec not on PATH"
    if rc == 126:
        return "REMOTE_ERR", stderr or "script too large for SMB/WMI command line"
    low = stderr.lower()
    if re.search(r"logon_failure|access_denied|authentication|login failure|"
                 r"invalid credentials", low):
        return "AUTH_FAIL", "SMB/WMI authentication rejected"
    if re.search(r"connection error|timed out|no route to host|connection refused|"
                 r"unreachable", low):
        return "UNREACHABLE", "SMB/WMI endpoint unreachable"
    return "REMOTE_ERR", stderr or f"wmiexec exited rc={rc}"


# --------------------------------------------------------------------- transport implementations
def _winrm_run(target: Target, script_text: str, *, password: str, auth: str,
               tls: bool, timeout: int, cert_validation: str = "ignore") -> tuple[int, str, str]:
    """Send script_text as a PowerShell block over WinRM. Returns (rc, stdout, stderr).

    pywinrm's Session.run_ps wraps the script in `powershell.exe -EncodedCommand
    <base64-utf16-le>` which keeps the script in-memory on the target (no
    disk write — matches the OPSEC property the ADR documents)."""
    if not HAS_PYWINRM:
        return (127, "", "pywinrm not installed (pip install pywinrm)")
    scheme = "https" if tls else "http"
    # IPv6 hosts must be bracketed in the URL (urllib's parser otherwise
    # treats the trailing :N of the address as a port). Matches the Linux
    # orchestrator's parse_spec output convention.
    host_in_url = f"[{target.host}]" if ":" in target.host else target.host
    endpoint = f"{scheme}://{host_in_url}:{target.port}/wsman"
    transport_kw = {"ntlm": "ntlm", "basic": "basic",
                    "kerberos": "kerberos", "credssp": "credssp"}[auth]
    try:
        session = winrm.Session(
            endpoint,
            auth=(target.user, password),
            transport=transport_kw,
            server_cert_validation=cert_validation,
            read_timeout_sec=timeout * 2,    # WinRM read should be ~2x connect
            operation_timeout_sec=timeout,
        )
        r = session.run_ps(script_text)
        return (r.status_code,
                (r.std_out or b"").decode("utf-8", errors="replace"),
                (r.std_err or b"").decode("utf-8", errors="replace"))
    except Exception as e:                   # noqa: BLE001  surface as winenum.err
        return (255, "", f"{type(e).__name__}: {e}")


def _smb_admin_run(target: Target, script_text: str, *, password: str,
                   timeout: int) -> tuple[int, str, str]:
    """SMB fallback via impacket-wmiexec. Per ADR-003 D2 requires admin creds; the
    operator MUST pass --use-smb-admin to enable this path.

    Delivery is an in-memory `powershell -EncodedCommand` (no script FILE
    staged to disk). HOWEVER — per ADR-006 post-review (resolves
    non-blocking rec #2) — impacket's wmiexec family retrieves command
    OUTPUT via a transient file written to the ADMIN$ share (and a
    temporary WMI/service-control-manager process), so this transport does
    NOT carry the full no-on-disk-artifact guarantee ADR-002 D1 documents
    for the WinRM/SSH stdin-pipe transports. State this plainly to the
    operator rather than implying parity — see the module docstring's SMB
    CAVEAT paragraph.

    WMI Win32_Process.Create caps the CommandLine near 8191 chars, so this
    only fits smaller --scripts; the default Invoke-PrivEscEnum.ps1 is too
    large and returns a clear, actionable refusal rather than silently
    staging to disk (which would need its own §9 consent).

    NOTE (ADR-003): like the WinRM path, this transport is NOT exercised in CI —
    the first real run against a known-good host is the validation."""
    wmiexec = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not wmiexec:
        return (127, "", "impacket-wmiexec not on PATH (pipx install impacket)")

    enc = base64.b64encode(script_text.encode("utf-16-le")).decode("ascii")
    ps_cmd = f"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}"
    if len(ps_cmd) > 8000:
        return (126, "",
                f"--script too large for the SMB/WMI command line "
                f"({len(ps_cmd)} chars > 8000). The default Invoke-PrivEscEnum.ps1 does not "
                "fit inline. Options: (a) use the WinRM or ssh transport, (b) pass a smaller "
                "--script, or (c) run impacket-psexec/-smbexec manually with a staged "
                "script + engagement scoping (disk write needs its own §9 consent).")

    # impacket target string: [DOMAIN/]user:password@host  (user may arrive as CORP\jay)
    user = target.user
    dom = ""
    if "\\" in user:
        dom, user = user.split("\\", 1)
    elif "/" in user:
        dom, user = user.split("/", 1)
    principal = f"{dom}/{user}" if dom else user
    conn = f"{principal}:{password}@{target.host}"
    try:
        p = subprocess.run([wmiexec, conn, ps_cmd],
                           capture_output=True, text=True, timeout=max(timeout * 4, 60))
        return (p.returncode, p.stdout or "", p.stderr or "")
    except subprocess.TimeoutExpired:
        return (255, "", f"impacket-wmiexec timed out after {max(timeout * 4, 60)}s")
    except Exception as e:                    # noqa: BLE001  surface as winenum.err
        return (255, "", f"{type(e).__name__}: {e}")


@dataclass
class TransportResult:
    """Uniform per-attempt outcome every transport class returns. The
    orchestrator (`run_one_host`) turns exactly one of these — the one
    that "wins" the auto/explicit fallthrough — into the per-host
    `HostResult` below, adding timing/byte-count bookkeeping that's an
    orchestration concern, not a transport concern."""
    rc: int
    stdout: str
    stderr: str
    status: str          # OK | AUTH_FAIL | UNREACHABLE | REMOTE_ERR
    fail_reason: str = ""


class Transport:
    """Base class for the pluggable transport layer (ADR-006 D1c-1). Each
    subclass implements `available()` (soft dependency check — must NEVER
    raise or import-fail so --help/--dry-run keep working), a human
    `unavailable_reason()`, and `run(target, script_text, args) ->
    TransportResult`."""
    name = "base"

    @staticmethod
    def available() -> bool:
        raise NotImplementedError

    @staticmethod
    def unavailable_reason() -> str:
        return "dependency not installed"

    def run(self, target: Target, script_text: str, args: argparse.Namespace) -> TransportResult:
        raise NotImplementedError


class WinRMTransport(Transport):
    name = "winrm"

    @staticmethod
    def available() -> bool:
        return HAS_PYWINRM

    @staticmethod
    def unavailable_reason() -> str:
        return "pywinrm not installed"

    def run(self, target: Target, script_text: str, args: argparse.Namespace) -> TransportResult:
        rc, stdout, stderr = _winrm_run(
            target, script_text,
            password=args.password or "",
            auth=args.auth,
            tls=args.tls,
            timeout=args.connect_timeout,
        )
        status, reason = _classify_winrm(rc, stderr)
        return TransportResult(rc, stdout, stderr, status, reason)


class SSHTransport(Transport):
    name = "ssh"

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("ssh"))

    @staticmethod
    def unavailable_reason() -> str:
        return "ssh not installed"

    def run(self, target: Target, script_text: str, args: argparse.Namespace) -> TransportResult:
        password = args.password or None
        key = args.key or None
        known_hosts = Path(args.output).resolve() / "known_hosts"
        argv, mode = build_ssh_argv(
            target, user=target.user, key=key, password=password,
            ssh_port=args.ssh_port, connect_timeout=args.connect_timeout,
            known_hosts=known_hosts,
        )
        needs_password = mode in ("PASS", "KEY_THEN_PASS")
        cmd = argv
        env = os.environ.copy()
        if needs_password:
            if not shutil.which("sshpass"):
                msg = ("sshpass not installed — cannot use --pass over the ssh transport "
                       "(apt/dnf install sshpass, or use --key with a running ssh-agent for "
                       "non-interactive key auth instead).")
                warn(f"{target.host}: {msg}")
                return TransportResult(127, "", msg, "AUTH_FAIL", "sshpass_missing")
            env["SSHPASS"] = password or ""
            cmd = ["sshpass", "-e"] + argv
        timeout_s = max(args.connect_timeout * 4, 30)
        try:
            p = subprocess.run(cmd, input=script_text, capture_output=True,
                               text=True, timeout=timeout_s, env=env)
            rc, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return TransportResult(255, "", f"ssh timed out after {timeout_s}s",
                                   "UNREACHABLE", "connection timed out")
        except FileNotFoundError as e:
            return TransportResult(127, "", str(e), "UNREACHABLE", "ssh_or_sshpass_missing")
        except Exception as e:                # noqa: BLE001
            return TransportResult(255, "", f"{type(e).__name__}: {e}", "UNREACHABLE", "exception")
        status, reason = _classify_ssh_result(rc, stderr, password_used=needs_password)
        return TransportResult(rc, stdout, stderr, status, reason)


class SMBTransport(Transport):
    name = "smb"

    @staticmethod
    def available() -> bool:
        return bool(shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py"))

    @staticmethod
    def unavailable_reason() -> str:
        return "impacket not installed"

    def run(self, target: Target, script_text: str, args: argparse.Namespace) -> TransportResult:
        if not args.password:
            return TransportResult(2, "", "smb transport requires --pass (admin creds)",
                                   "AUTH_FAIL", "no_password")
        rc, stdout, stderr = _smb_admin_run(
            target, script_text, password=args.password, timeout=args.connect_timeout,
        )
        status, reason = _classify_smb(rc, stderr)
        return TransportResult(rc, stdout, stderr, status, reason)


TRANSPORT_CLASSES: dict[str, type] = {
    "winrm": WinRMTransport,
    "ssh": SSHTransport,
    "smb": SMBTransport,
}


# --------------------------------------------------------------------- per-host runner
@dataclass
class HostResult:
    target: Target
    rc: int
    started: str
    elapsed_s: int
    stdout_bytes: int
    stderr_bytes: int
    transport: str    # "winrm" | "ssh" | "smb" | "resume-skip" | "dry-run"
    status: str = "OK"          # OK | AUTH_FAIL | UNREACHABLE | REMOTE_ERR
    fail_reason: str = ""


def run_one_host(target: Target, script_text: str, args: argparse.Namespace,
                 out_dir: Path, usable_order: list[str]) -> HostResult:
    # Sanitise host into a single safe path component for the OUTPUT dir only —
    # a hostile/malformed targets line (e.g. ../../x) must never make mkdir
    # escape out_dir (OPSEC §9). The transport connection still uses target.host.
    safe_host = re.sub(r"[^A-Za-z0-9._:-]", "_", target.host) or "host"
    if safe_host in (".", ".."):
        safe_host = "host"
    hdir = out_dir / safe_host
    hdir.mkdir(parents=True, exist_ok=True)
    t0 = int(time.time())
    started = datetime.now(timezone.utc).isoformat()

    if args.resume and (hdir / ".done").exists():
        log(f"resume-skip: {target.host} (prior rc=0)")
        return HostResult(target, 0, started, 0, 0, 0, "resume-skip", "OK", "resume-skip-prior-run")

    if args.dry_run:
        host_disp = f"[{target.host}]" if ":" in target.host else target.host
        order_disp = ",".join(usable_order) if usable_order else "<none usable>"
        print(f"[DRY] {target.user}@{host_disp}:{target.port}  ->  {hdir}/winenum.txt"
              f"  (transport-order={order_disp}, auth={args.auth})")
        return HostResult(target, 0, started, 0, 0, 0, "dry-run", "OK", "")

    attempts: list[str] = []
    result: Optional[TransportResult] = None
    used_transport = "none"
    for name in usable_order:
        cls = TRANSPORT_CLASSES[name]
        outcome = cls().run(target, script_text, args)
        attempts.append(f"{name}={outcome.status}")
        result = outcome
        used_transport = name
        if outcome.status in ("OK", "REMOTE_ERR"):
            # Authentication succeeded (script ran, whether or not it exited
            # cleanly) — this transport "won"; stop the fallthrough here.
            break
        # else AUTH_FAIL / UNREACHABLE — try the next transport in order.

    if result is None:
        result = TransportResult(2, "", "no usable transport for this host",
                                 "UNREACHABLE", "no_transport_available")
        used_transport = "none"

    fail_reason = result.fail_reason
    if result.status not in ("OK", "REMOTE_ERR") and len(attempts) > 1:
        fail_reason = f"{fail_reason} (attempted: {', '.join(attempts)})"

    (hdir / "winenum.txt").write_text(result.stdout)
    (hdir / "winenum.err").write_text(result.stderr)

    elapsed = int(time.time()) - t0
    meta = {
        "host": target.host, "user": target.user, "port": target.port,
        "rc": result.rc, "status": result.status, "fail_reason": fail_reason,
        "started": started, "elapsed_s": elapsed,
        "size_bytes": len(result.stdout.encode("utf-8")),
        "err_bytes":  len(result.stderr.encode("utf-8")),
        "transport": used_transport, "transports_attempted": attempts,
        "auth": args.auth,
        "tls": args.tls,
        "script": str(args.script),
    }
    (hdir / "_meta.json").write_text(json.dumps(meta, indent=2))
    if result.status == "OK":
        (hdir / ".done").touch()

    if os.environ.get("ENUM_THROTTLE") == "1":
        time.sleep(int(os.environ.get("ENUM_THROTTLE_DELAY", "1")))

    return HostResult(target, result.rc, started, elapsed,
                      meta["size_bytes"], meta["err_bytes"], used_transport,
                      result.status, fail_reason)


# --------------------------------------------------------------------- main
def _run_log(out_dir: Path, msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with (out_dir / "run.log").open("a") as f:
        f.write(f"{ts}  {msg}\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=(
            "TRANSPORT-VALIDATION CAVEAT (ADR-003 / ADR-006):\n"
            "  winrm (pywinrm against live Windows 5985/5986), ssh (Windows\n"
            "  OpenSSH Server port 22), and smb (impacket-wmiexec) are NOT\n"
            "  exercised against live Windows in this codebase's CI — no\n"
            "  domain-joined Windows host is available. Mock-transport unit\n"
            "  tests cover target parsing, IPv6 bracketing, output layout,\n"
            "  --transport ordering/fallthrough, dependency-absent\n"
            "  degradation, ssh argv construction (incl. the BatchMode/\n"
            "  sshpass regression check), and status classification. The\n"
            "  actual transports are verified by the operator's first real\n"
            "  run against a known-good host per transport. Treat that as\n"
            "  engagement prep, not the engagement.\n"
            "  See: aranumtoolkit/docs/ADR-003-20MAY2026-windows-bulk-enum-design.md\n"
            "       aranumtoolkit/docs/ADR-006-28JUL2026-bulk-enum-overhaul.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True,
                    help="one host or user@host[:port] per line; '#' comments OK")
    ap.add_argument("-u", "--user", default="",
                    help="default username for bare-host lines")
    ap.add_argument("-p", "--pass", dest="password",
                    help="password (NTLM/Basic/CredSSP/ssh-password/SMB all use this)")
    ap.add_argument("--key", default=None,
                    help="SSH private key path (ssh transport only; KEY / KEY_THEN_PASS "
                         "modes per the ADR-006 SSH-option-spec table). Ignored by other "
                         "transports.")
    ap.add_argument("--transport", action="append", default=None,
                    help="{auto,winrm,ssh,smb} — comma-list or repeatable. Default: auto "
                         "(winrm -> ssh, +smb only if --use-smb-admin). auto/explicit list "
                         "tries each in order until one AUTHENTICATES (rc doesn't matter "
                         "past that point); smb is never added silently — see --use-smb-admin.")
    ap.add_argument("--auth", choices=("ntlm", "basic", "kerberos", "credssp"),
                    default="ntlm",
                    help="winrm auth method (default: ntlm). basic requires --tls.")
    ap.add_argument("--port", type=int, default=0,
                    help="default WinRM port (auto: 5986 if --tls else 5985)")
    ap.add_argument("--ssh-port", type=int, default=22,
                    help="ssh transport port (default: 22)")
    ap.add_argument("--tls", action="store_true",
                    help="use HTTPS:5986 for winrm (server_cert_validation=ignore by default)")
    ap.add_argument("--connect-timeout", type=int, default=10,
                    help="seconds (default: 10)")
    ap.add_argument("--script", default=str(DEFAULT_SCRIPT),
                    help=f"PowerShell script to ship (default: {DEFAULT_SCRIPT.name})")
    ap.add_argument("--use-smb-admin", action="store_true",
                    help="Explicit consent to use the smb transport (impacket-wmiexec) at "
                         "all — REQUIRES admin creds + --pass; per ADR-003 D2 / ADR-006. "
                         "Without this flag, smb is refused if requested via --transport and "
                         "never added to the auto default. BREAKS the no-on-disk-artifact "
                         "guarantee winrm/ssh keep — see module docstring SMB CAVEAT. "
                         "Delivers the script as an in-memory powershell -EncodedCommand; "
                         "fits smaller --scripts only (the default is too large for the WMI "
                         "cmdline — it then returns rc=126 + guidance).")
    ap.add_argument("-o", "--output", required=True, help="results dir")
    ap.add_argument("-P", "--parallel", type=int, default=4,
                    help=f"parallel workers (default 4, capped at {PARALLEL_CAP})")
    ap.add_argument("--throttle", action="store_true",
                    help="gentle mode: -P 1 + ENUM_THROTTLE_DELAY between hosts")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan, no connections")
    ap.add_argument("--resume", action="store_true",
                    help="skip hosts with .done from a prior run")
    args = ap.parse_args()

    # --- arg validation ---
    targets_path = Path(args.targets)
    if not targets_path.is_file():
        err(f"targets file not found: {targets_path}"); return 2
    script_path = Path(args.script)
    if not script_path.is_file():
        err(f"script not found: {script_path}"); return 2
    if args.parallel > PARALLEL_CAP:
        err(f"parallel capped at {PARALLEL_CAP} (you asked for {args.parallel})")
        return 2
    if args.auth == "basic" and not args.tls:
        err("auth=basic over HTTP is refused (clear-text password); pass --tls")
        return 2
    if args.use_smb_admin and not args.password:
        err("--use-smb-admin requires --pass (admin creds)")
        return 2

    try:
        transport_order = resolve_transport_order(args.transport, args.use_smb_admin)
    except ValueError as e:
        err(str(e)); return 2

    if args.key and "ssh" not in transport_order:
        warn("--key given but the ssh transport is not in the resolved transport order — ignored")

    # --- dependency-absent degradation (ADR-006 D1c-2) ---
    usable_order: list[str] = []
    for name in transport_order:
        cls = TRANSPORT_CLASSES[name]
        if cls.available():
            usable_order.append(name)
        else:
            warn(f"transport '{name}' unavailable ({cls.unavailable_reason()}) — skipping")
    if not usable_order and not args.dry_run:
        err("no requested transport is usable (all unavailable) — see messages above")
        return 2

    if args.port == 0:
        args.port = 5986 if args.tls else 5985

    # --- effective parallel under --throttle ---
    explicit_parallel = ("-P" in sys.argv) or ("--parallel" in sys.argv)
    if args.throttle:
        os.environ["ENUM_THROTTLE"] = "1"
        os.environ.setdefault("ENUM_THROTTLE_DELAY", "1")
        if not explicit_parallel:
            args.parallel = 1
            print(_c(f"[*] --throttle: parallel=1 (default; override with -P N)", "C"))
        else:
            print(_c(f"[*] --throttle: parallel={args.parallel}  (operator-explicit; "
                     "--throttle did not override)", "C"))
        print(_c(f"    inter-host delay: {os.environ['ENUM_THROTTLE_DELAY']}s", "C"))

    # --- output dir + audit copies ---
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "hosts.txt").write_text(targets_path.read_text())
    _run_log(out_dir, "=== bulk-enum-windows run started ===")
    _run_log(out_dir, f"targets={targets_path} outdir={out_dir} "
                     f"parallel={args.parallel} throttle={args.throttle} "
                     f"resume={args.resume}")
    _run_log(out_dir, f"user={args.user or '<bare>'} auth={args.auth} "
                     f"tls={args.tls} port={args.port} script={script_path.name} "
                     f"transport_order={','.join(transport_order)} "
                     f"usable={','.join(usable_order) or '<none>'}")

    print(_c(f"[*] transport order: {','.join(transport_order)}"
             f"{'  (usable: ' + ','.join(usable_order) + ')' if usable_order != transport_order else ''}",
             "C"))

    # --- parse targets ---
    # default_port already accounts for --tls (set to 5986 if --tls else 5985
    # at lines above), so parse_spec inherits the correct fallback. This is
    # the WinRM-port field; the ssh transport uses --ssh-port independently.
    # Per-target ports in the targets file override the WinRM port field.
    targets: list[Target] = []
    default_port = args.port
    for line in targets_path.read_text().splitlines():
        t = parse_spec(line, args.user or os.environ.get("USER", ""), default_port)
        if t is None:
            continue
        targets.append(t)
    if not targets:
        err("no host entries in targets file (after stripping comments / blanks)")
        return 1
    log(f"{len(targets)} host(s) to enumerate -> {out_dir} (parallel={args.parallel})")
    _run_log(out_dir, f"dispatch: {len(targets)} hosts, parallel={args.parallel}")

    script_text = script_path.read_text()

    # --- dispatch ---
    results: list[HostResult] = []
    if args.parallel == 1:
        for t in targets:
            results.append(run_one_host(t, script_text, args, out_dir, usable_order))
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futs = {pool.submit(run_one_host, t, script_text, args, out_dir, usable_order): t
                    for t in targets}
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:                   # noqa: BLE001
                    t = futs[f]
                    err(f"{t.host}: orchestrator exception: {type(e).__name__}: {e}")

    # --- summary ---
    ok = sum(1 for r in results if r.status == "OK" and r.transport not in ("resume-skip", "dry-run"))
    fail = sum(1 for r in results if r.status != "OK")
    skip = sum(1 for r in results if r.transport in ("resume-skip", "dry-run"))
    with (out_dir / "_summary.tsv").open("w") as f:
        f.write("#host\trc\tstatus\telapsed_s\tsize_kb\ttransport\tfail_reason\n")
        for r in sorted(results, key=lambda x: x.target.host):
            size_kb = (r.stdout_bytes + 1023) // 1024
            f.write(f"{r.target.host}\t{r.rc}\t{r.status}\t{r.elapsed_s}\t{size_kb}\t"
                    f"{r.transport}\t{r.fail_reason}\n")

    print()
    print("=== bulk-enum-windows complete ===")
    print(f"OK={ok}  FAIL={fail}  SKIP={skip}")
    if fail > 0:
        print("Failed hosts:")
        for r in sorted([r for r in results if r.status != "OK"], key=lambda x: x.target.host):
            print(f"  - {r.target.host}(status={r.status}, rc={r.rc}, "
                  f"transport={r.transport}, reason={r.fail_reason})")
    print(f"Summary: {out_dir}/_summary.tsv")
    print(f"Per-host: {out_dir}/<host>/winenum.txt")
    print(f"Next: aranumtoolkit/network/report.py {out_dir}    "
          "# findings.json + report.md + report.html")
    _run_log(out_dir, f"complete: OK={ok} FAIL={fail} SKIP={skip}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
