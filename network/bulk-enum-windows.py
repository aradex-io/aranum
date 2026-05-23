#!/usr/bin/env python3
"""bulk-enum-windows.py — run Invoke-PrivEscEnum.ps1 against many Windows
hosts in parallel over WinRM. Per ADR-003.

Mirrors the bulk-enum-linux.sh CLI shape so an operator who knows one
knows the other:

    --targets FILE         host or user@host per line; '#' comments OK
    --user USER            default username
    --pass PASSWORD        password (NTLM/Basic/CredSSP all auth-via-password)
    --auth {ntlm,basic,kerberos,credssp}   default: ntlm
    --port N               default 5985 (HTTP) or 5986 (HTTPS via --tls)
    --tls                  use HTTPS:5986 (defaults to insecure cert mode)
    --script PATH          script to ship (default: windows/Invoke-PrivEscEnum.ps1)
    --use-smb-admin        opt-in SMB+wmiexec fallback for WinRM-unreachable
                           hosts. REQUIRES admin creds. Per ADR-003 D2.
    -o, --output DIR       results dir
    -P, --parallel N       default 4, cap 16
    --throttle             gentle mode (-P 1 + inter-host delay)
    --dry-run              print plan + effective config, no connections
    --resume               skip hosts with .done from a prior run
    --connect-timeout SEC  default 10

Output layout matches ADR-002 D5 / J's bulk-enum-linux.sh layout — only
the filename changes (winenum.txt vs linenum.txt). report.py auto-detects
both formats in the same $OUT dir.

WHAT THIS DOES NOT VALIDATE: see ADR-003's "What this ADR DOES NOT
validate" section. The WinRM transport is unverified pre-engagement on
this codebase's CI. The operator's first run against a known-good Windows
VM is the validation; consider it part of engagement prep.
"""
from __future__ import annotations

import argparse
import json
import os
import re
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

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCRIPT = REPO_ROOT / "windows" / "Invoke-PrivEscEnum.ps1"
PARALLEL_CAP = 16


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


# --------------------------------------------------------------------- per-host runner
@dataclass
class HostResult:
    target: Target
    rc: int
    started: str
    elapsed_s: int
    stdout_bytes: int
    stderr_bytes: int
    transport: str    # "winrm" | "smb-admin" | "dry-run"


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
    """SMB+wmiexec fallback via impacket-wmiexec. Per ADR-003 D2 requires
    admin creds; the operator MUST pass --use-smb-admin to enable this path."""
    wmiexec = shutil.which("impacket-wmiexec") or shutil.which("wmiexec.py")
    if not wmiexec:
        return (127, "", "impacket-wmiexec not on PATH (pip install impacket)")
    # We can't pipe arbitrary PowerShell over wmiexec cleanly — wmiexec's interactive
    # shell wraps each command. The supported flow is: stage the script via SMB write,
    # invoke it, clean up. We do NOT implement that here — it materially changes the
    # OPSEC surface (disk write + service start). Operators who need that path should
    # use impacket-psexec / impacket-smbexec directly with engagement-specific scoping.
    return (126, "",
            "--use-smb-admin path is documented-but-not-yet-implemented in this iteration\n"
            "(would require staging the script via SMB write + service exec, which has\n"
            "materially larger forensic footprint than the WinRM path — needs its own\n"
            "explicit-consent dialogue per CLAUDE.md §9 invariant 1. Use WinRM, or run\n"
            "impacket-wmiexec / -psexec directly with your engagement scoping.)")


def run_one_host(target: Target, script_text: str, args: argparse.Namespace,
                 out_dir: Path) -> HostResult:
    hdir = out_dir / target.host
    hdir.mkdir(parents=True, exist_ok=True)
    t0 = int(time.time())
    started = datetime.now(timezone.utc).isoformat()

    if args.resume and (hdir / ".done").exists():
        log(f"resume-skip: {target.host} (prior rc=0)")
        return HostResult(target, 0, started, 0, 0, 0, "resume-skip")

    if args.dry_run:
        host_disp = f"[{target.host}]" if ":" in target.host else target.host
        print(f"[DRY] {target.user}@{host_disp}:{target.port}  ->  {hdir}/winenum.txt"
              f"  (transport={'winrm-https' if args.tls else 'winrm'}, "
              f"auth={args.auth})")
        return HostResult(target, 0, started, 0, 0, 0, "dry-run")

    # WinRM first; --use-smb-admin only if WinRM fails AND the operator opted in.
    rc, stdout, stderr = _winrm_run(
        target, script_text,
        password=args.password or "",
        auth=args.auth,
        tls=args.tls,
        timeout=args.connect_timeout,
    )
    transport = "winrm"
    if rc != 0 and args.use_smb_admin:
        warn(f"{target.host}: WinRM rc={rc}, falling back to SMB-admin (operator opt-in)")
        rc2, stdout2, stderr2 = _smb_admin_run(
            target, script_text,
            password=args.password or "",
            timeout=args.connect_timeout,
        )
        if rc2 == 0:
            rc, stdout, stderr, transport = rc2, stdout2, stderr2, "smb-admin"
        else:
            # keep the winrm rc as authoritative; surface the smb-admin stderr too
            stderr = stderr + "\n--- smb-admin fallback ---\n" + stderr2

    (hdir / "winenum.txt").write_text(stdout)
    (hdir / "winenum.err").write_text(stderr)

    elapsed = int(time.time()) - t0
    meta = {
        "host": target.host, "user": target.user, "port": target.port,
        "rc": rc, "started": started, "elapsed_s": elapsed,
        "size_bytes": len(stdout.encode("utf-8")),
        "err_bytes":  len(stderr.encode("utf-8")),
        "transport": transport, "auth": args.auth,
        "tls": args.tls,
        "script": str(args.script),
    }
    (hdir / "_meta.json").write_text(json.dumps(meta, indent=2))
    if rc == 0:
        (hdir / ".done").touch()

    if os.environ.get("ENUM_THROTTLE") == "1":
        time.sleep(int(os.environ.get("ENUM_THROTTLE_DELAY", "1")))

    return HostResult(target, rc, started, elapsed,
                      meta["size_bytes"], meta["err_bytes"], transport)


# --------------------------------------------------------------------- main
def _run_log(out_dir: Path, msg: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with (out_dir / "run.log").open("a") as f:
        f.write(f"{ts}  {msg}\n")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog=(
            "TRANSPORT-VALIDATION CAVEAT (ADR-003):\n"
            "  The WinRM transport (pywinrm against live Windows 5985/5986) is\n"
            "  NOT exercised in this codebase's CI — no domain-joined Windows\n"
            "  host is available. Mock-pywinrm unit tests cover target parsing,\n"
            "  IPv6 bracketing, output layout, arg validation, --dry-run, and\n"
            "  --throttle precedence, but the actual transport is verified by\n"
            "  the operator's first real run against a known-good Windows VM.\n"
            "  Treat the first run as engagement prep, not the engagement.\n"
            "  See: docs/ADR-003-20MAY2026-windows-bulk-enum-design.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", required=True,
                    help="one host or user@host[:port] per line; '#' comments OK")
    ap.add_argument("-u", "--user", default="",
                    help="default username for bare-host lines")
    ap.add_argument("-p", "--pass", dest="password",
                    help="password (use ssh-agent-equivalent? not yet — kerberos for that)")
    ap.add_argument("--auth", choices=("ntlm", "basic", "kerberos", "credssp"),
                    default="ntlm",
                    help="auth method (default: ntlm). basic requires --tls.")
    ap.add_argument("--port", type=int, default=0,
                    help="default WinRM port (auto: 5986 if --tls else 5985)")
    ap.add_argument("--tls", action="store_true",
                    help="use HTTPS:5986 (server_cert_validation=ignore by default)")
    ap.add_argument("--connect-timeout", type=int, default=10,
                    help="seconds (default: 10)")
    ap.add_argument("--script", default=str(DEFAULT_SCRIPT),
                    help=f"PowerShell script to ship (default: {DEFAULT_SCRIPT.name})")
    ap.add_argument("--use-smb-admin", action="store_true",
                    help="SMB+wmiexec fallback (REQUIRES admin creds; per ADR-003 D2 — "
                         "documented but not implemented in this iteration; refuses "
                         "with rc=126 + reason)")
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
    if not args.dry_run and not HAS_PYWINRM:
        err("pywinrm not installed — pip install pywinrm (or run with --dry-run)")
        return 2
    if args.use_smb_admin and not args.password:
        err("--use-smb-admin requires --pass (admin creds)")
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
                     f"tls={args.tls} port={args.port} script={script_path.name}")

    # --- parse targets ---
    # default_port already accounts for --tls (set to 5986 if --tls else 5985
    # at lines 301-302 above), so parse_spec inherits the correct fallback.
    # Per-target ports in the targets file override it.
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
            results.append(run_one_host(t, script_text, args, out_dir))
    else:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futs = {pool.submit(run_one_host, t, script_text, args, out_dir): t
                    for t in targets}
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception as e:                   # noqa: BLE001
                    t = futs[f]
                    err(f"{t.host}: orchestrator exception: {type(e).__name__}: {e}")

    # --- summary ---
    ok = sum(1 for r in results if r.rc == 0 and r.transport != "resume-skip")
    fail = sum(1 for r in results if r.rc != 0)
    skip = sum(1 for r in results if r.transport in ("resume-skip", "dry-run"))
    with (out_dir / "_summary.tsv").open("w") as f:
        f.write("#host\trc\telapsed_s\tsize_kb\ttransport\n")
        for r in sorted(results, key=lambda x: x.target.host):
            size_kb = (r.stdout_bytes + 1023) // 1024
            f.write(f"{r.target.host}\t{r.rc}\t{r.elapsed_s}\t{size_kb}\t{r.transport}\n")

    print()
    print("=== bulk-enum-windows complete ===")
    print(f"OK={ok}  FAIL={fail}  SKIP={skip}")
    if fail > 0:
        print("Failed hosts:")
        for r in sorted([r for r in results if r.rc != 0], key=lambda x: x.target.host):
            print(f"  - {r.target.host}(rc={r.rc}, transport={r.transport})")
    print(f"Summary: {out_dir}/_summary.tsv")
    print(f"Per-host: {out_dir}/<host>/winenum.txt")
    print(f"Next: network/report.py {out_dir}    "
          "# findings.json + report.md + report.html")
    _run_log(out_dir, f"complete: OK={ok} FAIL={fail} SKIP={skip}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
