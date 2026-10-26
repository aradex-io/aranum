#!/usr/bin/env python3
"""local-enum.py -- aranum `--local` access layer (PLAN-001 S4, ADR-007).

Enumerate the privesc + hardening posture of every machine the operator holds
access to, over whichever pathway works, and file results in the bulk layout
report.py / report-dashboard.py already read:

    OUT/linux/<endpoint>/{_meta.json, linenum.txt, linenum.err}
    OUT/windows/<endpoint>/{_meta.json, winenum.txt, winenum.err}
    OUT/<os>/_aranum_bulk_root          (marks the directory as a bulk root)

Pathways and tiers (richest first; a pathway runs only when every richer one
failed to authenticate):

    local    full     --self: this machine, collectors run directly
    ssh      full     linux -> bulk-enum-linux.sh, windows -> bulk-enum-windows.py
    winrm    full     windows -> bulk-enum-windows.py
    exec     compact  windows -> wmiexec | smbexec | psexec (--win-exec), the
                      compact probe: privilege lines + host checks extracted
                      verbatim from Invoke-HostPosture.ps1, sized to the
                      method's command-line ceiling; omitted checks reported NA
    rdp/vnc  desktop  arrives in PLAN-001 S5 (refused here)

--transport SELECTS which pathways are allowed; it never reorders them.

EXEC CAVEAT (ADR-007 section 9): the exec methods write to the target through
their own mechanism (output file on ADMIN$; a service + batch file; an uploaded
service binary + service) and remove it themselves. They run only with BOTH
--win-exec <method> and --use-smb-admin. local/ssh/winrm write nothing.

Exit codes: 0 = run completed (per-host status is in each _meta.json);
            2 = usage / configuration error.
Authorized testing only.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

HERE = Path(__file__).resolve().parent
PROJECT_ROOT = HERE.parents[1]
LINUX_ENGINE = HERE / "bulk-enum-linux.sh"
WIN_ENGINE = HERE / "bulk-enum-windows.py"
LIN_PRIVESC = PROJECT_ROOT / "standalones" / "linux" / "linenum-fast.sh"
LIN_POSTURE = PROJECT_ROOT / "standalones" / "linux" / "host-posture.sh"
WIN_PRIVESC = PROJECT_ROOT / "standalones" / "windows" / "Invoke-PrivEscEnum.ps1"
WIN_POSTURE = PROJECT_ROOT / "standalones" / "windows" / "Invoke-HostPosture.ps1"

BULK_ROOT_MARKER = "_aranum_bulk_root"
PATHWAYS = ("local", "ssh", "winrm", "exec", "rdp", "vnc")
DESKTOP = ("rdp", "vnc")
EXEC_METHODS = ("wmiexec", "smbexec", "psexec")
# Ceilings for OUR command line (ADR-007 D4). Recorded from the impacket 0.13.1
# source, not yet measured live (S5 Windows lab).
EXEC_CEILING = {"wmiexec": 8000, "smbexec": 7800, "psexec": 4000}
# Host checks carried by the compact probe, in priority order. Only blocks that
# read no $Context are eligible; extraction is verbatim (ADR-007 D4).
PROBE_PRIORITY = (
    "WIN-SMB-SRVSIGN", "WIN-CRED-LMCOMPAT", "WIN-NR-LLMNR", "WIN-UAC-LATFP",
    "WIN-CRED-RUNASPPL", "WIN-AIE", "WIN-SMB-V1", "WIN-CRED-NOLMHASH", "WIN-UAC-LUA",
    "WIN-LDAP-CLISIGN", "WIN-SMB-CLISIGN", "WIN-NR-WPAD", "WIN-ANON-RESTRICT",
    "WIN-PS-V2", "WIN-UAC-CONSENT", "WIN-AUTOLOGON",
)
PROBE_HEADER = "== aranum compact probe (windows) =="
PROBE_END = "== aranum compact probe end =="
ANNOTATION_HEADER = "== aranum local-enum annotations =="
PARALLEL_CAP = 16
WIN_SIGNAL_PORTS = {135, 139, 445, 3389, 5985, 5986}
VIA_BY_PORT = {22: "ssh", 5985: "winrm", 5986: "winrm", 445: "exec", 3389: "rdp"}
VIA_BY_PORT.update({p: "vnc" for p in range(5900, 5911)})
NOT_WINDOWS_PRODUCT = re.compile(r"samba|xrdp|linux|ubuntu|debian|red ?hat|centos|"
                                 r"fedora|freebsd|openbsd|alpine|suse", re.I)
HOST_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
NT_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def err(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[?] {msg}", file=sys.stderr)


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


class UsageError(Exception):
    """A configuration problem: reported and exit 2."""


def _load_win_engine():
    """bulk-enum-windows.py as a module: one endpoint_key / parse_spec /
    _classify_smb / build_posture_payload, never a second copy."""
    spec = importlib.util.spec_from_file_location("aranum_bulk_enum_windows", WIN_ENGINE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aranum_bulk_enum_windows"] = mod
    spec.loader.exec_module(mod)
    return mod


WE = _load_win_engine()


# --------------------------------------------------------------------- inputs
@dataclass
class HostSpec:
    host: str
    port: Optional[int] = None          # explicit port from a targets line
    user: str = ""                      # explicit user from a targets line
    os: str = "unknown"                 # linux | windows | unknown
    via: Optional[set] = None           # allowed pathways (None = any)
    source: str = "targets"
    winrm_port: Optional[int] = None    # from inventory (5985 / 5986)


@dataclass
class Cred:
    user: str = ""
    password: Optional[str] = None
    key: Optional[str] = None
    nthash: Optional[str] = None
    domain: str = ""

    def auth_label(self) -> str:
        parts = [n for n, v in (("key", self.key), ("password", self.password),
                                ("nthash", self.nthash)) if v]
        return "+".join(parts) or "none"


def _parse_via(raw: str, where: str) -> set:
    out = set()
    for piece in raw.split(","):
        piece = piece.strip().lower()
        if not piece:
            continue
        if piece not in PATHWAYS:
            raise UsageError(f"{where}: unknown pathway {piece!r} (valid: {', '.join(PATHWAYS)})")
        out.add(piece)
    return out


def parse_targets_line(line: str, lineno: int) -> Optional[HostSpec]:
    """`[user@]host[:port] [os=linux|windows] [via=ssh,winrm,...] [user=NAME]`."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    tokens = line.split()
    where = f"targets line {lineno}"
    t = WE.parse_spec(tokens[0], "", 0)
    if t is None or not t.host or not HOST_RE.match(t.host) or t.host in (".", ".."):
        raise UsageError(f"{where}: cannot parse host from {tokens[0]!r}")
    if t.port_explicit and not 1 <= t.port <= 65535:
        raise UsageError(f"{where}: port out of range in {tokens[0]!r}")
    spec = HostSpec(host=t.host, port=t.port if t.port_explicit else None, user=t.user)
    for tok in tokens[1:]:
        if "=" not in tok:
            raise UsageError(f"{where}: expected key=value, got {tok!r}")
        k, v = tok.split("=", 1)
        k = k.lower()
        if k == "os":
            if v.lower() not in ("linux", "windows"):
                raise UsageError(f"{where}: os must be linux or windows, got {v!r}")
            spec.os = v.lower()
        elif k == "via":
            spec.via = _parse_via(v, where)
        elif k == "user":
            spec.user = v
        else:
            raise UsageError(f"{where}: unknown key {k!r} (os, via, user)")
    return spec


def load_targets(path: Path) -> list:
    if not path.is_file():
        raise UsageError(f"targets file not found: {path}")
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        s = parse_targets_line(line, i)
        if s is not None:
            out.append(s)
    return out


def infer_os(ports: set, products: list) -> str:
    """ADR-007 D3 rule 2: product evidence first, then ports. A port is only
    Windows evidence when no product on the host names a non-Windows stack
    (Samba on 445, xrdp on 3389)."""
    text = " ".join(products)
    if re.search(r"windows|microsoft", text, re.I):
        return "windows"
    non_windows = bool(NOT_WINDOWS_PRODUCT.search(text))
    if not non_windows and ports & WIN_SIGNAL_PORTS:
        return "windows"
    if 22 in ports:
        return "linux"
    return "unknown"


def load_inventory(path: Path) -> list:
    """Access candidates from auto-enum's inventory.json (nmap-parse.py --json)."""
    if not path.is_file():
        raise UsageError(f"inventory not found: {path}")
    try:
        inv = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise UsageError(f"cannot parse inventory {path}: {e}") from e
    hosts: dict = {}
    for e in inv.get("entries", []) if isinstance(inv, dict) else []:
        if not isinstance(e, dict) or e.get("state") not in ("open", None):
            continue
        if str(e.get("proto", "tcp")).lower() != "tcp":
            continue
        ip = str(e.get("ip") or "")
        try:
            port = int(e.get("port"))
        except (TypeError, ValueError):
            continue
        if not ip or not HOST_RE.match(ip):
            continue
        h = hosts.setdefault(ip, {"ports": set(), "products": []})
        h["ports"].add(port)
        prod = " ".join(str(e.get(k) or "") for k in ("service", "product", "extrainfo")).strip()
        if prod:
            h["products"].append(prod)
    out = []
    for ip, h in hosts.items():
        via = {VIA_BY_PORT[p] for p in h["ports"] if p in VIA_BY_PORT}
        if not via:
            continue
        winrm_port = 5985 if 5985 in h["ports"] else (5986 if 5986 in h["ports"] else None)
        out.append(HostSpec(host=ip, os=infer_os(h["ports"], h["products"]), via=via,
                            source="inventory", winrm_port=winrm_port))
    return out


def load_creds(path: Path) -> list:
    """`<host|*> <user> <secret>` per line. secret: an existing file = SSH key,
    `nt:<32 hex>` = NT hash, anything else = password (may contain spaces)."""
    if not path.is_file():
        raise UsageError(f"creds file not found: {path}")
    mode = path.stat().st_mode
    if mode & 0o077:
        warn(f"creds file {path} is readable by group/other (mode {oct(mode & 0o777)}); chmod 600")
    rows = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        parts = raw.strip().split(None, 2)
        if len(parts) != 3:
            raise UsageError(f"creds line {i}: expected '<host|*> <user> <secret>'")
        sel, user, secret = parts
        c = Cred(user=user)
        if secret.startswith("nt:"):
            if not NT_RE.match(secret[3:]):
                raise UsageError(f"creds line {i}: nt: secret must be 32 hex characters")
            c.nthash = secret[3:].lower()
        elif Path(secret).expanduser().is_file():
            c.key = str(Path(secret).expanduser())
        else:
            c.password = secret
        rows.append((sel, c))
    return rows


def resolve_cred(spec: HostSpec, creds_rows: list, default: Cred) -> Cred:
    """Host-specific lines, else `*` lines, else the CLI defaults. Within the
    chosen level the user is the target's explicit user (or the level's first
    user) and secrets from every line with that user are merged."""
    for level in ([c for s, c in creds_rows if s == spec.host],
                  [c for s, c in creds_rows if s == "*"]):
        if not level:
            continue
        user = spec.user or level[0].user
        same = [c for c in level if c.user == user]
        if not same:
            continue
        merged = Cred(user=user, domain=default.domain)
        for c in same:
            merged.password = merged.password or c.password
            merged.key = merged.key or c.key
            merged.nthash = merged.nthash or c.nthash
        return merged
    return Cred(user=spec.user or default.user, password=default.password, key=default.key,
                nthash=default.nthash, domain=default.domain)


# --------------------------------------------------------------------- compact probe
def _ps_skip_string(src: str, i: int) -> int:
    """Index just past the PowerShell string literal starting at src[i]."""
    q = src[i]
    i += 1
    while i < len(src):
        c = src[i]
        if q == '"' and c == "`":
            i += 2
            continue
        if c == q:
            if i + 1 < len(src) and src[i + 1] == q:      # doubled quote = escaped
                i += 2
                continue
            return i + 1
        i += 1
    raise ValueError("unterminated string literal")


def ps_match_brace(src: str, open_idx: int) -> int:
    """Index of the `}` closing the `{` at open_idx, skipping string literals,
    `#` line comments and `<# #>` block comments."""
    depth = 0
    i = open_idx
    while i < len(src):
        c = src[i]
        if c in "'\"":
            i = _ps_skip_string(src, i)
            continue
        if c == "<" and src.startswith("<#", i):
            j = src.find("#>", i + 2)
            if j < 0:
                raise ValueError("unterminated block comment")
            i = j + 2
            continue
        if c == "#":
            j = src.find("\n", i)
            i = len(src) if j < 0 else j
            continue
        if c == "`":
            i += 2
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced braces")


def extract_check_block(src: str, check_id: str) -> str:
    """The verbatim `Invoke-PostureCheck '<id>' { ... }` statement."""
    m = re.search(r"Invoke-PostureCheck\s+'" + re.escape(check_id) + r"'\s*\{", src)
    if not m:
        raise KeyError(check_id)
    end = ps_match_brace(src, m.end() - 1)
    return src[m.start():end + 1]


PRELUDE_NAMES = ("lsa", "sys", "lmSrv", "lmWks")
AUTOMATIC_VARS = {"null", "true", "false", "_", "executioncontext"}


def extract_prelude(src: str) -> dict:
    out = {}
    for name in PRELUDE_NAMES:
        m = re.search(r"^[ \t]*\$" + name + r"\s*=\s*('[^'\r\n]*')[ \t]*$", src, re.M)
        if m:
            out[name] = f"${name}={m.group(1)}"
    return out


def block_variables(block: str) -> tuple:
    """(referenced, assigned) variable names in a block, ignoring string contents."""
    stripped = re.sub(r"'(?:[^']|'')*'", "''", block)
    refs = {v.lower() for v in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", stripped)}
    assigned = {v.lower() for v in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)", stripped)}
    return refs, assigned


def minify_ps(text: str) -> str:
    """Indentation and full-line comments only -- never compression/packing."""
    keep = []
    for line in text.replace("\r\n", "\n").split("\n"):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        keep.append(s)
    return "\n".join(keep)


# Same names and semantics as Invoke-HostPosture.ps1's framing helpers (the
# parity test proves identical POSTURE lines under a stubbed registry).
PROBE_HELPERS = r"""$script:S=@{}
function Write-PostureLine{param([string]$Id,[string]$Status,[string]$Detail)
if($script:S.ContainsKey($Id)){return}
$script:S[$Id]=$true
$d=[string]$Detail -replace '[\|\r\n]',' '
$d=$d -replace '[\x00-\x1f\x7f]',' '
Write-Output ('POSTURE|{0}|{1}|{2}' -f $Id,$Status,$d)}
function New-PostureResult{param([string]$Status,[string]$Detail)
@{AranumPostureStatus=$Status;AranumPostureDetail=$Detail}}
function Invoke-PostureCheck{param([string]$Id,[scriptblock]$Block)
try{$r=& $Block|Where-Object{$_ -is [hashtable] -and $_.ContainsKey('AranumPostureStatus')}|Select-Object -Last 1
if($null -eq $r){Write-PostureLine $Id 'ERR' 'check returned no result'}else{Write-PostureLine $Id $r.AranumPostureStatus $r.AranumPostureDetail}}
catch{Write-PostureLine $Id 'ERR' ('check failed: '+$_.Exception.Message)}}
function Get-RegValue{param([string]$Path,[string]$Name)
try{$i=Get-ItemProperty -LiteralPath $Path -ErrorAction Stop}catch [System.Management.Automation.ItemNotFoundException]{return $null}
if($null -eq $i){return $null}
$p=$i.PSObject.Properties[$Name]
if($null -eq $p){return $null}
return $p.Value}
function Get-RegPolicy{param([string]$Path,[string]$Name,[int[]]$Allowed)
$v=Get-RegValue $Path $Name
if($null -eq $v){return $null}
$t=([string]$v).Trim()
if(-not($t -match '^-?[0-9]{1,10}$') -or ($Allowed -notcontains [int64]$t)){throw ($Name+'='+$t+' outside documented values ('+($Allowed -join ',')+')')}
return [int]$t}
function Format-RegText{param($Value)
if($null -eq $Value){return 'unset'}
return [string]$Value}"""

# Invoke-PrivEscEnum.ps1's "Useful token privileges" lines, verbatim text, so
# report.py's existing winenum rules grade them.
PROBE_PRIVS = r"""$w=(whoami.exe /priv) -join "`n"
foreach($p in @('SeImpersonatePrivilege','SeAssignPrimaryTokenPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeLoadDriverPrivilege','SeTcbPrivilege','SeManageVolumePrivilege','SeSecurityPrivilege','SeCreateTokenPrivilege')){
if($w -match $p){$l=($w -split "`n")|Where-Object{$_ -match $p}
if($l -match 'Enabled'){"[+] $p (ENABLED)"}else{"[-] $p (disabled - can still be enabled)"}}}"""


class ProbeTooLarge(Exception):
    pass


@dataclass
class Probe:
    method: str
    script: str
    command: str
    checks: list
    omitted: list
    ceiling: int

    @property
    def chars(self) -> int:
        return len(self.command)


def encode_command(script: str) -> str:
    enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {enc}"


def eligible_blocks(src: str) -> dict:
    """{check_id: minified block} for every PROBE_PRIORITY id that reads only
    the prelude variables and its own locals."""
    prelude = {k.lower() for k in extract_prelude(src)}
    out = {}
    for cid in PROBE_PRIORITY:
        try:
            block = extract_check_block(src, cid)
        except KeyError:
            continue
        refs, assigned = block_variables(block)
        if "context" in refs:
            continue
        if refs - assigned - prelude - AUTOMATIC_VARS:
            continue
        out[cid] = minify_ps(block)
    return out


def all_host_check_ids(src: str) -> list:
    m = re.search(r"\$script:AranumHostCheckIds\s*=\s*@\((.*?)\)", src, re.S)
    return re.findall(r"'([A-Z0-9-]+)'", m.group(1)) if m else []


def build_probe(method: str, *, ceiling: Optional[int] = None,
                posture_src: Optional[str] = None) -> Probe:
    """Greedy, priority-ordered compact probe for one exec method. Refuses
    (ProbeTooLarge) when even the core -- helpers, privilege lines and the
    first check -- would exceed the method's ceiling. Never truncates."""
    if method not in EXEC_CEILING:
        raise ValueError(f"unknown exec method {method!r}")
    ceiling = EXEC_CEILING[method] if ceiling is None else ceiling
    src = posture_src if posture_src is not None else WIN_POSTURE.read_text(encoding="utf-8")
    blocks = eligible_blocks(src)
    prelude = extract_prelude(src)
    if not blocks:
        raise ProbeTooLarge("no eligible posture check could be extracted")

    def assemble(ids: list) -> str:
        need = set()
        for cid in ids:
            refs, _ = block_variables(blocks[cid])
            need |= {n for n in PRELUDE_NAMES if n.lower() in refs}
        parts = [f"'{PROBE_HEADER}'", PROBE_HELPERS, PROBE_PRIVS]
        parts += [prelude[n] for n in PRELUDE_NAMES if n in need]
        parts += [blocks[c] for c in ids]
        parts.append(f"'{PROBE_END}'")
        return "\n".join(parts) + "\n"

    order = [c for c in PROBE_PRIORITY if c in blocks]
    chosen = [order[0]]
    core_chars = len(encode_command(assemble(chosen)))
    if core_chars > ceiling:
        raise ProbeTooLarge(
            f"the {method} compact probe core is {core_chars} chars, over the "
            f"{method} ceiling of {ceiling}; use winrm or ssh for this host")
    for cid in order[1:]:
        if len(encode_command(assemble(chosen + [cid]))) <= ceiling:
            chosen.append(cid)
    script = assemble(chosen)
    host_ids = all_host_check_ids(src)
    omitted = [c for c in host_ids if c not in chosen]
    return Probe(method, script, encode_command(script), chosen, omitted, ceiling)


def annotate_omitted(text: str, method: str, omitted: list) -> str:
    if not omitted:
        return text
    lines = [ANNOTATION_HEADER]
    lines += [f"POSTURE|{c}|NA|not carried by the {method} compact probe "
              f"(use winrm/ssh for this check)" for c in omitted]
    sep = "" if not text or text.endswith("\n") else "\n"
    return text + sep + "\n".join(lines) + "\n"


# --------------------------------------------------------------------- process + fs helpers
def run_bounded(argv: list, *, timeout: int, stdin_data: Optional[str] = None,
                stdout_path: Optional[Path] = None, stderr_path: Optional[Path] = None) -> tuple:
    """Run argv in its own process group under a wall-clock bound. Output goes to
    the given files when set (so a timeout keeps partial output), else is
    returned. Returns (rc, stdout, stderr, timed_out); rc 124 on timeout."""
    out_f = open(stdout_path, "wb") if stdout_path else None
    err_f = open(stderr_path, "wb") if stderr_path else None
    try:
        p = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=out_f or subprocess.PIPE, stderr=err_f or subprocess.PIPE,
            start_new_session=True)
        timed_out = False
        try:
            out, errb = p.communicate(
                input=stdin_data.encode("utf-8") if stdin_data is not None else None,
                timeout=timeout if timeout > 0 else None)
        except subprocess.TimeoutExpired:
            timed_out = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(p.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    out, errb = p.communicate(timeout=10)
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                out, errb = p.communicate()
        rc = 124 if timed_out else p.returncode
        return (rc, (out or b"").decode("utf-8", "replace"),
                (errb or b"").decode("utf-8", "replace"), timed_out)
    finally:
        for f in (out_f, err_f):
            if f:
                f.close()


def write_json_atomic(path: Path, obj: dict) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def mark_root(root: Path, os_name: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    m = root / BULK_ROOT_MARKER
    if not m.exists():
        m.write_text(json.dumps({"writer": "local-enum.py", "os": os_name}) + "\n")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------- planning
@dataclass
class PlanRow:
    host: str
    os: str
    pathway: str
    tier: str
    engine: str
    note: str = ""

    def line(self) -> str:
        return "|".join(("PLAN", self.host, self.os, self.pathway, self.tier,
                        self.engine, self.note.replace("|", "/")))


@dataclass
class HostPlan:
    spec: HostSpec
    cred: Cred
    pathways: list = field(default_factory=list)    # ordered, e.g. ["winrm","ssh","wmiexec"]
    rows: list = field(default_factory=list)
    skip: str = ""


def _ssh_usable(c: Cred) -> bool:
    return bool(c.user) and bool(c.key or c.password or os.environ.get("SSH_AUTH_SOCK"))


def plan_host(spec: HostSpec, cred: Cred, allowed: set, win_exec: Optional[str],
              probe, probe_error: str = "") -> HostPlan:
    """Build the ordered pathway list and the dry-run PLAN rows for one host.
    `probe` is a Probe (built once per run) or None; probe_error is the refuse
    message when the chosen exec method could not carry even the core."""
    hp = HostPlan(spec, cred)
    host_via = spec.via if spec.via is not None else set(PATHWAYS)
    osn = spec.os
    ladder = ["winrm", "ssh", "exec"] if osn == "windows" else ["ssh"]
    reasons = []
    for pw in ladder:
        if pw not in allowed:
            reasons.append(f"{pw}:not-selected")
            continue
        if pw not in host_via:
            reasons.append(f"{pw}:not-offered")
            continue
        if not cred.user:
            reasons.append(f"{pw}:no-user")
            continue
        if pw == "ssh" and not _ssh_usable(cred):
            reasons.append("ssh:no-credentials")
            continue
        if pw == "winrm" and not cred.password:
            reasons.append("winrm:no-password")
            continue
        if pw == "exec":
            if not (cred.password or cred.nthash):
                reasons.append("exec:no-credentials")
                continue
            if probe is None:
                reasons.append(f"{win_exec}:probe-too-large")
                hp.rows.append(PlanRow(spec.host, osn, win_exec, "compact", "compact-probe",
                                       f"fits=no refuse ({probe_error})"))
                continue
            hp.pathways.append(win_exec)
            auth = "nthash" if not cred.password else "password"
            note = (f"fits=yes chars={probe.chars}/{probe.ceiling} "
                    f"checks={len(probe.checks)} omitted={len(probe.omitted)} auth={auth}")
            hp.rows.append(PlanRow(spec.host, osn, win_exec, "compact", "compact-probe", note))
            continue
        hp.pathways.append(pw)
        engine = "bulk-enum-linux.sh" if osn == "linux" else (
            "bulk-enum-windows.py" if osn == "windows" else "ssh-banner->engine")
        note = f"user={cred.user} auth={cred.auth_label()}"
        if osn == "unknown":
            note += " os=resolve-by-ssh-banner"
        hp.rows.append(PlanRow(spec.host, osn, pw, "full", engine, note))
    offered_desktop = sorted(host_via & set(DESKTOP))
    if not hp.pathways:
        cred_only = bool(reasons) and all(
            r.endswith(("no-credentials", "no-password", "no-user")) for r in reasons)
        why = "no-credentials" if cred_only else "no-pathway"
        if offered_desktop and spec.via is not None:
            reasons.append(f"{'+'.join(offered_desktop)}:desktop-tier-arrives-in-S5")
        hp.skip = why
        hp.rows.append(PlanRow(spec.host, osn, "-", "skip", "-",
                               f"skip:{why} ({' '.join(reasons)})"))
    return hp


def ssh_banner_os(host: str, port: int, timeout: int) -> Optional[str]:
    """Read one SSH banner to resolve an unknown OS. Opened only at run time,
    never during --dry-run."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256).decode("ascii", "replace")
    except OSError:
        return None
    if not data.startswith("SSH-"):
        return None
    return "windows" if "windows" in data.lower() else "linux"


# --------------------------------------------------------------------- engine delegation
def _spec_line(user: str, host: str, port: Optional[int]) -> str:
    h = f"[{host}]" if ":" in host else host
    return f"{user}@{h}" + (f":{port}" if port else "")


def _collect_engine_dirs(engine_out: Path, root: Path) -> dict:
    """Move every engine host dir that has _meta.json up into the OS root;
    return {(host, user): dest_dir}."""
    found = {}
    if not engine_out.is_dir():
        return found
    for d in sorted(engine_out.iterdir()):
        if not d.is_dir() or not (d / "_meta.json").is_file():
            continue
        dest = root / d.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(d), str(dest))
        try:
            meta = json.loads((dest / "_meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        found[(str(meta.get("host", "")), str(meta.get("user", "")))] = dest
    return found


def _win_user(c: Cred) -> str:
    if c.domain and "\\" not in c.user and "/" not in c.user and "@" not in c.user:
        return f"{c.domain}\\{c.user}"
    return c.user


def run_linux_engine(group: list, cred: Cred, out: Path, gid: int, args) -> dict:
    root = out / "linux"
    mark_root(root, "linux")
    work = root / "_engine" / f"g{gid}"
    work.mkdir(parents=True, exist_ok=True)
    tf = work / "targets.txt"
    tf.write_text("".join(_spec_line(cred.user, hp.spec.host, hp.spec.port) + "\n"
                          for hp in group))
    eng_out = work / "out"
    argv = ["bash", str(LINUX_ENGINE), "--targets", str(tf), "-o", str(eng_out),
            "--with-posture", "-P", str(args.parallel),
            "--connect-timeout", str(args.connect_timeout),
            "--host-timeout", str(args.host_timeout)]
    if cred.key:
        argv += ["-k", cred.key]
    if cred.password:
        argv += ["--pass", cred.password]
    log(f"linux ssh engine: {len(group)} host(s), group g{gid}")
    rc, _o, _e, _ = run_bounded(argv, timeout=0, stdout_path=work / "engine.out",
                                stderr_path=work / "engine.err")
    if rc != 0:
        warn(f"bulk-enum-linux.sh exited rc={rc} (group g{gid}); see {work / 'engine.err'}")
    return _collect_engine_dirs(eng_out, root)


def run_windows_engine(group: list, cred: Cred, transports: list, tls: bool,
                       out: Path, gid: int, args) -> dict:
    root = out / "windows"
    mark_root(root, "windows")
    work = root / "_engine" / f"g{gid}"
    work.mkdir(parents=True, exist_ok=True)
    tf = work / "targets.txt"
    user = _win_user(cred)
    default_winrm = 5986 if tls else 5985
    lines = []
    for hp in group:
        port = hp.spec.port
        if (port is None and transports != ["ssh"] and hp.spec.winrm_port
                and hp.spec.winrm_port != default_winrm):
            port = hp.spec.winrm_port
        lines.append(_spec_line(user, hp.spec.host, port))
    tf.write_text("\n".join(lines) + "\n")
    eng_out = work / "out"
    argv = [sys.executable, str(WIN_ENGINE), "--targets", str(tf), "-o", str(eng_out),
            "--transport", ",".join(transports), "--with-posture",
            "-P", str(args.parallel), "--connect-timeout", str(args.connect_timeout)]
    if args.ad:
        argv.append("--ad")
    if tls:
        argv.append("--tls")
    if cred.password:
        argv += ["-p", cred.password]
    if cred.key:
        argv += ["--key", cred.key]
    log(f"windows engine ({','.join(transports)}): {len(group)} host(s), group g{gid}")
    rc, _o, _e, _ = run_bounded(argv, timeout=0, stdout_path=work / "engine.out",
                                stderr_path=work / "engine.err")
    if rc != 0:
        warn(f"bulk-enum-windows.py exited rc={rc} (group g{gid}); see {work / 'engine.err'}")
    return _collect_engine_dirs(eng_out, root)


# --------------------------------------------------------------------- exec compact probe runner
IMPACKET_NOISE = re.compile(r"^(Impacket v\S+ - Copyright|\[\*\]|\[-\]|\[!\]|\[\+\])")
PROMPT_PREFIX = re.compile(r"^[A-Za-z]:\\[^>\r\n]*>")


def find_exec_tool(method: str) -> Optional[str]:
    return shutil.which(f"impacket-{method}") or shutil.which(f"{method}.py")


def exec_argv(tool: str, method: str, host: str, cred: Cred, command: str) -> tuple:
    """(argv, stdin_data). smbexec reads commands from stdin (impacket 0.13.1
    has no command positional); wmiexec/psexec take the command as an argument.
    Credentials appear on argv, matching the existing SMB transport (ADR-006)."""
    user, dom = cred.user, cred.domain
    if "\\" in user:
        dom, user = user.split("\\", 1)
    elif "/" in user:
        dom, user = user.split("/", 1)
    principal = f"{dom}/{user}" if dom else user
    h = f"[{host}]" if ":" in host else host
    argv = [tool]
    if cred.password:
        target = f"{principal}:{cred.password}@{h}"
    else:
        argv += ["-hashes", f":{cred.nthash}"]
        target = f"{principal}@{h}"
    argv.append(target)
    if method == "smbexec":
        return argv, f"{command}\nexit\n"
    return argv + [command], None


def clean_exec_output(raw: str) -> tuple:
    """(stdout, noise): impacket banner/status lines and shell prompts removed."""
    keep, noise = [], []
    for line in raw.replace("\r\n", "\n").split("\n"):
        if IMPACKET_NOISE.match(line.strip()):
            noise.append(line)
            continue
        keep.append(PROMPT_PREFIX.sub("", line))
    text = "\n".join(keep).strip("\n")
    return (text + "\n" if text else ""), "\n".join(noise)


def classify_exec(out: str, errtxt: str, timed_out: bool) -> tuple:
    """Grade the probe outcome from its output, as _classify_smb does for the
    SMB transport. The probe markers decide OK; auth/reach patterns otherwise."""
    if timed_out:
        return "HOST_TIMEOUT", "exec probe exceeded --host-timeout"
    if PROBE_HEADER in out and PROBE_END in out:
        return "OK", ""
    low = (out + "\n" + errtxt).lower()
    if re.search(r"logon_failure|access_denied|authentication|login failure|"
                 r"invalid credentials|status_access_denied", low):
        return "AUTH_FAIL", "exec authentication rejected"
    if re.search(r"connection error|timed out|no route to host|connection refused|"
                 r"unreachable|connresettError|connection reset", low):
        return "UNREACHABLE", "exec endpoint unreachable"
    if PROBE_HEADER in out:
        return "REMOTE_ERR", "probe started but did not complete (output truncated?)"
    return "REMOTE_ERR", (errtxt.strip().splitlines() or ["exec probe produced no output"])[-1]


def run_exec_probe(host: str, cred: Cred, method: str, probe, hdir: Path,
                   args) -> dict:
    """Run the compact probe for one host over one exec method. Returns the
    _meta.json fields the caller merges/writes."""
    tool = find_exec_tool(method)
    started = now_iso()
    t0 = time.time()
    base = {
        "host": host, "user": cred.user, "port": "",
        "transport": method, "capability": "compact-probe",
        "probe_checks": probe.checks, "probe_omitted": probe.omitted,
        "probe_chars": probe.chars, "probe_ceiling": probe.ceiling,
        "started": started, "auth": "nthash" if not cred.password else "password",
    }
    if not tool:
        base.update(status="DEP_MISSING", rc=127,
                    fail_reason=f"neither impacket-{method} nor {method}.py on PATH "
                                "(pipx install impacket)",
                    elapsed_s=0)
        (hdir / "winenum.txt").write_text("")
        (hdir / "winenum.err").write_text(base["fail_reason"] + "\n")
        base["size_bytes"] = 0
        base["err_bytes"] = len(base["fail_reason"]) + 1
        return base
    argv, stdin_data = exec_argv(tool, method, host, cred, probe.command)
    rc, out, errtxt, timed_out = run_bounded(
        argv, timeout=args.host_timeout, stdin_data=stdin_data)
    body, noise = clean_exec_output(out)
    body = annotate_omitted(body, method, probe.omitted)
    err_full = ("\n".join(x for x in (noise, errtxt) if x)).strip()
    (hdir / "winenum.txt").write_text(body)
    (hdir / "winenum.err").write_text(err_full + ("\n" if err_full else ""))
    status, reason = classify_exec(out, errtxt, timed_out)
    base.update(status=status, rc=rc, fail_reason=reason,
                elapsed_s=int(time.time() - t0),
                size_bytes=len(body.encode("utf-8")),
                err_bytes=len(err_full.encode("utf-8")))
    return base


# --------------------------------------------------------------------- self-scan (local host)
def _which_powershell() -> Optional[str]:
    return shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")


def run_self_scan(out: Path, args, default: Cred) -> int:
    """Enumerate THIS machine directly (no transport). Posture collector first
    (fast), then the privesc collector (its SUID walk can run minutes), sharing
    one wall-clock --host-timeout; partial output is kept on timeout."""
    osn = "windows" if os.name == "nt" else "linux"
    root = out / osn
    mark_root(root, osn)
    hdir = root / "localhost"
    hdir.mkdir(parents=True, exist_ok=True)
    started = now_iso()
    t0 = time.time()
    budget = args.host_timeout

    def remaining() -> int:
        if budget <= 0:
            return 0
        return max(1, budget - int(time.time() - t0))

    timed_out = False
    if osn == "linux":
        ev = hdir / "linenum.txt"
        erf = hdir / "linenum.err"
        posture = Path(args.linux_posture_script) if args.linux_posture_script else LIN_POSTURE
        privesc = Path(args.linux_script) if args.linux_script else LIN_PRIVESC
        with open(ev, "wb") as o, open(erf, "wb") as e:
            for label, script in (("posture", posture), ("privesc", privesc)):
                o.write(f"== aranum local self-scan: {label} ({script.name}) ==\n".encode())
                o.flush()
                rc, so, se, to = run_bounded(["bash", str(script)], timeout=remaining())
                o.write(so.encode("utf-8", "replace"))
                o.write(b"\n")
                e.write(f"== {label} rc={rc} ==\n".encode())
                e.write(se.encode("utf-8", "replace"))
                timed_out = timed_out or to
                if to:
                    break
    else:
        ps = _which_powershell()
        ev = hdir / "winenum.txt"
        erf = hdir / "winenum.err"
        if not ps:
            (hdir / "winenum.txt").write_text("")
            erf.write_text("no PowerShell (pwsh/powershell) on PATH\n")
            _write_self_meta(hdir, osn, started, int(time.time() - t0), "DEP_MISSING",
                             "no PowerShell interpreter", ev, erf)
            return 0
        payload = WE.build_posture_payload(WIN_PRIVESC.read_text(encoding="utf-8"),
                                           WIN_POSTURE.read_text(encoding="utf-8"), ad=args.ad)
        rc, so, se, to = run_bounded([ps, "-NoProfile", "-NonInteractive", "-Command", "-"],
                                     timeout=remaining(), stdin_data=payload)
        ev.write_text(so)
        erf.write_text(se)
        timed_out = to
    status = "HOST_TIMEOUT" if timed_out else "OK"
    reason = "self-scan exceeded --host-timeout (partial output kept)" if timed_out else ""
    _write_self_meta(hdir, osn, started, int(time.time() - t0), status, reason, ev, erf)
    log(f"self-scan ({osn}): localhost status={status}")
    return 0


def _write_self_meta(hdir: Path, osn: str, started: str, elapsed: int, status: str,
                     reason: str, ev: Path, erf: Path) -> None:
    write_json_atomic(hdir / "_meta.json", {
        "host": "localhost", "user": "", "port": "",
        "rc": 0 if status == "OK" else 1, "status": status, "fail_reason": reason,
        "transport": "local", "artifact_id": "localhost",
        "started": started, "elapsed_s": elapsed,
        "size_bytes": ev.stat().st_size if ev.exists() else 0,
        "err_bytes": erf.stat().st_size if erf.exists() else 0,
    })


# --------------------------------------------------------------------- run orchestration
def _group_key(cred: Cred) -> tuple:
    return (cred.user, cred.password, cred.key, cred.nthash, cred.domain)


def execute_plans(plans: list, out: Path, allowed: set, win_exec: Optional[str],
                  probe, tls: bool, args) -> None:
    """Run every planned host, engines grouped by credential, exec probes per host."""
    # Resolve unknown OS by SSH banner before grouping.
    for hp in plans:
        if hp.spec.os == "unknown" and hp.pathways and not args.dry_run:
            port = hp.spec.port or 22
            resolved = ssh_banner_os(hp.spec.host, port, args.connect_timeout)
            if resolved:
                hp.spec.os = resolved
                log(f"{hp.spec.host}: ssh banner -> os={resolved}")
            else:
                hp.spec.os = "linux"
                warn(f"{hp.spec.host}: ssh banner unreadable; assuming linux")

    lin = [hp for hp in plans if hp.spec.os == "linux" and hp.pathways]
    win_full = [hp for hp in plans if hp.spec.os == "windows" and hp.pathways
                and hp.pathways[0] in ("winrm", "ssh")]
    win_exec_hosts = [hp for hp in plans if hp.spec.os == "windows" and hp.pathways
                      and hp.pathways[0] in EXEC_METHODS]

    gid = 0
    groups: dict = {}
    for hp in lin:
        groups.setdefault(_group_key(hp.cred), (hp.cred, []))[1].append(hp)
    for _k, (cred, grp) in groups.items():
        gid += 1
        run_linux_engine(grp, cred, out, gid, args)

    wgroups: dict = {}
    for hp in win_full:
        order = [p for p in hp.pathways if p in ("winrm", "ssh")]
        wgroups.setdefault((_group_key(hp.cred), tuple(order)), (hp.cred, order, []))[2].append(hp)
    for _k, (cred, order, grp) in wgroups.items():
        gid += 1
        run_windows_engine(grp, cred, order, tls, out, gid, args)

    if win_exec_hosts:
        root = out / "windows"
        mark_root(root, "windows")
        for hp in win_exec_hosts:
            key = WE.endpoint_key(WE.Target(user=_win_user(hp.cred), host=hp.spec.host,
                                            port=hp.spec.port or 445, raw_spec=hp.spec.host))
            hdir = root / key
            hdir.mkdir(parents=True, exist_ok=True)
            meta = run_exec_probe(hp.spec.host, hp.cred, hp.pathways[0], probe, hdir, args)
            write_json_atomic(hdir / "_meta.json", meta)
            log(f"exec probe ({hp.pathways[0]}): {hp.spec.host} status={meta['status']}")


# --------------------------------------------------------------------- CLI
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="local-enum.py",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Authorized testing only. See aranumtoolkit/docs/ADR-007-26OCT2026-"
               "local-access-layer.md (section 9 on the exec methods' target-side writes).")
    src = ap.add_argument_group("targets")
    src.add_argument("--targets", help="file: '[user@]host[:port] [os=] [via=] [user=]' per line")
    src.add_argument("--from-inventory", help="auto-enum inventory.json (nmap-parse.py --json)")
    src.add_argument("--self", dest="self_scan", action="store_true",
                     help="also enumerate THIS machine directly (no transport)")
    cr = ap.add_argument_group("credentials (operator-supplied only)")
    cr.add_argument("-u", "--user", default="", help="default username")
    cr.add_argument("-p", "--password", "--pass", dest="password", help="default password")
    cr.add_argument("--key", help="default SSH private key path")
    cr.add_argument("-H", "--hash", dest="nthash", help="default NT hash (exec methods only)")
    cr.add_argument("-d", "--domain", default="", help="default domain (windows)")
    cr.add_argument("--creds", help="per-host creds file: '<host|*> <user> <secret>' per line")
    sel = ap.add_argument_group("pathway selection")
    sel.add_argument("--transport", default="auto",
                     help="comma list over {auto,local,ssh,winrm,exec,rdp,vnc}; SELECTS allowed "
                          "pathways (never reorders). Default auto = local(+--self),winrm,ssh "
                          "(+exec only with --win-exec and --use-smb-admin).")
    sel.add_argument("--win-exec", choices=EXEC_METHODS,
                     help="exec method for the windows compact probe")
    sel.add_argument("--use-smb-admin", action="store_true",
                     help="explicit consent for the exec methods (they write to the target "
                          "via their own mechanism; see ADR-007 section 9). Required with exec.")
    sel.add_argument("--tls", action="store_true", help="winrm over HTTPS:5986")
    sel.add_argument("--ad", action="store_true", help="also run read-only AD posture checks")
    sel.add_argument("--desktop-ok", action="store_true",
                     help="(reserved) acknowledge rdp/vnc desktop pathways -- not yet "
                          "available; arrives in PLAN-001 S5")
    sel.add_argument("--vnc-automate", action="store_true", help=argparse.SUPPRESS)
    tun = ap.add_argument_group("tuning")
    tun.add_argument("-P", "--parallel", type=int, default=4,
                     help=f"parallel workers (default 4, capped {PARALLEL_CAP})")
    tun.add_argument("--connect-timeout", type=int, default=10, help="seconds (default 10)")
    tun.add_argument("--host-timeout", type=int, default=600,
                     help="per-host wall-clock cap, seconds (default 600; 0 = unlimited)")
    tun.add_argument("--linux-script", help="override the Linux privesc collector (self-scan)")
    tun.add_argument("--linux-posture-script", help="override the Linux posture collector (self-scan)")
    tun.add_argument("--windows-script", help="override the Windows privesc collector (self-scan)")
    tun.add_argument("--dry-run", action="store_true", help="print the PLAN rows, open nothing")
    ap.add_argument("-o", "--output", required=True, help="results dir (bulk layout)")
    return ap


def resolve_allowed(transport: str, *, self_scan: bool, win_exec: Optional[str],
                    use_smb_admin: bool, desktop_ok: bool) -> set:
    """Expand --transport into the set of allowed pathways, enforcing the exec
    consent gate and the S5 desktop refusal."""
    items = [p.strip().lower() for p in transport.split(",") if p.strip()]
    bad = [p for p in items if p not in ("auto",) + PATHWAYS]
    if bad:
        raise UsageError(f"unknown transport(s): {', '.join(bad)}")
    requested_desktop = (set(items) & set(DESKTOP)) or desktop_ok
    if requested_desktop:
        raise UsageError("rdp/vnc desktop pathways are not yet available -- they arrive in "
                         "PLAN-001 S5. Drop them from --transport (and --desktop-ok) for now.")
    if "auto" in items or not items:
        allowed = {"ssh", "winrm"}
        if self_scan:
            allowed.add("local")
        if win_exec and use_smb_admin:
            allowed.add("exec")
        return allowed
    allowed = set(items)
    if "exec" in allowed:
        if not win_exec:
            raise UsageError("--transport exec requires --win-exec {wmiexec,smbexec,psexec}")
        if not use_smb_admin:
            raise UsageError("--transport exec requires --use-smb-admin (the exec methods write "
                             "to the target via their own mechanism; ADR-007 section 9)")
    if self_scan:
        allowed.add("local")
    return allowed


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if not (args.targets or args.from_inventory or args.self_scan):
            raise UsageError("nothing to do: pass --targets, --from-inventory, and/or --self")
        if args.win_exec and not args.use_smb_admin:
            raise UsageError("--win-exec requires --use-smb-admin (exec methods write to the "
                             "target via their own mechanism; ADR-007 section 9)")
        if args.nthash and not NT_RE.match(args.nthash):
            raise UsageError("-H/--hash must be a 32-hex NT hash")
        if not 1 <= args.parallel <= PARALLEL_CAP:
            raise UsageError(f"-P must be in 1..{PARALLEL_CAP}")
        if args.host_timeout < 0:
            raise UsageError("--host-timeout must be >= 0")
        allowed = resolve_allowed(args.transport, self_scan=args.self_scan,
                                  win_exec=args.win_exec, use_smb_admin=args.use_smb_admin,
                                  desktop_ok=args.desktop_ok)
        default = Cred(user=args.user, password=args.password, key=args.key,
                       nthash=args.nthash, domain=args.domain)
        specs: list = []
        if args.targets:
            specs += load_targets(Path(args.targets))
        if args.from_inventory:
            specs += load_inventory(Path(args.from_inventory))
        creds_rows = load_creds(Path(args.creds)) if args.creds else []

        probe = None
        probe_error = ""
        if "exec" in allowed:
            try:
                probe = build_probe(args.win_exec)
            except ProbeTooLarge as e:
                probe_error = str(e)
                warn(f"compact probe will refuse for {args.win_exec}: {e}")
    except UsageError as e:
        err(str(e))
        return 2

    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)

    plans = [plan_host(s, resolve_cred(s, creds_rows, default), allowed,
                       args.win_exec, probe, probe_error) for s in specs]

    if args.dry_run:
        if args.self_scan and "local" in allowed:
            osn = "windows" if os.name == "nt" else "linux"
            print(PlanRow("localhost", osn, "local", "full", "self-scan", "self").line())
        for hp in plans:
            for row in hp.rows:
                print(row.line())
        return 0

    if args.self_scan and "local" in allowed:
        run_self_scan(out, args, default)
    execute_plans(plans, out, allowed, args.win_exec, probe, args.tls, args)
    log(f"local-enum complete -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
