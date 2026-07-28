#!/usr/bin/env python3
"""ssh-key-triage.py — "which unknown key is good for what?"

Authorized-testing triage of a pile of operator-held SSH private keys against
an operator-authorized host list. Two phases:

  INVENTORY (local, non-destructive): for each key — type (rsa/ed25519/ecdsa/
    dsa), bit size, SHA256 + MD5 fingerprint, encrypted?, whether a passphrase
    from --passwords unlocks it, derived public key, PEM vs OpenSSH format,
    comment. Uses paramiko + cryptography; degrades to an `ssh-keygen`
    shell-out if paramiko is unavailable. --help / --dry-run never import-fail.

  MATCH (network): build a key x host x user acceptance matrix via a
    NON-DESTRUCTIVE publickey-only probe — one key per connection:

        ssh -i KEY -o BatchMode=yes -o PreferredAuthentications=publickey \\
            -o PubkeyAuthentication=yes -o PasswordAuthentication=no \\
            -o IdentitiesOnly=yes -o ConnectTimeout=... USER@HOST true

    This is pure publickey auth validation. It NEVER attempts password auth,
    NEVER writes to a target, and honours lockout hygiene: --max-per-user cap
    (key attempts per user@host) + --throttle inter-attempt delay, plus a
    per-engagement known_hosts silo (accept-new) exactly like bulk-enum.

Outputs (to --output): key-triage.json (full matrix + inventory),
key-triage.md (human matrix), authorized-pairs.txt (key,user,host triples
ready to feed bulk-enum-linux.sh).

CLAUDE.md §9: read-only on targets; no password spraying; no persistence.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import glob
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ------------------------------------------------------------------ optional deps
try:
    import paramiko  # type: ignore

    HAVE_PARAMIKO = True
except Exception:  # pragma: no cover - exercised only where paramiko absent
    HAVE_PARAMIKO = False

PARALLEL_CAP = 16


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


# ================================================================== inventory
def _key_format(path: Path) -> str:
    """PEM vs OpenSSH by the private-key armor header."""
    try:
        with open(path, "r", errors="replace") as fh:
            first = fh.readline().strip()
    except OSError:
        return "unknown"
    if "OPENSSH PRIVATE KEY" in first:
        return "openssh"
    if "PRIVATE KEY" in first:  # RSA/EC/PKCS8 PEM
        return "pem"
    return "unknown"


def _sibling_comment(path: Path) -> Optional[str]:
    """Best-effort comment from a sibling <key>.pub (OpenSSH keeps it there)."""
    pub = Path(str(path) + ".pub")
    if pub.is_file():
        try:
            parts = pub.read_text(errors="replace").split()
            if len(parts) >= 3:
                return " ".join(parts[2:]).strip()
        except OSError:
            pass
    return None


def _fingerprints(pub_blob: bytes) -> tuple[str, str]:
    """(SHA256:base64-nopad, MD5:aa:bb:..) over the SSH public-key blob."""
    sha = base64.b64encode(hashlib.sha256(pub_blob).digest()).decode().rstrip("=")
    md5 = hashlib.md5(pub_blob).hexdigest()
    md5_c = ":".join(md5[i : i + 2] for i in range(0, len(md5), 2))
    return f"SHA256:{sha}", f"MD5:{md5_c}"


_TYPE_LABEL = {
    "ssh-rsa": "rsa",
    "ssh-ed25519": "ed25519",
    "ssh-dss": "dsa",
}


def _label_for(name: str) -> str:
    if name.startswith("ecdsa-"):
        return "ecdsa"
    return _TYPE_LABEL.get(name, name)


def _paramiko_key_classes() -> list:
    # DSSKey was removed in paramiko 5.x (DSA deprecated) — resolve defensively
    # so we support both old and new paramiko without an AttributeError.
    names = ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey")
    return [c for c in (getattr(paramiko, n, None) for n in names) if c is not None]


def _paramiko_load(path: Path, password: Optional[str]):
    """Try each key class; re-raise PasswordRequiredException (== encrypted)."""
    classes = _paramiko_key_classes()
    last = None
    for cls in classes:
        try:
            return cls.from_private_key_file(str(path), password=password)
        except paramiko.PasswordRequiredException:
            raise
        except paramiko.SSHException as exc:
            last = exc
            continue
    raise last or paramiko.SSHException("unrecognized private-key format")


def inventory_key_paramiko(path: Path, passphrases: list[str]) -> dict:
    rec: dict = {
        "path": str(path),
        "format": _key_format(path),
        "comment": _sibling_comment(path),
        "encrypted": False,
        "unlocked": None,
        "type": None,
        "bits": None,
        "fingerprint_sha256": None,
        "fingerprint_md5": None,
        "public_key": None,
        "error": None,
    }
    key = None
    try:
        key = _paramiko_load(path, None)
    except paramiko.PasswordRequiredException:
        rec["encrypted"] = True
        rec["unlocked"] = False
        for pw in passphrases:
            try:
                key = _paramiko_load(path, pw)
                rec["unlocked"] = True
                break
            except Exception:
                continue
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
        return rec

    if key is None:
        # encrypted and no supplied passphrase unlocked it — inventory what we can
        if rec["encrypted"] and not passphrases:
            rec["error"] = "encrypted (no --passwords supplied to attempt unlock)"
        elif rec["encrypted"]:
            rec["error"] = "encrypted (no supplied passphrase matched)"
        return rec

    try:
        blob = key.asbytes()
        rec["type"] = _label_for(key.get_name())
        rec["bits"] = key.get_bits()
        sha, md5 = _fingerprints(blob)
        rec["fingerprint_sha256"] = sha
        rec["fingerprint_md5"] = md5
        rec["public_key"] = f"{key.get_name()} {base64.b64encode(blob).decode()}"
    except Exception as exc:  # pragma: no cover - defensive
        rec["error"] = f"derive-public-failed: {exc}"
    return rec


def _run(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )


def inventory_key_keygen(path: Path, passphrases: list[str]) -> dict:
    """Fallback inventory via `ssh-keygen` when paramiko is unavailable."""
    rec: dict = {
        "path": str(path),
        "format": _key_format(path),
        "comment": _sibling_comment(path),
        "encrypted": False,
        "unlocked": None,
        "type": None,
        "bits": None,
        "fingerprint_sha256": None,
        "fingerprint_md5": None,
        "public_key": None,
        "error": None,
    }
    try:
        r = _run(["ssh-keygen", "-l", "-f", str(path)])
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        rec["error"] = f"ssh-keygen unavailable: {exc}"
        return rec
    if r.returncode != 0:
        rec["error"] = f"ssh-keygen -l failed: {r.stderr.strip()}"
        return rec
    # "2048 SHA256:xxxx comment (RSA)"
    parts = r.stdout.strip().split()
    if len(parts) >= 2:
        try:
            rec["bits"] = int(parts[0])
        except ValueError:
            pass
        rec["fingerprint_sha256"] = parts[1]
    if parts and parts[-1].startswith("(") and parts[-1].endswith(")"):
        rec["type"] = parts[-1].strip("()").lower()
    m = _run(["ssh-keygen", "-l", "-E", "md5", "-f", str(path)])
    if m.returncode == 0:
        mp = m.stdout.strip().split()
        if len(mp) >= 2:
            rec["fingerprint_md5"] = mp[1]
    # Encryption detection: derive public with empty passphrase.
    y = _run(["ssh-keygen", "-y", "-P", "", "-f", str(path)])
    if y.returncode == 0:
        rec["public_key"] = y.stdout.strip()
    else:
        if "incorrect passphrase" in (y.stderr + y.stdout).lower() or "load failed" in (
            y.stderr
        ).lower():
            rec["encrypted"] = True
            rec["unlocked"] = False
            for pw in passphrases:
                yp = _run(["ssh-keygen", "-y", "-P", pw, "-f", str(path)])
                if yp.returncode == 0:
                    rec["unlocked"] = True
                    rec["public_key"] = yp.stdout.strip()
                    break
    return rec


def inventory_key(path: Path, passphrases: list[str]) -> dict:
    if HAVE_PARAMIKO:
        return inventory_key_paramiko(path, passphrases)
    return inventory_key_keygen(path, passphrases)


# ================================================================== probe argv
def build_probe_argv(
    key_path: str,
    user: str,
    host: str,
    port: int,
    known_hosts: str,
    connect_timeout: int,
    extra_opts: Optional[list[str]] = None,
    ssh_bin: str = "ssh",
    remote_cmd: str = "true",
) -> list[str]:
    """Canonical NON-DESTRUCTIVE publickey-only probe argv (ADR-006 BLOCKER 3
    key-probe row): BatchMode=yes, PubkeyAuthentication NOT disabled,
    IdentitiesOnly=yes, PasswordAuthentication=no. One key per connection."""
    argv = [
        ssh_bin,
        "-i",
        key_path,
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "LogLevel=ERROR",
        "-p",
        str(port),
    ]
    if extra_opts:
        for opt in extra_opts:
            argv += ["-o", opt]
    # IPv6 destinations must be bracketed.
    dest_host = f"[{host}]" if ":" in host else host
    argv += [f"{user}@{dest_host}", remote_cmd]
    return argv


def _classify(rc: int, stderr: str) -> str:
    if rc == 0:
        return "ACCEPTED"
    low = stderr.lower()
    if any(
        s in low
        for s in ("connection refused", "timed out", "no route", "could not resolve", "connection closed")
    ):
        return "UNREACHABLE"
    if "permission denied" in low:
        return "DENIED"
    if rc == 255:
        return "UNREACHABLE"
    return "ERROR"


def probe_one(
    key_path: str,
    user: str,
    host: str,
    port: int,
    known_hosts: str,
    connect_timeout: int,
    extra_opts: Optional[list[str]],
    ssh_bin: str,
    throttle: float,
) -> dict:
    if throttle > 0:
        time.sleep(throttle)
    argv = build_probe_argv(
        key_path, user, host, port, known_hosts, connect_timeout, extra_opts, ssh_bin
    )
    try:
        r = _run(argv, timeout=connect_timeout + 15)
        rc, err = r.returncode, r.stderr
    except subprocess.TimeoutExpired:
        rc, err = 124, "local ssh probe timed out"
    except FileNotFoundError as exc:
        rc, err = 127, f"ssh binary not found: {exc}"
    status = _classify(rc, err)
    return {
        "key": key_path,
        "user": user,
        "host": host,
        "port": port,
        "rc": rc,
        "status": status,
        "accepted": status == "ACCEPTED",
        "stderr": err.strip()[:200],
    }


# ================================================================== targets
def load_targets(args, script_dir: Path) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []

    def add(host: str, port: int) -> None:
        host = host.strip()
        if host and (host, port) not in targets:
            targets.append((host, port))

    if args.targets:
        for raw in Path(args.targets).read_text(errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("[") and "]:" in line:  # [ipv6]:port
                host = line[1 : line.index("]")]
                port = int(line[line.index("]:") + 2 :])
            elif line.count(":") == 1:
                host, _, p = line.partition(":")
                port = int(p) if p.isdigit() else args.port
            else:
                host, port = line, args.port
            add(host, port)

    if args.nmap:
        parser = script_dir / "nmap-parse.py"
        if not parser.is_file():
            _log(f"[!] --nmap given but nmap-parse.py not found at {parser}")
        else:
            try:
                r = _run(
                    [sys.executable, str(parser), args.nmap, "--service", "ssh"],
                    timeout=60,
                )
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith("["):
                        continue
                    if line.startswith("[") and "]:" in line:
                        continue
                    host, _, p = line.rpartition(":")
                    if host and p.isdigit():
                        add(host, int(p))
                    else:
                        add(line, args.port)
            except (subprocess.TimeoutExpired, OSError) as exc:
                _log(f"[!] nmap-parse.py failed: {exc}")
    return targets


# ================================================================== output
def render_markdown(inventory: list[dict], matrix: list[dict], users, targets) -> str:
    out: list[str] = ["# SSH key triage\n"]
    out.append(f"_generated {datetime.now(timezone.utc).isoformat()}_\n")

    out.append("## Key inventory\n")
    out.append("| key | type | bits | SHA256 | encrypted | unlocked | format |")
    out.append("|---|---|---|---|---|---|---|")
    for k in inventory:
        out.append(
            "| {path} | {type} | {bits} | {fp} | {enc} | {unl} | {fmt} |".format(
                path=os.path.basename(k["path"]),
                type=k.get("type") or "?",
                bits=k.get("bits") or "?",
                fp=(k.get("fingerprint_sha256") or "?"),
                enc=k.get("encrypted"),
                unl=k.get("unlocked"),
                fmt=k.get("format"),
            )
        )
    out.append("")

    out.append("## Acceptance matrix (key x user@host)\n")
    if not matrix:
        out.append("_no probes run (inventory-only / --dry-run)._\n")
    else:
        out.append("| key | user@host:port | status |")
        out.append("|---|---|---|")
        for m in matrix:
            mark = "ACCEPTED" if m["accepted"] else m["status"]
            out.append(
                "| {k} | {u}@{h}:{p} | {s} |".format(
                    k=os.path.basename(m["key"]),
                    u=m["user"],
                    h=m["host"],
                    p=m["port"],
                    s=mark,
                )
            )
    out.append("")
    accepted = [m for m in matrix if m["accepted"]]
    out.append(f"**{len(accepted)} accepted pair(s)** out of {len(matrix)} probe(s).\n")
    return "\n".join(out) + "\n"


def write_outputs(outdir: Path, doc: dict) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "key-triage.json").write_text(json.dumps(doc, indent=2) + "\n")
    md = render_markdown(
        doc["inventory"], doc["matrix"], doc["users"], doc["targets"]
    )
    (outdir / "key-triage.md").write_text(md)
    # authorized-pairs.txt — key,user,host triples for bulk-enum-linux.sh
    lines = ["# key,user,host  — accepted publickey pairs (feed to bulk-enum-linux.sh)"]
    for m in doc["matrix"]:
        if m["accepted"]:
            host = m["host"] if m["port"] == 22 else f"{m['host']}:{m['port']}"
            lines.append(f"{m['key']},{m['user']},{host}")
    (outdir / "authorized-pairs.txt").write_text("\n".join(lines) + "\n")


# ================================================================== cli
def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="ssh-key-triage.py",
        description="Inventory unknown SSH keys and matrix-probe them "
        "(publickey-only, non-destructive) against authorized hosts.",
    )
    ap.add_argument("--keys", required=True, help="directory OR glob of private keys")
    ap.add_argument("--targets", help="host list file (host | host:port per line)")
    ap.add_argument("--nmap", help="nmap .xml/.gnmap/.nmap (hosts w/ 22 open via nmap-parse.py)")
    ap.add_argument(
        "--users",
        default="",
        help="comma-list of usernames (default: root + current user)",
    )
    ap.add_argument("--passwords", help="file of candidate key passphrases (one/line)")
    ap.add_argument("--port", type=int, default=22, help="default SSH port (22)")
    ap.add_argument("--connect-timeout", type=int, default=8, help="ssh ConnectTimeout")
    ap.add_argument(
        "--parallel", type=int, default=4, help=f"parallel probes (cap {PARALLEL_CAP})"
    )
    ap.add_argument(
        "--max-per-user",
        type=int,
        default=5,
        help="max key attempts per user@host (lockout hygiene; 0 = unlimited)",
    )
    ap.add_argument(
        "--throttle", type=float, default=0.0, help="seconds delay before each probe"
    )
    ap.add_argument("--ssh-opt", action="append", default=[], help="extra -o K=V (repeatable)")
    ap.add_argument("--ssh-bin", default="ssh", help="ssh binary (default: ssh on PATH)")
    ap.add_argument("--dry-run", action="store_true", help="inventory + print plan, no probes")
    ap.add_argument("--output", default="./key-triage-results", help="output directory")
    return ap.parse_args(argv)


def collect_key_paths(keys_arg: str) -> list[Path]:
    p = Path(keys_arg)
    paths: list[Path] = []
    if p.is_dir():
        for entry in sorted(p.iterdir()):
            if entry.is_file() and not entry.name.endswith(".pub"):
                paths.append(entry)
    else:
        for hit in sorted(glob.glob(keys_arg)):
            hp = Path(hit)
            if hp.is_file() and not hp.name.endswith(".pub"):
                paths.append(hp)
    return paths


def _looks_like_private_key(path: Path) -> bool:
    try:
        with open(path, "r", errors="replace") as fh:
            head = fh.read(64)
        return "PRIVATE KEY" in head
    except OSError:
        return False


def run(args: argparse.Namespace) -> int:
    script_dir = Path(__file__).resolve().parent
    outdir = Path(args.output)

    key_paths = [p for p in collect_key_paths(args.keys) if _looks_like_private_key(p)]
    if not key_paths:
        _log(f"[!] no private keys found in --keys {args.keys}")
        return 2

    passphrases: list[str] = []
    if args.passwords:
        try:
            passphrases = [
                l.rstrip("\n") for l in Path(args.passwords).read_text().splitlines() if l.strip()
            ]
        except OSError as exc:
            _log(f"[!] --passwords unreadable: {exc}")

    if not HAVE_PARAMIKO:
        _log("[?] paramiko not installed — inventory via ssh-keygen fallback (degraded).")

    inventory = [inventory_key(p, passphrases) for p in key_paths]

    users = [u for u in args.users.split(",") if u.strip()]
    if not users:
        users = sorted({"root", os.environ.get("USER") or os.environ.get("USERNAME") or "root"})

    targets = load_targets(args, script_dir)

    parallel = max(1, min(args.parallel, PARALLEL_CAP))
    known_hosts = str(outdir / "known_hosts")

    # Build the probe plan: for each user@host, at most --max-per-user keys.
    plan: list[tuple[str, str, str, int]] = []
    for host, port in targets:
        for user in users:
            keys_for = [i["path"] for i in inventory]
            if args.max_per_user and args.max_per_user > 0:
                keys_for = keys_for[: args.max_per_user]
            for kp in keys_for:
                plan.append((kp, user, host, port))

    if args.dry_run or not targets:
        if not targets:
            _log("[?] no targets supplied — inventory-only run.")
        outdir.mkdir(parents=True, exist_ok=True)
        doc = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "tool": "ssh-key-triage",
            "params": {
                "keys": args.keys,
                "users": users,
                "port": args.port,
                "parallel": parallel,
                "max_per_user": args.max_per_user,
                "throttle": args.throttle,
                "dry_run": bool(args.dry_run),
                "paramiko": HAVE_PARAMIKO,
            },
            "inventory": inventory,
            "targets": [f"{h}:{p}" for h, p in targets],
            "users": users,
            "matrix": [],
            "planned_probes": len(plan),
        }
        write_outputs(outdir, doc)
        print(f"[+] inventoried {len(inventory)} key(s); {len(plan)} probe(s) planned "
              f"({'DRY-RUN — not executed' if args.dry_run else 'no targets'}).")
        print(f"[+] output: {outdir}")
        if plan:
            k, u, h, pt = plan[0]
            print("[+] probe argv template:")
            print("    " + " ".join(build_probe_argv(k, u, h, pt, known_hosts, args.connect_timeout, args.ssh_opt, args.ssh_bin)))
        return 0

    outdir.mkdir(parents=True, exist_ok=True)
    Path(known_hosts).touch(exist_ok=True)

    matrix: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = [
            ex.submit(
                probe_one,
                kp,
                user,
                host,
                port,
                known_hosts,
                args.connect_timeout,
                args.ssh_opt,
                args.ssh_bin,
                args.throttle,
            )
            for (kp, user, host, port) in plan
        ]
        for f in concurrent.futures.as_completed(futs):
            matrix.append(f.result())

    matrix.sort(key=lambda m: (m["host"], m["user"], m["key"]))
    doc = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "tool": "ssh-key-triage",
        "params": {
            "keys": args.keys,
            "users": users,
            "port": args.port,
            "parallel": parallel,
            "max_per_user": args.max_per_user,
            "throttle": args.throttle,
            "dry_run": False,
            "paramiko": HAVE_PARAMIKO,
        },
        "inventory": inventory,
        "targets": [f"{h}:{p}" for h, p in targets],
        "users": users,
        "matrix": matrix,
    }
    write_outputs(outdir, doc)
    accepted = [m for m in matrix if m["accepted"]]
    print(f"[+] {len(inventory)} key(s), {len(targets)} host(s), {len(matrix)} probe(s)")
    print(f"[+] {len(accepted)} accepted pair(s) -> {outdir}/authorized-pairs.txt")
    for m in accepted:
        print(f"    ACCEPTED: {os.path.basename(m['key'])} -> {m['user']}@{m['host']}:{m['port']}")
    return 0


def main(argv=None) -> int:
    args = parse_args(argv)
    if args.parallel > PARALLEL_CAP:
        _log(f"[!] --parallel capped at {PARALLEL_CAP} (asked {args.parallel})")
    try:
        return run(args)
    except KeyboardInterrupt:  # pragma: no cover
        _log("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
