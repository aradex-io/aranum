#!/usr/bin/env python3
"""spray-scheduler.py — lockout-policy-aware credential spray scheduler.

Wraps creds/default-creds-sweep.py (or any operator-supplied sweeper) with
a throttle that respects an account-lockout policy: do NO MORE than
`--threshold N` attempts per principal within `--interval M` minutes. This
prevents the operator from accidentally locking out the very accounts
they're trying to validate.

Important defaults: --threshold 3 / --interval 30 mirrors a common AD
default policy. Override with what the target domain actually uses
(query via `net accounts` or `Get-ADDefaultDomainPasswordPolicy`).

Per REVIEW-001 §2.9 + ADR-004 D4: this is a wrapper, NOT a new spray
engine. We do not implement the network-side spray ourselves — we just
sequence the operator's existing tool with safe pacing.

Examples:
    spray-scheduler.py --threshold 3 --interval 30 \\
                       --users users.txt --passwords passlist.txt \\
                       --tool nxc --tool-args 'smb 10.0.0.10'

    # With our default-creds-sweep.py:
    spray-scheduler.py --threshold 2 --interval 60 \\
                       --users svcaccts.txt --passwords seasons.txt \\
                       --tool creds/default-creds-sweep.py \\
                       --tool-args '--targets targets.txt'

Authorized testing only.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty(): return s
    codes = {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m"}
    return f"{codes.get(code, '')}{s}\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--users", required=True, type=Path,
                    help="path to usernames file (one per line)")
    ap.add_argument("--passwords", required=True, type=Path,
                    help="path to passwords file (one per line, no quoting)")
    ap.add_argument("--threshold", type=int, default=3,
                    help="MAX attempts per principal per interval (default: 3)")
    ap.add_argument("--interval", type=int, default=30,
                    help="lockout interval in minutes (default: 30)")
    ap.add_argument("--tool", required=True,
                    help="external spray tool to invoke (e.g. 'nxc', '../creds/default-creds-sweep.py')")
    ap.add_argument("--tool-args", default="",
                    help="extra args appended to each invocation (shell-split)")
    ap.add_argument("--user-flag",  default="-u",
                    help="how the tool expects the user flag (default: -u)")
    ap.add_argument("--pass-flag",  default="-p",
                    help="how the tool expects the pass flag (default: -p)")
    ap.add_argument("--state-file", type=Path, default=Path(".spray-state.json"),
                    help="persistent state for resume (default: .spray-state.json)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan, do NOT invoke the tool")
    args = ap.parse_args()

    if not args.users.is_file():
        print(_c(f"[!] users file missing: {args.users}", "R"), file=sys.stderr); return 2
    if not args.passwords.is_file():
        print(_c(f"[!] passwords file missing: {args.passwords}", "R"), file=sys.stderr); return 2

    users = [u.strip() for u in args.users.read_text().splitlines() if u.strip() and not u.startswith("#")]
    pws   = [p.rstrip("\n") for p in args.passwords.read_text().splitlines() if p.rstrip("\n")]

    print(_c(f"[*] {len(users)} user(s) × {len(pws)} password(s) — total {len(users)*len(pws)} attempts", "Y"))
    print(_c(f"[*] lockout policy: <= {args.threshold} attempts per user per {args.interval} min", "Y"))

    # state: per-user list of attempt timestamps; persisted between runs
    state: dict[str, list[float]] = defaultdict(list)
    if args.state_file.is_file():
        try:
            raw = json.loads(args.state_file.read_text())
            for u, ts_list in raw.items():
                state[u] = ts_list
            print(_c(f"[*] resumed state from {args.state_file} — "
                     f"{sum(len(v) for v in state.values())} prior attempt(s)", "Y"))
        except Exception:
            pass

    interval_sec = args.interval * 60
    tool_extra   = shlex.split(args.tool_args)

    total = 0
    for pw in pws:
        for user in users:
            now = time.time()
            recent = [t for t in state[user] if t > now - interval_sec]
            state[user] = recent  # prune
            if len(recent) >= args.threshold:
                # need to wait until the oldest recent attempt ages out
                wait_until = recent[0] + interval_sec
                sleep_for = max(1.0, wait_until - now)
                if args.dry_run:
                    print(_c(f"[DRY] would sleep {int(sleep_for)}s for {user} "
                             f"({len(recent)} attempts in last {args.interval}m)", "Y"))
                else:
                    print(_c(f"[!] {user}: {len(recent)} attempts in last {args.interval}m — "
                             f"sleeping {int(sleep_for)}s", "Y"))
                    time.sleep(sleep_for)
                    now = time.time()
                    state[user] = [t for t in state[user] if t > now - interval_sec]

            cmd = [args.tool] + tool_extra + [args.user_flag, user, args.pass_flag, pw]
            cmd_str = " ".join(shlex.quote(x) for x in cmd)
            if args.dry_run:
                print(f"  [DRY] {cmd_str}")
            else:
                print(f"  [*] {datetime.now(timezone.utc).isoformat()}  {cmd_str}")
                try:
                    subprocess.run(cmd, timeout=30, check=False)
                except FileNotFoundError:
                    print(_c(f"[!] tool not found: {args.tool}", "R"), file=sys.stderr)
                    return 3
                except subprocess.TimeoutExpired:
                    print(_c(f"[!] tool timed out: {cmd_str}", "Y"), file=sys.stderr)

            # Only record real attempts in the lockout state — dry-run does
            # not contact the target so it cannot lock anyone out.
            if not args.dry_run:
                state[user].append(time.time())
                args.state_file.write_text(json.dumps(dict(state), indent=2))
            total += 1

    print(_c(f"[+] spray-scheduler done — {total} attempts queued / executed", "G"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted; state file preserved for --resume", file=sys.stderr); sys.exit(130)
