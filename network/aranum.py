#!/usr/bin/env python3
"""aranum.py — unified network wrapper CLI.

This module is a thin dispatcher. Every functional subcommand forwards all
received arguments to an existing script via subprocess; no scanner logic is
reimplemented here.

Subcommands:
  plan        -> network/plan.py
  run         -> network/auto-enum.sh
  report      -> network/report.py
  dashboard   -> network/report-dashboard.py
  merge       -> network/merge-results.py
  queue       -> network/autoenum-diff.sh
  bulk-linux  -> network/bulk-enum-linux.sh
  bulk-windows-> network/bulk-enum-windows.py
"""

from __future__ import annotations

import subprocess
import sys
import json
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent


def _script_path(name: str) -> Path:
    return SCRIPT_DIR / name


_COMMANDS = {
    # command: (runner, script)
    "plan": ("python", _script_path("plan.py")),
    "run": ("bash", _script_path("auto-enum.sh")),
    "report": ("python", _script_path("report.py")),
    "dashboard": ("python", _script_path("report-dashboard.py")),
    "merge": ("python", _script_path("merge-results.py")),
    "bulk-linux": ("bash", _script_path("bulk-enum-linux.sh")),
    "bulk-windows": ("python", _script_path("bulk-enum-windows.py")),
}
_LOCAL_COMMANDS = {"queue"}


def _build_help() -> str:
    cmds = ", ".join(sorted(set(_COMMANDS) | _LOCAL_COMMANDS))
    return (
        "Usage: aranum <subcommand> [args...]\n"
        "\n"
        "Subcommands:\n"
        f"  {cmds}\n"
    )


def _to_runner(runner: str) -> list[str]:
    return [str(sys.executable)] if runner == "python" else ["bash"]


def build_command(command: str, args: Sequence[str]) -> list[str]:
    if command not in _COMMANDS:
        raise ValueError(f"unknown subcommand: {command}")

    runner, script = _COMMANDS[command]
    if not script.exists():
        raise FileNotFoundError(f"script not found: {script}")

    return _to_runner(runner) + [str(script)] + list(args)


def _queue_help() -> str:
    return (
        "Usage: aranum queue <outdir> [--list] [--status STATUS]\n"
        "\n"
        "Reads <outdir>/queue.jsonl and prints a compact operator queue view.\n"
    )


def _queue(args: Sequence[str]) -> int:
    args = list(args)
    if not args or args[0] in {"-h", "--help"}:
        print(_queue_help().rstrip())
        return 0
    outdir = Path(args.pop(0))
    status = None
    list_only = False
    i = 0
    while i < len(args):
        if args[i] == "--list":
            list_only = True
            i += 1
        elif args[i] == "--status" and i + 1 < len(args):
            status = args[i + 1]
            i += 2
        else:
            print(f"[!] unknown queue arg: {args[i]}", file=sys.stderr)
            print(_queue_help().rstrip(), file=sys.stderr)
            return 2
    queue = outdir / "queue.jsonl"
    if not queue.is_file():
        print(f"[!] queue.jsonl missing: {queue}", file=sys.stderr)
        return 2
    count = 0
    with queue.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            if status and item.get("status") != status:
                continue
            count += 1
            target = item.get("target_label")
            if not target and isinstance(item.get("target"), dict):
                t = item["target"]
                ip = str(t.get("ip", ""))
                host = f"[{ip}]" if ":" in ip else ip
                target = f"{host}:{t.get('port', '')}"
            print(
                f"{item.get('priority', 0):>3} "
                f"{item.get('status', 'pending'):<10} "
                f"{item.get('phase', ''):<4} "
                f"{item.get('service', ''):<16} "
                f"{target or ''} "
                f"{item.get('task_id', '')}"
            )
    if not list_only:
        print(f"queue items: {count}", file=sys.stderr)
    return 0


def run(command: str, args: Sequence[str]) -> int:
    if command == "queue":
        return _queue(args)
    try:
        cmd = build_command(command, args)
    except (FileNotFoundError, ValueError) as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2

    return subprocess.run(cmd).returncode


def print_help() -> None:
    print(_build_help().rstrip())
    for c in sorted(set(_COMMANDS) | _LOCAL_COMMANDS):
        if c in _LOCAL_COMMANDS:
            print(f"  - {c}: built-in queue viewer")
        else:
            runner, script = _COMMANDS[c]
            print(f"  - {c}: {runner} {script.name}")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        print_help()
        return 0

    cmd = args[0]
    if cmd not in _COMMANDS and cmd not in _LOCAL_COMMANDS:
        print(f"[!] unknown command: {cmd}", file=sys.stderr)
        print_help()
        return 2

    return run(cmd, args[1:])


if __name__ == "__main__":
    sys.exit(main())
