#!/usr/bin/env python3
"""aranum.py — unified network wrapper CLI.

This module is a thin dispatcher. Scanner/report generation still lives in the
existing scripts; aranum.py only normalizes common operator shortcuts and then
forwards to those scripts via subprocess.

Subcommands:
  plan        -> aranumtoolkit/network/plan.py
  run         -> aranumtoolkit/network/auto-enum.sh
  report      -> aranumtoolkit/network/report.py
  dashboard   -> aranumtoolkit/network/report-dashboard.py
  merge       -> aranumtoolkit/network/merge-results.py
  iter        -> aranumtoolkit/network/iterative-enum.sh
  bulk-linux  -> aranumtoolkit/network/bulk-enum-linux.sh
  bulk-windows-> aranumtoolkit/network/bulk-enum-windows.py
"""

from __future__ import annotations

import subprocess
import sys
import json
import shutil
import socket
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Sequence

PROJECT_ROOT = Path(__file__).resolve().parent
SCRIPT_DIR = PROJECT_ROOT / "aranumtoolkit" / "network"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"
_SESSION_VALUE_FLAGS = {"--session", "--session-name"}


def _script_path(name: str) -> Path:
    return SCRIPT_DIR / name


_COMMANDS = {
    # command: (runner, script)
    "plan": ("python", _script_path("plan.py")),
    "run": ("bash", _script_path("auto-enum.sh")),
    "report": ("python", _script_path("report.py")),
    "dashboard": ("python", _script_path("report-dashboard.py")),
    "merge": ("python", _script_path("merge-results.py")),
    "iter": ("bash", _script_path("iterative-enum.sh")),
    "bulk-linux": ("bash", _script_path("bulk-enum-linux.sh")),
    "bulk-windows": ("python", _script_path("bulk-enum-windows.py")),
}
_LOCAL_COMMANDS = {"queue"}
_RUN_REPORT_FLAGS = {"-report", "--report"}
_RUN_DASHBOARD_FLAGS = {"-dashboard", "--dashboard"}
_RUN_SERVE_FLAGS = {"-serve", "--serve"}
_NMAP_SUFFIXES = (".xml", ".gnmap", ".nmap")
_DEFAULT_DASHBOARD_BIND = "127.0.0.1"
_DEFAULT_DASHBOARD_PORT = 8765
_AUTO_ENUM_VALUE_FLAGS = {
    "-i", "--input",
    "-o", "--output",
    "-u", "--user",
    "-p", "--password",
    "-H", "--hash",
    "-d", "--domain",
    "--dc-ip",
    "-P", "--parallel",
    "--only",
    "--exclude",
    "--profile",
    "--phase",
    "--queue",
    "--skip-low-priority",
}


def _build_help() -> str:
    cmds = ", ".join(sorted(set(_COMMANDS) | _LOCAL_COMMANDS))
    return (
        "Usage: aranum <subcommand> [args...]\n"
        "\n"
        "Examples:\n"
        "  aranum run scan01 -report --session-name acme   # generates artifacts, non-blocking\n"
        "  aranum run scan01 -serve  --session-name acme   # also serves the dashboard (blocks)\n"
        "  aranum iter --session-name acme\n"
        "  aranum dashboard               # newest outputs/<session>/raw + reports/dashboard\n"
        "\n"
        "Output layout:\n"
        "  outputs/<session>/raw      raw scanner/dispatcher output\n"
        "  outputs/<session>/inputs   derived inputs: hosts, users, scope, loot\n"
        "  outputs/<session>/reports  report.md/html/json and dashboard files\n"
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


def _session_default() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _strip_session_args(args: Sequence[str]) -> tuple[list[str], str, bool]:
    out: list[str] = []
    session = ""
    explicit = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _SESSION_VALUE_FLAGS:
            if i + 1 >= len(args):
                raise ValueError(f"{arg} requires a value")
            session = args[i + 1]
            explicit = True
            i += 2
        elif arg.startswith("--session-name=") or arg.startswith("--session="):
            session = arg.split("=", 1)[1]
            explicit = True
            i += 1
        else:
            out.append(arg)
            i += 1
    return out, session or _session_default(), explicit


def _is_safe_session(session: str) -> bool:
    """A session name must be a single, simple path component — no separators,
    no traversal, no leading dot — so it can never escape OUTPUTS_DIR."""
    return (
        bool(session)
        and session not in (".", "..")
        and not session.startswith(".")
        and not any(c in session for c in "/\\")
        and all(c.isalnum() or c in "._-" for c in session)
    )


def _session_dirs(session: str) -> dict[str, Path]:
    if not _is_safe_session(session):
        print(f"[!] invalid session name: {session!r} "
              "(use letters, digits, '.', '_', '-'; no '/' or '..')",
              file=sys.stderr)
        sys.exit(2)
    base = OUTPUTS_DIR / session
    dirs = {
        "base": base,
        "raw": base / "raw",
        "inputs": base / "inputs",
        "reports": base / "reports",
    }
    for path in dirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return dirs


def _add_default_output(args: Sequence[str], output: Path) -> list[str]:
    args = list(args)
    if _has_option(args, {"-o", "--output"}):
        return args
    return args + ["-o", str(output)]


def _copy_report_artifacts(raw: Path, reports: Path) -> None:
    for name in ("findings.json", "report.md", "report.html"):
        src = raw / name
        if src.is_file():
            shutil.copy2(src, reports / name)


def _copy_input_artifact(scan: str | None, inputs: Path) -> None:
    if not scan:
        return
    src = Path(scan)
    if src.is_file():
        shutil.copy2(src, inputs / src.name)


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
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print("[!] skipping malformed queue.jsonl line", file=sys.stderr)
                continue
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


def _dashboard_help() -> str:
    return (
        "Usage: aranum dashboard [outdir] [-o DIR] [--bulk] [--rules FILE]\n"
        "                         [--bind ADDR] [--port N] [--open] [--no-serve]\n"
        "\n"
        "Generates the report-dashboard.py static HTML dashboard and starts a local report server.\n"
        "If outdir is omitted, aranum uses the newest scan-looking directory in cwd.\n"
        "Default dashboard output is a sibling directory: <outdir>-dashboard.\n"
        "Default server bind is 127.0.0.1 with the first free port at or above 8765.\n"
    )


def _is_generated_dashboard_dir(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / "index.html").is_file()
        and (path / "assets" / "dashboard.css").is_file()
        and (path / "assets" / "dashboard.js").is_file()
    )


def _looks_like_scan_outdir(path: Path) -> bool:
    if not path.is_dir() or _is_generated_dashboard_dir(path):
        return False
    sentinel_names = {
        "inventory.json",
        "services.txt",
        "run.log",
        "queue.jsonl",
        "guidance.json",
        "findings.json",
        "report.md",
        "report.html",
    }
    if any((path / name).exists() for name in sentinel_names):
        return True
    try:
        for child in path.iterdir():
            if not child.is_dir() or _is_generated_dashboard_dir(child):
                continue
            if (child / "_dispatcher.log").is_file() or (child / "_meta.json").is_file():
                return True
            try:
                if any(grand.is_dir() for grand in child.iterdir()):
                    return True
            except OSError:
                continue
    except OSError:
        return False
    return False


def _candidate_mtime(path: Path) -> float:
    mtimes = [path.stat().st_mtime]
    for name in ("run.log", "inventory.json", "findings.json", "report.html"):
        fp = path / name
        if fp.exists():
            mtimes.append(fp.stat().st_mtime)
    return max(mtimes)


def _find_latest_outdir() -> Path | None:
    roots = [Path.cwd()]
    if SCRIPT_DIR != roots[0]:
        roots.append(SCRIPT_DIR)

    candidates: list[Path] = []
    if OUTPUTS_DIR.is_dir():
        for session in OUTPUTS_DIR.iterdir():
            raw = session / "raw"
            if _looks_like_scan_outdir(raw):
                candidates.append(raw)
    for root in roots:
        if _looks_like_scan_outdir(root):
            candidates.append(root)
        try:
            for child in root.iterdir():
                if _looks_like_scan_outdir(child):
                    candidates.append(child)
        except OSError:
            continue

    if not candidates:
        return None
    return max(candidates, key=_candidate_mtime)


def _default_dashboard_output(outdir: Path) -> Path:
    outdir = outdir.resolve()
    if outdir.name == "raw" and outdir.parent.parent == OUTPUTS_DIR.resolve():
        return outdir.parent / "reports" / "dashboard"
    return outdir.parent / f"{outdir.name}-dashboard"


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _port_is_free(bind: str, port: int) -> bool:
    try:
        with socket.create_server((bind, port), reuse_port=False):
            return True
    except OSError:
        return False


def _first_free_port(bind: str, start: int) -> int:
    for port in range(start, 65536):
        if _port_is_free(bind, port):
            return port
    raise RuntimeError(f"no free TCP port found on {bind} at or above {start}")


def _serve_dashboard(output: Path, bind: str, port: int, open_after: bool) -> int:
    url = f"http://{bind}:{port}/"
    print(f"[*] report server: {url}", file=sys.stderr)
    print("[*] press Ctrl-C to stop", file=sys.stderr)
    if open_after:
        webbrowser.open(url)
    return subprocess.run(
        [str(sys.executable), "-m", "http.server", str(port), "--bind", bind],
        cwd=str(output),
    ).returncode


def _run_dashboard(args: Sequence[str], session: str | None = None) -> int:
    args = list(args)
    if args and args[0] in {"-h", "--help", "help"}:
        print(_dashboard_help().rstrip())
        return 0

    outdir: Path | None = None
    output: Path | None = None
    rules: Path | None = None
    bulk = False
    open_after = False
    serve = True
    bind = _DEFAULT_DASHBOARD_BIND
    port: int | None = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-o", "--output"}:
            if i + 1 >= len(args):
                print(f"[!] {arg} requires a directory", file=sys.stderr)
                return 2
            output = Path(args[i + 1])
            i += 2
        elif arg.startswith("--output="):
            output = Path(arg.split("=", 1)[1])
            i += 1
        elif arg == "--rules":
            if i + 1 >= len(args):
                print("[!] --rules requires a file", file=sys.stderr)
                return 2
            rules = Path(args[i + 1])
            i += 2
        elif arg.startswith("--rules="):
            rules = Path(arg.split("=", 1)[1])
            i += 1
        elif arg == "--bulk":
            bulk = True
            i += 1
        elif arg == "--bind":
            if i + 1 >= len(args):
                print("[!] --bind requires an address", file=sys.stderr)
                return 2
            bind = args[i + 1]
            i += 2
        elif arg.startswith("--bind="):
            bind = arg.split("=", 1)[1]
            i += 1
        elif arg == "--port":
            if i + 1 >= len(args):
                print("[!] --port requires a port", file=sys.stderr)
                return 2
            try:
                port = int(args[i + 1])
            except ValueError:
                print(f"[!] invalid --port: {args[i + 1]}", file=sys.stderr)
                return 2
            i += 2
        elif arg.startswith("--port="):
            try:
                port = int(arg.split("=", 1)[1])
            except ValueError:
                print(f"[!] invalid --port: {arg.split('=', 1)[1]}", file=sys.stderr)
                return 2
            i += 1
        elif arg == "--open":
            open_after = True
            i += 1
        elif arg == "--no-serve":
            serve = False
            i += 1
        elif arg.startswith("-"):
            print(f"[!] unknown dashboard arg: {arg}", file=sys.stderr)
            print(_dashboard_help().rstrip(), file=sys.stderr)
            return 2
        elif outdir is None:
            outdir = Path(arg)
            i += 1
        else:
            print(f"[!] unexpected dashboard arg: {arg}", file=sys.stderr)
            print(_dashboard_help().rstrip(), file=sys.stderr)
            return 2

    if outdir is None and session is not None:
        candidate = OUTPUTS_DIR / session / "raw"
        if candidate.is_dir():
            outdir = candidate
        else:
            print(f"[!] session raw output not found: {candidate}", file=sys.stderr)
            return 2

    if outdir is None:
        outdir = _find_latest_outdir()
        if outdir is None:
            print("[!] no scan output directory found; pass one explicitly", file=sys.stderr)
            print(_dashboard_help().rstrip(), file=sys.stderr)
            return 2
        print(f"[*] dashboard: using latest output directory: {outdir}", file=sys.stderr)

    if not outdir.is_dir():
        print(f"[!] dashboard outdir not found: {outdir}", file=sys.stderr)
        return 2
    if _is_generated_dashboard_dir(outdir):
        print(
            f"[!] {outdir} looks like generated dashboard output; "
            "pass the scan output directory instead",
            file=sys.stderr,
        )
        return 2

    output = output or _default_dashboard_output(outdir)
    if _is_relative_to(output, outdir):
        print(
            "[!] warning: dashboard output is inside the scan output tree; "
            "future reports may re-ingest generated HTML",
            file=sys.stderr,
        )

    cmd = build_command("dashboard", [str(outdir), "--output", str(output)])
    if bulk:
        cmd.append("--bulk")
    if rules is not None:
        cmd += ["--rules", str(rules)]

    rc = subprocess.run(cmd).returncode
    if rc != 0 or not serve:
        if rc == 0 and open_after:
            webbrowser.open((output / "index.html").resolve().as_uri())
        return rc

    if port is None:
        try:
            port = _first_free_port(bind, _DEFAULT_DASHBOARD_PORT)
        except RuntimeError as e:
            print(f"[!] {e}", file=sys.stderr)
            return 2
    elif not 1 <= port <= 65535:
        print(f"[!] invalid --port: {port}", file=sys.stderr)
        return 2
    return _serve_dashboard(output, bind, port, open_after)


def _extract_option(args: Sequence[str], names: set[str]) -> str | None:
    i = 0
    while i < len(args):
        arg = args[i]
        for name in names:
            if arg.startswith(f"{name}="):
                return arg.split("=", 1)[1]
        if arg in names and i + 1 < len(args):
            return args[i + 1]
        if arg in _AUTO_ENUM_VALUE_FLAGS:
            i += 2
        else:
            i += 1
    return None


def _has_option(args: Sequence[str], names: set[str]) -> bool:
    return _extract_option(args, names) is not None


def _resolve_scan_token(token: str) -> Path:
    p = Path(token)
    if p.is_file():
        return p
    if p.suffix in _NMAP_SUFFIXES:
        return p
    for suffix in _NMAP_SUFFIXES:
        candidate = Path(f"{token}{suffix}")
        if candidate.is_file():
            return candidate
    return p


def _first_bare_arg(args: Sequence[str]) -> tuple[int, str] | None:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _AUTO_ENUM_VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        return i, arg
    return None


def _prepare_run_args(args: Sequence[str]) -> tuple[list[str], bool, bool]:
    run_args: list[str] = []
    generate_report = False
    serve_dashboard = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _RUN_REPORT_FLAGS:
            generate_report = True
            i += 1
        elif arg in _RUN_DASHBOARD_FLAGS:
            generate_report = True
            i += 1
        elif arg in _RUN_SERVE_FLAGS:
            # Opt-in: chain report + dashboard AND start the blocking report server.
            generate_report = True
            serve_dashboard = True
            i += 1
        else:
            run_args.append(arg)
            i += 1

    if not _has_option(run_args, {"-i", "--input"}):
        bare = _first_bare_arg(run_args)
        if bare is not None:
            idx, token = bare
            resolved = _resolve_scan_token(token)
            del run_args[idx]
            run_args = ["-i", str(resolved)] + run_args

    return run_args, generate_report, serve_dashboard


def _run_auto_enum(args: Sequence[str], session: str) -> int:
    dirs = _session_dirs(session)
    run_args, generate_report, serve_dashboard = _prepare_run_args(args)
    run_args = _add_default_output(run_args, dirs["raw"])
    _copy_input_artifact(_extract_option(run_args, {"-i", "--input"}), dirs["inputs"])
    rc = subprocess.run(build_command("run", run_args)).returncode
    if rc != 0 or not generate_report:
        return rc

    outdir = Path(_extract_option(run_args, {"-o", "--output"}) or dirs["raw"])
    report_cmd = build_command("report", [str(outdir), "--label", session])
    rc = subprocess.run(report_cmd).returncode
    if rc != 0:
        return rc
    _copy_report_artifacts(outdir, dirs["reports"])
    # Generate-only by default so `aranum run … -report` stays non-interactive
    # (a scheduled/CI wrapper must not block on http.server). Opt into the blocking
    # report server with `-serve`/`--serve`.
    dash_dir = dirs["reports"] / "dashboard"
    dash_args = [str(outdir), "--output", str(dash_dir)]
    if not serve_dashboard:
        dash_args.append("--no-serve")
    rc = _run_dashboard(dash_args)
    if not serve_dashboard:
        index = dash_dir / "index.html"
        print(f"[*] dashboard generated: file://{index}", file=sys.stderr)
    return rc


def _run_iterative(args: Sequence[str], session: str) -> int:
    dirs = _session_dirs(session)
    iter_args = _add_default_output(args, dirs["inputs"])
    if not _has_option(iter_args, {"--enum-output"}) and (dirs["raw"] / "inventory.json").is_file():
        iter_args += ["--enum-output", str(dirs["raw"])]
    return subprocess.run(build_command("iter", iter_args)).returncode


def _run_bulk(command: str, args: Sequence[str], session: str) -> int:
    dirs = _session_dirs(session)
    default = dirs["raw"] / command
    bulk_args = _add_default_output(args, default)
    return subprocess.run(build_command(command, bulk_args)).returncode


def run(command: str, args: Sequence[str], session: str, session_explicit: bool = False) -> int:
    if command == "queue":
        return _queue(args)
    if command == "run":
        return _run_auto_enum(args, session)
    if command == "iter":
        return _run_iterative(args, session)
    if command in {"bulk-linux", "bulk-windows"}:
        return _run_bulk(command, args, session)
    if command == "dashboard":
        return _run_dashboard(args, session if session_explicit else None)
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
        elif c == "dashboard":
            print("  - dashboard: wrapper for report-dashboard.py with safe defaults")
        elif c == "run":
            print("  - run: bash auto-enum.sh; -report chains report + dashboard (non-blocking), -serve also serves it")
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

    try:
        cmd_args, session, session_explicit = _strip_session_args(args[1:])
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 2
    return run(cmd, cmd_args, session, session_explicit)


if __name__ == "__main__":
    sys.exit(main())
