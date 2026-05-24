#!/usr/bin/env python3
"""plan.py — build operator-focused task plans from nmap scan output.

This is a planning-only layer that uses existing nmap-parse.py helpers to
derive host/port/service inventory and expand it into execution tasks.

Outputs:
  - plan.json   : full plan for the selected profile + filters
  - queue.jsonl : one JSON task per line in queue order
  - guidance.json : operator-facing guidance and execution notes
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NETWORK_DIR = Path(__file__).resolve().parent
PARSER_PATH = NETWORK_DIR / "nmap-parse.py"
SERVICE_METADATA_PATH = NETWORK_DIR / "service-metadata.json"
ENGAGEMENT_PROFILE_PATH = NETWORK_DIR / "engagement-profiles.json"
METADATA_FIELDS = (
    "priority_base",
    "risk",
    "default_enabled",
    "requires_opt_in",
    "requires_auth",
    "cost",
    "tags",
    "followups",
    "docs",
    "confidence",
    "priority",
    "next_actions",
)
SERVICE_PRIORITY_DEFAULTS = {
    "ot-untouched": 950,
    "docker": 920,
    "kubernetes": 920,
    "etcd": 900,
    "vault": 880,
    "backup": 850,
    "smb": 840,
    "ldap": 830,
    "kerberos": 820,
    "winrm": 780,
    "mssql": 760,
    "redis": 750,
    "consul": 740,
    "http": 700,
    "https": 700,
    "ipmi": 690,
    "ssh": 680,
    "rdp": 660,
    "mysql": 650,
    "postgres": 650,
    "mongo": 650,
    "elastic": 650,
    "activemq": 640,
    "rabbitmq": 630,
    "unknown": 620,
}


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location("nmap_parse", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load parser module from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _coerce_phase_list(raw: Any) -> list[dict[str, str]]:
    phases: list[dict[str, str]] = []
    if not raw:
        return phases
    for item in raw:
        if isinstance(item, dict):
            pid = item.get("id")
            if pid is None:
                continue
            name = item.get("name", str(pid))
            desc = item.get("description", "")
        else:
            if item is None:
                continue
            pid = item
            name = item
            desc = ""
        phases.append(
            {
                "id": str(pid),
                "name": str(name),
                "description": str(desc),
            }
        )
    seen = set()
    deduped = []
    for p in phases:
        if p["id"] in seen:
            continue
        seen.add(p["id"])
        deduped.append(p)
    return deduped


def _normalize_service_records(metadata: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    defaults = _coerce_phase_list(metadata.get("defaults", {}).get("phases", []))
    if not defaults:
        defaults = [{"id": "1", "name": "discovery", "description": "default discovery phase"}]
    default_entry = {
        "dispatcher": metadata.get("defaults", {}).get("dispatcher"),
        "manual": bool(metadata.get("defaults", {}).get("manual", False)),
        "phases": {p["id"]: p for p in defaults},
        "notes": list(metadata.get("defaults", {}).get("notes", [])),
    }
    for field in METADATA_FIELDS:
        if field in metadata.get("defaults", {}):
            default_entry[field] = metadata["defaults"][field]
    services = {}
    for name, raw_cfg in metadata.get("services", {}).items():
        raw_phases = _coerce_phase_list(raw_cfg.get("phases", []))
        if not raw_phases:
            raw_phases = defaults
        svc_entry = {
            "dispatcher": raw_cfg.get("dispatcher"),
            "manual": bool(raw_cfg.get("manual", False)),
            "phases": {p["id"]: p for p in raw_phases},
            "notes": list(raw_cfg.get("notes", [])),
        }
        for field in METADATA_FIELDS:
            if field in raw_cfg:
                svc_entry[field] = raw_cfg[field]
            elif field in default_entry:
                svc_entry[field] = default_entry[field]
        services[name.lower()] = svc_entry
    return services, default_entry


def _normalize_profile(profile_name: str, profiles: dict[str, Any]) -> dict[str, Any]:
    cfg = profiles.get(profile_name)
    if cfg is None:
        raise ValueError(f"unknown profile '{profile_name}'")
    service_filter_cfg = cfg.get("service_filter", {})
    include = [x.lower() for x in service_filter_cfg.get("include", ["*"]) if str(x).strip()]
    if not include:
        include = ["*"]
    include_seen = []
    for item in include:
        if item not in include_seen:
            include_seen.append(item)
    exclude = [x.lower() for x in service_filter_cfg.get("exclude", []) if str(x).strip()]
    exclude_seen = []
    for item in exclude:
        if item not in exclude_seen:
            exclude_seen.append(item)
    return {
        "label": cfg.get("label", profile_name),
        "description": cfg.get("description", ""),
        "service_filter": {
            "include": include_seen,
            "exclude": exclude_seen,
        },
        "phase_filter": [str(x) for x in cfg.get("phase_filter", ["all"]) if str(x).strip()],
    }


def _parse_range(raw: str) -> list[str]:
    m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", raw)
    if not m:
        return [str(int(raw.strip()))]
    start = int(m.group(1))
    end = int(m.group(2))
    if start > end:
        start, end = end, start
    return [str(i) for i in range(start, end + 1)]


def _parse_phase_filter(raw: str | None, available: set[str]) -> list[str] | None:
    if raw is None:
        return None
    tokens = [x.strip() for x in raw.split(",") if x.strip()]
    if not tokens:
        return []
    out: list[str] = []
    for t in tokens:
        low = t.lower()
        if low in {"all", "*"}:
            return None
        for piece in re.split(r"\s+", t):
            if not piece:
                continue
            for p in _parse_range(piece):
                if not p.isdigit():
                    continue
                if not available or p in available:
                    out.append(p)
    # preserve first-seen order, remove duplicates
    deduped: list[str] = []
    seen = set()
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        deduped.append(p)
    return deduped


def _parse_shard(raw: str | None) -> tuple[int, int] | None:
    if raw is None:
        return None
    for sep in ("/", ","):
        if sep in raw:
            parts = [x.strip() for x in raw.split(sep)]
            break
    else:
        raise ValueError("shard must be INDEX/TOTAL (or INDEX,TOTAL)")
    if len(parts) != 2:
        raise ValueError("shard must be INDEX/TOTAL (or INDEX,TOTAL)")
    index = int(parts[0])
    total = int(parts[1])
    if index < 1 or total < 1:
        raise ValueError("shard indexes must be positive integers")
    if index > total:
        raise ValueError("shard index cannot be greater than total shards")
    return index, total


def _select_services(entry: dict[str, Any], service_cfgs: dict[str, Any], default_cfg: dict[str, Any], service_filter: dict[str, Any]) -> list[str]:
    included = set(service_filter["include"])
    excluded = set(service_filter["exclude"])
    categories = [x.lower() for x in (entry.get("categories") or [])]
    if not categories:
        categories = ["unknown"]
    services: list[str] = []
    for svc in categories:
        if svc in excluded:
            continue
        if "*" in included or not included:
            services.append(svc)
            continue
        if svc in included:
            services.append(svc)
            continue
        # If service not in profile include list and service has no metadata, treat it
        # as manually reviewed and still emit guidance. This is safer than silently
        # dropping targets from operator flow.
        if svc not in service_cfgs and not default_cfg.get("manual", True):
            services.append(svc)
    return services


def _select_task_phases(
    requested: list[str] | None,
    available_phases: dict[str, dict[str, str]],
) -> list[tuple[str, dict[str, str]] | None]:
    if requested is None:
        # CLI/profile did not constrain phases; keep everything this service exposes.
        return [(pid, p) for pid, p in available_phases.items()]
    if not requested:
        return []
    selected = []
    selected_ids = set(requested)
    for pid, phase in available_phases.items():
        if pid in selected_ids:
            selected.append((pid, phase))
    return selected


def _task_id(task: dict[str, Any]) -> str:
    t = task["target"]
    return f"{task['service']}::{t['ip']}:{t['port']}:{task['phase']}"


def _target_label(entry: dict[str, Any]) -> str:
    ip = str(entry["ip"])
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{entry['port']}"


def _priority(service: str, cfg: dict[str, Any], phase_id: str) -> int:
    try:
        base = int(cfg.get("priority_base", 300))
    except (TypeError, ValueError):
        base = 300
    if base == 300 and service in SERVICE_PRIORITY_DEFAULTS:
        base = SERVICE_PRIORITY_DEFAULTS[service]
    try:
        phase_penalty = max(0, int(phase_id) - 1) * 20
    except ValueError:
        phase_penalty = 0
    return max(0, min(999, base - phase_penalty))


def _list_field(cfg: dict[str, Any], key: str) -> list[str]:
    raw = cfg.get(key, [])
    if not isinstance(raw, list):
        return []
    return [str(x) for x in raw if str(x).strip()]


def _build_tasks(
    parser_mod,
    input_path: Path,
    services: dict[str, Any],
    defaults: dict[str, Any],
    phase_filter: list[str] | None,
    service_filter: dict[str, Any],
    shard: tuple[int, int] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries = list(parser_mod.dispatch(input_path))
    entries = list(entries)
    tasks: list[dict[str, Any]] = []
    skipped_services: list[dict[str, Any]] = []
    for entry in entries:
        entry["categories"] = parser_mod.categorize(int(entry["port"]), entry["service"])
        for svc in _select_services(entry, services, defaults, service_filter):
            cfg = services.get(svc, defaults)
            selected_phase_pairs = _select_task_phases(
                phase_filter,
                cfg["phases"],
            )
            if not selected_phase_pairs:
                skipped_services.append(
                    {
                        "service": svc,
                        "ip": entry["ip"],
                        "port": entry["port"],
                        "proto": entry["proto"],
                        "reason": "no matching phase after filtering",
                    }
                )
                continue
            for phase_id, phase in selected_phase_pairs:
                target_label = _target_label(entry)
                priority = _priority(svc, cfg, phase_id)
                task = {
                    "schema_version": 1,
                    "service": svc,
                    "phase": phase_id,
                    "phase_name": phase["name"],
                    "phase_description": phase["description"],
                    "manual": bool(cfg.get("manual", False)),
                    "dispatcher": cfg.get("dispatcher"),
                    "target_label": target_label,
                    "host": entry["ip"],
                    "port": entry["port"],
                    "proto": entry["proto"],
                    "priority": priority,
                    "risk": cfg.get("risk", defaults.get("risk", "read-safe")),
                    "cost": cfg.get("cost", defaults.get("cost", "low")),
                    "requires_auth": bool(cfg.get("requires_auth", defaults.get("requires_auth", False))),
                    "requires_opt_in": bool(cfg.get("requires_opt_in", defaults.get("requires_opt_in", False))),
                    "default_enabled": bool(cfg.get("default_enabled", defaults.get("default_enabled", True))),
                    "status": "pending",
                    "reason": [
                        f"{svc} mapped to {phase['name']}",
                        f"priority base {cfg.get('priority_base', defaults.get('priority_base', 300))}",
                    ],
                    "output_hint": f"{svc}/{str(entry['ip']).replace(':', '_')}_{entry['port']}",
                    "tags": _list_field(cfg, "tags"),
                    "followups": _list_field(cfg, "followups"),
                    "docs": _list_field(cfg, "docs"),
                    "next_actions": _list_field(cfg, "next_actions"),
                    "target": {
                        "ip": entry["ip"],
                        "hostname": entry.get("hostname", ""),
                        "port": entry["port"],
                        "proto": entry["proto"],
                        "service": entry["service"],
                        "product": entry.get("product", ""),
                        "version": entry.get("version", ""),
                        "extrainfo": entry.get("extrainfo", ""),
                    },
                    "notes": list(cfg.get("notes", [])),
                }
                task["task_id"] = _task_id(task)
                tasks.append(task)
    # Stable ordering for deterministic sharding and test expectations.
    tasks.sort(key=lambda t: (
        t["service"], t["target"]["ip"], t["target"]["port"], t["phase"], t["task_id"]
    ))

    unsharded_count = len(tasks)
    if shard is not None:
        index, total = shard
        tasks = [t for n, t in enumerate(tasks, start=1) if ((n - 1) % total) + 1 == index]

    # Deduplicate in case metadata+profile combinations produce overlap.
    deduped: list[dict[str, Any]] = []
    seen = set()
    for task in tasks:
        if task["task_id"] in seen:
            continue
        seen.add(task["task_id"])
        deduped.append(task)
    tasks = deduped
    tasks.sort(key=lambda t: (-int(t.get("priority", 0)), t["service"], t["target"]["ip"], t["target"]["port"], t["phase"]))

    summary = {
        "input": str(input_path),
        "hosts": len({e["ip"] for e in entries}),
        "open_ports": len(entries),
        "services_discovered": len(set(
            svc
            for e in entries
            for svc in (
                [x.lower() for x in (parser_mod.categorize(int(e["port"]), e["service"]) or ["unknown"])]
            )
        )),
        "tasks_pre_shard": unsharded_count,
        "tasks_in_queue": len(tasks),
        "service_counts": dict(Counter(t["service"] for t in tasks)),
        "phase_counts": dict(Counter(t["phase"] for t in tasks)),
        "skipped_by_phase_filter": len(skipped_services),
        "skipped_services": skipped_services,
    }
    return tasks, summary


def _build_guidance(
    plan: dict[str, Any],
    summary: dict[str, Any],
    profile_name: str,
    profile_cfg: dict[str, Any],
    phase_filter: list[str] | None,
    shard: tuple[int, int] | None,
) -> dict[str, Any]:
    manual = [t for t in plan["tasks"] if t["manual"] or not t["dispatcher"]]
    guidance_items: list[dict[str, Any]] = []
    for svc in sorted({t["service"] for t in manual}):
        svc_tasks = [t for t in manual if t["service"] == svc]
        first = svc_tasks[0]
        guidance_items.append({
            "id": f"guidance:manual:{svc}",
            "priority": int(first.get("priority", 500)),
            "type": "manual-handoff",
            "title": f"{svc} requires operator handoff",
            "reason": "Planner found targets that are intentionally not auto-dispatched or require explicit scope confirmation.",
            "recommended_next": first.get("next_actions", ["Review planner task list"])[0] if first.get("next_actions") else "Review planner task list",
            "evidence": [t["target_label"] for t in svc_tasks[:10]],
        })
    gated = [t for t in plan["tasks"] if t.get("requires_opt_in")]
    for svc in sorted({t["service"] for t in gated}):
        svc_tasks = [t for t in gated if t["service"] == svc]
        guidance_items.append({
            "id": f"guidance:gated:{svc}",
            "priority": max(int(t.get("priority", 0)) for t in svc_tasks),
            "type": "gated-surface",
            "title": f"{svc} detected but gated",
            "reason": "This service has additional OPSEC or safety constraints and should not run without explicit operator approval.",
            "recommended_next": svc_tasks[0].get("next_actions", ["Confirm authorization before enabling"])[0],
            "evidence": [t["target_label"] for t in svc_tasks[:10]],
        })
    guidance_items.sort(key=lambda g: -int(g.get("priority", 0)))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": {
            "name": profile_name,
            "label": profile_cfg["label"],
            "description": profile_cfg["description"],
            "phase_filter": phase_filter if phase_filter is not None else ["all"],
            "service_filter": profile_cfg["service_filter"],
        },
        "shard": {
            "enabled": shard is not None,
            "index": shard[0] if shard else 1,
            "total": shard[1] if shard else 1,
        },
        "counts": {
            "queue_tasks": len(plan["tasks"]),
            "manual_tasks": len(manual),
            "services": summary["services_discovered"],
            "phases": sorted(summary["phase_counts"].items(), key=lambda x: x[0]),
        },
        "manual_services": sorted({t["service"] for t in manual}),
        "manual_tasks": manual,
        "guidance": guidance_items,
        "next_steps": [
            "Apply queue.jsonl in order for deterministic, operator-tuned execution.",
            "Manual services require operator follow-up before dispatch.",
            "Rerun with --shard INDEX/TOTAL to split across runners.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build an operator plan from nmap output.")
    p.add_argument("input", nargs="?", help="Nmap output file (.xml/.gnmap/.nmap)")
    p.add_argument("-i", "--input", dest="input_opt", help="Nmap output file (.xml/.gnmap/.nmap)")
    p.add_argument("--output", "-o", default="plan-out", help="Directory for plan.json / queue.jsonl / guidance.json")
    p.add_argument(
        "--profile",
        default=None,
        help="Engagement profile name (default from engagement-profiles.json)",
    )
    p.add_argument(
        "--phase",
        default=None,
        help="Comma-separated phase filter, e.g. 1,2 or 1-3; all=all phases",
    )
    p.add_argument(
        "--shard",
        default=None,
        help="Shard selector for queue partitioning, e.g. 2/5",
    )
    p.add_argument(
        "--service-metadata",
        default=str(SERVICE_METADATA_PATH),
        help=f"Path to service metadata JSON (default: {SERVICE_METADATA_PATH})",
    )
    p.add_argument(
        "--engagement-profiles",
        default=str(ENGAGEMENT_PROFILE_PATH),
        help=f"Path to engagement profile JSON (default: {ENGAGEMENT_PROFILE_PATH})",
    )

    args = p.parse_args(argv)

    input_value = args.input_opt or args.input
    if not input_value:
        p.print_usage(sys.stderr)
        print("error: input is required", file=sys.stderr)
        return 2
    input_path = Path(input_value)
    if not input_path.exists():
        print(f"error: input does not exist: {input_path}", file=sys.stderr)
        return 2

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        metadata = _load_json(Path(args.service_metadata))
        profile_data = _load_json(Path(args.engagement_profiles))
    except OSError as exc:
        print(f"error: failed to load metadata/profiles file: {exc}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as exc:
        print(f"error: invalid json in metadata/profiles file: {exc}", file=sys.stderr)
        return 3

    parser_mod = _load_module(PARSER_PATH)
    service_cfgs, default_cfg = _normalize_service_records(metadata)
    profiles = profile_data.get("profiles", {})
    default_profile = profile_data.get("defaults", {}).get("profile", "default")
    profile_name = args.profile or default_profile
    try:
        profile_cfg = _normalize_profile(profile_name, profiles)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    # available phases for validation include all phase IDs declared in the metadata
    # and the selected service profiles. We validate against defaults so that
    # unknown services can still be accepted when requested.
    avail_phases = {
        pid
        for svc_cfg in service_cfgs.values()
        for pid in svc_cfg["phases"].keys()
    }
    try:
        cli_phase_filter = _parse_phase_filter(args.phase, avail_phases)
    except ValueError as exc:
        print(f"error: invalid --phase value: {exc}", file=sys.stderr)
        return 5

    profile_phase_filter = profile_cfg["phase_filter"]
    requested_phases = cli_phase_filter
    if requested_phases is None:
        # profile-specified filter, if absent then all
        requested_phases = None
        if profile_phase_filter:
            if any(x.lower() in {"all", "*"} for x in profile_phase_filter):
                requested_phases = None
            else:
                requested_phases = [str(x) for x in profile_phase_filter]

    try:
        shard = _parse_shard(args.shard)
    except ValueError as exc:
        print(f"error: invalid --shard value: {exc}", file=sys.stderr)
        return 6

    try:
        tasks, summary = _build_tasks(
            parser_mod=parser_mod,
            input_path=input_path,
            services=service_cfgs,
            defaults=default_cfg,
            phase_filter=requested_phases,
            service_filter=profile_cfg["service_filter"],
            shard=shard,
        )
    except Exception as exc:  # pragma: no cover - parser or category edge case
        print(f"error: failed to build plan: {exc}", file=sys.stderr)
        return 7

    plan = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": str(input_path),
        "profile": profile_name,
        "phase_filter": requested_phases if requested_phases is not None else ["all"],
        "service_filter": profile_cfg["service_filter"],
        "shard": {"enabled": shard is not None, "index": shard[0] if shard else 1, "total": shard[1] if shard else 1},
        "summary": summary,
        "tasks": tasks,
    }

    plan_path = out_dir / "plan.json"
    queue_path = out_dir / "queue.jsonl"
    guidance_path = out_dir / "guidance.json"

    with plan_path.open("w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2)
    with queue_path.open("w", encoding="utf-8") as f:
        for task in tasks:
            f.write(json.dumps(task, sort_keys=True))
            f.write("\n")
        if not tasks:
            pass
    guidance = _build_guidance(plan, summary, profile_name, profile_cfg, requested_phases, shard)
    with guidance_path.open("w", encoding="utf-8") as f:
        json.dump(guidance, f, indent=2)

    print(f"[planner] wrote {len(tasks)} tasks to {plan_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
