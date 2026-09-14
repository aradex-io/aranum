#!/usr/bin/env python3
"""aranum_to_recce.py — ingest aranum output into a recce engagement datastore.

Reads aranum's machine-readable `findings.json` (schema v2, from
`aranumtoolkit/network/report.py`) plus — for FULL service/port coverage — the
service inventory aranum discovered (nmap XML, `nmap-parse --json` inventory,
and/or the raw output tree), and writes them into a recce SQLite datastore
(`results.sqlite`), then regenerates recce's spreadsheets (`enumeration.xlsx`
+ `.md`/`.csv`).

Net effect: run aranum for its wide/deep active enumeration + exploitation, then
hand the results to recce so EVERY discovered host, port and service — and every
finding — populates recce's engagement-tracking workbook (Checklist, Services,
Vulnerabilities, Overview, ...).

Port/service coverage (in order of richness; all sources are merged):
  1. `--nmap scan.xml`      native recce parse (OS, per-port product/version, NSE)
  2. `--inventory inv.json` aranum `nmap-parse --json` — every open (ip,port,svc)
  3. raw output tree        `<service>/<ip>_<port>/` dirs, auto-detected
  4. findings.json          ports embedded in findings; a portless finding is
                            pinned to its service's canonical port via aranum's
                            own SERVICE_MAP, so no service is dropped.

Give it an aranum session dir (`outputs/<session>/`) and it auto-discovers the
findings.json, the scan input, and the raw tree.

Design
------
* One-directional: aranum data -> recce store -> recce spreadsheets.
* Loose coupling: we translate aranum *data* and drive recce's *public* data
  model (`recce.models`) + datastore (`recce.store`). No code is copied either
  way, so aranum's CC-BY-NC-SA and recce's MIT license stay independent.
* Re-runnable: recce's `upsert_host` merges, so re-ingesting never duplicates
  and never wipes the operator's spreadsheet ticks.

recce (MIT, https://github.com/dloucks01/Python -> recce/) must be importable:
`pip install` it, put it on PYTHONPATH, or pass `--recce-path /path/to/recce`.
"""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_NMAP_PARSE = os.path.normpath(os.path.join(_HERE, "..", "network", "nmap-parse.py"))

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_PORT_RE = re.compile(r"https?://[^\s/:]+:(\d{1,5})")
_PROTO_PORT_RE = re.compile(r"\b(\d{2,5})/(?:tcp|udp)\b")
_COLON_PORT_RE = re.compile(r":(\d{2,5})\b")
# raw tree leaf dirs are named <ip>_<port> (e.g. 10.0.0.5_445, or v6 with '_' sep)
_RAW_LEAF_RE = re.compile(r"^(?P<ip>.+)_(?P<port>\d{1,5})$")

# aranum and recce share the same severity vocabulary — pass-through with a
# defensive fallback.
_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# For a portless finding, min(ports) is usually the canonical port, but a few
# services list a legacy/secondary port first — pin those explicitly.
_PRIMARY_PORT_OVERRIDE = {"smb": 445, "nfs": 2049, "rabbitmq": 15672,
                          "http": 80, "https": 443}


# ----------------------------------------------------- aranum SERVICE_MAP (DRY)

def _load_service_ports() -> dict[str, set[int]]:
    """Load aranum's authoritative service->ports table from nmap-parse.py.

    Falls back to an empty map (findings without an explicit port simply stay
    portless) if nmap-parse.py can't be imported, so the exporter still runs.
    """
    try:
        spec = importlib.util.spec_from_file_location("_aranum_nmap_parse", _NMAP_PARSE)
        mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
        spec.loader.exec_module(mod)                         # type: ignore[union-attr]
        return {cat: set(ports) for cat, (ports, _rx) in mod.SERVICE_MAP.items()}
    except Exception as e:                                    # noqa: BLE001
        print(f"[!] could not load SERVICE_MAP from {_NMAP_PARSE} ({e}); "
              "portless findings will stay portless.", file=sys.stderr)
        return {}


def _primary_port(service: str, svc_ports: dict[str, set[int]]) -> int | None:
    ports = svc_ports.get((service or "").lower())
    if not ports:
        return None
    if service.lower() in _PRIMARY_PORT_OVERRIDE:
        ov = _PRIMARY_PORT_OVERRIDE[service.lower()]
        if ov in ports:
            return ov
    return min(ports)


# --------------------------------------------------------------------------- recce

def _load_recce(recce_path: str | None):
    """Import the recce package, optionally after adding `recce_path` to sys.path."""
    if recce_path:
        p = os.path.abspath(os.path.expanduser(recce_path))
        candidates = []
        if os.path.isfile(os.path.join(p, "recce", "__init__.py")):
            candidates.append(p)                       # parent of the package
        if os.path.isfile(os.path.join(p, "__init__.py")) and \
                os.path.basename(p) == "recce":
            candidates.append(os.path.dirname(p))      # the package dir itself
        for c in candidates or [p]:
            if c not in sys.path:
                sys.path.insert(0, c)
    try:
        import recce  # noqa: F401
        return recce
    except ImportError as e:
        sys.exit(
            "error: could not import the recce package "
            f"({e}). Install recce, put it on PYTHONPATH, or pass "
            "--recce-path /path/to/recce (the dir containing the recce/ package)."
        )


# ----------------------------------------------------------------------- helpers

def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
        return True
    except ValueError:
        return False


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _resolve_ip(finding: dict) -> str | None:
    host = (finding.get("host") or "").strip()
    if _is_ip(host):
        return host
    m = _IPV4_RE.search(finding.get("line") or "")
    return m.group(1) if m else None


def _resolve_port(finding: dict) -> int | None:
    raw = str(finding.get("port") or "").strip()
    if raw.isdigit() and 0 < int(raw) < 65536:
        return int(raw)
    line = finding.get("line") or ""
    for rx in (_URL_PORT_RE, _PROTO_PORT_RE, _COLON_PORT_RE):
        m = rx.search(line)
        if m:
            port = int(m.group(1))
            if 0 < port < 65536:
                return port
    return None


def _severity(finding: dict) -> str:
    sev = (finding.get("severity") or "info").lower()
    return sev if sev in _SEVERITIES else "info"


def _resolve_finding_endpoint(finding: dict, inventory_records: list[dict]
                              ) -> tuple[int | None, str]:
    """Resolve port/protocol without inventing TCP for ambiguous legacy data."""
    ip = _resolve_ip(finding)
    if not ip:
        return None, ""
    service = str(finding.get("service") or "").strip()
    port = _resolve_port(finding)
    explicit_protocol = str(finding.get("protocol") or "").lower()
    candidates = [e for e in inventory_records if e["ip"] == ip
                  and (port is None or e["port"] == port)
                  and (e.get("service") == service or service in e.get("categories", []))]
    choices = {(e["port"], e["protocol"]) for e in candidates if e.get("protocol")}
    if port is None and len(choices) == 1:
        port = next(iter(choices))[0]
    protocols = {proto for candidate_port, proto in choices
                 if port is None or candidate_port == port}
    protocol = explicit_protocol if explicit_protocol in {"tcp", "udp"} else (
        next(iter(protocols)) if len(protocols) == 1 else "")
    return port, protocol


def _coverage_states(doc: dict) -> dict[tuple[str, int, str], str]:
    """Collapse coverage records with incomplete states taking precedence."""
    out: dict[tuple[str, int, str], str] = {}
    for record in (doc.get("summary", {}).get("coverage", []) or []):
        try:
            key = (str(record.get("host", "")), int(record.get("port")),
                   str(record.get("protocol", "")).lower())
        except (TypeError, ValueError):
            continue
        status = str(record.get("status", "")).lower()
        if status == "skip":
            status = "skipped"
        prior = out.get(key)
        rank = {"failed": 4, "skipped": 3, "unassessed": 2,
                "done": 1, "confirmed": 1, "assessed_clean": 1, "ok": 1}
        if prior is None or rank.get(status, 0) > rank.get(prior, 0):
            out[key] = status
    return out


def _successful_coverage(doc: dict) -> set[tuple[str, int, str]]:
    successful = {"done", "confirmed", "assessed_clean", "ok"}
    return {key for key, status in _coverage_states(doc).items() if status in successful}


def _authoritative_incomplete_coverage(doc: dict) -> set[tuple[str, int, str]]:
    return {key for key, status in _coverage_states(doc).items()
            if status in {"failed", "skipped", "unassessed"}}


def _subnet_size(subnet: str) -> int:
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return 0
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


# ---------------------------------------------------------- port-inventory sources

def _ports_from_inventory(path: str) -> list[dict]:
    """aranum `nmap-parse --json` inventory -> list of port dicts.

    Accepts the documented `{summary, entries[]}` shape (entries carry
    ip/port/proto/service/product/version) and is tolerant of a bare list.
    """
    with open(path) as fh:
        doc = json.load(fh)
    entries = doc.get("entries", doc) if isinstance(doc, dict) else doc
    out = []
    for e in entries or []:
        ip = (e.get("ip") or "").strip()
        port = e.get("port")
        if not _is_ip(ip) or not isinstance(port, int):
            continue
        protocol = str(e.get("proto") or e.get("protocol") or "").strip().lower()
        if protocol not in {"tcp", "udp"}:
            # Protocol-less inventory cannot prove a TCP endpoint.  Skip it
            # unless another explicit source supplies the transport.
            continue
        out.append({
            "ip": ip, "port": port,
            "protocol": protocol,
            "service": e.get("service") or "",
            "product": e.get("product") or "",
            "version": e.get("version") or "",
            "extrainfo": e.get("extrainfo") or "",
            "hostname": e.get("hostname") or "",
            "categories": [str(c).lower() for c in (e.get("categories") or [])],
        })
    return out


def _ports_from_scan(path: str) -> list[dict]:
    """Use aranum's parser for XML, gnmap, and normal nmap inputs."""
    spec = importlib.util.spec_from_file_location("_aranum_scan_parser", _NMAP_PARSE)
    mod = importlib.util.module_from_spec(spec)          # type: ignore[arg-type]
    spec.loader.exec_module(mod)                         # type: ignore[union-attr]
    out = []
    for entry in mod.dispatch(Path(path)):
        item = dict(entry)
        item["protocol"] = str(item.pop("proto", "") or "").lower()
        item["categories"] = mod.categorize(int(item["port"]), str(item.get("service", "")))
        out.append(item)
    return out


def _ports_from_raw_tree(raw_dir: str, svc_ports: dict[str, set[int]] | None = None,
                         known_ports: list[dict] | None = None
                         ) -> list[dict]:
    """Enumerate (ip, port, service) from an aranum raw tree.

    Handles both documented leaf layouts (report.py accepts both):
      <service>/<ip>_<port>/   -> exact port
      <service>/<ip>/          -> port unknown; pinned to the service's canonical
                                  port via SERVICE_MAP so the service still lands.
    """
    svc_ports = svc_ports or {}
    out = []
    if not os.path.isdir(raw_dir):
        return out
    for service in os.listdir(raw_dir):
        sdir = os.path.join(raw_dir, service)
        if not os.path.isdir(sdir) or service.startswith("_"):
            continue
        for leaf in os.listdir(sdir):
            if not os.path.isdir(os.path.join(sdir, leaf)):
                continue
            m = _RAW_LEAF_RE.match(leaf)
            if m and _is_ip(m.group("ip")) and 0 < int(m.group("port")) < 65536:
                ip, port = m.group("ip"), int(m.group("port"))
            elif _is_ip(leaf):
                ip, port = leaf, _primary_port(service, svc_ports)  # bare-IP leaf
                if port is None:
                    continue
            else:
                continue
            matches = [e for e in (known_ports or []) if e["ip"] == ip and e["port"] == port
                       and (e.get("service") == service or service in e.get("categories", []))]
            protocols = {str(e.get("protocol", "")) for e in matches if e.get("protocol")}
            protocol = next(iter(protocols)) if len(protocols) == 1 else ""
            out.append({"ip": ip, "port": port, "protocol": protocol,
                        "service": service, "product": "", "version": "",
                        "extrainfo": "", "hostname": ""})
    return out


def _autodiscover(findings_path: str) -> dict[str, str | None]:
    """From a findings.json path (typically outputs/<session>/reports/findings.json),
    locate a sibling scan XML, inventory.json, and raw/ tree."""
    reports = os.path.dirname(os.path.abspath(findings_path))
    session = os.path.dirname(reports)          # outputs/<session>/
    found: dict[str, str | None] = {"nmap": None, "inventory": None, "raw": None}
    # inventory.json anywhere obvious
    for cand in (os.path.join(reports, "inventory.json"),
                 os.path.join(session, "inventory.json"),
                 os.path.join(session, "raw", "inventory.json"),
                 os.path.join(session, "inputs", "inventory.json")):
        if os.path.isfile(cand):
            found["inventory"] = cand
            break
    # Scan input under inputs/ — all formats accepted by nmap-parse.py.
    inputs = os.path.join(session, "inputs")
    if os.path.isdir(inputs):
        scans = [os.path.join(inputs, f) for f in sorted(os.listdir(inputs))
                 if f.lower().endswith((".xml", ".gnmap", ".nmap"))]
        if scans:
            found["nmap"] = scans[0]
    # raw tree: a dir with <service>/<ip[_port]>/ leaves.
    def _looks_like_raw(cand: str) -> bool:
        if not os.path.isdir(cand):
            return False
        for svc in os.listdir(cand):
            sdir = os.path.join(cand, svc)
            if not os.path.isdir(sdir) or svc.startswith("_"):
                continue
            for leaf in os.listdir(sdir):
                if not os.path.isdir(os.path.join(sdir, leaf)):
                    continue
                base = leaf.rsplit("_", 1)[0] if _RAW_LEAF_RE.match(leaf) else leaf
                if _is_ip(base):
                    return True
        return False

    for cand in (os.path.join(session, "raw"), session):
        if _looks_like_raw(cand):
            found["raw"] = cand
            break
    return found


# ------------------------------------------------------------------ core ingest

def ingest(findings_path: str, out_dir: str, recce, *,
           nmap_path: str | None = None, inventory_path: str | None = None,
           raw_dir: str | None = None, label: str | None = None,
           no_autodiscover: bool = False, quiet: bool = False) -> str:
    """Translate aranum output into a recce engagement dir. Returns the xlsx path."""
    from recce.models import Host, Port, Vuln  # noqa: F401
    from recce.store import Store
    from recce.targets import _subnet_of
    from recce import cli as recce_cli

    svc_ports = _load_service_ports()

    with open(findings_path) as fh:
        doc = json.load(fh)
    findings = doc.get("findings", [])
    title = label or doc.get("label") or "aranum import"

    # Auto-discover companion scan/inventory/raw unless the operator was explicit.
    if not no_autodiscover:
        disc = _autodiscover(findings_path)
        nmap_path = nmap_path or disc["nmap"]
        inventory_path = inventory_path or disc["inventory"]
        raw_dir = raw_dir or disc["raw"]

    hosts: dict[str, Any] = {}

    def _host(ip: str):
        h = hosts.get(ip)
        if h is None:
            h = Host(ip=ip, subnet=_subnet_of(ip), enumerated=False)
            hosts[ip] = h
        return h

    def _ensure_port(h, portid: int, protocol: str, service: str = "",
                     product: str = "", version: str = "", extrainfo: str = "",
                     vuln_scanned: bool = False):
        for p in h.ports:
            if p.portid == portid and p.protocol == protocol:
                p.service = service or p.service
                p.product = product or p.product
                p.version = version or p.version
                p.extrainfo = extrainfo or p.extrainfo
                p.vuln_scanned = p.vuln_scanned or vuln_scanned
                return p
        p = Port(portid=portid, protocol=protocol, state="open", service=service,
                 product=product, version=version, extrainfo=extrainfo,
                 vuln_scanned=vuln_scanned)
        h.ports.append(p)
        return p

    # 1) Native nmap parse (richest: OS + per-port product/version + scripts).
    src_counts = {"nmap": 0, "inventory": 0, "raw": 0, "findings": 0}
    inventory_records: list[dict] = []
    if nmap_path:
        if str(nmap_path).lower().endswith(".xml"):
            from recce import parser as np
            for h in np.parse_nmap_xml(nmap_path):
                h.subnet = _subnet_of(h.ip)
                h.enumerated = False
                for p in h.ports:
                    p.vuln_scanned = False
                    inventory_records.append({"ip": h.ip, "port": p.portid,
                                              "protocol": p.protocol,
                                              "service": p.service,
                                              "categories": []})
                hosts[h.ip] = h
                src_counts["nmap"] += len(h.ports)
        else:
            for e in _ports_from_scan(nmap_path):
                inventory_records.append(e)
                _ensure_port(_host(e["ip"]), e["port"], e["protocol"], e["service"],
                             e.get("product", ""), e.get("version", ""), e.get("extrainfo", ""))
                src_counts["nmap"] += 1

    # 2) aranum nmap-parse --json inventory — every discovered (ip,port,service).
    if inventory_path:
        for e in _ports_from_inventory(inventory_path):
            inventory_records.append(e)
            _ensure_port(_host(e["ip"]), e["port"], e["protocol"], e["service"],
                         e["product"], e["version"], e["extrainfo"])
            src_counts["inventory"] += 1

    # 3) raw output tree — services that dispatched but produced no JSON port.
    if raw_dir:
        for e in _ports_from_raw_tree(raw_dir, svc_ports, inventory_records):
            if not e["protocol"]:
                # Ambiguous/unknown raw paths are evidence containers, not proof
                # of TCP. Inventory or task state must provide the transport.
                continue
            _ensure_port(_host(e["ip"]), e["port"], e["protocol"], e["service"])
            src_counts["raw"] += 1

    # 4) Fold every aranum finding in as a recce Vuln on the right host/port,
    #    creating the port (via SERVICE_MAP for portless findings) if new.
    authoritative_incomplete = _authoritative_incomplete_coverage(doc)
    skipped = 0
    seen: set[str] = set()
    n_vulns = 0
    for f in findings:
        ip = _resolve_ip(f)
        if not ip:
            skipped += 1
            continue
        h = _host(ip)
        service = (f.get("service") or "").strip()
        port, protocol = _resolve_finding_endpoint(f, inventory_records)
        if port is not None:
            if not protocol:
                skipped += 1
                continue
            finding_endpoint = (ip, port, protocol)
            _ensure_port(h, port, protocol, service,
                         vuln_scanned=finding_endpoint not in authoritative_incomplete)
            src_counts["findings"] += 1

        line = f.get("line") or ""
        cves = sorted({m.upper() for m in _CVE_RE.findall(line)})
        extras = []
        if f.get("evidence_path"):
            extras.append(f"evidence: {f['evidence_path']}")
        if f.get("priority"):
            extras.append(f"priority: {f['priority']}")
        na = f.get("next_actions") or []
        if na:
            extras.append("next: " + "; ".join(na))
        output = line + ("\n" + "\n".join(extras) if extras else "")

        v = Vuln(
            ip=ip, port=port, protocol=protocol if port is not None else "",
            script_id=f"aranum:{service or 'network'}", state="",
            title=(f.get("title") or line or f"aranum:{service}")[:200],
            output=output, severity=_severity(f), ids=cves, cwes=[],
            source="aranum", remediation="",
            confidence=(f.get("confidence") or ""),
        )
        if v.key in seen:
            continue
        seen.add(v.key)
        h.vulns.append(v)
        n_vulns += 1

    if not hosts:
        sys.exit("error: no hosts/ports resolved from any source. Nothing to "
                 "ingest. Point --nmap/--inventory at the scan, or check the "
                 "findings.json.")

    # Completion comes only from target-specific execution state. Discovery,
    # skipped tasks, failures, and raw directories do not prove enumeration.
    for host_name, portid, protocol in _successful_coverage(doc):
        host = hosts.get(host_name)
        if host is None:
            continue
        for p in host.ports:
            if p.portid == portid and p.protocol == protocol:
                p.vuln_scanned = True
    # A queue-derived failed/skipped state wins even if stale evidence or an
    # older success record exists for this endpoint.
    for host_name, portid, protocol in authoritative_incomplete:
        host = hosts.get(host_name)
        if host is None:
            continue
        for p in host.ports:
            if p.portid == portid and p.protocol == protocol:
                p.vuln_scanned = False
    for h in hosts.values():
        h.enumerated = bool(h.ports) and all(bool(p.vuln_scanned) for p in h.ports)

    # 5) Write into the recce datastore + regenerate its spreadsheets.
    paths = recce_cli._open_paths(out_dir)
    store = Store(paths["db"])
    try:
        store.set_meta("engagement", title)
        for subnet in {h.subnet for h in hosts.values() if h.subnet}:
            store.set_scope(subnet, _subnet_size(subnet))
        for h in hosts.values():
            store.upsert_host(h)
        recce_cli._generate_reports(store, paths, title, quiet=quiet)
    finally:
        store.close()

    if not quiet:
        total_ports = sum(len(h.ports) for h in hosts.values())
        srcs = ", ".join(f"{k}={v}" for k, v in src_counts.items() if v)
        print(f"[+] aranum -> recce: {len(hosts)} host(s), {total_ports} port(s), "
              f"{n_vulns} finding(s) ingested"
              + (f" [{srcs}]" if srcs else "")
              + (f"; {skipped} unattributable finding(s) skipped" if skipped else "")
              + f".\n    datastore: {paths['db']}\n    workbook:  {paths['xlsx']}")
    return paths["xlsx"]


def _resolve_source(source: str) -> str:
    """Accept a findings.json path OR an aranum session/reports dir; return the
    findings.json path."""
    if os.path.isfile(source):
        return source
    if os.path.isdir(source):
        for cand in (os.path.join(source, "findings.json"),
                     os.path.join(source, "reports", "findings.json")):
            if os.path.isfile(cand):
                return cand
    raise SystemExit(f"error: no findings.json found at {source!r} "
                     "(pass a findings.json or an aranum session dir).")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest aranum output (findings + full port inventory) into a "
                    "recce engagement workbook.")
    ap.add_argument("source", help="aranum findings.json, or a session dir "
                                    "(outputs/<session>/) to auto-discover it")
    ap.add_argument("-o", "--output", default="./recce-from-aranum",
                    help="recce engagement dir to create/update "
                         "(default: ./recce-from-aranum)")
    ap.add_argument("--nmap", help="nmap .xml aranum scanned (full port/product/OS)")
    ap.add_argument("--inventory", help="aranum `nmap-parse --json` inventory.json "
                                        "(every discovered open port)")
    ap.add_argument("--raw-dir", help="aranum raw output tree (<service>/<ip>_<port>/)")
    ap.add_argument("--no-autodiscover", action="store_true",
                    help="don't auto-locate companion scan/inventory/raw next to "
                         "findings.json")
    ap.add_argument("--label", help="engagement title (default: findings.json label)")
    ap.add_argument("--recce-path", help="dir containing the recce/ package, if "
                                         "recce is not already importable")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    findings = _resolve_source(args.source)
    for opt in ("nmap", "inventory", "raw_dir"):
        val = getattr(args, opt)
        if val and not os.path.exists(val):
            ap.error(f"--{opt.replace('_', '-')} not found: {val}")

    recce = _load_recce(args.recce_path)
    ingest(findings, args.output, recce, nmap_path=args.nmap,
           inventory_path=args.inventory, raw_dir=args.raw_dir, label=args.label,
           no_autodiscover=args.no_autodiscover, quiet=args.quiet)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
