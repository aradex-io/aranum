#!/usr/bin/env python3
"""report-dashboard.py — multi-page HTML dashboard for aratool runs.

Reads the $OUTDIR produced by `auto-enum.sh` (or a bulk-enum tree from
`bulk-enum-linux.sh`/`bulk-enum-windows.py`) and emits a static HTML site
that operators can open in any browser. No server, no CDN, no build step.

Pages:
    index.html              dashboard overview (severity tiles, top hosts/svcs)
    hosts.html              all hosts table (sortable + searchable)
    host_<safe-ip>.html     per-host findings + service inventory
    services.html           all services table
    service_<svc>.html      per-service findings + host list
    severity.html           severity landing
    severity_<sev>.html     filtered findings (critical/high/medium/low/info)
    timeline.html           chronological from run.log
    coverage.html           dispatch matrix
    data.json               client-side search payload
    assets/dashboard.css    styles
    assets/dashboard.js     filter/sort/search/theme-toggle

Stdlib only. Uses `report.py`'s `walk_findings` + severity rules as the data
layer — no duplication of classification logic.

Usage:
    python3 aranumtoolkit/network/report-dashboard.py --output dashboard/ <OUTDIR>
    python3 aranumtoolkit/network/report-dashboard.py --output dashboard/ --bulk <BULK-OUTDIR>
"""
from __future__ import annotations
import argparse
import html as _html
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# Reuse report.py — single source of truth for severity rules + walkers.
_THIS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_THIS_DIR))
import report as rpt  # noqa: E402

# --------------------------------------------------------------- constants
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

NAV_ITEMS = [
    ("Dashboard", "index.html"),
    ("Inbox",     "inbox.html"),
    ("Guidance",  "guidance.html"),
    ("Hosts",     "hosts.html"),
    ("Inventory", "inventory.html"),
    ("Services",  "services.html"),
    ("Severity",  "severity.html"),
    ("Timeline",  "timeline.html"),
    ("Coverage",  "coverage.html"),
]

# Default ports for services where the dispatcher doesn't encode the port in
# its filenames AND the finding text doesn't always carry a port. Best-effort —
# operators interpret missing port as "default for that service".
DEFAULT_PORTS: dict[str, list[int]] = {
    "smb":         [445, 139],
    "ldap":        [389, 636],
    "kerberos":    [88],
    "winrm":       [5985, 5986],
    "rdp":         [3389],
    "ssh":         [22],
    "ftp":         [21],
    "snmp":        [161],
    "nfs":         [2049],
    "dns":         [53],
    "mssql":       [1433],
    "mysql":       [3306],
    "postgres":    [5432],
    "mongo":       [27017],
    "redis":       [6379],
    "vnc":         [5900],
    "rabbitmq":    [15672, 5672],
    "memcached":   [11211],
    "couchdb":     [5984],
    "etcd":        [2379, 2380],
    "docker":      [2375, 2376],
    "kubernetes":  [6443, 8080, 10250],
    "ipmi":        [623],
    "elastic":     [9200, 5601],
    "jmx":         [1099, 9999],
    "ajp":         [8009],
    "oracle":      [1521],
    "pop3":        [110, 995],
    "imap":        [143, 993],
    "telnet":      [23],
    "rsync":       [873],
    "mqtt":        [1883, 8883],
    "sip":         [5060],
    "ipp":         [631],
    "zookeeper":   [2181],
    "cassandra":   [9042],
    "kafka":       [9092],
    "neo4j":       [7474, 7687],
    "influxdb":    [8086],
    "solr":        [8983],
    "consul":      [8500],
    "vault":       [8200],
    "msrpc":       [135],
    "netbios-ns":  [137],
    "ike":         [500],
    "slp":         [427],
    "radius":      [1812, 1813],
    "print":       [9100, 515],
    "flexnet":     [27000],
    "hpc":         [6817, 9618, 8088],
    "monitoring":  [10050, 5666, 8089],
    "backup":      [9392, 1556],
    "jabber":      [5222, 5269],
    "http":        [80, 443, 8080, 8443],
}

# Regex for finding ports inside artifact filenames like:
#   seal_https_8200.txt     → 8200
#   jetdirect_9100_banner.bin → 9100
#   yarn_8088_info.json     → 8088
_PORT_IN_FILENAME = re.compile(r"_(\d{2,5})(?:_|\.)")

# Regex for finding ports inside arbitrary finding text:
#   - "http://10.0.0.5:8090/something"
#   - "https://[::1]:8200"
#   - "Vault reachable (https): 10.0.0.50:8200 — ..."
#   - bare "10.0.0.5:445"
_PORT_IN_TEXT = re.compile(
    r"(?:"
    r"://(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})"  # url://host:port
    r"|"
    r"(?<![0-9])(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b"      # ipv4:port
    r")"
)
# Regex for extracting an IPv4 from arbitrary text (re-attribution of
# `(dispatcher)`-bucketed findings to real hosts).
_IPV4_IN_TEXT = re.compile(r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3})(?![0-9.])")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Scheme → default port mapping. Used when a finding line carries a URL
# without an explicit port (e.g., `https://10.0.0.30/` → port 443).
_SCHEME_DEFAULTS: list[tuple[str, int]] = [
    ("https://",  443),
    ("http://",   80),
    ("ssh://",    22),
    ("ftp://",    21),
    ("rsync://",  873),
    ("ldap://",   389),
    ("ldaps://",  636),
]


def find_best_port(line: str, candidate_ports: set[int]) -> int | None:
    """Resolve a finding line to the most likely port among candidates.

    Resolution order:
      1. Explicit ports in line text (regex match).
      2. Scheme default from URL prefix (e.g., https:// → 443).
      3. Single candidate (no ambiguity).
      4. None → attribute to all candidates (caller's choice).
    """
    explicit: set[int] = set()
    for m in _PORT_IN_TEXT.finditer(line):
        p = int(m.group(1) or m.group(2) or 0)
        if 1 <= p <= 65535 and p in candidate_ports:
            explicit.add(p)
    if explicit:
        return min(explicit)
    line_l = line.lower()
    for sch, dport in _SCHEME_DEFAULTS:
        if sch in line_l and dport in candidate_ports:
            return dport
    if len(candidate_ports) == 1:
        return next(iter(candidate_ports))
    return None

# --------------------------------------------------------------- helpers
def e(s) -> str:
    """HTML-escape, accepting any type."""
    return _html.escape(str(s) if s is not None else "", quote=True)


def safe_name(s: str) -> str:
    """Map an arbitrary string (IP, hostname, service name) to a filesystem-safe
    filename component. Replaces `:`, `/`, `\\`, spaces, brackets."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(s)).strip("-") or "unknown"


def fmt_time(ts: str | None) -> str:
    if not ts:
        return ""
    return e(ts)


def severity_chip(sev: str) -> str:
    if not sev or sev == "none":
        return '<span class="muted">—</span>'
    return (
        f'<span class="chip chip-{e(sev)}" '
        f'data-severity="{e(sev)}">{e(sev.upper())}</span>'
    )


def truncate(s: str, n: int = 240) -> str:
    s = s.strip()
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def max_severity(findings: list[dict]) -> str:
    """Return the highest-severity string in a finding list, or 'none' if empty.
    The sentinel 'none' is rendered as a muted em-dash by severity_chip()."""
    if not findings:
        return "none"
    return min((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 99))


def finding_priority(f: dict) -> int:
    """Return operator priority for a finding, deriving a stable fallback for
    legacy report.py findings that predate structured priority fields."""
    if isinstance(f.get("priority"), int):
        return f["priority"]
    if isinstance(f.get("priority"), str):
        pri = f["priority"].upper().strip()
        if pri in {"P0", "P1", "P2", "P3"}:
            return {"P0": 950, "P1": 800, "P2": 600, "P3": 350}[pri]
        if pri.isdigit():
            return int(pri)
    sev_base = {"critical": 900, "high": 750, "medium": 550, "low": 300, "info": 100}
    service_bonus = {
        "smb": 60, "ldap": 60, "kerberos": 60, "winrm": 50, "mssql": 45,
        "docker": 80, "kubernetes": 80, "etcd": 80, "vault": 70,
        "backup": 70, "ipmi": 60, "http": 20, "https": 20,
    }
    return min(999, sev_base.get(f.get("severity", "info"), 100) + service_bonus.get(f.get("service", ""), 0))


def finding_title(f: dict) -> str:
    if f.get("title"):
        return str(f["title"])
    line = _ANSI_RE.sub("", str(f.get("line", ""))).strip()
    return truncate(line, 110) or "Finding"


def finding_confidence(f: dict) -> str:
    return str(f.get("confidence") or "medium")


def finding_status(f: dict) -> str:
    return str(f.get("triage_status") or "new")


def finding_next_action(f: dict) -> str:
    actions = f.get("next_actions")
    if isinstance(actions, list) and actions:
        return str(actions[0])
    return "Review evidence and validate impact"


def build_inbox(findings: list[dict]) -> list[dict]:
    rank = {"new": 0, "needs-validation": 1, "accepted": 2, "suppressed": 3}
    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    rows = []
    for f in findings:
        row = dict(f)
        row["priority"] = finding_priority(f)
        row["title"] = finding_title(f)
        row["confidence"] = finding_confidence(f)
        row["triage_status"] = finding_status(f)
        row["next_action"] = finding_next_action(f)
        rows.append(row)
    rows.sort(key=lambda r: (
        rank.get(r["triage_status"], 9),
        -int(r["priority"]),
        SEVERITY_RANK.get(r.get("severity", "info"), 99),
        confidence_rank.get(r["confidence"], 9),
        r.get("host", ""),
        r.get("service", ""),
    ))
    return rows


# --------------------------------------------------------------- run-log scrape
_RUNLOG_LINE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+(?P<msg>.*)$")


def read_run_log(out_dir: Path) -> list[dict]:
    """Parse `run.log` lines into ordered events. Lines without timestamps are
    folded into the previous event."""
    rl = out_dir / "run.log"
    if not rl.is_file():
        return []
    events: list[dict] = []
    last: dict | None = None
    for line in rl.read_text(errors="replace").splitlines():
        m = _RUNLOG_LINE.match(line)
        if m:
            last = {"ts": m.group("ts"), "msg": m.group("msg")}
            events.append(last)
        elif last is not None:
            last["msg"] += " " + line.strip()
    return events


def read_guidance(out_dir: Path) -> list[dict]:
    """Load optional planner guidance. The planner writes guidance.json at the
    auto-enum output root; dashboards generated from older runs simply get an
    empty guidance page."""
    gp = out_dir / "guidance.json"
    if not gp.is_file():
        return []
    try:
        obj = json.loads(gp.read_text(errors="replace"))
    except Exception:
        return [{
            "id": "guidance:parse-error",
            "priority": 0,
            "type": "dashboard-warning",
            "title": "guidance.json could not be parsed",
            "reason": f"Invalid JSON in {gp.name}",
            "recommended_next": "Regenerate the planner guidance",
            "evidence": [str(gp)],
        }]
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in ("guidance", "items", "recommendations"):
            if isinstance(obj.get(key), list):
                return obj[key]
    return []


# --------------------------------------------------------------- aggregation
def build_index(out_dir: Path, bulk: bool, rules_path: Path | None) -> dict:
    """Produce the in-memory model that every renderer reads from."""
    rules = rpt._load_rules(rules_path)
    if bulk:
        findings = list(rpt.walk_findings_bulk(out_dir, rules))
    else:
        findings = list(rpt.walk_findings(out_dir, rules))

    # ----- re-attribute (dispatcher)-bucketed findings to real hosts -----
    # `report.walk_findings` assigns `host="(dispatcher)"` to lines scraped
    # from `$OUTDIR/<svc>/_dispatcher.log`. The lines themselves frequently
    # name a host (e.g. "UNAUTH: Jenkins API exposed: http://10.0.0.20:8080").
    # Promote those to the actual host so the per-host page sees them.
    # Collect the known-host set from per-host directories.
    known_hosts: set[str] = set()
    if not bulk:
        for svc_dir in out_dir.iterdir():
            if (
                not svc_dir.is_dir()
                or svc_dir.name.startswith("_")
                or rpt._is_generated_dashboard_dir(svc_dir)
            ):
                continue
            for host_dir in svc_dir.iterdir():
                if host_dir.is_dir():
                    name = host_dir.name
                    if "_" in name and name.rsplit("_", 1)[-1].isdigit():
                        known_hosts.add(name.rsplit("_", 1)[0])
                    else:
                        known_hosts.add(name)
        # Also accept hosts that appear in _targets_*.txt files
        for tf in out_dir.glob("_targets_*.txt"):
            try:
                for line in tf.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    if line.startswith("["):
                        ip = line.split("]:", 1)[0].lstrip("[")
                    else:
                        ip = line.rsplit(":", 1)[0]
                    known_hosts.add(ip)
            except Exception:
                pass

    for f in findings:
        if f["host"] != "(dispatcher)":
            continue
        m = _IPV4_IN_TEXT.search(f["line"])
        if m and m.group(1) in known_hosts:
            f["host"] = m.group(1)
        # If text contains a v6 in brackets we could also match, but our
        # fixtures are v4-only and v6 in finding text is rare in practice.

    summary = rpt._summary(findings)

    # Group findings by host + service for cheap lookup
    by_host: dict[str, list[dict]] = defaultdict(list)
    by_service: dict[str, list[dict]] = defaultdict(list)
    by_severity: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_host[f["host"]].append(f)
        by_service[f["service"]].append(f)
        by_severity[f["severity"]].append(f)

    # Service inventory per host — every dir under $OUT/<svc>/<ip>/ that exists
    services_per_host: dict[str, set[str]] = defaultdict(set)
    hosts_per_service: dict[str, set[str]] = defaultdict(set)
    if not bulk:
        for svc_dir in sorted(
            p for p in out_dir.iterdir()
            if p.is_dir() and not rpt._is_generated_dashboard_dir(p)
        ):
            for host_dir in sorted(p for p in svc_dir.iterdir() if p.is_dir()):
                name = host_dir.name
                ip = name.rsplit("_", 1)[0] if "_" in name and name.rsplit("_", 1)[-1].isdigit() else name
                services_per_host[ip].add(svc_dir.name)
                hosts_per_service[svc_dir.name].add(ip)
    else:
        # Bulk-enum: every top-level dir is a host
        for host_dir in sorted(p for p in out_dir.iterdir() if p.is_dir()):
            for fname, svc in (("linenum.txt", "linenum"), ("winenum.txt", "winenum")):
                if (host_dir / fname).is_file():
                    services_per_host[host_dir.name].add(svc)
                    hosts_per_service[svc].add(host_dir.name)

    events = read_run_log(out_dir)
    per_host_verdicts = rpt._per_host_verdicts(findings) if bulk else {}

    # ----- port discovery (three sources, unioned) -----
    # Map (host, service) -> set[int] of ports observed.
    ports_per_host_svc: dict[tuple[str, str], set[int]] = defaultdict(set)

    if not bulk:
        # Source 1 — authoritative: $OUTDIR/_targets_<svc>.txt lines are
        # exactly what auto-enum dispatched.
        for tf in out_dir.glob("_targets_*.txt"):
            svc = tf.name[len("_targets_"): -len(".txt")]
            try:
                for line in tf.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue
                    if line.startswith("["):
                        # [v6]:port
                        ip, _, port = line.rpartition("]:")
                        ip = ip.lstrip("[")
                    else:
                        ip, _, port = line.rpartition(":")
                    if port.isdigit():
                        ports_per_host_svc[(ip, svc)].add(int(port))
            except Exception:
                pass

        # Source 2 — filenames under $OUTDIR/<svc>/<ip>/*.
        for svc_dir in out_dir.iterdir():
            if (
                not svc_dir.is_dir()
                or svc_dir.name.startswith("_")
                or rpt._is_generated_dashboard_dir(svc_dir)
            ):
                continue
            for host_dir in svc_dir.iterdir():
                if not host_dir.is_dir():
                    continue
                ip = host_dir.name.rsplit("_", 1)[0] if "_" in host_dir.name and host_dir.name.rsplit("_", 1)[-1].isdigit() else host_dir.name
                # If the dir name already encodes <ip>_<port>, capture it
                if "_" in host_dir.name and host_dir.name.rsplit("_", 1)[-1].isdigit():
                    ports_per_host_svc[(ip, svc_dir.name)].add(int(host_dir.name.rsplit("_", 1)[-1]))
                for fp in host_dir.rglob("*"):
                    if not fp.is_file():
                        continue
                    for m in _PORT_IN_FILENAME.finditer(fp.name):
                        p = int(m.group(1))
                        if 1 <= p <= 65535:
                            ports_per_host_svc[(ip, svc_dir.name)].add(p)

    # Source 3 — finding-line text.
    for f in findings:
        for m in _PORT_IN_TEXT.finditer(f["line"]):
            p = int(m.group(1) or m.group(2) or 0)
            if 1 <= p <= 65535 and f["host"] != "(dispatcher)":
                ports_per_host_svc[(f["host"], f["service"])].add(p)

    # Last-resort defaults: if a (host, service) ended up with no port at
    # all but we know it was probed (has artifacts or findings), inject the
    # service's default port(s) so the inventory row isn't blank.
    seen_pairs = set()
    for h in services_per_host:
        for s in services_per_host[h]:
            seen_pairs.add((h, s))
    for f in findings:
        if f["host"] != "(dispatcher)":
            seen_pairs.add((f["host"], f["service"]))
    for (h, s) in seen_pairs:
        if not ports_per_host_svc.get((h, s)):
            for p in DEFAULT_PORTS.get(s, []):
                ports_per_host_svc[(h, s)].add(p)

    # ----- inventory records (host, port, service) flat list -----
    # Each record bundles findings, evidence files, and severity rollup.
    inventory: list[dict] = []
    for (host, svc), ports in ports_per_host_svc.items():
        host_svc_findings = [f for f in by_host.get(host, []) if f["service"] == svc]
        evidence_files: list[str] = []
        if not bulk:
            host_dir = out_dir / svc / host
            if host_dir.is_dir():
                evidence_files = sorted(
                    str(fp.relative_to(out_dir))
                    for fp in host_dir.rglob("*")
                    if fp.is_file()
                )
        # Pre-assign each finding to its best port (explicit > scheme > single
        # candidate). Findings that can't be pinned to a single port are
        # attributed to ALL candidate ports — better to over-report than to
        # drop visibility.
        findings_per_port: dict[int, list[dict]] = defaultdict(list)
        for f in host_svc_findings:
            best = find_best_port(f["line"], ports)
            if best is not None:
                findings_per_port[best].append(f)
            else:
                for p in ports:
                    findings_per_port[p].append(f)
        for port in sorted(ports):
            row_findings = findings_per_port.get(port, [])
            inventory.append({
                "host": host,
                "port": port,
                "service": svc,
                "n_findings": len(row_findings),
                "max_severity": max_severity(row_findings),
                "findings": row_findings,
                "evidence_files": evidence_files,
                "state": "findings" if row_findings else "probed",
            })

    # Sort inventory: host, then port number
    def _ip_key(ip: str):
        try:
            return tuple(int(x) for x in ip.split("."))
        except Exception:
            return (999, 999, 999, 999, ip)
    inventory.sort(key=lambda r: (_ip_key(r["host"]), r["port"], r["service"]))

    # Build a per-host inventory index for fast per-host page rendering
    inventory_by_host: dict[str, list[dict]] = defaultdict(list)
    for row in inventory:
        inventory_by_host[row["host"]].append(row)

    return {
        "out_dir": str(out_dir),
        "bulk": bulk,
        "findings": findings,
        "summary": summary,
        "by_host": dict(by_host),
        "by_service": dict(by_service),
        "by_severity": dict(by_severity),
        "services_per_host": {h: sorted(v) for h, v in services_per_host.items()},
        "hosts_per_service": {s: sorted(v) for s, v in hosts_per_service.items()},
        "events": events,
        "per_host_verdicts": per_host_verdicts,
        "inventory": inventory,
        "inventory_by_host": dict(inventory_by_host),
        "inbox": build_inbox(findings),
        "guidance": read_guidance(out_dir),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# --------------------------------------------------------------- page chrome
def render_navbar(active: str) -> str:
    items = []
    for label, href in NAV_ITEMS:
        cls = "nav-link active" if label.lower() == active.lower() else "nav-link"
        items.append(f'<a class="{cls}" href="{href}">{e(label)}</a>')
    return f"""
<header class="topnav">
  <div class="brand">
    <span class="brand-mark">▣</span>
    <span class="brand-text">aratool</span>
    <span class="brand-sub">engagement dashboard</span>
  </div>
  <nav class="navlinks">{''.join(items)}</nav>
  <div class="navtools">
    <input class="search" id="globalsearch" placeholder="search…" type="search" />
    <button class="iconbtn" id="themetoggle" aria-label="Toggle theme">◐</button>
  </div>
</header>
"""


def render_page(title: str, body: str, active: str, breadcrumbs: list[tuple[str, str]] | None = None) -> str:
    crumb_html = ""
    if breadcrumbs:
        parts = []
        for label, href in breadcrumbs:
            if href:
                parts.append(f'<a href="{href}">{e(label)}</a>')
            else:
                parts.append(f'<span>{e(label)}</span>')
        crumb_html = f'<div class="breadcrumbs">{" / ".join(parts)}</div>'
    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{e(title)} — aratool</title>
<link rel="stylesheet" href="assets/dashboard.css" />
</head>
<body>
{render_navbar(active)}
<main class="container">
{crumb_html}
<h1 class="pagetitle">{e(title)}</h1>
{body}
</main>
<footer class="footer">
  <span>aratool report-dashboard · generated by <code>aranumtoolkit/network/report-dashboard.py</code></span>
</footer>
<script src="assets/dashboard.js"></script>
</body>
</html>
"""


def render_page_subdir(title: str, body: str, active: str, breadcrumbs=None) -> str:
    """Same as render_page but for pages one directory deep (assets path
    needs `../assets/…`). Currently unused — all pages live at the root —
    but kept for future expansion."""
    html_str = render_page(title, body, active, breadcrumbs)
    return html_str.replace('href="assets/', 'href="../assets/').replace('src="assets/', 'src="../assets/').replace('href="index.html"', 'href="../index.html"').replace('href="hosts.html"', 'href="../hosts.html"').replace('href="services.html"', 'href="../services.html"').replace('href="severity.html"', 'href="../severity.html"').replace('href="timeline.html"', 'href="../timeline.html"').replace('href="coverage.html"', 'href="../coverage.html"')


# --------------------------------------------------------------- index page
def render_index(model: dict) -> str:
    summary = model["summary"]
    counts = summary["counts"]
    findings = model["findings"]
    by_host = model["by_host"]
    by_service = model["by_service"]
    services_per_host = model["services_per_host"]

    # Severity tiles
    tiles = []
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        tiles.append(f"""
        <a class="tile tile-{e(sev)}" href="severity_{e(sev)}.html">
          <div class="tile-count">{n}</div>
          <div class="tile-label">{e(sev.upper())}</div>
        </a>""")

    # Top hosts — by max severity rank, then count
    host_rows = []
    hosts_sorted = sorted(
        by_host.items(),
        key=lambda kv: (SEVERITY_RANK.get(max_severity(kv[1]), 99), -len(kv[1])),
    )
    for host, fs in hosts_sorted[:10]:
        ms = max_severity(fs)
        n = len(fs)
        svcs = ", ".join(services_per_host.get(host, [])[:6])
        if len(services_per_host.get(host, [])) > 6:
            svcs += f', <span class="muted">+{len(services_per_host[host]) - 6}</span>'
        host_rows.append(f"""
        <tr>
          <td><a href="host_{e(safe_name(host))}.html">{e(host)}</a></td>
          <td>{severity_chip(ms)}</td>
          <td class="num">{n}</td>
          <td>{svcs or '<span class="muted">—</span>'}</td>
        </tr>""")

    # Top services — by finding count
    svc_rows = []
    services_sorted = sorted(by_service.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for svc, fs in services_sorted[:10]:
        ms = max_severity(fs)
        n = len(fs)
        hosts_count = len(model["hosts_per_service"].get(svc, []))
        svc_rows.append(f"""
        <tr>
          <td><a href="service_{e(safe_name(svc))}.html">{e(svc)}</a></td>
          <td>{severity_chip(ms)}</td>
          <td class="num">{n}</td>
          <td class="num">{hosts_count}</td>
        </tr>""")

    # Recent findings (last 8)
    recent_rows = []
    for f in findings[-8:][::-1]:
        recent_rows.append(f"""
        <tr>
          <td>{severity_chip(f['severity'])}</td>
          <td><code class="mono">{e(truncate(f['line'], 120))}</code></td>
          <td><a href="host_{e(safe_name(f['host']))}.html">{e(f['host'])}</a></td>
          <td>{e(f['service'])}</td>
        </tr>""")

    # Hosts count for the hero = total hosts touched (any service dir) so the
    # number matches the hosts.html row count, not just hosts with findings.
    n_hosts_with_findings = len(summary['hosts'])
    n_hosts_total = len(set(list(model["by_host"].keys()) + list(model["services_per_host"].keys())))
    n_services = len(set(list(model["by_service"].keys()) + list(model["hosts_per_service"].keys())))
    n_findings = len(findings)
    n_events = len(model['events'])
    n_ports = len(model["inventory"])
    n_ports_with_findings = sum(1 for r in model["inventory"] if r["state"] == "findings")

    # Noisiest ports widget — top N (host, port, service) by finding count
    noisy_rows = []
    for r in sorted(model["inventory"], key=lambda x: -x["n_findings"])[:8]:
        if r["n_findings"] == 0:
            continue
        noisy_rows.append(f"""
        <tr>
          <td><a href="host_{e(safe_name(r['host']))}.html">{e(r['host'])}</a></td>
          <td class="num">{r['port']}</td>
          <td><a href="service_{e(safe_name(r['service']))}.html">{e(r['service'])}</a></td>
          <td>{severity_chip(r['max_severity'])}</td>
          <td class="num">{r['n_findings']}</td>
        </tr>""")
    body = f"""
<section class="hero">
  <p class="hero-sub">
    <strong>{n_findings}</strong> finding{'s' if n_findings != 1 else ''} ·
    <strong>{n_hosts_total}</strong> host{'s' if n_hosts_total != 1 else ''}
    ({n_hosts_with_findings} with findings) ·
    <strong>{n_ports}</strong> port{'s' if n_ports != 1 else ''} probed
    ({n_ports_with_findings} with findings) ·
    <strong>{n_services}</strong> service{'s' if n_services != 1 else ''}.
    Source: <code class="mono">{e(model['out_dir'])}</code>.
    Generated {e(model['generated_at'])}.
  </p>
  <p class="hero-cta"><a href="inventory.html">→ open the inventory (master port table)</a></p>
</section>

<section class="tiles">
{''.join(tiles)}
</section>

<section class="grid2">
  <div class="card">
    <h2 class="card-title">Top hosts</h2>
    <p class="card-sub">By max severity, then finding count.</p>
    <table class="data">
      <thead><tr><th>Host</th><th>Max sev</th><th class="num">Findings</th><th>Services</th></tr></thead>
      <tbody>{''.join(host_rows) if host_rows else '<tr><td colspan="4" class="muted">no hosts with findings</td></tr>'}</tbody>
    </table>
    <p class="card-foot"><a href="hosts.html">→ all hosts</a></p>
  </div>

  <div class="card">
    <h2 class="card-title">Top services</h2>
    <p class="card-sub">By finding count.</p>
    <table class="data">
      <thead><tr><th>Service</th><th>Max sev</th><th class="num">Findings</th><th class="num">Hosts</th></tr></thead>
      <tbody>{''.join(svc_rows) if svc_rows else '<tr><td colspan="4" class="muted">no services</td></tr>'}</tbody>
    </table>
    <p class="card-foot"><a href="services.html">→ all services</a></p>
  </div>
</section>

<section class="grid2">
  <div class="card">
    <h2 class="card-title">Noisiest ports</h2>
    <p class="card-sub">Top (host, port, service) by finding count. <a href="inventory.html">→ full inventory</a>.</p>
    <table class="data">
      <thead><tr><th>Host</th><th class="num">Port</th><th>Service</th><th>Max sev</th><th class="num">Findings</th></tr></thead>
      <tbody>{''.join(noisy_rows) if noisy_rows else '<tr><td colspan="5" class="muted">no ports with findings</td></tr>'}</tbody>
    </table>
  </div>

  <div class="card">
    <h2 class="card-title">Recent findings</h2>
    <p class="card-sub">Most-recent {min(8, len(findings))} of {len(findings)}.</p>
    <table class="data">
      <thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Service</th></tr></thead>
      <tbody>{''.join(recent_rows) if recent_rows else '<tr><td colspan="4" class="muted">no findings</td></tr>'}</tbody>
    </table>
  </div>
</section>

<section class="card">
  <h2 class="card-title">Run summary</h2>
  <table class="data data-kv">
    <tbody>
      <tr><td>Output directory</td><td><code class="mono">{e(model['out_dir'])}</code></td></tr>
      <tr><td>Hosts probed</td><td class="num">{n_hosts_total}</td></tr>
      <tr><td>Hosts with findings</td><td class="num">{n_hosts_with_findings}</td></tr>
      <tr><td>Open ports indexed</td><td class="num">{n_ports}</td></tr>
      <tr><td>Ports with findings</td><td class="num">{n_ports_with_findings}</td></tr>
      <tr><td>Services exercised</td><td class="num">{n_services}</td></tr>
      <tr><td>Findings emitted</td><td class="num">{n_findings}</td></tr>
      <tr><td>Run-log events</td><td class="num">{n_events}</td></tr>
      <tr><td>Mode</td><td>{'bulk-enum' if model['bulk'] else 'auto-enum'}</td></tr>
      <tr><td>Generated</td><td>{e(model['generated_at'])}</td></tr>
    </tbody>
  </table>
</section>
"""
    return render_page("Dashboard", body, "Dashboard")


# --------------------------------------------------------------- hosts list
def render_hosts(model: dict) -> str:
    rows = []
    by_host = model["by_host"]
    services_per_host = model["services_per_host"]
    all_hosts = sorted(set(list(by_host.keys()) + list(services_per_host.keys())))
    for host in all_hosts:
        fs = by_host.get(host, [])
        ms = max_severity(fs)
        sev_counts = Counter(f["severity"] for f in fs)
        sev_chips = " ".join(
            f'<span class="chip chip-{e(s)} chip-mini">{n}</span>'
            for s in SEVERITY_ORDER if (n := sev_counts.get(s, 0))
        )
        svcs = services_per_host.get(host, [])
        host_key = safe_name(host)
        n_ports = len(model["inventory_by_host"].get(host, []))
        # Summary row (always visible) + inline detail row (hidden by default;
        # toggled per-row by the chevron OR globally by the toolbar buttons).
        rows.append(f"""
        <tr class="hostrow" data-host="{e(host)}" data-severity="{e(ms)}" data-findings="{len(fs)}" data-detail-id="d-{e(host_key)}">
          <td>
            <button class="expand-btn" type="button" data-toggle="d-{e(host_key)}" aria-label="Toggle detail">▸</button>
            <a href="host_{e(host_key)}.html">{e(host)}</a>
          </td>
          <td>{severity_chip(ms)}</td>
          <td class="num">{len(fs)}</td>
          <td class="num">{n_ports}</td>
          <td>{sev_chips or '<span class="muted">—</span>'}</td>
          <td>{e(', '.join(svcs)) or '<span class="muted">—</span>'}</td>
        </tr>
        <tr class="hostdetail" id="d-{e(host_key)}" hidden>
          <td colspan="6">
            <div class="hostdetail-pane">
              <div class="hostdetail-head">
                <strong>{e(host)}</strong>
                <span class="muted">· {n_ports} port{'s' if n_ports != 1 else ''} · {len(fs)} finding{'s' if len(fs) != 1 else ''}</span>
                <a class="hostdetail-link" href="host_{e(host_key)}.html">open full page →</a>
              </div>
              <table class="data data-inner">
                <thead><tr>
                  <th class="num">Port</th>
                  <th>Service</th>
                  <th>State</th>
                  <th class="num">Findings</th>
                  <th>Detail</th>
                </tr></thead>
                <tbody>{_render_host_port_rows(model, host, details_open=True) or '<tr><td colspan="5" class="muted">no port data</td></tr>'}</tbody>
              </table>
            </div>
          </td>
        </tr>""")
    body = f"""
<div class="card">
  <div class="toolbar">
    <div class="toolbar-info">{len(all_hosts)} host{'s' if len(all_hosts) != 1 else ''} discovered. Click a column header to sort, ▸ on any row to expand inline, or use the toolbar to expand them all.</div>
    <div class="toolbar-actions">
      <button class="btn" type="button" id="expand-all-hosts">Expand all</button>
      <button class="btn" type="button" id="collapse-all-hosts">Collapse all</button>
    </div>
  </div>
  <table class="data sortable filterable hosts-with-detail" id="hosts-table">
    <thead><tr>
      <th data-sort="text">Host</th>
      <th data-sort="severity">Max sev</th>
      <th class="num" data-sort="num">Findings</th>
      <th class="num" data-sort="num">Ports</th>
      <th>Severity breakdown</th>
      <th data-sort="text">Services</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="6" class="muted">no hosts</td></tr>'}</tbody>
  </table>
</div>
"""
    return render_page("Hosts", body, "Hosts")


# --------------------------------------------------------------- per-host
def _render_host_port_rows(model: dict, host: str, details_open: bool = True) -> str:
    """Return the `<tr>` blocks for a host's port × service table.

    Shared between the per-host detail page and the hosts-page inline-expand
    view. `details_open=True` expands the findings panel inside each row by
    default; the evidence-files sublist always stays collapsed (less noise).
    """
    inv_rows = model["inventory_by_host"].get(host, [])
    out: list[str] = []
    open_attr = " open" if details_open else ""
    for r in inv_rows:
        sev = r["max_severity"]
        state_chip = (
            severity_chip(sev) if r["state"] == "findings"
            else '<span class="chip chip-info">PROBED</span>'
        )
        # Findings panel
        if r["findings"]:
            inner = []
            for f in r["findings"]:
                inner.append(f"""
                <tr>
                  <td>{severity_chip(f['severity'])}</td>
                  <td><code class="mono">{e(truncate(f['line'], 320))}</code></td>
                  <td><code class="mono small">{e(f['evidence_path'])}</code></td>
                </tr>""")
            finding_rows_html = f"""
            <table class="data data-inner">
              <thead><tr><th>Sev</th><th>Finding</th><th>Evidence</th></tr></thead>
              <tbody>{''.join(inner)}</tbody>
            </table>
            """
        else:
            finding_rows_html = '<p class="muted">No severity-tagged findings. Dispatcher artifacts (if any) listed below.</p>'
        # Evidence file list (filtered to this service's tree)
        ev_files = [
            ef for ef in r["evidence_files"]
            if f"/{r['service']}/" in ("/" + ef.replace("\\", "/")) or ef.startswith(f"{r['service']}/")
        ]
        ev_html = ""
        if ev_files:
            items = "".join(f'<li><code class="mono small">{e(ef)}</code></li>' for ef in ev_files[:50])
            extra = f'<li class="muted">+{len(ev_files) - 50} more not shown</li>' if len(ev_files) > 50 else ''
            ev_html = f'<details class="evidence-list"><summary>Evidence files ({len(ev_files)})</summary><ul>{items}{extra}</ul></details>'

        summary_label = (
            f"{r['n_findings']} finding{'s' if r['n_findings'] != 1 else ''}"
            if r['n_findings'] else "artifacts only"
        )
        out.append(f"""
        <tr data-port="{r['port']}" data-service="{e(r['service'])}" data-severity="{e(sev)}">
          <td class="num">{r['port']}</td>
          <td><a href="service_{e(safe_name(r['service']))}.html">{e(r['service'])}</a></td>
          <td>{state_chip}</td>
          <td class="num">{r['n_findings']}</td>
          <td>
            <details{open_attr}>
              <summary>{summary_label}</summary>
              <div class="expand-pane">
                {finding_rows_html}
                {ev_html}
              </div>
            </details>
          </td>
        </tr>""")
    return "".join(out)


def render_host_detail(model: dict, host: str) -> str:
    fs = model["by_host"].get(host, [])
    svcs = model["services_per_host"].get(host, [])
    ms = max_severity(fs)
    sev_counts = Counter(f["severity"] for f in fs)
    inv_rows = model["inventory_by_host"].get(host, [])

    # Port × Service table — findings open by default per operator feedback.
    port_rows = _render_host_port_rows(model, host, details_open=True)

    svc_chips = " ".join(
        f'<a class="chip chip-svc" href="service_{e(safe_name(s))}.html">{e(s)}</a>'
        for s in svcs
    )
    sev_summary = " ".join(
        f'<span class="chip chip-{e(s)}">{e(s.upper())}: {n}</span>'
        for s in SEVERITY_ORDER if (n := sev_counts.get(s, 0))
    )

    body = f"""
<section class="hero">
  <p class="hero-sub">
    Highest severity: {severity_chip(ms)}
    · {len(fs)} finding{'s' if len(fs) != 1 else ''}
    · {len(inv_rows)} port{'s' if len(inv_rows) != 1 else ''} across {len(svcs)} service{'s' if len(svcs) != 1 else ''}.
  </p>
  <p>{sev_summary or '<span class="muted">no findings emitted on this host</span>'}</p>
</section>

<section class="card">
  <h2 class="card-title">Port × Service inventory</h2>
  <p class="card-sub">Every probed port on this host. Click a row to expand inline — no extra page load. Sortable by port or finding count.</p>
  <table class="data sortable filterable" id="host-ports-table">
    <thead><tr>
      <th class="num" data-sort="num">Port</th>
      <th data-sort="text">Service</th>
      <th data-sort="severity">State</th>
      <th class="num" data-sort="num">Findings</th>
      <th>Detail</th>
    </tr></thead>
    <tbody>{port_rows if port_rows else '<tr><td colspan="5" class="muted">no port data — was this host actually probed?</td></tr>'}</tbody>
  </table>
</section>

<section class="card">
  <h2 class="card-title">Quick service jump</h2>
  <p>{svc_chips or '<span class="muted">no services routed to this host</span>'}</p>
</section>
"""
    return render_page(
        f"Host · {host}",
        body,
        "Hosts",
        breadcrumbs=[("Hosts", "hosts.html"), (host, "")],
    )


# --------------------------------------------------------------- services list
def render_services(model: dict) -> str:
    rows = []
    by_service = model["by_service"]
    hosts_per_service = model["hosts_per_service"]
    all_services = sorted(set(list(by_service.keys()) + list(hosts_per_service.keys())))
    for svc in all_services:
        fs = by_service.get(svc, [])
        ms = max_severity(fs)
        hosts = hosts_per_service.get(svc, [])
        sev_counts = Counter(f["severity"] for f in fs)
        sev_chips = " ".join(
            f'<span class="chip chip-{e(s)} chip-mini">{n}</span>'
            for s in SEVERITY_ORDER if (n := sev_counts.get(s, 0))
        )
        rows.append(f"""
        <tr data-service="{e(svc)}" data-severity="{e(ms)}" data-findings="{len(fs)}">
          <td><a href="service_{e(safe_name(svc))}.html">{e(svc)}</a></td>
          <td>{severity_chip(ms)}</td>
          <td class="num">{len(fs)}</td>
          <td class="num">{len(hosts)}</td>
          <td>{sev_chips or '<span class="muted">—</span>'}</td>
        </tr>""")
    body = f"""
<div class="card">
  <p class="card-sub">{len(all_services)} service{'s' if len(all_services) != 1 else ''} exercised. Click a column header to sort. Use the global search to filter.</p>
  <table class="data sortable filterable" id="services-table">
    <thead><tr>
      <th data-sort="text">Service</th>
      <th data-sort="severity">Max sev</th>
      <th class="num" data-sort="num">Findings</th>
      <th class="num" data-sort="num">Hosts</th>
      <th>Severity breakdown</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="5" class="muted">no services</td></tr>'}</tbody>
  </table>
</div>
"""
    return render_page("Services", body, "Services")


# --------------------------------------------------------------- per-service
def render_service_detail(model: dict, svc: str) -> str:
    fs = model["by_service"].get(svc, [])
    hosts = model["hosts_per_service"].get(svc, [])
    ms = max_severity(fs)
    sev_counts = Counter(f["severity"] for f in fs)

    finding_rows = []
    for f in fs:
        finding_rows.append(f"""
        <tr data-severity="{e(f['severity'])}" data-host="{e(f['host'])}">
          <td>{severity_chip(f['severity'])}</td>
          <td><code class="mono">{e(truncate(f['line'], 280))}</code></td>
          <td><a href="host_{e(safe_name(f['host']))}.html">{e(f['host'])}</a></td>
          <td><code class="mono small">{e(f['evidence_path'])}</code></td>
        </tr>""")

    host_chips = " ".join(
        f'<a class="chip chip-host" href="host_{e(safe_name(h))}.html">{e(h)}</a>'
        for h in hosts
    )

    sev_summary = " ".join(
        f'<span class="chip chip-{e(s)}">{e(s.upper())}: {n}</span>'
        for s in SEVERITY_ORDER if (n := sev_counts.get(s, 0))
    )

    body = f"""
<section class="hero">
  <p class="hero-sub">
    Highest severity: {severity_chip(ms)}
    · {len(fs)} finding{'s' if len(fs) != 1 else ''}
    · {len(hosts)} host{'s' if len(hosts) != 1 else ''} exercised.
  </p>
  <p>{sev_summary or '<span class="muted">no findings emitted for this service</span>'}</p>
</section>

<section class="card">
  <h2 class="card-title">Hosts with this service</h2>
  <p>{host_chips or '<span class="muted">no hosts routed to this service</span>'}</p>
</section>

<section class="card">
  <h2 class="card-title">All findings</h2>
  <table class="data sortable filterable">
    <thead><tr>
      <th data-sort="severity">Sev</th>
      <th>Finding</th>
      <th data-sort="text">Host</th>
      <th>Evidence</th>
    </tr></thead>
    <tbody>{''.join(finding_rows) if finding_rows else '<tr><td colspan="4" class="muted">no findings</td></tr>'}</tbody>
  </table>
</section>
"""
    return render_page(
        f"Service · {svc}",
        body,
        "Services",
        breadcrumbs=[("Services", "services.html"), (svc, "")],
    )


# --------------------------------------------------------------- inventory (master port table)
def render_inventory(model: dict) -> str:
    inv = model["inventory"]
    rows = []
    for r in inv:
        # Top-finding preview (first finding line, truncated)
        preview = ""
        if r["findings"]:
            preview = f'<code class="mono small">{e(truncate(r["findings"][0]["line"], 120))}</code>'
        else:
            preview = '<span class="muted">no severity-tagged findings — probe artifacts only</span>'
        state_chip = (
            f'<span class="chip chip-{e(r["max_severity"])}">{e(r["max_severity"].upper() if r["max_severity"] != "none" else "PROBED")}</span>'
            if r["state"] == "findings"
            else '<span class="chip chip-info">PROBED</span>'
        )
        rows.append(f"""
        <tr data-host="{e(r['host'])}" data-port="{r['port']}" data-service="{e(r['service'])}" data-severity="{e(r['max_severity'])}" data-findings="{r['n_findings']}">
          <td><a href="host_{e(safe_name(r['host']))}.html">{e(r['host'])}</a></td>
          <td class="num">{r['port']}</td>
          <td><a href="service_{e(safe_name(r['service']))}.html">{e(r['service'])}</a></td>
          <td>{state_chip}</td>
          <td class="num">{r['n_findings']}</td>
          <td>{preview}</td>
        </tr>""")
    # Severity counts in the inventory
    sev_counts: Counter = Counter(r["max_severity"] for r in inv if r["state"] == "findings")
    sev_summary = " ".join(
        f'<span class="chip chip-{e(s)}">{e(s.upper())}: {n}</span>'
        for s in SEVERITY_ORDER if (n := sev_counts.get(s, 0))
    )
    probed_only = sum(1 for r in inv if r["state"] == "probed")
    body = f"""
<section class="hero">
  <p class="hero-sub">
    <strong>{len(inv)}</strong> open port{'s' if len(inv) != 1 else ''} across
    <strong>{len({r['host'] for r in inv})}</strong> host{'s' if len({r['host'] for r in inv}) != 1 else ''}.
    {sum(1 for r in inv if r['state'] == 'findings')} with findings · {probed_only} probed only.
  </p>
  <p>{sev_summary or '<span class="muted">no severity-tagged findings yet</span>'}</p>
</section>

<div class="card">
  <p class="card-sub">
    Click a column header to sort. Use the global search to filter — try
    typing a port number, an IP, or a service name. Each row links to the
    relevant host/service detail page.
  </p>
  <table class="data sortable filterable" id="inventory-table">
    <thead><tr>
      <th data-sort="text">Host</th>
      <th class="num" data-sort="num">Port</th>
      <th data-sort="text">Service</th>
      <th data-sort="severity">State</th>
      <th class="num" data-sort="num">Findings</th>
      <th>Top finding</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="6" class="muted">no inventory entries — no _targets_*.txt files, no per-host artifacts, and no port-bearing finding text were detected</td></tr>'}</tbody>
  </table>
</div>
"""
    return render_page("Inventory", body, "Inventory")


# --------------------------------------------------------------- inbox + guidance
def render_inbox(model: dict) -> str:
    inbox = model.get("inbox", [])
    rows = []
    for f in inbox:
        host = f.get("host", "")
        svc = f.get("service", "")
        rows.append(f"""
        <tr data-host="{e(host)}" data-service="{e(svc)}" data-status="{e(f.get('triage_status', 'new'))}">
          <td><span class="status status-{e(f.get('triage_status', 'new'))}">{e(f.get('triage_status', 'new'))}</span></td>
          <td class="num priority">{e(f.get('priority', 0))}</td>
          <td>{severity_chip(f.get('severity', 'info'))}</td>
          <td>{e(f.get('confidence', 'medium'))}</td>
          <td><a href="host_{e(safe_name(host))}.html">{e(host)}</a></td>
          <td class="num">{e(f.get('port', '') or '')}</td>
          <td><a href="service_{e(safe_name(svc))}.html">{e(svc)}</a></td>
          <td><strong>{e(f.get('title', 'Finding'))}</strong><br><code class="mono small">{e(truncate(f.get('line', ''), 180))}</code></td>
          <td>{e(f.get('next_action', 'Review evidence and validate impact'))}</td>
          <td><code class="mono small">{e(f.get('evidence_path', ''))}</code></td>
        </tr>""")
    body = f"""
<section class="hero">
  <p class="hero-sub">
    Operator inbox sorted by triage status, priority, severity, confidence, then target.
    Priority is supplied by structured findings when present and derived from severity/service otherwise.
  </p>
</section>

<section class="card">
  <table class="data sortable filterable" id="inbox-table">
    <thead><tr>
      <th data-sort="text">Status</th>
      <th class="num" data-sort="num">Priority</th>
      <th data-sort="severity">Severity</th>
      <th data-sort="text">Confidence</th>
      <th data-sort="text">Host</th>
      <th class="num" data-sort="num">Port</th>
      <th data-sort="text">Service</th>
      <th>Finding</th>
      <th>Next action</th>
      <th>Evidence</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="10" class="muted">no findings in inbox</td></tr>'}</tbody>
  </table>
</section>
"""
    return render_page("Inbox", body, "Inbox")


def render_guidance(model: dict) -> str:
    guidance = sorted(model.get("guidance", []), key=lambda g: -int(g.get("priority", 0) or 0))
    rows = []
    for g in guidance:
        evidence = g.get("evidence", [])
        if isinstance(evidence, list):
            evidence_txt = ", ".join(str(x) for x in evidence[:4])
            if len(evidence) > 4:
                evidence_txt += f", +{len(evidence) - 4} more"
        else:
            evidence_txt = str(evidence)
        rows.append(f"""
        <tr>
          <td class="num priority">{e(g.get('priority', 0))}</td>
          <td>{e(g.get('type', 'guidance'))}</td>
          <td><strong>{e(g.get('title', 'Guidance'))}</strong><br><span class="muted">{e(g.get('reason', ''))}</span></td>
          <td>{e(g.get('recommended_next', 'Review planner output'))}</td>
          <td><code class="mono small">{e(evidence_txt)}</code></td>
        </tr>""")
    body = f"""
<section class="hero">
  <p class="hero-sub">
    Planner guidance highlights coverage gaps, gated surfaces, skipped high-value work, and follow-up opportunities.
  </p>
</section>

<section class="card">
  <table class="data sortable filterable" id="guidance-table">
    <thead><tr>
      <th class="num" data-sort="num">Priority</th>
      <th data-sort="text">Type</th>
      <th>Recommendation</th>
      <th>Next step</th>
      <th>Evidence</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="5" class="muted">no guidance.json present for this run</td></tr>'}</tbody>
  </table>
</section>
"""
    return render_page("Guidance", body, "Guidance")


# --------------------------------------------------------------- severity landing + per-severity
def render_severity_landing(model: dict) -> str:
    cards = []
    counts = model["summary"]["counts"]
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        cards.append(f"""
        <a class="bigtile bigtile-{e(sev)}" href="severity_{e(sev)}.html">
          <div class="bigtile-count">{n}</div>
          <div class="bigtile-label">{e(sev.upper())}</div>
          <div class="bigtile-sub">view all {e(sev)} findings</div>
        </a>""")
    body = f"""
<p class="card-sub">Browse findings filtered by severity. Severity is assigned by <code class="mono">aranumtoolkit/network/report.py</code>'s rule set; per-finding rules can be overridden with <code class="mono">--rules</code> when invoking the generator.</p>
<section class="bigtiles">
{''.join(cards)}
</section>
"""
    return render_page("Severity", body, "Severity")


def render_severity_detail(model: dict, sev: str) -> str:
    fs = model["by_severity"].get(sev, [])
    rows = []
    for f in fs:
        rows.append(f"""
        <tr data-host="{e(f['host'])}" data-service="{e(f['service'])}">
          <td><code class="mono">{e(truncate(f['line'], 280))}</code></td>
          <td><a href="host_{e(safe_name(f['host']))}.html">{e(f['host'])}</a></td>
          <td><a href="service_{e(safe_name(f['service']))}.html">{e(f['service'])}</a></td>
          <td><code class="mono small">{e(f['evidence_path'])}</code></td>
        </tr>""")
    body = f"""
<section class="hero">
  <p class="hero-sub">{severity_chip(sev)} · {len(fs)} finding{'s' if len(fs) != 1 else ''}</p>
</section>

<section class="card">
  <table class="data sortable filterable">
    <thead><tr>
      <th>Finding</th>
      <th data-sort="text">Host</th>
      <th data-sort="text">Service</th>
      <th>Evidence</th>
    </tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="4" class="muted">no findings at this severity</td></tr>'}</tbody>
  </table>
</section>
"""
    return render_page(
        f"Severity · {sev.upper()}",
        body,
        "Severity",
        breadcrumbs=[("Severity", "severity.html"), (sev.upper(), "")],
    )


# --------------------------------------------------------------- timeline
def render_timeline(model: dict) -> str:
    events = model["events"]
    rows = []
    for ev in events:
        msg = ev["msg"]
        # Highlight dispatch lines
        cls = ""
        if "dispatch-begin" in msg:
            cls = "evt-begin"
        elif "dispatch-end" in msg:
            cls = "evt-end"
        elif "ot-untouched" in msg or "WARNING" in msg.upper():
            cls = "evt-warn"
        rows.append(f"""
        <tr class="{cls}">
          <td class="mono small">{e(ev['ts'])}</td>
          <td><code class="mono">{e(truncate(msg, 240))}</code></td>
        </tr>""")
    body = f"""
<section class="hero">
  <p class="hero-sub">{len(events)} event{'s' if len(events) != 1 else ''} from <code class="mono">run.log</code>.</p>
</section>

<section class="card">
  <table class="data filterable">
    <thead><tr><th>Time</th><th>Event</th></tr></thead>
    <tbody>{''.join(rows) if rows else '<tr><td colspan="2" class="muted">no run.log found in OUTDIR</td></tr>'}</tbody>
  </table>
</section>
"""
    return render_page("Timeline", body, "Timeline")


# --------------------------------------------------------------- coverage matrix
def render_coverage(model: dict) -> str:
    services_per_host = model["services_per_host"]
    hosts_per_service = model["hosts_per_service"]
    all_services = sorted(hosts_per_service.keys())
    all_hosts = sorted(services_per_host.keys())

    if not all_services or not all_hosts:
        body = '<div class="card"><p class="muted">No coverage data — run auto-enum.sh first.</p></div>'
        return render_page("Coverage", body, "Coverage")

    # Build the matrix as a wide table. For very-many-hosts cases the row
    # count is bounded by host count, not the cross product.
    header_cells = "".join(
        f'<th class="rotated"><span>{e(s)}</span></th>' for s in all_services
    )
    rows = []
    for host in all_hosts:
        host_svcs = set(services_per_host.get(host, []))
        host_findings_by_svc = defaultdict(int)
        host_max_by_svc = {}
        for f in model["by_host"].get(host, []):
            host_findings_by_svc[f["service"]] += 1
            cur = host_max_by_svc.get(f["service"])
            if cur is None or SEVERITY_RANK[f["severity"]] < SEVERITY_RANK[cur]:
                host_max_by_svc[f["service"]] = f["severity"]
        cells = []
        for svc in all_services:
            if svc in host_svcs:
                ms = host_max_by_svc.get(svc, "info")
                n = host_findings_by_svc.get(svc, 0)
                cells.append(
                    f'<td class="cov cov-{e(ms)}" title="{e(svc)} on {e(host)}: {n} findings, max {e(ms)}">'
                    f'<span class="cov-n">{n if n else "•"}</span></td>'
                )
            else:
                cells.append('<td class="cov cov-empty"></td>')
        rows.append(
            f'<tr><td><a href="host_{e(safe_name(host))}.html">{e(host)}</a></td>{"".join(cells)}</tr>'
        )

    body = f"""
<section class="hero">
  <p class="hero-sub">
    Coverage matrix — which dispatchers ran against which hosts, with finding count + max severity per cell. Hover for detail.
  </p>
</section>

<section class="card scrollx">
  <table class="data coverage-matrix">
    <thead><tr><th class="sticky-l">Host</th>{header_cells}</tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>
"""
    return render_page("Coverage", body, "Coverage")


# --------------------------------------------------------------- data.json
def export_data_json(model: dict) -> str:
    """Compact payload used for client-side search/jumping."""
    payload = {
        "generated_at": model["generated_at"],
        "out_dir": model["out_dir"],
        "summary": {
            "counts": model["summary"]["counts"],
            "n_hosts": len(model["summary"]["hosts"]),
            "n_services": len(model["summary"]["services"]),
            "n_ports": len(model["inventory"]),
        },
        "inventory": [
            {
                "host":     r["host"],
                "port":     r["port"],
                "service":  r["service"],
                "state":    r["state"],
                "n":        r["n_findings"],
                "sev":      r["max_severity"],
                "page":     f"host_{safe_name(r['host'])}.html",
            }
            for r in model["inventory"]
        ],
        "hosts": [
            {
                "ip": h,
                "page": f"host_{safe_name(h)}.html",
                "findings": len(model["by_host"].get(h, [])),
                "max_severity": max_severity(model["by_host"].get(h, [])),
                "services": model["services_per_host"].get(h, []),
            }
            for h in sorted(set(list(model["by_host"].keys()) + list(model["services_per_host"].keys())))
        ],
        "services": [
            {
                "name": s,
                "page": f"service_{safe_name(s)}.html",
                "findings": len(model["by_service"].get(s, [])),
                "max_severity": max_severity(model["by_service"].get(s, [])),
                "hosts": model["hosts_per_service"].get(s, []),
            }
            for s in sorted(set(list(model["by_service"].keys()) + list(model["hosts_per_service"].keys())))
        ],
        "inbox": [
            {
                "status": f.get("triage_status", "new"),
                "priority": f.get("priority", 0),
                "severity": f.get("severity", "info"),
                "confidence": f.get("confidence", "medium"),
                "host": f.get("host", ""),
                "port": f.get("port", ""),
                "service": f.get("service", ""),
                "title": f.get("title", ""),
                "page": f"host_{safe_name(f.get('host', ''))}.html",
            }
            for f in model.get("inbox", [])
        ],
        "guidance": model.get("guidance", []),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


# --------------------------------------------------------------- assets (CSS + JS)
CSS_TEMPLATE = r"""
/* aratool dashboard — minimal, modern, dark-by-default. Light theme via [data-theme="light"].
   No external deps. All sizes use rem; severity colours are CSS custom props. */
:root {
  --bg:           #0d1117;
  --bg-elev:     #161b22;
  --bg-elev-2:   #1c2128;
  --border:       #30363d;
  --border-soft:  #21262d;
  --text:         #e6edf3;
  --text-muted:   #7d8590;
  --text-strong:  #ffffff;
  --link:         #2f81f7;
  --link-hover:   #79c0ff;
  --code-bg:      #0d1117;
  --shadow:       0 1px 0 rgba(0,0,0,.04), 0 8px 24px rgba(0,0,0,.12);

  --sev-critical: #f04747;
  --sev-high:     #f0883e;
  --sev-medium:   #e3b341;
  --sev-low:      #2f81f7;
  --sev-info:     #7d8590;

  --radius:       8px;
  --radius-lg:    12px;
  --gap:          16px;
  --gap-lg:       24px;
  --maxw:         1400px;
  --font-sans:    -apple-system, ui-sans-serif, "Segoe UI", system-ui, "Helvetica Neue", Arial, sans-serif;
  --font-mono:    ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace;
}

[data-theme="light"] {
  --bg:           #ffffff;
  --bg-elev:      #f6f8fa;
  --bg-elev-2:    #eef1f4;
  --border:       #d0d7de;
  --border-soft:  #e3e7eb;
  --text:         #1f2328;
  --text-muted:   #59636e;
  --text-strong:  #000000;
  --link:         #0969da;
  --link-hover:   #0550ae;
  --code-bg:      #f6f8fa;
}

* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  color: var(--text);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}
a { color: var(--link); text-decoration: none; }
a:hover { color: var(--link-hover); text-decoration: underline; }
code, .mono { font-family: var(--font-mono); font-size: 12.5px; }
.mono.small { font-size: 11.5px; color: var(--text-muted); }
code { background: var(--code-bg); padding: 2px 5px; border-radius: 4px; border: 1px solid var(--border-soft); }

/* topnav */
.topnav {
  position: sticky; top: 0; z-index: 10;
  display: flex; align-items: center; gap: var(--gap-lg);
  padding: 12px 24px;
  background: rgba(13,17,23,0.85);
  backdrop-filter: saturate(120%) blur(8px);
  -webkit-backdrop-filter: saturate(120%) blur(8px);
  border-bottom: 1px solid var(--border);
}
[data-theme="light"] .topnav { background: rgba(255,255,255,0.92); }
.brand { display: flex; align-items: baseline; gap: 8px; }
.brand-mark { color: var(--sev-low); font-size: 18px; transform: translateY(1px); }
.brand-text { font-weight: 700; color: var(--text-strong); letter-spacing: -0.01em; }
.brand-sub  { color: var(--text-muted); font-size: 12px; }
.navlinks { display: flex; gap: 4px; flex: 1; }
.nav-link {
  padding: 6px 12px; border-radius: 6px;
  color: var(--text-muted); font-weight: 500;
  text-decoration: none;
}
.nav-link:hover { color: var(--text); background: var(--bg-elev); text-decoration: none; }
.nav-link.active { color: var(--text-strong); background: var(--bg-elev-2); }
.navtools { display: flex; gap: 8px; align-items: center; }
.search {
  background: var(--bg-elev); border: 1px solid var(--border);
  color: var(--text); padding: 6px 10px; border-radius: 6px;
  font-family: var(--font-sans); font-size: 13px; width: 220px;
  outline: none; transition: border-color .15s;
}
.search:focus { border-color: var(--link); }
.iconbtn {
  background: var(--bg-elev); border: 1px solid var(--border);
  color: var(--text); width: 32px; height: 32px; border-radius: 6px;
  cursor: pointer; font-size: 14px;
}
.iconbtn:hover { background: var(--bg-elev-2); }

/* layout */
.container { max-width: var(--maxw); margin: 0 auto; padding: 24px 24px 60px; }
.pagetitle { font-size: 22px; font-weight: 600; letter-spacing: -0.01em; margin: 8px 0 20px; color: var(--text-strong); }
.breadcrumbs { color: var(--text-muted); font-size: 12.5px; margin-bottom: 8px; }
.breadcrumbs a { color: var(--text-muted); }
.breadcrumbs a:hover { color: var(--link); }
.muted { color: var(--text-muted); }
.footer { padding: 18px 24px; color: var(--text-muted); font-size: 12px; border-top: 1px solid var(--border-soft); text-align: center; }

/* hero */
.hero { margin-bottom: 20px; }
.hero-sub { font-size: 14.5px; color: var(--text-muted); }
.hero-sub strong { color: var(--text-strong); }

/* tile grid (small severity tiles) */
.tiles {
  display: grid; gap: var(--gap);
  grid-template-columns: repeat(5, minmax(0, 1fr));
  margin-bottom: var(--gap-lg);
}
.tile {
  display: flex; flex-direction: column; gap: 4px;
  padding: 16px 18px; border-radius: var(--radius-lg);
  background: var(--bg-elev);
  border: 1px solid var(--border);
  color: var(--text);
  text-decoration: none; transition: transform .12s, border-color .12s;
}
.tile:hover { transform: translateY(-1px); border-color: var(--text-muted); text-decoration: none; }
.tile-count { font-size: 28px; font-weight: 700; color: var(--text-strong); letter-spacing: -0.02em; }
.tile-label { font-size: 11px; font-weight: 700; color: var(--text-muted); letter-spacing: 0.06em; }
.tile-critical { border-left: 3px solid var(--sev-critical); }
.tile-high     { border-left: 3px solid var(--sev-high); }
.tile-medium   { border-left: 3px solid var(--sev-medium); }
.tile-low      { border-left: 3px solid var(--sev-low); }
.tile-info     { border-left: 3px solid var(--sev-info); }

/* big tiles (severity landing) */
.bigtiles { display: grid; gap: var(--gap); grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); }
.bigtile {
  display: block; padding: 22px; border-radius: var(--radius-lg);
  background: var(--bg-elev); border: 1px solid var(--border);
  text-decoration: none; color: var(--text);
}
.bigtile:hover { border-color: var(--text-muted); text-decoration: none; transform: translateY(-1px); }
.bigtile-count { font-size: 40px; font-weight: 700; color: var(--text-strong); }
.bigtile-label { font-size: 14px; font-weight: 700; letter-spacing: 0.05em; margin-top: 4px; }
.bigtile-sub   { color: var(--text-muted); font-size: 12px; margin-top: 4px; }
.bigtile-critical .bigtile-label { color: var(--sev-critical); }
.bigtile-high     .bigtile-label { color: var(--sev-high); }
.bigtile-medium   .bigtile-label { color: var(--sev-medium); }
.bigtile-low      .bigtile-label { color: var(--sev-low); }
.bigtile-info     .bigtile-label { color: var(--sev-info); }

/* cards + grid */
.grid2 { display: grid; gap: var(--gap-lg); grid-template-columns: 1fr 1fr; margin-bottom: var(--gap-lg); }
@media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } .tiles { grid-template-columns: repeat(2, 1fr); } }

.card {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 18px 20px;
  margin-bottom: var(--gap-lg);
}
.card-title { font-size: 14px; font-weight: 600; color: var(--text-strong); margin: 0 0 4px; }
.card-sub { color: var(--text-muted); font-size: 12.5px; margin: 0 0 12px; }
.card-foot { margin: 10px 0 0; font-size: 12.5px; }
.scrollx { overflow-x: auto; }

/* tables */
.data { width: 100%; border-collapse: collapse; }
.data th {
  text-align: left; padding: 8px 10px;
  font-weight: 600; font-size: 11.5px; letter-spacing: 0.04em;
  color: var(--text-muted); text-transform: uppercase;
  border-bottom: 1px solid var(--border);
  background: var(--bg-elev-2);
  position: sticky; top: 56px; z-index: 1;
}
.data td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border-soft);
  vertical-align: top;
}
.data tr:last-child td { border-bottom: none; }
.data tr:hover td { background: var(--bg-elev-2); }
.data .num { text-align: right; font-variant-numeric: tabular-nums; }
.data.sortable th[data-sort] { cursor: pointer; user-select: none; }
.data.sortable th[data-sort]:hover { color: var(--text); }
.data.sortable th[data-sort]::after { content: ""; display: inline-block; margin-left: 6px; opacity: 0.4; }
.data.sortable th[data-sort].asc::after  { content: " ▲"; opacity: 1; }
.data.sortable th[data-sort].desc::after { content: " ▼"; opacity: 1; }
.data-kv td:first-child { width: 220px; color: var(--text-muted); }

/* severity chips */
.chip {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 10.5px; font-weight: 700; letter-spacing: 0.05em;
  vertical-align: middle; line-height: 1.5;
}
.chip-mini { padding: 0 6px; font-weight: 600; letter-spacing: 0.02em; }
.chip-critical { background: color-mix(in srgb, var(--sev-critical) 22%, transparent); color: var(--sev-critical); border: 1px solid color-mix(in srgb, var(--sev-critical) 40%, transparent); }
.chip-high     { background: color-mix(in srgb, var(--sev-high) 22%, transparent);     color: var(--sev-high);     border: 1px solid color-mix(in srgb, var(--sev-high) 40%, transparent); }
.chip-medium   { background: color-mix(in srgb, var(--sev-medium) 22%, transparent);   color: var(--sev-medium);   border: 1px solid color-mix(in srgb, var(--sev-medium) 40%, transparent); }
.chip-low      { background: color-mix(in srgb, var(--sev-low) 22%, transparent);      color: var(--sev-low);      border: 1px solid color-mix(in srgb, var(--sev-low) 40%, transparent); }
.chip-info     { background: color-mix(in srgb, var(--sev-info) 22%, transparent);     color: var(--sev-info);     border: 1px solid color-mix(in srgb, var(--sev-info) 40%, transparent); }
.chip-svc, .chip-host {
  background: var(--bg-elev-2); color: var(--text); border: 1px solid var(--border);
  margin-right: 4px; margin-bottom: 4px; text-decoration: none;
}
  .chip-svc:hover, .chip-host:hover { background: var(--bg-elev); color: var(--text-strong); text-decoration: none; }
  .priority { font-weight: 700; color: var(--text-strong); font-variant-numeric: tabular-nums; }
  .status {
    display: inline-block; padding: 2px 7px; border-radius: 4px;
    font-size: 10.5px; font-weight: 700; letter-spacing: 0.03em;
    background: var(--bg-elev-2); color: var(--text-muted); border: 1px solid var(--border);
  }
  .status-new { color: var(--link-hover); border-color: color-mix(in srgb, var(--link) 45%, transparent); }
  .status-needs-validation { color: var(--sev-medium); border-color: color-mix(in srgb, var(--sev-medium) 45%, transparent); }
  .status-accepted { color: var(--sev-high); border-color: color-mix(in srgb, var(--sev-high) 45%, transparent); }
  .status-suppressed { color: var(--text-muted); opacity: .75; }

  /* coverage matrix */
.coverage-matrix { font-size: 12.5px; }
.coverage-matrix th.sticky-l { position: sticky; left: 0; z-index: 2; background: var(--bg-elev-2); }
.coverage-matrix th.rotated  { writing-mode: vertical-rl; transform: rotate(180deg); height: 140px; padding: 8px 4px; }
.coverage-matrix td.cov { text-align: center; padding: 4px 6px; min-width: 32px; }
.cov-empty { background: transparent; }
.cov-critical { background: color-mix(in srgb, var(--sev-critical) 30%, transparent); color: var(--sev-critical); }
.cov-high     { background: color-mix(in srgb, var(--sev-high) 30%, transparent);     color: var(--sev-high); }
.cov-medium   { background: color-mix(in srgb, var(--sev-medium) 30%, transparent);   color: var(--sev-medium); }
.cov-low      { background: color-mix(in srgb, var(--sev-low) 30%, transparent);      color: var(--sev-low); }
.cov-info     { background: color-mix(in srgb, var(--sev-info) 20%, transparent);     color: var(--text-muted); }
.cov-n { font-variant-numeric: tabular-nums; font-weight: 600; }

/* event flavours */
.evt-begin td:nth-child(2) { color: var(--text); }
.evt-end   td:nth-child(2) { color: var(--text-muted); }
.evt-warn  { background: color-mix(in srgb, var(--sev-high) 8%, transparent); }

/* expandable rows (per-host port table + evidence) */
.hero-cta { margin-top: 6px; font-size: 13px; }
.hero-cta a { font-weight: 600; }
details > summary {
  cursor: pointer; color: var(--link);
  list-style: none;
  user-select: none;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before {
  content: "▸"; display: inline-block; margin-right: 6px;
  transition: transform .12s; transform-origin: center;
  color: var(--text-muted); font-size: 10px;
}
details[open] > summary::before { transform: rotate(90deg); }
details > summary:hover { color: var(--link-hover); }
.expand-pane {
  margin-top: 10px; padding: 12px;
  background: var(--bg);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius);
}
.data .data-inner {
  width: 100%; margin: 4px 0;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius);
  background: var(--bg);
}
.data .data-inner th {
  background: transparent;
  position: static;
  font-size: 10.5px;
  padding: 6px 8px;
}
.data .data-inner td { padding: 6px 8px; border-bottom-color: var(--border-soft); }

/* evidence file list */
details.evidence-list { margin-top: 10px; }
details.evidence-list > summary { color: var(--text-muted); font-size: 12px; }
details.evidence-list ul {
  margin: 8px 0 0; padding-left: 18px;
  max-height: 240px; overflow-y: auto;
  font-family: var(--font-mono); font-size: 11.5px;
}
details.evidence-list li { padding: 1px 0; }

/* inventory + port tables tweaks */
#inventory-table td:nth-child(2),
#host-ports-table td:nth-child(1) { font-weight: 600; color: var(--text-strong); }

/* hosts page: expand-all toolbar + inline-detail rows */
.toolbar {
  display: flex; align-items: center; gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
.toolbar-info { color: var(--text-muted); font-size: 12.5px; flex: 1; min-width: 240px; }
.toolbar-actions { display: flex; gap: 6px; }
.btn {
  background: var(--bg-elev-2); border: 1px solid var(--border);
  color: var(--text); padding: 6px 12px; border-radius: 6px;
  font-family: var(--font-sans); font-size: 12px; font-weight: 500;
  cursor: pointer; transition: background .12s, border-color .12s;
}
.btn:hover { background: var(--bg-elev); border-color: var(--text-muted); }
.btn.active { background: var(--link); color: #ffffff; border-color: var(--link); }
.expand-btn {
  background: transparent; border: 1px solid var(--border-soft);
  color: var(--text-muted); width: 22px; height: 22px; line-height: 1;
  border-radius: 4px; cursor: pointer; font-size: 12px;
  margin-right: 8px; transition: transform .12s, color .12s, border-color .12s;
  display: inline-flex; align-items: center; justify-content: center;
}
.expand-btn:hover { color: var(--text); border-color: var(--text-muted); }
.expand-btn.open { transform: rotate(90deg); color: var(--link); border-color: var(--link); }

.hostdetail > td { padding: 0; background: var(--bg); }
.hostdetail-pane { padding: 14px 18px 16px; border-left: 3px solid var(--link); background: var(--bg); }
.hostdetail-head { display: flex; align-items: baseline; gap: 8px; margin-bottom: 10px; }
.hostdetail-head strong { color: var(--text-strong); }
.hostdetail-link { margin-left: auto; font-size: 12px; }
.hosts-with-detail tbody tr.hostrow:hover td { background: var(--bg-elev-2); cursor: default; }
.hosts-with-detail tbody tr.hostdetail:hover td { background: var(--bg); }
"""

JS_TEMPLATE = r"""
// aratool dashboard — vanilla JS. No deps. ~150 lines.
(function () {
  "use strict";

  // ---- theme toggle (persists in localStorage) ----
  const THEME_KEY = "aratool-theme";
  const root = document.documentElement;
  const saved = localStorage.getItem(THEME_KEY);
  if (saved === "light") root.setAttribute("data-theme", "light");
  const themeBtn = document.getElementById("themetoggle");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const cur = root.getAttribute("data-theme");
      const next = cur === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      localStorage.setItem(THEME_KEY, next);
    });
  }

  // ---- global search: filters any .filterable table by row text ----
  const search = document.getElementById("globalsearch");
  if (search) {
    const applyFilter = () => {
      const q = search.value.trim().toLowerCase();
      document.querySelectorAll("table.filterable tbody tr").forEach(tr => {
        if (!q) { tr.style.display = ""; return; }
        const text = tr.textContent.toLowerCase();
        tr.style.display = text.indexOf(q) === -1 ? "none" : "";
      });
    };
    search.addEventListener("input", applyFilter);

    // Quick-jump: pressing Enter when search starts with `>` jumps to a page.
    // > host 10.0.0.5  → host_10-0-0-5.html (best match from data.json)
    // > svc smb        → service_smb.html
    let dataCache = null;
    const loadData = () =>
      dataCache ? Promise.resolve(dataCache)
                : fetch("data.json").then(r => r.json()).then(d => { dataCache = d; return d; }).catch(() => null);
    search.addEventListener("keydown", async e => {
      if (e.key !== "Enter") return;
      const q = search.value.trim();
      if (!q.startsWith(">")) return;
      const body = q.slice(1).trim().toLowerCase();
      const d = await loadData();
      if (!d) return;
      let candidates;
      if (body.startsWith("host ") || body.startsWith("h ")) {
        const term = body.split(/\s+/, 2)[1] || "";
        candidates = d.hosts.filter(h => h.ip.toLowerCase().includes(term));
        if (candidates[0]) window.location = candidates[0].page;
      } else if (body.startsWith("svc ") || body.startsWith("s ") || body.startsWith("service ")) {
        const term = body.split(/\s+/, 2)[1] || "";
        candidates = d.services.filter(s => s.name.toLowerCase().includes(term));
        if (candidates[0]) window.location = candidates[0].page;
      }
    });
  }

  // ---- sortable tables ----
  // For tables with paired hostrow/hostdetail rows (hosts page), sort pairs
  // so detail rows stay attached to their parent after sorting.
  const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };
  document.querySelectorAll("table.sortable").forEach(table => {
    const ths = table.querySelectorAll("thead th[data-sort]");
    ths.forEach((th, colIdx) => {
      th.addEventListener("click", () => {
        const mode = th.getAttribute("data-sort");
        const asc = !th.classList.contains("asc");
        ths.forEach(o => o.classList.remove("asc", "desc"));
        th.classList.add(asc ? "asc" : "desc");
        const tbody = table.querySelector("tbody");
        // Build sort units: if a row has class "hostrow", pair it with its
        // immediately-following "hostdetail" sibling.
        const allRows = Array.from(tbody.querySelectorAll("tr"));
        const units = [];
        for (let i = 0; i < allRows.length; i++) {
          const r = allRows[i];
          if (r.classList.contains("hostdetail")) continue; // attached to prior
          const detail = (allRows[i + 1] && allRows[i + 1].classList.contains("hostdetail"))
              ? allRows[i + 1] : null;
          units.push({ head: r, detail });
        }
        const cmp = (a, b) => {
          let va = a.head.children[colIdx]?.textContent.trim() || "";
          let vb = b.head.children[colIdx]?.textContent.trim() || "";
          if (mode === "num") {
            return (parseFloat(va) || 0) - (parseFloat(vb) || 0);
          }
          if (mode === "severity") {
            return (SEVERITY_RANK[va.toLowerCase()] ?? 99) - (SEVERITY_RANK[vb.toLowerCase()] ?? 99);
          }
          return va.localeCompare(vb, undefined, { numeric: true });
        };
        units.sort(cmp);
        if (!asc) units.reverse();
        units.forEach(u => { tbody.appendChild(u.head); if (u.detail) tbody.appendChild(u.detail); });
      });
    });
  });

  // ---- hosts page: expand-all / collapse-all toolbar ----
  const toggleDetail = (btn, force) => {
    const id = btn.getAttribute("data-toggle");
    const detail = document.getElementById(id);
    if (!detail) return;
    const willOpen = (force === undefined) ? detail.hasAttribute("hidden") : force;
    if (willOpen) {
      detail.removeAttribute("hidden");
      btn.classList.add("open");
    } else {
      detail.setAttribute("hidden", "");
      btn.classList.remove("open");
    }
  };
  document.querySelectorAll(".expand-btn[data-toggle]").forEach(btn => {
    btn.addEventListener("click", () => toggleDetail(btn));
  });
  const expandAll = document.getElementById("expand-all-hosts");
  const collapseAll = document.getElementById("collapse-all-hosts");
  if (expandAll) {
    expandAll.addEventListener("click", () => {
      document.querySelectorAll(".expand-btn[data-toggle]").forEach(b => toggleDetail(b, true));
      expandAll.classList.add("active");
      collapseAll && collapseAll.classList.remove("active");
    });
  }
  if (collapseAll) {
    collapseAll.addEventListener("click", () => {
      document.querySelectorAll(".expand-btn[data-toggle]").forEach(b => toggleDetail(b, false));
      collapseAll.classList.add("active");
      expandAll && expandAll.classList.remove("active");
    });
  }

  // ---- filter awareness: when a hostrow is hidden by search, also hide its detail row ----
  if (search) {
    search.addEventListener("input", () => {
      document.querySelectorAll(".hostrow").forEach(tr => {
        const id = tr.getAttribute("data-detail-id");
        if (!id) return;
        const detail = document.getElementById(id);
        if (!detail) return;
        // Mirror visibility — but don't override expanded state when row visible
        if (tr.style.display === "none") {
          detail.style.display = "none";
        } else {
          detail.style.display = "";
        }
      });
    });
  }

  // ---- highlight active row on hover for tables ---- (CSS already does this)

  // ---- keyboard nav: `/` focuses search, Esc clears ----
  document.addEventListener("keydown", e => {
    if (e.key === "/" && document.activeElement !== search) {
      if (search) { e.preventDefault(); search.focus(); search.select(); }
    }
    if (e.key === "Escape" && document.activeElement === search) {
      search.value = ""; search.dispatchEvent(new Event("input")); search.blur();
    }
  });
})();
"""


# --------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a multi-page HTML dashboard from an aratool $OUTDIR.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("outdir", type=Path, help="aratool output directory (the --output of auto-enum.sh).")
    ap.add_argument("--output", required=True, type=Path, help="Destination directory for the dashboard.")
    ap.add_argument("--bulk", action="store_true", help="Treat OUTDIR as a bulk-enum-standalones/linux/-windows tree.")
    ap.add_argument("--rules", type=Path, default=None, help="Optional --rules FILE passed to report.py (one JSON-line per rule).")
    args = ap.parse_args()

    if not args.outdir.is_dir():
        print(f"error: outdir does not exist or is not a directory: {args.outdir}", file=sys.stderr)
        return 2

    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "assets").mkdir(exist_ok=True)

    model = build_index(args.outdir, args.bulk, args.rules)

    # Write all pages
    pages: list[tuple[str, str]] = []
    pages.append(("index.html", render_index(model)))
    pages.append(("inbox.html", render_inbox(model)))
    pages.append(("guidance.html", render_guidance(model)))
    pages.append(("hosts.html", render_hosts(model)))
    pages.append(("inventory.html", render_inventory(model)))
    pages.append(("services.html", render_services(model)))
    pages.append(("severity.html", render_severity_landing(model)))
    for sev in SEVERITY_ORDER:
        pages.append((f"severity_{sev}.html", render_severity_detail(model, sev)))
    pages.append(("timeline.html", render_timeline(model)))
    pages.append(("coverage.html", render_coverage(model)))

    all_hosts = sorted(set(list(model["by_host"].keys()) + list(model["services_per_host"].keys())))
    for host in all_hosts:
        pages.append((f"host_{safe_name(host)}.html", render_host_detail(model, host)))

    all_services = sorted(set(list(model["by_service"].keys()) + list(model["hosts_per_service"].keys())))
    for svc in all_services:
        pages.append((f"service_{safe_name(svc)}.html", render_service_detail(model, svc)))

    for name, content in pages:
        (out / name).write_text(content, encoding="utf-8")

    # Assets + data
    (out / "assets" / "dashboard.css").write_text(CSS_TEMPLATE, encoding="utf-8")
    (out / "assets" / "dashboard.js").write_text(JS_TEMPLATE, encoding="utf-8")
    (out / "data.json").write_text(export_data_json(model), encoding="utf-8")

    # Summary to stdout
    print(f"dashboard: wrote {len(pages)} page(s) + assets to {out}", file=sys.stderr)
    print(f"  hosts: {len(all_hosts)}  services: {len(all_services)}  findings: {len(model['findings'])}", file=sys.stderr)
    print(f"  open:  file://{out.resolve()}/index.html", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
