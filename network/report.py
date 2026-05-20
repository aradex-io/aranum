#!/usr/bin/env python3
"""report.py — unified findings report from an auto-enum output tree.

Walks an auto-enum.sh output directory (the one passed as -o / --output) and
emits three artifacts at its root:

    report.md       — Markdown: per-service summary table, per-host findings,
                      links to raw evidence files
    findings.json   — flat machine-readable list: {host, port, service,
                      finding, severity, evidence_path, ...}
    report.html     — single-file HTML rendering of report.md (no external CSS,
                      embeds a minimal stylesheet)

Severity heuristics (anchored on the markers the dispatchers actually emit):

    CRITICAL  — "CRITICAL"-prefixed log lines, unauth daemon detected, OT
                signal, etcd v2/keys unauth, Docker 2375 unauth, k8s 8080
                insecure apiserver
    HIGH      — "EXPOSED" lines (paths/admin UIs), "UNAUTH" lines, "TRUST"
                (postgres trust auth), "ANON AUTH" (mysql), default-cred
                hits, RealVNC bypass, JWT alg=none, CVE-* signal markers
    MEDIUM    — CORS reflection without credentials, "key-only" SSH advisory,
                signing-disabled relay candidates, version-range CVE candidate
                signals (without confirmed unauth)
    LOW       — informational banners, version fingerprints, normal HTTP
                discovery, MUC items, etc.

Operator can override severity rules via --severity-rules FILE (one JSON
object per line — see jabber/README.md for an example).

--redact replaces target IPs/hostnames with <TARGET-N> for shareable output.
"""

from __future__ import annotations
import argparse
import datetime
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable

# ---------------------------------------------------- color (stdout only)
def _c(s: str, code: str) -> str:
    if not sys.stdout.isatty():
        return s
    return {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m",
            "C": "\033[1;36m", "M": "\033[1;35m"}.get(code, "") + s + "\033[0m"


# ---------------------------------------------------- severity rules
# (regex, severity) pairs evaluated in order. First match wins per line.
# Anchored on the markers the dispatchers emit (err/hit/log color flags +
# the literal "CRITICAL"/"EXPOSED"/"UNAUTH"/etc. words in their log lines).
_DEFAULT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bCRITICAL\b", re.I),                                 "critical"),
    (re.compile(r"\bUNAUTH (?:Docker|etcd|/v2/keys|kubelet|apiserver)\b", re.I), "critical"),
    (re.compile(r"\binsecure apiserver\b", re.I),                       "critical"),
    (re.compile(r"\bauth bypass\b", re.I),                              "critical"),
    (re.compile(r"\bcipher 0\b", re.I),                                 "critical"),
    (re.compile(r"\bremote command execution\b", re.I),                 "critical"),
    (re.compile(r"\bguest:guest\b", re.I),                              "critical"),
    (re.compile(r"\bEXPOSED\b", re.I),                                  "high"),
    (re.compile(r"\bUNAUTH\b", re.I),                                   "high"),
    (re.compile(r"\bTRUST AUTH\b", re.I),                               "high"),
    (re.compile(r"\bANON AUTH\b", re.I),                                "high"),
    (re.compile(r"\bUSER_EXISTS\b", re.I),                              "high"),
    (re.compile(r"\bRealVNC\b.*\bbypass\b", re.I),                      "high"),
    (re.compile(r"\balg=none\b", re.I),                                 "high"),
    (re.compile(r"\bdefault[- ]cred", re.I),                            "high"),
    (re.compile(r"\bCVE-\d{4}-\d{4,7}\b.*\b(candidate|VULNERABLE|signal)\b", re.I), "medium"),
    (re.compile(r"\bsigning disabled\b|\bsigning enabled but not required\b", re.I), "medium"),
    (re.compile(r"\bCORS\b.*\breflect", re.I),                          "medium"),
    (re.compile(r"\bKEY_ONLY\b", re.I),                                 "medium"),
    (re.compile(r"\bAUTH OK\b", re.I),                                  "medium"),
    (re.compile(r"\b(OpenSSH|nginx|Apache|MySQL|PostgreSQL|Redis)\b", re.I), "low"),
]

# Markers we strip when the line is wrapped in dispatcher color codes
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _classify(line: str, rules: list[tuple[re.Pattern, str]]) -> str | None:
    """Return the severity for a line, or None if no rule matched."""
    line = _ANSI_RE.sub("", line)
    for pat, sev in rules:
        if pat.search(line):
            return sev
    return None


def _load_rules(path: Path | None) -> list[tuple[re.Pattern, str]]:
    rules: list[tuple[re.Pattern, str]] = list(_DEFAULT_RULES)
    if path:
        for ln in path.read_text().splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            obj = json.loads(ln)
            rules.append((re.compile(obj["pattern"], re.I), obj["severity"]))
    return rules


# ---------------------------------------------------- redaction
class Redactor:
    """Maintains a stable mapping from raw target tokens to <TARGET-N>."""
    def __init__(self, enable: bool):
        self.enable = enable
        self._map: dict[str, str] = {}
        self._counter = 0

    def _ip_re(self) -> re.Pattern:
        # IPv4 only; v6 is far more complex and engagement-rare relative to v4
        return re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __call__(self, text: str) -> str:
        if not self.enable:
            return text
        def _sub(m):
            key = m.group(0)
            if key not in self._map:
                self._counter += 1
                self._map[key] = f"<TARGET-{self._counter}>"
            return self._map[key]
        return self._ip_re().sub(_sub, text)


# ---------------------------------------------------- walker
def walk_findings(out_dir: Path, rules) -> Iterable[dict]:
    """Yield finding dicts. Each finding has:
        host, port, service, severity, line, evidence_path
    """
    for svc_dir in sorted(p for p in out_dir.iterdir() if p.is_dir()):
        service = svc_dir.name
        # Two layouts in use across the toolkit:
        #   $OUT/$service/<ip>/<file>          (most dispatchers)
        #   $OUT/$service/<ip>_<port>/<file>   (enum-jabber, enum-docker, ...)
        for host_dir in sorted(p for p in svc_dir.iterdir() if p.is_dir()):
            name = host_dir.name
            if "_" in name and name.rsplit("_", 1)[-1].isdigit():
                host, port = name.rsplit("_", 1)
            else:
                host, port = name, ""
            for fp in sorted(host_dir.rglob("*")):
                if not fp.is_file() or fp.stat().st_size == 0:
                    continue
                # Only scan text-ish files (skip JSON/XML — we'd re-parse them
                # which is more work than this report wants to do).
                try:
                    text = fp.read_text(errors="replace")
                except Exception:
                    continue
                for line in text.splitlines():
                    sev = _classify(line, rules)
                    if sev is None:
                        continue
                    yield {
                        "host": host,
                        "port": port,
                        "service": service,
                        "severity": sev,
                        "line": line.strip()[:300],
                        "evidence_path": str(fp.relative_to(out_dir)),
                    }
        # Also scan top-level _dispatcher.log / _hints.txt / _findings.txt
        for top_fp in sorted(svc_dir.glob("_*")):
            if not top_fp.is_file():
                continue
            try:
                text = top_fp.read_text(errors="replace")
            except Exception:
                continue
            for line in text.splitlines():
                sev = _classify(line, rules)
                if sev is None:
                    continue
                yield {
                    "host": "(dispatcher)",
                    "port": "",
                    "service": service,
                    "severity": sev,
                    "line": line.strip()[:300],
                    "evidence_path": str(top_fp.relative_to(out_dir)),
                }


# ---------------------------------------------------- renderers
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _summary(findings: list[dict]) -> dict:
    counts = defaultdict(int)
    by_service = defaultdict(lambda: defaultdict(int))
    hosts = set()
    services = set()
    for f in findings:
        counts[f["severity"]] += 1
        by_service[f["service"]][f["severity"]] += 1
        if f["host"] != "(dispatcher)":
            hosts.add(f["host"])
        services.add(f["service"])
    return {
        "hosts": sorted(hosts),
        "services": sorted(services),
        "counts": dict(counts),
        "by_service": {s: dict(v) for s, v in by_service.items()},
    }


def render_markdown(findings: list[dict], summary: dict, run_label: str,
                    redactor: Redactor) -> str:
    out = [f"# Findings report — {run_label}", ""]
    out.append(f"_Generated {datetime.datetime.now(datetime.timezone.utc).isoformat()}Z_")
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append(f"- **Hosts**: {len(summary['hosts'])}")
    out.append(f"- **Services**: {len(summary['services'])}")
    out.append("- **Findings by severity**:")
    for sev in ("critical", "high", "medium", "low"):
        n = summary["counts"].get(sev, 0)
        out.append(f"  - {sev}: {n}")
    out.append("")
    out.append("## Findings by service")
    out.append("")
    out.append("| Service | Critical | High | Medium | Low |")
    out.append("|---|---:|---:|---:|---:|")
    for svc in sorted(summary["by_service"]):
        c = summary["by_service"][svc]
        out.append(f"| {svc} | {c.get('critical',0)} | {c.get('high',0)} | {c.get('medium',0)} | {c.get('low',0)} |")
    out.append("")
    out.append("## Findings detail (CRITICAL + HIGH only)")
    out.append("")
    bucket = defaultdict(list)
    for f in findings:
        if f["severity"] in ("critical", "high"):
            bucket[f["host"]].append(f)
    for host in sorted(bucket):
        out.append(f"### {redactor(host)}")
        out.append("")
        out.append("| Service | Port | Sev | Line | Evidence |")
        out.append("|---|---|---|---|---|")
        for f in sorted(bucket[host], key=lambda x: (_SEV_ORDER[x["severity"]], x["service"])):
            line = redactor(f["line"]).replace("|", "\\|")
            out.append(f"| {f['service']} | {f['port']} | **{f['severity']}** | {line} | `{f['evidence_path']}` |")
        out.append("")
    return "\n".join(out) + "\n"


_HTML_STYLE = """
body { font-family: -apple-system, sans-serif; max-width: 1200px; margin: 2em auto; padding: 0 1em; color:#222; }
h1, h2, h3 { color: #111; }
h1 { border-bottom: 2px solid #444; padding-bottom: 0.2em; }
h2 { border-bottom: 1px solid #aaa; padding-bottom: 0.1em; margin-top: 2em; }
table { border-collapse: collapse; width: 100%; margin: 0.5em 0 1em 0; font-size: 0.92em; }
th, td { border: 1px solid #ccc; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #f4f4f4; }
td.critical, td .critical { color: #c00; font-weight: 600; }
td.high, td .high { color: #d80; font-weight: 600; }
code { background: #f4f4f4; padding: 1px 4px; border-radius: 3px; }
"""


def render_html(md_text: str) -> str:
    """Trivial Markdown -> HTML for the subset we emit. We don't pull in a
    Markdown library — operators may need to drop this on a stripped jump
    box. Supported: H1-H3, tables, lists, **bold**, `code`, paragraphs."""
    lines = md_text.splitlines()
    out = []
    in_table = False
    in_list = False
    in_para = False

    def close_para():
        nonlocal in_para
        if in_para:
            out.append("</p>"); in_para = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>"); in_list = False

    def close_table():
        nonlocal in_table
        if in_table:
            out.append("</table>"); in_table = False

    for raw in lines:
        line = html.escape(raw)
        # Headings
        m = re.match(r"^(#{1,3}) (.+)$", line)
        if m:
            close_para(); close_list(); close_table()
            level = len(m.group(1))
            out.append(f"<h{level}>{m.group(2)}</h{level}>")
            continue
        # Table separator row
        if re.match(r"^\|[-:| ]+\|$", line):
            continue
        # Table row
        if line.startswith("|") and line.endswith("|"):
            close_para(); close_list()
            cells = [c.strip() for c in line[1:-1].split("|")]
            if not in_table:
                out.append('<table><tr>' + "".join(f"<th>{_inline(c)}</th>" for c in cells) + "</tr>")
                in_table = True
            else:
                out.append("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in cells) + "</tr>")
            continue
        close_table()
        # List item
        if re.match(r"^\s*-\s+", line):
            close_para()
            if not in_list:
                out.append("<ul>"); in_list = True
            txt = re.sub(r"^\s*-\s+", "", line)
            out.append(f"<li>{_inline(txt)}</li>")
            continue
        close_list()
        # Italic-emphasis line
        if line.startswith("_") and line.endswith("_") and len(line) > 2:
            close_para()
            out.append(f"<p><i>{_inline(line[1:-1])}</i></p>")
            continue
        # Blank line
        if line.strip() == "":
            close_para()
            continue
        # Paragraph
        if not in_para:
            out.append("<p>"); in_para = True
        out.append(_inline(line))
    close_para(); close_list(); close_table()

    return (f"<!doctype html><html><head><meta charset='utf-8'><title>aratool report</title>"
            f"<style>{_HTML_STYLE}</style></head><body>" + "\n".join(out) + "</body></html>")


def _inline(s: str) -> str:
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


# ---------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out_dir", help="auto-enum output directory (the one passed to -o)")
    ap.add_argument("--label", default="", help="run label (default: dir name)")
    ap.add_argument("--severity-rules", help="one JSON object per line — adds custom severity rules")
    ap.add_argument("--redact", action="store_true",
                    help="replace IP addresses with <TARGET-N> for shareable output")
    ap.add_argument("--no-html", action="store_true", help="skip report.html")
    ap.add_argument("--findings-only", action="store_true",
                    help="just write findings.json (no .md or .html)")
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    if not out_dir.is_dir():
        print(_c(f"[!] not a directory: {out_dir}", "R"), file=sys.stderr)
        return 2

    rules = _load_rules(Path(args.severity_rules) if args.severity_rules else None)
    redactor = Redactor(args.redact)
    label = args.label or out_dir.name

    findings = list(walk_findings(out_dir, rules))
    summary = _summary(findings)

    # Always emit findings.json (machine-readable)
    findings_json = {
        "label": label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "redacted": args.redact,
        "summary": summary,
        "findings": findings,
    }
    if args.redact:
        for f in findings_json["findings"]:
            f["host"] = redactor(f["host"])
            f["line"] = redactor(f["line"])
        findings_json["summary"]["hosts"] = [redactor(h) for h in summary["hosts"]]
    (out_dir / "findings.json").write_text(json.dumps(findings_json, indent=2))
    print(_c(f"[+] findings.json written ({len(findings)} findings)", "G"))

    if args.findings_only:
        return 0

    md = render_markdown(findings, summary, label, redactor)
    (out_dir / "report.md").write_text(md)
    print(_c(f"[+] report.md written", "G"))

    if not args.no_html:
        (out_dir / "report.html").write_text(render_html(md))
        print(_c(f"[+] report.html written", "G"))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
