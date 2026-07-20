#!/usr/bin/env python3
"""nmap-parse.py — turn nmap output into a service inventory.

Reads .xml (preferred), .gnmap, or .nmap and emits JSON or per-service IP:port
lists. Designed for piping into auto-enum.sh dispatch.

Examples:
    # XML -> structured JSON
    ./nmap-parse.py scan.xml --json > inventory.json

    # Emit IP:port lines for a single service category
    ./nmap-parse.py scan.xml --service smb
    # 10.0.0.5:445
    # 10.0.0.6:445
    # ...

    # All services, grouped, plain output
    ./nmap-parse.py scan.gnmap --grouped

Service categories (matched on port AND nmap-detected service name):
    smb, ldap, kerberos, winrm, rdp, mssql, mysql, postgres, http, https,
    ssh, ftp, smtp, snmp, dns, nfs, redis, mongo, elastic, telnet, vnc,
    rsync, oracle, ipmi, pop3, imap, sip, mqtt, ajp.
"""

from __future__ import annotations
import argparse, json, re, sys
import xml.etree.ElementTree as _stdlib_ET
from pathlib import Path
from collections import defaultdict
from typing import Iterable

# ---------------------------------------------------------------- XML hardening
# Untrusted nmap XML can contain DOCTYPE declarations, external entities
# (XXE → arbitrary file disclosure / SSRF), and entity-expansion bombs
# (billion-laughs → CPU/memory DoS). Operator-only use is low risk, but a CI
# pipeline taking XML from a less-trusted source is not.
#
# Preferred: defusedxml.ElementTree — drop-in replacement that rejects DTDs
# and entity expansion by default. If unavailable, fall back to stdlib with
# a custom TreeBuilder target that rejects DOCTYPE explicitly.
try:
    import defusedxml.ElementTree as ET   # type: ignore[import-not-found]
    _XML_BACKEND = "defusedxml"
except ImportError:                       # noqa: BLE001
    ET = _stdlib_ET                       # type: ignore[assignment]
    _XML_BACKEND = "stdlib+hardened"
    print(
        "[!] defusedxml not installed — using hardened stdlib parser. "
        "For full XXE/billion-laughs immunity: pip install defusedxml",
        file=sys.stderr,
    )


# DTD constructs that enable XXE / billion-laughs.
#   * <!ENTITY ...>     declares an entity (XXE-via-internal-entity, billion-laughs)
#   * SYSTEM "..." or PUBLIC "..." inside DOCTYPE  (external DTD load)
# Plain `<!DOCTYPE nmaprun>` (no internal subset, no external ref) is benign and
# nmap emits one, so we must not blanket-reject DOCTYPE.
_DANGEROUS_DTD_RE = re.compile(
    rb"<!ENTITY|<!DOCTYPE\b[^>\[]*\b(SYSTEM|PUBLIC)\b",
    re.IGNORECASE,
)


def _parse_xml_hardened(path: Path) -> _stdlib_ET.ElementTree:
    """Stdlib parse path that pre-scans for the DTD constructs that enable
    XXE / billion-laughs. Used only when defusedxml is not installed —
    defusedxml's ElementTree.parse() rejects these via expat handlers and
    is preferred. The pre-scan is intentionally conservative; if it matches,
    we refuse rather than risk a misparse."""
    if _XML_BACKEND == "defusedxml":
        return ET.parse(path)                          # type: ignore[return-value]
    # Pre-scan the raw bytes for dangerous DTD constructs. We scan the WHOLE
    # file (not a fixed prolog cap): an attacker can pad the prolog with a large
    # comment to push a DOCTYPE/ENTITY past any bounded scan. Refuse files above
    # a generous safety cap rather than scan unbounded memory.
    with open(path, "rb") as f:
        content = f.read(100_000_000)
        if f.read(1):
            raise ValueError(
                "refusing to parse XML — dangerous DTD scan: file exceeds the "
                "100MB safety cap; install defusedxml for safe streaming parse"
            )
    m = _DANGEROUS_DTD_RE.search(content)
    if m:
        raise ValueError(
            f"refusing to parse XML — dangerous DTD construct detected "
            f"({m.group(0)!r}) in the prolog. Possible XXE / billion-laughs. "
            f"Install defusedxml (pip install defusedxml) for safe parsing of "
            f"XML files containing entity declarations."
        )
    return _stdlib_ET.parse(path)

# Map service-category -> (port set, service-name regex). A host:port matches
# if its port is in the port set OR the nmap-detected service name matches.
SERVICE_MAP = {
    "smb":        ({139, 445},                  r"^(microsoft-ds|netbios-ssn|smb)"),
    "ldap":       ({389, 636, 3268, 3269},      r"^(ldap|ldapssl|globalcat)"),
    "kerberos":   ({88, 464},                   r"^(kerberos|kpasswd)"),
    "winrm":      ({5985, 5986, 47001},         r"^(wsman|winrm)"),
    "rdp":        ({3389},                      r"^(ms-wbt-server|rdp)"),
    "mssql":      ({1433, 1434},                r"^(ms-sql|mssql)"),
    "mysql":      ({3306},                      r"^mysql"),
    "postgres":   ({5432},                      r"^postgresql"),
    "http":       ({80, 81, 8000, 8008, 8080, 8081, 8888, 7001, 7002, 9000, 9090, 5000}, r"^(http|http-proxy|http-alt)$"),
    "https":      ({443, 4443, 8443, 9443, 10443}, r"^(https|http-alt-ssl|ssl/http)"),
    "ssh":        ({22, 2222},                  r"^ssh"),
    "ftp":        ({21, 990},                   r"^(ftp|ftps)"),
    "smtp":       ({25, 465, 587, 2525},        r"^(smtp|smtps|submission)"),
    "snmp":       ({161, 162},                  r"^snmp"),
    "dns":        ({53},                        r"^domain"),
    "nfs":        ({2049, 111},                 r"^(nfs|rpcbind|portmap)"),
    "redis":      ({6379},                      r"^redis"),
    "mongo":      ({27017, 27018, 27019},       r"^mongo"),
    "elastic":    ({9200, 9300},                r"^elastic"),
    "telnet":     ({23, 992},                   r"^telnet"),
    "vnc":        ({5800, 5900, 5901, 5902},    r"^vnc"),
    "rsync":      ({873},                       r"^rsync"),
    "oracle":     ({1521, 1522, 1526},          r"^oracle"),
    "ipmi":       ({623},                       r"^(asf-rmcp|ipmi)"),
    "pop3":       ({110, 995},                  r"^pop3"),
    "imap":       ({143, 993},                  r"^imap"),
    "ajp":        ({8009},                      r"^ajp13"),
    "sip":        ({5060, 5061},                r"^sip"),
    "mqtt":       ({1883, 8883},                r"^mqtt"),
    "activemq":   ({61616, 8161, 5672, 61613}, r"^(activemq|stomp|amqp)"),
    "jmx":        ({1099, 9999, 9010, 11099},   r"^(java-rmi|jmx|jmxrmi)"),
    # P1 services added in iteration C. Memcached (11211) is unauth by default
    # and frequently world-reachable. RabbitMQ mgmt (15672) ships with the
    # famous guest/guest default. CouchDB (5984/6984) has CVE-2017-12635 +
    # CVE-2022-24706 chains. etcd (2379) holds the entire k8s control-plane
    # secret store on misconfigured clusters.
    "rabbitmq":    ({5672, 15672, 15671, 5671}, r"^(amqp|rabbitmq)"),
    "memcached":   ({11211},                    r"^memcached"),
    "couchdb":     ({5984, 6984},               r"a^"),  # nmap fingerprints as http
    "etcd":        ({2379, 2380},               r"a^"),  # nmap fingerprints as ssl/http or http
    # Modern cloud-native services (REVIEW-004). NATS 4222 (client INFO banner) +
    # 8222 (monitoring /varz leaks full server config incl. routes/creds).
    # ClickHouse 8123 HTTP is unauth on the default `default` user out of the box.
    "nats":        ({4222, 8222},               r"^nats"),
    "clickhouse":  ({8123},                      r"a^"),  # fingerprints as http
    # Container-orchestration APIs added in iteration B. docker_api is the
    # remote Docker daemon (2375 unauth = direct host RCE — flag as CRITICAL);
    # 2376 is TLS-authenticated. Kubernetes splits into apiserver (6443 TLS,
    # 8080 legacy-insecure) and kubelet (10250 — exec without auth in older
    # configs). Both use a never-match regex because nmap fingerprints them
    # as generic ssl/http / http; the dispatcher does product-detection.
    "docker":      ({2375, 2376}, r"a^"),
    "kubernetes":  ({6443, 8080, 10250, 10255, 10256}, r"a^"),
    # Two XMPP-family categories so dispatchers can route differently:
    # `xmpp` covers the standard server-side protocol ports (c2s, s2s, BOSH/WS,
    # link-local, Openfire file-transfer proxy), while `openfire-admin` flags
    # the Openfire admin console (separate dispatcher path — CVE-2023-32315
    # detection / exploitation lives there, not in the generic xmpp probe).
    "xmpp":            ({5222, 5223, 5269, 5280, 5281, 5298, 7777},
                        r"^(xmpp|jabber|xmpp-client|xmpp-server)"),
    # Openfire's admin console listens on 9090/9091 and nmap fingerprints it
    # as plain "http"/"https" — so we deliberately use a no-match regex here
    # to ensure this category is port-set-only (otherwise every http port would
    # collide on openfire-admin). The dedicated dispatcher handles version
    # detection from the served HTML.
    "openfire-admin":  ({9090, 9091}, r"a^"),  # `a^` is the canonical never-match regex
    # Iteration E2 — Tier 2a high-yield services
    "cassandra":   ({9042, 9160},          r"^(cassandra|apani1)"),
    "consul":      ({8500, 8501},          r"a^"),  # fingerprints as http
    "influxdb":    ({8086, 8088},          r"^influxdb"),
    "ipp":         ({631},                 r"^(ipp|cups)"),
    "kafka":       ({9092, 9093},          r"^kafka"),
    "msrpc":       ({135},                 r"^(msrpc|ms-rpc|epmap)"),
    "netbios-ns":  ({137},                 r"^netbios-ns"),
    "neo4j":       ({7474, 7687},          r"^neo4j"),
    "solr":        ({8983, 8984},          r"a^"),  # fingerprints as http
    "vault":       ({8200, 8201},          r"a^"),  # fingerprints as http/https
    "zookeeper":   ({2181, 2182},          r"^zookeeper"),
    # I-K (low-risk iteration-I cluster) — network print services
    "print":      ({9100, 515},             r"^(jetdirect|hp-pdl-datastr|printer|lpd|spooler)"),
    # I-C — FlexNet Publisher / FLEXlm license servers (engineering/science)
    "flexnet":    ({27000, 27001, 27002, 27003, 27004, 27005, 27006, 27007, 27008, 27009},
                   r"^(flexlm|lm-x|lmgrd)"),
    # I-F — HPC schedulers (Slurm slurmctld + slurmd, HTCondor collector, YARN RM)
    "hpc":        ({6817, 6818, 9618, 8088},
                   r"^(slurmctld|slurmd|condor|yarn|hadoop|resourcemanager)"),
    # I-G — monitoring / lab-data (Zabbix agent + server, NRPE, Splunk mgmt)
    "monitoring": ({10050, 10051, 5666, 8089},
                   r"^(zabbix|nrpe|nagios|splunk|splunkd)"),
    # I-H — backup infrastructure detection (Veeam REST, CommVault, NetBackup)
    "backup":     ({9392, 8400, 81, 1556, 7778, 7779, 8543},
                   r"^(veeam|commvault|netbackup|vnetd|pbx_exchange|bpcd|avamar|cohesity|rubrik)"),
    # Operator-centric expansion — artifact/container registries, platform
    # control planes, and storage fabrics. HTTP product detection catches
    # these on random ports; these categories prioritize common fixed ports.
    "artifact":   ({5000, 8081, 8082, 8083},
                   r"^(docker-registry|registry|nexus|artifactory|harbor)"),
    "platform":   ({4646, 9443},
                   r"^(nomad|portainer|rancher|argocd|argo-cd)"),
    "storage":    ({3260, 3300, 6789, 7480, 9000, 9001, 24007},
                   r"^(iscsi|ceph|radosgw|gluster|glusterd|minio)"),
    # T4 — OT/ICS sentinel category. Routes the OT ports so they appear in
    # surface-area inventory, but auto-enum.sh does NOT dispatch to any
    # standalones/ot/ script — operators must invoke standalones/ot/ot-enum.sh --ics-confirm by hand
    # (ADR-005 D1). The category name `ot-untouched` is intentional: the
    # auto-enum dispatcher loop has no `enum-ot-untouched.sh`, so a port that
    # matches will fall through to the "no dispatcher" path with a hint.
    "ot-untouched": ({502, 102, 44818, 47808, 4840, 20000, 2404},
                     r"^(modbus|mbap|iso-tsap|ethernet-ip|bacnet|opcua|opc-ua|dnp3|iec-104)"),
    # Iteration E4 — opt-in aggressive UDP services. These categories route but
    # auto-enum.sh strips them from the auto-derived service list by default;
    # enable with --ike / --slp / --radius / --aggressive. Each dispatcher also
    # checks an ENUM_RUN_X=1 env gate (set by auto-enum on the flag) and refuses
    # to run otherwise.
    "ike":        ({500, 4500},              r"^(isakmp|ike)"),
    "slp":        ({427},                    r"^svrloc"),
    "radius":     ({1812, 1813, 1645, 1646}, r"^radius"),
}


def categorize(port: int, service: str) -> list[str]:
    cats = []
    svc = (service or "").lower()
    for cat, (ports, regex) in SERVICE_MAP.items():
        if port in ports:
            cats.append(cat); continue
        if re.match(regex, svc):
            cats.append(cat)
    return cats


def parse_xml(path: Path):
    """Yield dicts: {ip, hostname, port, proto, state, service, product, version, extrainfo}"""
    tree = _parse_xml_hardened(path)
    for host in tree.iterfind("host"):
        # skip down hosts
        st = host.find("status")
        if st is not None and st.get("state") not in ("up", "unknown"):
            continue
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")
        hostname = ""
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name") or ""
        for port in host.iterfind("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port.get("portid")
            if portid is None or not portid.isdigit() or not (1 <= int(portid) <= 65535):
                continue   # hand-edited / truncated scan — skip bogus/out-of-range port
            svc = port.find("service")
            yield {
                "ip":        ip,
                "hostname":  hostname,
                "port":      int(portid),
                "proto":     port.get("protocol"),
                "state":     "open",
                "service":   (svc.get("name") if svc is not None else "") or "",
                "product":   (svc.get("product") if svc is not None else "") or "",
                "version":   (svc.get("version") if svc is not None else "") or "",
                "extrainfo": (svc.get("extrainfo") if svc is not None else "") or "",
                "tunnel":    (svc.get("tunnel") if svc is not None else "") or "",
            }


GNMAP_LINE = re.compile(r"Host:\s+(\S+)\s+\(([^)]*)\)\s+Ports:\s+(.+?)(?:\s+Ignored State.*)?$")

def parse_gnmap(path: Path):
    """Greppable format: Host: <ip> (<hostname>) Ports: 22/open/tcp//ssh///, 80/open/tcp//http/// """
    for line in path.read_text(errors="replace").splitlines():
        m = GNMAP_LINE.search(line)
        if not m:
            continue
        ip, hostname, ports_blob = m.groups()
        for chunk in ports_blob.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = chunk.split("/")
            if len(parts) < 5 or parts[1] != "open":
                continue
            try:
                port = int(parts[0])
            except ValueError:
                continue
            yield {
                "ip":        ip,
                "hostname":  hostname,
                "port":      port,
                "proto":     parts[2],
                "state":     "open",
                "service":   parts[4],
                # gnmap Ports: field layout is
                # portid/state/proto/owner/service/rpcinfo/version/ — so parts[6]
                # is the version banner, not the product. (XML is the preferred
                # path and gets product/version right; this only affects gnmap.)
                "product":   "",
                "version":   parts[6] if len(parts) > 6 else "",
                "extrainfo": "",
                "tunnel":    "",
            }


NMAP_HOST_RE  = re.compile(r"^Nmap scan report for\s+(\S+)(?:\s+\(([^)]+)\))?")
NMAP_PORT_RE  = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?")

def parse_nmap(path: Path):
    """Normal nmap text output. Less reliable but works as a fallback."""
    cur_ip = cur_host = None
    host_down = False
    for line in path.read_text(errors="replace").splitlines():
        m = NMAP_HOST_RE.match(line)
        if m:
            a, b = m.groups()
            # Either "Nmap scan report for 10.0.0.1" or "Nmap scan report for host (10.0.0.1)"
            if b:
                cur_host, cur_ip = a, b
            else:
                cur_host, cur_ip = "", a
            host_down = False
            continue
        if line.startswith("Host seems down") or "0 hosts up" in line:
            host_down = True
            continue
        if host_down or not cur_ip:
            continue
        m = NMAP_PORT_RE.match(line)
        if m:
            port, proto, svc, rest = m.groups()
            # Keep the full version string instead of truncating to first word.
            yield {
                "ip":        cur_ip,
                "hostname":  cur_host or "",
                "port":      int(port),
                "proto":     proto,
                "state":     "open",
                "service":   svc,
                "product":   (rest or "").strip(),
                "version":   "",
                "extrainfo": "",
                "tunnel":    "",
            }


def dispatch(path: Path) -> Iterable[dict]:
    suf = path.suffix.lower()
    if suf == ".xml":
        return parse_xml(path)
    if suf == ".gnmap":
        return parse_gnmap(path)
    if suf == ".nmap":
        return parse_nmap(path)
    # Heuristic on contents
    head = path.read_text(errors="replace")[:512]
    if head.lstrip().startswith("<?xml"):
        return parse_xml(path)
    if "Host: " in head and "Ports:" in head:
        return parse_gnmap(path)
    return parse_nmap(path)


def main():
    ap = argparse.ArgumentParser(description="Parse nmap output into a service inventory.")
    ap.add_argument("input", help="Path to .xml / .gnmap / .nmap file")
    out = ap.add_mutually_exclusive_group()
    out.add_argument("--json",     action="store_true", help="Emit JSON inventory")
    out.add_argument("--grouped",  action="store_true", help="Emit grouped text by service category")
    out.add_argument("--service",  metavar="CAT", help="Emit IP:port lines for one service category")
    out.add_argument("--unknown",  action="store_true", help="Emit IP:port lines for ports that match NO category")
    out.add_argument("--all-ports", action="store_true", help="Emit every open IP:port (categorized + uncategorized)")
    out.add_argument("--list-categories", action="store_true", help="Print known categories")
    ap.add_argument("--with-service", action="store_true", help="Append service/product/version columns to --service / --unknown / --all-ports output")
    ap.add_argument("--no-cat",    action="store_true", help="Skip categorization (raw entries)")
    args = ap.parse_args()

    if args.list_categories:
        for c in sorted(SERVICE_MAP):
            ports, regex = SERVICE_MAP[c]
            print(f"{c:10s}  ports={sorted(ports)}  svc={regex}")
        return 0

    path = Path(args.input)
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr); return 2

    try:
        entries = list(dispatch(path))
    except Exception as e:                              # noqa: BLE001
        # Surface DOCTYPE / entity-expansion rejections cleanly. Cover both
        # backends: defusedxml raises defusedxml.common.EntitiesForbidden /
        # DTDForbidden, and the stdlib fallback's _RejectDTD raises ValueError.
        name = type(e).__name__
        if name in ("EntitiesForbidden", "DTDForbidden", "ExternalReferenceForbidden") \
           or "DOCTYPE" in str(e) or "Entit" in str(e) or "dangerous DTD" in str(e):
            print(
                f"error: refusing to parse XML — {name}: {e}\n"
                f"       file may contain XXE / billion-laughs payload. "
                f"If the file is genuinely trusted, parse with an unhardened tool.",
                file=sys.stderr,
            )
            return 3
        if isinstance(e, _stdlib_ET.ParseError):
            print(f"error: malformed XML in {path}: {e}", file=sys.stderr)
            return 2
        raise
    if not entries:
        # Distinguish "couldn't parse this" from "parsed fine, nothing open".
        # A genuinely empty scan still carries a structural anchor (Host:,
        # Nmap scan report, <nmaprun, Status:). None present = the input is not
        # recognizable nmap output — fail loud (rc2) rather than emit an empty
        # inventory that is byte-identical to a clean all-hosts-down scan.
        sample = path.read_text(errors="replace")
        anchored = (
            "Host: " in sample or "Nmap scan report for" in sample
            or "Nmap done" in sample or "Status: Up" in sample
            or "Status: Down" in sample or "<nmaprun" in sample
            or sample.lstrip().startswith("<?xml")
        )
        if not anchored:
            print(
                f"error: {path}: unrecognized or empty nmap output — no host / "
                f"scan-report records found. Pass real .xml/.gnmap/.nmap output.",
                file=sys.stderr,
            )
            return 2
    for e in entries:
        e["categories"] = [] if args.no_cat else categorize(e["port"], e["service"])

    def fmt_ip_port(ip, port):
        # Wrap IPv6 in brackets so the result is unambiguous to shell splitters.
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

    def emit(e):
        line = fmt_ip_port(e["ip"], e["port"])
        if args.with_service:
            extras = " ".join(x for x in [e.get("service",""), e.get("product",""), e.get("version","")] if x).strip()
            if extras: line += f"\t{extras}"
        return line

    # Default to JSON if no mode chosen
    if args.json or (not args.grouped and not args.service and not args.unknown and not args.all_ports):
        # group by category for convenience as well
        bucket = defaultdict(list)
        unknown = []
        for e in entries:
            ip_port = fmt_ip_port(e["ip"], e["port"])
            if e["categories"]:
                for c in e["categories"]:
                    bucket[c].append(ip_port)
            else:
                unknown.append(ip_port)
        out = {
            "summary": {
                "hosts":      len({e["ip"] for e in entries}),
                "open_ports": len(entries),
                "unknown":    sorted(set(unknown)),
                "categories": {c: sorted(set(v)) for c, v in bucket.items()},
            },
            "entries": entries,
        }
        print(json.dumps(out, indent=2))
        return 0

    if args.service:
        cat = args.service.lower()
        seen = set()
        for e in entries:
            if cat in e["categories"]:
                key = fmt_ip_port(e["ip"], e["port"])
                if key in seen: continue
                seen.add(key)
                print(emit(e))
        return 0

    if args.unknown:
        seen = set()
        for e in entries:
            if not e["categories"]:
                key = fmt_ip_port(e["ip"], e["port"])
                if key in seen: continue
                seen.add(key)
                print(emit(e))
        return 0

    if args.all_ports:
        seen = set()
        for e in entries:
            key = fmt_ip_port(e["ip"], e["port"])
            if key in seen: continue
            seen.add(key)
            print(emit(e))
        return 0

    if args.grouped:
        bucket = defaultdict(list)
        for e in entries:
            ip_port = fmt_ip_port(e["ip"], e["port"])
            for c in e["categories"]:
                bucket[c].append(f"{ip_port}  {e['service']} {e['product']} {e['version']}".strip())
        for c in sorted(bucket):
            print(f"\n=== {c.upper()} ===")
            for line in sorted(set(bucket[c])):
                print(f"  {line}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
