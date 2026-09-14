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
object per line — see standalones/jabber/README.md for an example).

--redact replaces target IPs/hostnames with <TARGET-N> for shareable output.
"""

from __future__ import annotations

import argparse
import hashlib
import datetime
import html
import ipaddress
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


_FINDINGS_SCHEMA_VERSION = "2"
_DEFAULT_SERVICE_METADATA: dict[str, dict] = {
    "defaults": {},
    "services": {},
}
_FINDING_ID_PREFIX = f"AR-{_FINDINGS_SCHEMA_VERSION}"
_SEVERITY_TO_CONFIDENCE = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
}
_SEVERITY_TO_PRIORITY = {
    "critical": "P0",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
}
_SEVERITY_TO_TAGS = {
    "critical": ["critical", "triage:high"],
    "high": ["high", "triage:med"],
    "medium": ["medium", "triage:low"],
    "low": ["low", "triage:low"],
}
_SEVERITY_TO_NEXT_ACTIONS = {
    "critical": ["validate", "contain", "remediate", "track"],
    "high": ["validate", "remediate", "track"],
    "medium": ["validate", "track"],
    "low": ["review", "track"],
}


def _load_service_metadata(out_dir: Path | None = None) -> dict[str, dict]:
    """Load repository metadata, then overlay run-local metadata.

    Precedence is repository defaults < ``<out>/network`` < ``<out>``.  Both
    defaults and individual service records are merged field-by-field so a
    run-local file can override one title/priority without copying the catalog.
    """
    files: list[Path] = [Path(__file__).resolve().parent / "service-metadata.json"]
    if out_dir is not None:
        files.append(out_dir / "network" / "service-metadata.json")
        files.append(out_dir / "service-metadata.json")

    merged_defaults: dict[str, object] = {}
    merged_services: dict[str, dict] = {}
    for fp in files:
        if not fp.is_file():
            continue
        try:
            raw = json.loads(fp.read_text(errors="replace"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue

        services_raw = raw.get("services")
        if isinstance(services_raw, dict):
            services = services_raw
        else:
            services = {
                k: v for k, v in raw.items()
                if isinstance(k, str) and k not in {"defaults"}
                and isinstance(v, dict)
            }

        merged_defaults.update(_coerce_service_metadata_fields(raw.get("defaults")))
        for service, cfg in _coerce_service_metadata_services(services).items():
            merged_services[service] = {**merged_services.get(service, {}), **cfg}
    return {"defaults": merged_defaults, "services": merged_services}


def _coerce_service_metadata_fields(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        return {}
    return dict((k, v) for k, v in raw.items() if isinstance(k, str))


def _coerce_service_metadata_services(raw: object) -> dict[str, dict]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict] = {}
    for service, cfg in raw.items():
        if not isinstance(service, str):
            continue
        cfg_obj = _coerce_service_metadata_fields(cfg)
        if cfg_obj:
            out[service] = cfg_obj
    return out


def _coerce_list_text(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            continue
        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return out


def _coerce_str(value: object, *, fallback: str = "") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _finding_title(service: str, severity: str, line: str, cfg: dict[str, object]) -> str:
    title = _coerce_str(cfg.get("title"), fallback="")
    if not title:
        title = _coerce_str(cfg.get("title_template"), fallback="")
    if title:
        try:
            return title.format(service=service, severity=severity, line=line.strip())
        except (IndexError, KeyError):
            return title
    head = line.strip().split(":", 1)[0].strip()
    if head:
        return f"{service.upper()}: {head[:90]}"
    return f"{service.upper()}: {severity.upper()} finding"


def _compose_tags(service: str, severity: str, cfg: dict[str, object]) -> list[str]:
    tags = [severity, service]
    tags.extend(_SEVERITY_TO_TAGS.get(severity, []))
    tags.extend(_coerce_list_text(cfg.get("tags")))
    tags.extend(_coerce_list_text(cfg.get("categories")))
    deduped: list[str] = []
    seen: set[str] = set()
    for t in tags:
        if t in seen:
            continue
        seen.add(t)
        deduped.append(t)
    return deduped


def _next_actions(cfg: dict[str, object], severity: str) -> list[str]:
    actions = _coerce_list_text(cfg.get("next_actions"))
    return actions or _SEVERITY_TO_NEXT_ACTIONS.get(severity, ["track"])


def _structured_finding(
    host: str,
    port: str,
    service: str,
    severity: str,
    line: str,
    evidence_path: str,
    service_metadata: dict[str, dict],
    protocol: str = "",
) -> dict:
    cfg_defaults = _coerce_service_metadata_fields(service_metadata.get("defaults", {}))
    cfg_service = _coerce_service_metadata_fields(service_metadata.get("services", {}).get(service, {}))
    cfg = {**cfg_defaults, **cfg_service}
    complete_line = _clean_line(line).strip()
    normalized_line = complete_line[:300]
    evidence_identity = hashlib.sha256(complete_line.encode()).hexdigest()
    _id_seed = f"{service}|{host}|{port}|{protocol}|{severity}|{evidence_identity}"
    finding_id = f"{_FINDING_ID_PREFIX}-{hashlib.sha1(_id_seed.encode()).hexdigest()[:14]}"
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "service": service,
        "severity": severity,
        "line": normalized_line,
        "evidence_path": evidence_path,
        "evidence_paths": [evidence_path] if evidence_path else [],
        "evidence_identity": evidence_identity,
        "finding_id": finding_id,
        "title": _finding_title(service, severity, normalized_line, cfg),
        "confidence": _coerce_str(cfg.get("confidence"), fallback=_SEVERITY_TO_CONFIDENCE.get(severity, "medium")),
        "priority": _coerce_str(cfg.get("priority"), fallback=_SEVERITY_TO_PRIORITY.get(severity, "P3")),
        "tags": _compose_tags(service, severity, cfg),
        "next_actions": _next_actions(cfg, severity),
        "triage_status": _coerce_str(cfg.get("triage_status"), fallback="new"),
        "schema_version": _FINDINGS_SCHEMA_VERSION,
    }


# ---------------------------------------------------- severity rules
# (regex, severity) pairs evaluated in order. First match wins per line.
# Anchored on the markers the dispatchers emit (err/hit/log color flags +
# the literal "CRITICAL"/"EXPOSED"/"UNAUTH"/etc. words in their log lines).
_DEFAULT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bCRITICAL\b", re.I),                                 "critical"),
    (re.compile(r"\bUNAUTH (?:Docker|etcd|/v2/keys|kubelet|apiserver)\b", re.I), "critical"),
    # REVIEW-004 service-additions: NATS + ClickHouse (unauth-by-default).
    (re.compile(r"\bCRITICAL: UNAUTH NATS\b", re.I),                    "critical"),
    (re.compile(r"\bNATS auth_required=false\b", re.I),                "critical"),
    (re.compile(r"\bCRITICAL: UNAUTH ClickHouse\b", re.I),             "critical"),
    (re.compile(r"\bClickHouse HTTP interface alive\b", re.I),         "low"),
    (re.compile(r"\bNATS INFO banner\b", re.I),                        "low"),
    # enum-http.sh AD-surface detectors (ESC8 / Exchange / ADFS).
    (re.compile(r"\bESC8 relay target\b", re.I),                       "high"),
    (re.compile(r"\bExchange endpoint .* detected\b", re.I),           "medium"),
    (re.compile(r"\bADFS sign-on page detected\b", re.I),              "medium"),
    # REVIEW-004 TCP service-additions.
    (re.compile(r"\bUNAUTH git daemon\b", re.I),                       "critical"),
    (re.compile(r"\bOPEN PROXY:", re.I),                               "critical"),
    (re.compile(r"\bX11 OPEN DISPLAY\b", re.I),                        "critical"),
    (re.compile(r"\bTFTP readable config", re.I),                      "critical"),
    (re.compile(r"\bUNAUTH Couchbase mgmt\b", re.I),                   "critical"),
    (re.compile(r"\bUNAUTH RethinkDB\b", re.I),                        "critical"),
    (re.compile(r"\bUNAUTH Redis\b", re.I),                            "critical"),
    (re.compile(r"\bfinger responds with user info\b", re.I),         "medium"),
    (re.compile(r"\bAFP (?:server|shares)\b", re.I),                  "low"),
    (re.compile(r"\binsecure apiserver\b", re.I),                       "critical"),
    (re.compile(r"\bauth bypass\b", re.I),                              "critical"),
    (re.compile(r"\bcipher 0\b", re.I),                                 "critical"),
    (re.compile(r"\bremote command execution\b", re.I),                 "critical"),
    (re.compile(r"\bguest:guest\b", re.I),                              "critical"),
    (re.compile(r"\bEXPOSED\b", re.I),                                  "high"),
    # E2 tier-2a medium rules that contain "UNAUTH" — must precede the generic UNAUTH high rule
    # so first-match-wins classifies them at the intended severity.
    (re.compile(r"\bCUPS UNAUTH and POTENTIALLY VULN\b", re.I),         "high"),
    (re.compile(r"\bCUPS UNAUTH:", re.I),                               "medium"),
    (re.compile(r"\bConsul UNAUTH agent API:", re.I),                   "medium"),
    (re.compile(r"\bUNAUTH\b", re.I),                                   "high"),
    # E1 tier-1 dispatcher-specific HIGH rules (documented intent, survive generic rule rewrite)
    (re.compile(r"\bAJP responding without auth\b", re.I),               "high"),
    (re.compile(r"\bOracle (?:TNS:|SIDs discovered)", re.I),             "high"),
    (re.compile(r"\bPOP3 (?:plaintext-auth allowed|AUTH SUCCESS)", re.I),"high"),
    (re.compile(r"\bIMAP (?:plaintext-auth allowed|AUTH SUCCESS)", re.I),"high"),
    (re.compile(r"\bTelnet (?:open|device):", re.I),                     "high"),
    (re.compile(r"\brsync HIGH-VALUE module exposed", re.I),             "high"),
    (re.compile(r"\bMQTT UNAUTH broker\b", re.I),                        "high"),
    (re.compile(r"\bSIP service:", re.I),                                "high"),
    (re.compile(r"\bTRUST AUTH\b", re.I),                               "high"),
    (re.compile(r"\bANON AUTH\b", re.I),                                "high"),
    (re.compile(r"\bUSER_EXISTS\b", re.I),                              "high"),
    (re.compile(r"\bRealVNC\b.*\bbypass\b", re.I),                      "high"),
    (re.compile(r"\balg=none\b", re.I),                                 "high"),
    (re.compile(r"\bdefault[- ]cred", re.I),                            "high"),
    # E2 tier-2a HIGH rules
    (re.compile(r"\bZookeeper 4LW exposed:", re.I),                     "high"),
    (re.compile(r"\bZookeeper config exposed \(HIGH-VALUE\)", re.I),    "high"),
    (re.compile(r"\bCassandra UNAUTH CQL:", re.I),                      "high"),
    (re.compile(r"\bKafka UNAUTH broker:", re.I),                       "high"),
    (re.compile(r"\bNeo4j UNAUTH HTTP API:", re.I),                     "high"),
    (re.compile(r"\bNeo4j DEFAULT CRED \(neo4j/neo4j\) WORKED:", re.I),"high"),
    (re.compile(r"\bInfluxDB UNAUTH query API:", re.I),                 "high"),
    (re.compile(r"\bConsul UNAUTH KV dump \(HIGH-VALUE\)", re.I),       "high"),
    (re.compile(r"\bVault NOT INITIALIZED \(claim-init opportunity\)", re.I), "high"),
    (re.compile(r"\bNetBIOS workgroup mismatch \(HIGH-VALUE", re.I),    "high"),
    # E2 tier-2a MEDIUM rules
    (re.compile(r"Solr reachable:.+ — (1\.|2\.|3\.|4\.|5\.|6\.|7\.|8\.[0-9]\.|8\.10|8\.11\.[0-3])", re.I), "medium"),
    (re.compile(r"\bSolr cores exposed:", re.I),                        "medium"),
    (re.compile(r"\bMSRPC anonymous srvinfo:", re.I),                   "medium"),
    # Linux standalone privesc markers (container-detect / capabilities / group)
    # so they grade when run individually and fed to report.py (auto-enum path).
    (re.compile(r"\bdocker\.sock present\b", re.I),                    "critical"),
    (re.compile(r"\b(release_agent|notify_on_release|core_pattern|sysrq-trigger) writable\b", re.I), "critical"),
    (re.compile(r"\bCAP_SYS_ADMIN held\b|\blooks privileged\b", re.I), "critical"),
    (re.compile(r"\bpossible host PID namespace\b", re.I),             "high"),
    (re.compile(r"serviceaccount/token\b", re.I),                      "high"),
    (re.compile(r"\bcap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace|sys_module|sys_rawio)\S*\+ep", re.I), "high"),
    (re.compile(r"^\s*\[\+\]\s*(docker|lxd|lxc|disk|shadow|adm)\b", re.I | re.M), "high"),
    # redis-rce-lua.sh — Lua EVAL RCE surface on modern Redis.
    (re.compile(r"\bEVAL scripting REACHABLE\b", re.I),                "high"),
    (re.compile(r"\bLUA_RCE: CVE-2024-31449 candidate\b", re.I),       "high"),
    # enum-redis.sh — CVE-2022-0543 + Sentinel (the UNAUTH Redis critical is
    # hoisted above the generic UNAUTH→high rule; see near the git/couchbase block).
    (re.compile(r"\bCVE-2022-0543 candidate\b", re.I),                 "critical"),
    (re.compile(r"\bRedis Sentinel\b.*master topology", re.I),         "medium"),
    # proc-hardening-check.sh — weak sysctl/LSM/proc hardening (host audit).
    (re.compile(r"HARDENING:.*(ptrace_scope=0|unprivileged_bpf_disabled=0|suid_dumpable)", re.I), "medium"),
    (re.compile(r"\bHARDENING:\b", re.I),                              "low"),
    # regreSSHion is a pre-auth RCE — grade it high, ahead of the generic CVE rule.
    (re.compile(r"CVE-2024-6387 \(regreSSHion\)", re.I),                "high"),
    (re.compile(r"\bCVE-\d{4}-\d{4,7}\b.*\b(candidate|VULNERABLE|signal)\b", re.I), "medium"),
    (re.compile(r"\bsigning disabled\b|\bsigning enabled but not required\b", re.I), "medium"),
    (re.compile(r"\bCORS\b.*\breflect", re.I),                          "medium"),
    (re.compile(r"\bKEY_ONLY\b", re.I),                                 "medium"),
    (re.compile(r"\bAUTH OK\b", re.I),                                  "medium"),
    # E3 HTTP product-detect rules — CRITICAL for unauth Tomcat Manager and Jenkins Groovy console;
    # HIGH for all other unauth product exposures; MEDIUM for Spark UI (lower-impact API).
    # Ordered: most-specific (CRITICAL) first so first-match-wins classifies correctly.
    (re.compile(r"\bUNAUTH: Tomcat Manager exposed:", re.I),            "critical"),
    (re.compile(r"\bUNAUTH: Tomcat host-manager exposed:", re.I),       "critical"),
    (re.compile(r"\bUNAUTH: Jenkins API exposed:", re.I),               "critical"),
    (re.compile(r"\bCRITICAL: Jenkins Groovy script console reachable:", re.I), "critical"),
    (re.compile(r"\bJenkins user enumeration exposed:", re.I),          "high"),
    (re.compile(r"\bUNAUTH: GitLab API exposed:", re.I),                "high"),
    (re.compile(r"\bUNAUTH: SonarQube system info exposed:", re.I),     "high"),
    (re.compile(r"\bUNAUTH: Grafana datasources exposed:", re.I),       "high"),
    (re.compile(r"\bUNAUTH: Prometheus config exposed:", re.I),         "high"),
    (re.compile(r"\bHadoop NameNode UI exposed:", re.I),                "high"),
    (re.compile(r"\bHadoop JMX endpoint exposed:", re.I),               "high"),
    (re.compile(r"\bSpark UI applications API exposed:", re.I),         "medium"),
    # E4 opt-in aggressive UDP probes — IKE, SLP, RADIUS, vCenter.
    # Ordered: CRITICAL first (PSK hash harvest, SLP amplification, RADIUS bogus-accept
    # already caught by the top-level \bCRITICAL\b rule, but listed here explicitly
    # so the intent is clear and the rule survives a future rule-list rewrite).
    (re.compile(r"\bAGGRESSIVE MODE PSK HASH HARVESTED:", re.I),       "critical"),
    (re.compile(r"\bSLP AMPLIFICATION VECTOR \(CVE-2023-29552\):", re.I), "critical"),
    (re.compile(r"\bNTP AMPLIFICATION VECTOR \(CVE-2013-5211", re.I),   "critical"),
    (re.compile(r"\bNTP responds to mode-6 readvar\b", re.I),          "medium"),
    (re.compile(r"\bSSDP/UPnP responder\b", re.I),                     "medium"),
    (re.compile(r"\bmDNS/DNS-SD catalog\b", re.I),                     "low"),
    (re.compile(r"\bCRITICAL: RADIUS Access-Accept to bogus credential:", re.I), "critical"),
    (re.compile(r"\bRADIUS BlastRADIUS \(CVE-2024-3596\) precondition:", re.I), "high"),
    (re.compile(r"\bSLP service-type list exposed \(HIGH-VALUE\):", re.I), "high"),
    (re.compile(r"\bVMware vCenter SDK reachable:", re.I),              "high"),
    (re.compile(r"\bSLP open service registry:", re.I),                 "medium"),
    (re.compile(r"\bVMware vCenter UI:", re.I),                         "medium"),
    # I-D — BMC vendor consoles (out-of-band management). MEDIUM by default
    # because detection alone is engagement-meaningful (default-cred history),
    # but no UNAUTH evidence so not HIGH.
    (re.compile(r"\bBMC (HPE iLO|Dell iDRAC|Supermicro IPMI|Lenovo XCC/IMM|Cisco CIMC) detected:", re.I), "medium"),
    # I-J — VPN concentrator detection. HIGH because every supported vendor has
    # had at least one pre-auth CVE in 2023-2024 (CVE-2024-3400, -42475, -3519,
    # -46805/-21887, -40766) — fingerprint alone is high-yield.
    (re.compile(r"\bVPN (Cisco AnyConnect/ASA SSL VPN|Fortinet SSL VPN|Palo Alto GlobalProtect|Pulse/Ivanti Connect Secure|Citrix NetScaler Gateway|SonicWall SMA/NetExtender) detected:", re.I), "high"),
    # I-E — hypervisor / virtualization product consoles.
    # MEDIUM for detection-only (parity with BMC); HIGH for explicit UNAUTH
    # escalation (e.g., Proxmox /api2/json/version returning data without auth).
    (re.compile(r"\bUNAUTH: Proxmox version API exposed:", re.I),          "high"),
    (re.compile(r"\bHypervisor (VMware ESXi host|Proxmox VE|Nutanix Prism) detected:", re.I), "medium"),
    (re.compile(r"\bOpenStack Keystone detected:", re.I),                  "medium"),
    # I-I — source/CI product consoles (Gerrit + Atlassian stack).
    # MEDIUM for detection (Atlassian stack has perennial RCE history but
    # fingerprint alone doesn't confirm exploitability); HIGH for the Jira
    # serverInfo UNAUTH escalation (that endpoint disclosing version + base
    # URL + deployment type without auth is the classic Atlassian recon
    # entrypoint).
    (re.compile(r"\bUNAUTH: Jira serverInfo exposed:", re.I),              "high"),
    (re.compile(r"\bSource/CI (Gerrit|Atlassian Confluence|Atlassian Jira|Atlassian Bamboo) detected:", re.I), "medium"),
    # Operator-centric expansion — artifact registries, platform control planes,
    # storage fabrics, backup appliances, and additional source/CI products.
    (re.compile(r"\bArtifact Docker Registry UNAUTH catalog surface:", re.I), "high"),
    (re.compile(r"\bArtifact (Docker Registry|Sonatype Nexus|JFrog Artifactory|Harbor registry) detected:", re.I), "medium"),
    (re.compile(r"\bPlatform Nomad UNAUTH job inventory:", re.I),           "high"),
    (re.compile(r"\bPlatform (HashiCorp Nomad|Portainer|Rancher|Argo CD) detected:", re.I), "medium"),
    (re.compile(r"\bStorage iSCSI target exposed:", re.I),                  "high"),
    (re.compile(r"\bStorage (MinIO|Ceph/RADOSGW object gateway|Ceph monitor|Gluster management) (?:detected|reachable):", re.I), "medium"),
    (re.compile(r"\bBackup (Rubrik|Cohesity|Dell PowerProtect Data Manager) API detected:", re.I), "high"),
    (re.compile(r"\bDell Avamar / PowerProtect legacy service reachable:", re.I), "high"),
    (re.compile(r"\bSource/CI (TeamCity|GitHub Enterprise|Azure DevOps Server) detected:", re.I), "medium"),
    (re.compile(r"\bHTTP source fingerprint:", re.I),                "low"),
    (re.compile(r"\bRADIUS server reachable:", re.I),                   "low"),
    (re.compile(r"\bIKE/IPsec VPN endpoint reachable:", re.I),          "low"),
    (re.compile(r"\bIKE vendor:", re.I),                                "low"),
    # I-K — network print services (JetDirect 9100 / LPD 515). Unauth by design.
    # HIGH because PJL filesystem dump and stored-job-name credential leak are
    # established post-discovery follow-ups; LPD reachable is MEDIUM because
    # the default probe does not retrieve queue jobs unless a queue name hits.
    (re.compile(r"\bJetDirect / PJL UNAUTH:", re.I),                   "high"),
    (re.compile(r"\bLPD reachable:", re.I),                            "medium"),
    # I-C — FlexNet/FLEXlm license-server (engineering/science lab characteristic).
    # HIGH because lmstat-disclosed user list + product list is intelligence-grade.
    (re.compile(r"\bFlexNet UNAUTH lmstat disclosure:", re.I),         "high"),
    (re.compile(r"\bFlexNet/FLEXlm license server reachable:", re.I),  "medium"),
    # I-F — HPC schedulers. HIGH on YARN UNAUTH (apps inventory + scheduler config
    # are intelligence-grade); LOW on Slurm/HTCondor banner-only reachability.
    (re.compile(r"\bYARN UNAUTH app inventory:", re.I),                "high"),
    (re.compile(r"\bYARN ResourceManager UNAUTH:", re.I),              "high"),
    (re.compile(r"\bHTCondor collector reachable:", re.I),             "low"),
    (re.compile(r"\bSlurm scheduler reachable:", re.I),                "low"),
    # I-G — monitoring (Zabbix + NRPE + Splunk). HIGH on Zabbix agent UNAUTH and
    # Splunk mgmt API UNAUTH (both leak system identity + version); MEDIUM on
    # Zabbix server / NRPE reachability without obvious leak.
    (re.compile(r"\bZabbix agent UNAUTH metric query:", re.I),         "high"),
    (re.compile(r"\bSplunk mgmt API UNAUTH:", re.I),                   "high"),
    (re.compile(r"\bZabbix server reachable:", re.I),                  "medium"),
    (re.compile(r"\bNagios NRPE reachable:", re.I),                    "medium"),
    # I-H — backup infrastructure. HIGH on every detection because backup is
    # the highest-value lateral target — the detection itself is engagement-
    # meaningful even before any exploit.
    (re.compile(r"\bVeeam B&R REST detected:", re.I),                  "high"),
    (re.compile(r"\bCommVault detected:", re.I),                       "high"),
    (re.compile(r"\bVeritas NetBackup detected:", re.I),               "high"),
    # T4 — OT/ICS read-side identification (Modbus/S7/EnIP/BACnet/OPC-UA/DNP3/IEC-104).
    # Per ADR-005 D6: situational-awareness output, no CVE-lookup. LOW by default
    # (matches the docstring's "informational banners, version fingerprints" tier).
    # OPC-UA `None`-policy advertisement is intentionally also LOW — many servers
    # advertise None on the discovery endpoint only; correlating that with the
    # actual session security requires operator interpretation. NO CRITICAL rules
    # at T4 — write-side is hard-prohibited (ADR-005 D2).
    (re.compile(r"\bOPC-UA endpoint advertises 'None' security policy:", re.I), "low"),
    (re.compile(r"\bOT-ID (Modbus|S7|EtherNet/IP|BACnet|OPC-UA|DNP3|IEC-104)\b", re.I), "low"),
    (re.compile(r"\b(OpenSSH|nginx|Apache|MySQL|PostgreSQL|Redis)\b", re.I), "low"),
]

# Markers we strip when a line is wrapped in dispatcher color codes. Some
# shells/log collectors drop the ESC byte and leave literal "[1;32m" fragments.
_ANSI_RE = re.compile(r"(?:\x1b)?\[[0-9;]*m")

# Structured evidence the finding walkers skip — machine-readable artifacts, not
# finding text. Line-scanning them double-counts against sibling .txt and lets the
# broad LOW banner rule match JSON keys.
_SKIP_SCAN_SUFFIXES = {".json", ".xml", ".pem"}


def _clean_line(line: str) -> str:
    return _ANSI_RE.sub("", line)


# Prefilter cache: one combined alternation regex per (flag-group), built from the
# EXACT same rule patterns, so short-circuiting on it can never drop a finding — if
# none of the combined regexes matches, no individual rule can match either. This
# turns the per-line hot path from ~90 Python-level .search() calls into a couple of
# C-level alternation scans for the overwhelmingly-common no-match line.
_PREFILTER_CACHE: dict[tuple[tuple[str, int, str], ...], tuple] = {}


def _prefilter_for(rules: list[tuple[re.Pattern, str]]):
    # Content keys cannot alias when CPython recycles a short-lived list id.
    key = tuple((pat.pattern, pat.flags, sev) for pat, sev in rules)
    pf = _PREFILTER_CACHE.get(key)
    if pf is None:
        groups: dict[int, list[str]] = defaultdict(list)
        for pat, _sev in rules:
            groups[pat.flags].append(pat.pattern)
        combined = []
        for flags, pats in groups.items():
            try:
                combined.append(re.compile("|".join(f"(?:{p})" for p in pats), flags))
            except re.error:
                # A pattern that won't combine (named groups/backrefs) → disable the
                # prefilter entirely (fall back to the full loop; never drop findings).
                pf = ()
                _PREFILTER_CACHE[key] = pf
                return pf
        pf = tuple(combined)
        _PREFILTER_CACHE[key] = pf
    return pf


def _classify(line: str, rules: list[tuple[re.Pattern, str]]) -> str | None:
    """Return the severity for a line, or None if no rule matched."""
    # Cap length before regex: an operator-supplied --severity-rules pattern can
    # backtrack catastrophically (e.g. (a+)+$) on a long line; bounding the input
    # is a mitigation (Python re has no match timeout). Findings text we care
    # about is short; the normalized line is truncated to 300 chars downstream.
    line = _clean_line(line)[:4096]
    prefilter = _prefilter_for(rules)
    if prefilter and not any(cre.search(line) for cre in prefilter):
        return None
    for pat, sev in rules:
        if pat.search(line):
            return sev
    return None


def _load_rules(path: Path | None) -> list[tuple[re.Pattern, str]]:
    custom: list[tuple[re.Pattern, str]] = []
    if path:
        for lineno, ln in enumerate(path.read_text().splitlines(), 1):
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            try:
                obj = json.loads(ln)
                sev = obj["severity"]
                if sev not in _SEV_ORDER:
                    raise ValueError(
                        f"severity must be one of {sorted(_SEV_ORDER)}, got {sev!r}")
                custom.append((re.compile(obj["pattern"], re.I), sev))
            except (json.JSONDecodeError, KeyError, re.error, TypeError, ValueError) as exc:
                print(f"error: {path}:{lineno}: invalid severity rule ({exc})",
                      file=sys.stderr)
                sys.exit(2)
    # Explicit operator policy overrides defaults under first-match semantics.
    return custom + list(_DEFAULT_RULES)


# ---------------------------------------------------- redaction
def _looks_like_ip(token: str) -> bool:
    """True if token is an IPv4/IPv6 literal (bracketed or bare) — used to keep
    hostname redaction from re-matching IPs the IP patterns already cover."""
    t = token.strip().strip("[]")
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", t):
        return True
    return ":" in t and bool(re.fullmatch(r"[0-9A-Fa-f:.]+", t))


class Redactor:
    """Maintains a stable mapping from raw target tokens to <TARGET-N>.

    Redacts IPv4, bracketed AND bare IPv6, and — when seeded via
    set_known_hosts() — the exact hostnames discovered in the scan. Hostnames
    are redacted only from the known-host set (never a broad FQDN regex) so
    URLs, product strings, and CVE identifiers in evidence text are preserved.
    """
    def __init__(self, enable: bool):
        self.enable = enable
        self._map: dict[str, str] = {}
        self._counter = 0
        self._hosts: list[str] = []

    def set_known_hosts(self, hosts) -> None:
        # Longest-first so a parent domain never partially shadows a subdomain.
        self._hosts = sorted(
            {h.strip() for h in (hosts or []) if h and not _looks_like_ip(h)},
            key=len, reverse=True,
        )

    def _target_re(self) -> re.Pattern:
        ipv4 = r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])"
        bracketed_ipv6 = r"\[[0-9A-Fa-f:.]+\]"
        # Bare IPv6 CANDIDATE — any hex run with >=2 colons (covers mid-string
        # `::` compression like fe80::dead:beef). Over-matches on purpose; each
        # hit is validated with ipaddress in _sub so MACs/time/hex strings that
        # are not real addresses are left untouched.
        bare_ipv6 = r"(?<![0-9A-Fa-f:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,}(?![0-9A-Fa-f:.])"
        parts = [bracketed_ipv6, bare_ipv6, ipv4]
        if self._hosts:
            parts.append(r"\b(?:" + "|".join(re.escape(h) for h in self._hosts) + r")\b")
        return re.compile("|".join(parts))

    def __call__(self, text: str) -> str:
        if not self.enable:
            return text
        host_set = set(self._hosts)
        def _sub(m):
            key = m.group(0)
            # A colon-bearing, non-bracketed match is a bare-IPv6 candidate:
            # redact only if it is a real IP address or a known host, else leave
            # it (avoids mangling MACs / hex tokens the loose regex catches).
            if ":" in key and not key.startswith("["):
                try:
                    ipaddress.ip_address(key)
                except ValueError:
                    if key not in host_set:
                        return key
            if key not in self._map:
                self._counter += 1
                self._map[key] = f"<TARGET-{self._counter}>"
            return self._map[key]
        return self._target_re().sub(_sub, text)


# ---------------------------------------------------- bulk-enum severity rules
# Patterns specific to standalones/linux/linenum-fast.sh output. Operators can extend via
# --severity-rules just like for the network rules. Each entry is
# (compiled regex, severity). First-match wins.
#
# Anchored on what linenum-fast.sh actually prints (see standalones/linux/linenum-fast.sh
# section headers — SUDO, SUID, CAPABILITIES, WRITABLE, LD_*, etc.).
_BULK_GTFOBINS = (
    "bash", "sh", "dash", "ksh", "zsh", "csh", "tcsh",
    "less", "more", "vi", "vim", "nvim", "nano", "ed", "emacs",
    "awk", "gawk", "mawk", "sed", "grep", "find", "xargs",
    "perl", "python", "python2", "python3", "ruby", "lua", "node", "nodejs", "php",
    "gdb", "strace", "ltrace", "ftrace",
    "env", "nice", "nohup", "time", "timeout", "watch",
    "mount", "umount", "fusermount",
    "nmap", "ncat", "nc", "socat",
    "ssh", "scp", "sftp", "rsync",
    "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "xz", "7z",
    "base32", "base64", "xxd", "hexdump",
    "wget", "curl", "tftp",
    "busybox",
    "make", "cmake", "msfconsole",
    "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "pip", "pip3", "gem", "npm",
    "cp", "mv", "dd", "install", "tee", "tail", "head",
    "expect", "screen", "tmux",
    "ar", "ld",
    "git", "ssh-keyscan",
)
# Build one alternation so the SUID/SGID line regex stays fast.
_GTFO_ALT = "|".join(re.escape(b) for b in _BULK_GTFOBINS)
_BULK_RULES: list[tuple[re.Pattern, str]] = [
    # SUDO — NOPASSWD is the canonical root primitive
    (re.compile(r"NOPASSWD", re.I),                                              "critical"),
    (re.compile(r"\(ALL\s*:\s*ALL\)\s*ALL", re.I),                               "critical"),
    (re.compile(r"sudo version (1\.8\.[0-9]|1\.8\.1[0-9]|1\.8\.2[0-9]|1\.8\.31p1|1\.9\.[0-4])\b", re.I), "high"),
    # CAPABILITIES — these are root-equivalent or near-root via documented chains
    (re.compile(r"\bcap_(setuid|setgid|dac_read_search|dac_override|sys_admin|sys_ptrace|sys_module|chown|fowner|net_admin)\b\+ep", re.I), "critical"),
    (re.compile(r"\bcap_(net_raw|net_bind_service|kill|sys_rawio)\b\+ep", re.I), "high"),
    # SUID — match gtfobin binaries explicitly; non-gtfobin SUIDs are MEDIUM
    (re.compile(rf"^-rws.*\b/((?:[^/\s]+/)*)({_GTFO_ALT})\s*$", re.I | re.M),    "critical"),
    (re.compile(r"^-rws"),                                                       "medium"),
    # WRITABLE — world-writable in /etc, /usr, systemd, init
    (re.compile(r"^/(etc|usr|lib|lib64|sbin|bin)/.*\s.*\s.*\s.*world.*writable", re.I), "critical"),
    (re.compile(r"^-rw.r..rw.\s.*/etc/(passwd|shadow|sudoers|sudoers\.d)", re.I),"critical"),
    (re.compile(r"\bwritable\b.*/etc/systemd", re.I),                            "high"),
    (re.compile(r"\bwritable\b.*/etc/cron", re.I),                               "high"),
    # LD_* env in sudo env_keep
    (re.compile(r"env_keep.*LD_(PRELOAD|LIBRARY_PATH)", re.I),                   "critical"),
    # NFS no_root_squash
    (re.compile(r"\bno_root_squash\b", re.I),                                    "high"),
    # Docker
    (re.compile(r"Privileged:\s*true", re.I),                                    "critical"),
    (re.compile(r"docker.sock", re.I),                                           "high"),
    # SSH key with no passphrase + private key location not in user dir
    (re.compile(r"^-rw-+\s.*\sid_(rsa|ed25519|ecdsa|dsa)\b"),                    "high"),
    # Cred patterns in history / files
    (re.compile(r"(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*\S{4,}", re.I), "high"),
    # Old kernel — Dirty Pipe (CVE-2022-0847) fixed in 5.16.11/5.15.25
    (re.compile(r"Linux\s+\S+\s+(2\.|3\.|4\.|5\.([0-9]|1[0-5])\.)", re.I),       "medium"),
    # THICK-CLIENT / WORKSTATION app enumeration (ADR-006 1d — thickclient-hunt.sh
    # markers, shared with the Windows list). Keys/creds/sessions at rest = high.
    (re.compile(r"\bTHICKCLIENT-(SSHKEY-AT-REST|SAVED-SESSION|CRED-AT-REST|CONFIG-SECRET):", re.I), "high"),
    (re.compile(r"\bTHICKCLIENT-(RDP-CREDS|VPN-PROFILE|BROWSER-LOGINDB):", re.I), "medium"),
    (re.compile(r"\bTHICKCLIENT-(KEYRING|ELECTRON|APP):", re.I),                 "low"),
]


# ---------------------------------------------------- Windows bulk-enum severity rules
# Anchored on what standalones/windows/Invoke-PrivEscEnum.ps1 actually prints (see that
# script's Section / Sub / Hit functions — formatting is stable across runs).
_BULK_RULES_WIN: list[tuple[re.Pattern, str]] = [
    # ---- CRITICAL ---- (direct privesc primitives)
    # AlwaysInstallElevated ENABLED — msfvenom -f msi -> SYSTEM
    (re.compile(r"AlwaysInstallElevated ENABLED", re.I),                        "critical"),
    # SE* token privileges that are direct SYSTEM primitives when ENABLED.
    # Anchored on `\(ENABLED\)` (literal parens, no re.I) — Invoke-PrivEscEnum.ps1
    # always emits `(ENABLED)` upper-case for the enabled hit; the disabled
    # miss is `(disabled — can still be enabled)`. Without these anchors the
    # `.*ENABLED` regex with re.I matches the disabled-hint trailing "enabled".
    (re.compile(r"\bSe(Impersonate|AssignPrimaryToken|Debug|Tcb|CreateToken|LoadDriver)Privilege\s*\(ENABLED\)"), "critical"),
    # Service binary the current user can overwrite
    (re.compile(r"WRITABLE BINARY:", re.I),                                     "critical"),
    # AutoLogon password disclosed in registry
    (re.compile(r"DefaultPassword=", re.I),                                     "critical"),
    # Membership in fully-privileged groups (any of Domain/Enterprise/Schema
    # Admins, local Administrators, Backup/Server Operators)
    (re.compile(r"^\[\+\] Member of (Domain Admins|Enterprise Admins|Schema Admins|Administrators|Backup Operators|Server Operators|Hyper-V Administrators)", re.I | re.M), "critical"),
    # GPP cpassword surface — these files commonly contain decryptable creds
    (re.compile(r"^\[\+\] .*\\(Groups|Services|Scheduledtasks|DataSources|Printers|Drives)\.xml", re.I | re.M), "critical"),
    # Unattend / sysprep on disk — common cred-leak path
    (re.compile(r"^\[\+\] .*\\(Unattend(ed)?\.xml|sysprep\.(xml|inf)|unattend\.(xml|inf|txt))", re.I | re.M), "critical"),

    # ---- HIGH ---- (indirect privesc / needs second step)
    # Backup/restore/ownership-take privileges — read or write anything as SYSTEM-equivalent
    # Same `\(ENABLED\)` literal anchor as the CRITICAL Se* rule above.
    (re.compile(r"\bSe(Backup|Restore|TakeOwnership|ManageVolume|Security)Privilege\s*\(ENABLED\)"), "high"),
    # Unquoted service path (CRITICAL only if combined with writable dir — we'd
    # need cross-checking which the report layer doesn't do; flag HIGH so it
    # surfaces but isn't false-positive CRITICAL)
    (re.compile(r"^\[\+\] \S+ -> [A-Za-z]:\\Program Files\\.*\s.*\(StartMode=", re.I | re.M), "high"),
    # Writable PATH dir (the operator can drop a DLL planted by a system EXE)
    (re.compile(r"^\[\+\] WRITABLE: [A-Za-z]:\\", re.I | re.M),                 "high"),
    # Limited-but-privileged group memberships
    (re.compile(r"^\[\+\] Member of (Account Operators|Print Operators|DnsAdmins)", re.I | re.M), "high"),
    # Scheduled task running as SYSTEM/NETWORK SERVICE/Administrators
    (re.compile(r"^\[\+\] \[(SYSTEM|NETWORK SERVICE|.*Administrators)\] ", re.I | re.M), "high"),
    # SCCM client task sequences / credentials path (common but high-value)
    (re.compile(r"\\CCM\\Logs\\.*PasswordHash|naa[_-]?credential", re.I),       "high"),

    # ---- MEDIUM ----
    # SE* privileges that are present but disabled — operator can enable some
    # (Invoke-PrivEscEnum.ps1 prints `(disabled — can still be enabled)`)
    (re.compile(r"\bSe(Impersonate|AssignPrimaryToken|Debug|Backup|Restore|TakeOwnership)Privilege\s*\(disabled"), "medium"),
    # Lateral-movement-only group memberships
    (re.compile(r"^\[\+\] Member of (Remote Desktop Users|Remote Management Users)", re.I | re.M), "medium"),
    # Plaintext-secret patterns in user files (the script greps for these in
    # Documents / wwwroot / etc.)
    (re.compile(r"(?:password|passwd|secret|api[_-]?key|token=)\s*[=:]\s*\S{4,}", re.I), "medium"),
    # End-of-life Windows builds (Win7, Server 2008, 2008R2, 2012, 2012R2)
    (re.compile(r"OS:\s+Microsoft Windows (7|Server 2008|Server 2012)\b", re.I),"medium"),
    # THICK-CLIENT / WORKSTATION app enumeration (ADR-006 1d — Get-ThickClientEnum.ps1
    # markers, shared with the Linux list). Keys/creds/sessions at rest = high.
    (re.compile(r"\bTHICKCLIENT-(SSHKEY-AT-REST|SAVED-SESSION|CRED-AT-REST|CONFIG-SECRET):", re.I), "high"),
    (re.compile(r"\bTHICKCLIENT-(RDP-CREDS|VPN-PROFILE|BROWSER-LOGINDB):", re.I), "medium"),
    (re.compile(r"\bTHICKCLIENT-(KEYRING|ELECTRON|APP):", re.I),                 "low"),
]


# ---------------------------------------------------- AD-depth signal rules (D1.5)
# These layer on top of the default rules and apply to auto-enum.sh output
# tree files (enum-ldap.sh / enum-smb.sh / enum-kerberos.sh produce them).
# Anchored on the literal strings the D1.0-D1.4 commits emit.
_AD_DEPTH_RULES: list[tuple[re.Pattern, str]] = [
    # --- Certipy AD CS ---
    # Certipy's "ESCN (Vulnerable)" header is the canonical hit — and our
    # ADSI-based Get-ADCSMisconfig.ps1 mirrors that format for parity.
    (re.compile(r"ESC([1-9]|1[0-6])\s*\(Vulnerable\)", re.I),                    "critical"),
    # --- Invoke-PrivEscEnum.ps1 registry/AD-depth posture (REVIEW-004) ---
    (re.compile(r"\bWSUS over HTTP:", re.I),                                     "high"),
    (re.compile(r"\bLocalAccountTokenFilterPolicy=1\b", re.I),                   "high"),
    (re.compile(r"\bWDigest UseLogonCredential=1\b", re.I),                      "medium"),
    (re.compile(r"\bSCCM client present\b", re.I),                              "medium"),
    (re.compile(r"\bms-DS-MachineAccountQuota=\d", re.I),                        "medium"),
    (re.compile(r"\bLAPS: \d+ computer object\(s\) expose\b", re.I),             "critical"),
    (re.compile(r"\bWebClient service running — coercion\b", re.I),              "high"),
    # --- BloodHound collection presence — informational HIGH (signals to the
    # operator that a graph file exists worth importing into BloodHound CE)
    (re.compile(r"^BLOODHOUND_ZIP:", re.M),                                       "high"),
    # --- GPP cpassword (Group Policy Preferences AES-known cleartext) ---
    (re.compile(r"\bcpassword\s*=\s*['\"][^'\"]+['\"]"),                          "critical"),
    (re.compile(r"GPP cpassword= in ", re.I),                                     "critical"),
    # --- LAPS readable ---
    (re.compile(r"READABLE \(LAPSv[12]", re.I),                                   "critical"),
    (re.compile(r"ENCRYPTED \(LAPSv2\)", re.I),                                   "high"),
    # --- AD delegation findings (enum-ldap.sh §6) ---
    # Match either word order — dispatcher emits "N account(s) with UNCONSTRAINED DELEGATION"
    (re.compile(r"\bUNCONSTRAINED DELEGATION\b", re.I),                            "high"),
    (re.compile(r"\bmsDS-AllowedToActOnBehalfOfOtherIdentity", re.I),             "high"),
    # --- Kerberoast / AS-REP roast bulk findings (enum-kerberos.sh §3/§4) ---
    (re.compile(r"kerberoastable hash\(es\) captured", re.I),                     "critical"),
    (re.compile(r"AS-REP-roastable hash\(es\) captured", re.I),                   "critical"),
    # --- PetitPotam coerce viability (enum-smb.sh §7) ---
    (re.compile(r"PetitPotam coerce chain available", re.I),                      "high"),
    (re.compile(r"lsarpc anonymous reachable on DC", re.I),                       "critical"),
    # --- Pre-2000 computer-account candidates ---
    (re.compile(r"^objectClass:\s*computer$", re.M),                              "low"),
    # --- PrintNightmare exploitable config ---
    (re.compile(r"PrintNightmare configuration is exploitable", re.I),            "critical"),
    # --- Test-CoercedAuth local primitives ---
    (re.compile(r"SeImpersonate \+ Spooler running.*PrintSpoofer", re.I),         "critical"),
    (re.compile(r"SeImpersonate \+ DCOM reachable.*RoguePotato", re.I),           "high"),
    # --- Named pipe writable to current user (Get-NamedPipes.ps1) ---
    # Get-NamedPipes emits via Hit(), which prepends "[+] ", so a "^"-anchored
    # pattern never matched. Match the marker anywhere on the (per-line) input.
    (re.compile(r"WRITABLE PIPE:", re.I),                                         "high"),
    # --- D2.1 Linux CVE-check outputs ---
    # pwnkit: polkit < 0.120 banner. HIGH (not critical): version-only detection
    # can't distinguish a distro backport-patched revision from a vulnerable one.
    (re.compile(r"polkit\s+\S+\s+<\s+0\.120\s+—\s+PwnKit (?:vulnerable|candidate)", re.I), "high"),
    # looney: glibc in 2.34-2.38 banner (same version-only backport caveat → HIGH).
    (re.compile(r"glibc\s+\S+\s+in vulnerable window\s+2\.34-2\.38\s+—\s+Looney", re.I), "high"),
    # overlayfs: Ubuntu HWE vulnerable range banner
    (re.compile(r"kernel\s+\S+\s+in Ubuntu HWE.*CVE-2023-0386 vulnerable", re.I),  "critical"),
    # io_uring + namespaces — HIGH-tier "user-can-reach-kernel-CVE-surface" signals
    (re.compile(r"io_uring reachable to current user\s+—\s+known CVE surface", re.I), "high"),
    (re.compile(r"unshare -rU succeeded\s+—\s+unprivileged userns creation works", re.I), "high"),
    # apt-source writable hook surface
    (re.compile(r"WRITABLE.*root runs scripts from here on apt operations", re.I),  "critical"),
    (re.compile(r"/etc/apt/sources\.list WRITABLE", re.I),                          "critical"),
]


# ---------------------------------------------------- layout detector
def _is_bulk_enum_dir(out_dir: Path) -> bool:
    """Return True iff out_dir looks like a bulk-enum output tree.
    Heuristic: at least one direct subdir contains a `_meta.json` AND either
    a `linenum.txt` (Linux side, J) or a `winenum.txt` (Windows side, K).
    auto-enum.sh subdirs are service names containing host subdirs — they
    never contain a top-level linenum.txt/winenum.txt."""
    for sub in out_dir.iterdir():
        if not sub.is_dir() or sub.is_symlink():
            continue
        if (sub / "_meta.json").is_file():
            if (sub / "linenum.txt").is_file() or (sub / "winenum.txt").is_file():
                return True
    return False


def _is_generated_dashboard_dir(path: Path) -> bool:
    """Detect report-dashboard.py output so regenerated dashboards do not
    ingest their own static HTML/CSS/JS as service evidence."""
    return (
        path.is_dir()
        and (path / "index.html").is_file()
        and (path / "assets" / "dashboard.css").is_file()
        and (path / "assets" / "dashboard.js").is_file()
    )


def _inventory_endpoints(out_dir: Path) -> list[dict]:
    """Return canonical endpoint records available beside a run."""
    candidates = [out_dir / "inventory.json", out_dir / "raw" / "inventory.json"]
    records: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()
    for path in candidates:
        if not path.is_file():
            continue
        try:
            doc = json.loads(path.read_text(errors="replace"))
        except Exception:
            continue
        for entry in doc.get("entries", []) if isinstance(doc, dict) else []:
            if not isinstance(entry, dict):
                continue
            host = str(entry.get("ip", "")).strip()
            port = str(entry.get("port", "")).strip()
            protocol = str(entry.get("proto", "")).strip().lower()
            services = entry.get("categories") or [entry.get("service", "")]
            for service in services:
                service = str(service).strip().lower()
                if not host or not port or not service:
                    continue
                key = (host, port, protocol, service)
                if key not in seen:
                    seen.add(key)
                    records.append({"host": host, "port": port, "protocol": protocol,
                                    "service": service})
        break
    # Older/evidence-only runs may lack inventory.json. Preserve their assessed
    # coverage from explicit target lists and endpoint directories.
    target_re = re.compile(r"^\[([^]]+)\]:(\d+)$|^(.+):(\d+)$")
    for target_file in out_dir.glob("_targets_*.txt"):
        service = target_file.stem.removeprefix("_targets_")
        try:
            lines = target_file.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            match = target_re.match(line.strip())
            if not match:
                continue
            host, port = ((match.group(1), match.group(2)) if match.group(1)
                          else (match.group(3), match.group(4)))
            if any(r["host"] == host and r["port"] == port and r["service"] == service
                   for r in records):
                continue
            key = (host, port, "", service)
            if key not in seen:
                seen.add(key)
                records.append({"host": host, "port": port, "protocol": "",
                                "service": service})
    for svc_dir in out_dir.iterdir():
        if (not svc_dir.is_dir() or svc_dir.name.startswith((".", "_"))
                or _is_generated_dashboard_dir(svc_dir)):
            continue
        for host_dir in svc_dir.iterdir():
            if not host_dir.is_dir():
                continue
            context_path = host_dir / "_task-context.json"
            if context_path.is_file():
                try:
                    context = json.loads(context_path.read_text(errors="replace"))
                    target = context.get("target") or {}
                    host = str(target.get("ip", "")).strip()
                    port = str(target.get("port", "")).strip()
                    protocol = str(target.get("proto", "")).strip().lower()
                except Exception:
                    host = port = protocol = ""
                if host and port and protocol in {"tcp", "udp"}:
                    key = (host, port, protocol, svc_dir.name)
                    if key not in seen:
                        seen.add(key)
                        records.append({"host": host, "port": port,
                                        "protocol": protocol, "service": svc_dir.name})
                # A task directory without a valid dispatcher-authored context
                # is not an endpoint and must not become synthetic coverage.
                continue
            name = host_dir.name
            if "_" in name and name.rsplit("_", 1)[1].isdigit():
                host, port = name.rsplit("_", 1)
            else:
                host, port = name, ""
            if any(r["host"] == host and r["port"] == port and r["service"] == svc_dir.name
                   for r in records):
                continue
            key = (host, port, "", svc_dir.name)
            if key not in seen:
                seen.add(key)
                records.append({"host": host, "port": port, "protocol": "",
                                "service": svc_dir.name})
    return records


def _line_mentions_endpoint(line: str, host: str, port: str) -> bool:
    """Return true only for a structurally delimited endpoint mention.

    Matching known strings with ``in`` is unsafe here: ``10.0.0.1`` is a
    substring of ``10.0.0.10``.  Build address-family-aware token patterns and
    require an exact port when the line includes one.  Bare IPv6 host:port is
    supported because the inventory supplies the split unambiguously.
    """
    escaped_host = re.escape(host)
    escaped_port = re.escape(port)
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        address = None

    if isinstance(address, ipaddress.IPv6Address):
        address_chars = r"0-9A-Za-z_.:%"
        patterns = [
            rf"(?<![{address_chars}])\[{escaped_host}\]:{escaped_port}(?![{address_chars}])",
            rf"(?<![{address_chars}]){escaped_host}:{escaped_port}(?![{address_chars}])",
            rf"(?<![{address_chars}])\[{escaped_host}\](?!:\d)",
            rf"(?<![{address_chars}]){escaped_host}(?![{address_chars}]|:\d)",
        ]
        flags = re.IGNORECASE
    elif isinstance(address, ipaddress.IPv4Address):
        address_chars = r"0-9A-Za-z_.-"
        patterns = [
            rf"(?<![{address_chars}]){escaped_host}:{escaped_port}(?![{address_chars}])",
            rf"(?<![{address_chars}]){escaped_host}(?![{address_chars}]|:\d)",
        ]
        flags = 0
    else:
        # Hostnames are DNS-like tokens.  The same delimiter rule prevents a
        # known ``db1`` endpoint from matching ``db10`` or ``db1.example``.
        patterns = [
            rf"(?<![A-Za-z0-9_.-]){escaped_host}:{escaped_port}(?![A-Za-z0-9_.-])",
            rf"(?<![A-Za-z0-9_.-]){escaped_host}(?![A-Za-z0-9_.-]|:\d)",
        ]
        flags = re.IGNORECASE
    return any(re.search(pattern, line, flags) for pattern in patterns)


def _endpoint_in_text(line: str, endpoints: list[dict], service: str) -> dict | None:
    """Resolve one exact known endpoint from structured address tokens."""
    matches: list[dict] = []
    for endpoint in endpoints:
        if endpoint["service"] != service:
            continue
        host, port = endpoint["host"], endpoint["port"]
        if _line_mentions_endpoint(line, host, port):
            matches.append(endpoint)
    unique = {(m["host"], m["port"], m["protocol"]): m for m in matches}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _refresh_finding_identity(finding: dict) -> None:
    seed = "|".join(str(finding.get(k, "")) for k in
                    ("service", "host", "port", "protocol", "severity", "evidence_identity"))
    finding["finding_id"] = f"{_FINDING_ID_PREFIX}-{hashlib.sha1(seed.encode()).hexdigest()[:14]}"


def finalize_findings(out_dir: Path, findings: Iterable[dict]) -> list[dict]:
    """Attribute dispatcher evidence, preserve protocol, and deduplicate it."""
    endpoints = _inventory_endpoints(out_dir)
    deduped: dict[tuple[str, ...], dict] = {}
    for original in findings:
        finding = dict(original)
        service = str(finding.get("service", "")).lower()
        endpoint: dict | None = None
        host = str(finding.get("host", ""))
        port = str(finding.get("port", ""))
        if host == "(dispatcher)":
            endpoint = _endpoint_in_text(str(finding.get("line", "")), endpoints, service)
        else:
            possible = [e for e in endpoints if e["service"] == service and e["host"] == host
                        and (not port or e["port"] == port)]
            unique = {(e["host"], e["port"], e["protocol"]): e for e in possible}
            if len(unique) == 1:
                endpoint = next(iter(unique.values()))
            elif not endpoint:
                endpoint = _endpoint_in_text(str(finding.get("line", "")), endpoints, service)
        if endpoint:
            finding.update(endpoint)
        finding.setdefault("protocol", "")
        identity = str(finding.get("evidence_identity", ""))
        if not identity:
            identity = hashlib.sha256(str(finding.get("line", "")).encode()).hexdigest()
            finding["evidence_identity"] = identity
        _refresh_finding_identity(finding)
        key = tuple(str(finding.get(k, "")) for k in
                    ("host", "port", "protocol", "service", "severity", "evidence_identity"))
        path = str(finding.get("evidence_path", ""))
        finding["evidence_paths"] = [p for p in finding.get("evidence_paths", [path]) if p]
        prior = deduped.get(key)
        if prior is None:
            deduped[key] = finding
            continue
        for evidence_path in finding["evidence_paths"]:
            if evidence_path not in prior["evidence_paths"]:
                prior["evidence_paths"].append(evidence_path)
        # Prefer endpoint-specific evidence as the primary link, while retaining
        # dispatcher stdout as secondary provenance.
        if "_dispatcher.log" in str(prior.get("evidence_path", "")) and path:
            prior["evidence_path"] = path
    return list(deduped.values())


def _coverage(out_dir: Path, findings: list[dict]) -> list[dict]:
    endpoints = _inventory_endpoints(out_dir)
    states: dict[tuple[str, str, str, str], tuple[str, str]] = {}
    queue_authoritative = False
    current_run_id = ""
    declared_queue_authority: bool | None = None
    try:
        run_state = json.loads((out_dir / "run-state.json").read_text(errors="replace"))
        current_run_id = str(run_state.get("run_id", ""))
        if isinstance(run_state.get("queue_authoritative"), bool):
            declared_queue_authority = run_state["queue_authoritative"]
    except (OSError, ValueError, TypeError):
        pass

    # Output-local state is the sole primary authority. The parent location is
    # retained only for pre-R1/external-queue compatibility and is considered
    # only when the local snapshot is absent. Never merge the two campaigns.
    local_state = out_dir / "queue.state.jsonl"
    parent_state = out_dir.parent / "queue.state.jsonl"
    state_path = local_state if local_state.is_file() else (
        parent_state if parent_state.is_file() else None)
    if state_path is not None and declared_queue_authority is not False:
        raw_lines: list[str] = []
        try:
            raw_lines = [line for line in state_path.read_text(errors="replace").splitlines()
                         if line.strip()]
            matched_current_run = False
            for line in raw_lines:
                try:
                    state = json.loads(line)
                except (ValueError, TypeError):
                    continue
                # New queue records are inseparable from the run-state snapshot
                # that published them. Legacy records remain usable only when
                # no current run ID exists to disambiguate campaigns.
                if current_run_id and str(state.get("run_id", "")) != current_run_id:
                    continue
                matched_current_run = True
                target = state.get("target") or {}
                key = (str(target.get("ip", "")), str(target.get("port", "")),
                       str(target.get("proto", "")), str(state.get("service", "")))
                if all(key):
                    status = str(state.get("status", "unassessed")).lower()
                    if status == "done":
                        status = "assessed_clean"
                    if status == "skip":
                        status = "skipped"
                    # Any incomplete task for an endpoint is authoritative:
                    # a stale success marker or evidence from another phase
                    # cannot turn an incomplete endpoint into clean coverage.
                    prior = states.get(key)
                    rank = {"failed": 4, "skipped": 3, "unassessed": 2,
                            "assessed_clean": 1, "confirmed": 1, "ok": 1}
                    if prior is None or rank.get(status, 0) > rank.get(prior[0], 0):
                        states[key] = (status, str(state.get("reason", "")))
            if declared_queue_authority is True:
                queue_authoritative = True
            elif not current_run_id:
                queue_authoritative = True
            elif not raw_lines:
                # Legacy priority-filtered queue runs published an intentionally
                # empty file before run-state carried an explicit mode marker.
                queue_authoritative = True
            elif matched_current_run:
                queue_authoritative = True
        except OSError:
            pass
    finding_keys = {(str(f.get("host", "")), str(f.get("port", "")),
                     str(f.get("protocol", "")), str(f.get("service", ""))) for f in findings}
    coverage: list[dict] = []
    for endpoint in endpoints:
        key = (endpoint["host"], endpoint["port"], endpoint["protocol"], endpoint["service"])
        queue_state = states.get(key)
        status, reason = queue_state or ("unassessed", "no execution record")
        svc_dir = out_dir / endpoint["service"]
        authoritative_incomplete = queue_state is not None and status in {"failed", "skipped", "unassessed"}
        if authoritative_incomplete:
            pass
        elif queue_authoritative and queue_state is None:
            # No selected task means no assessment.  Service-wide artifacts,
            # stale markers, and findings from a different endpoint cannot
            # grant completion outside the authoritative queue scope.
            status, reason = "unassessed", "endpoint not selected by authoritative queue"
        elif key in finding_keys:
            status, reason = "confirmed", "finding evidence recorded"
        elif queue_state is not None and status != "unassessed":
            pass
        elif (svc_dir / ".done").is_file():
            status, reason = "assessed_clean", "dispatcher completed without a matched finding"
        elif (svc_dir / ".rc").is_file():
            try:
                rc = int((svc_dir / ".rc").read_text().strip())
            except (OSError, ValueError):
                rc = -1
            status, reason = (("assessed_clean", "dispatcher rc=0") if rc == 0
                              else ("failed", f"dispatcher rc={rc}"))
        elif svc_dir.is_dir() and any(p.is_file() and p.stat().st_size for p in svc_dir.rglob("*")
                                      if p.name not in {".rc"}):
            status, reason = "assessed_clean", "evidence recorded without matched finding"
        record = {**endpoint, "status": status, "reason": reason}
        if queue_authoritative:
            record["execution_authority"] = "queue"
        coverage.append(record)
    return coverage


# ---------------------------------------------------- walker
def walk_findings(out_dir: Path, rules, service_metadata: dict | None = None) -> Iterable[dict]:
    """Yield finding dicts. Each finding has:
        host, port, service, severity, line, evidence_path plus
        structured fields for schema v2.
    """
    if service_metadata is None:
        service_metadata = _load_service_metadata(out_dir)
    _root = out_dir.resolve()
    for svc_dir in sorted(p for p in out_dir.iterdir() if p.is_dir() and not _is_generated_dashboard_dir(p)):
        service = svc_dir.name
        # Two layouts in use across the toolkit:
        #   $OUT/$service/<ip>/<file>          (most dispatchers)
        #   $OUT/$service/<ip>_<port>/<file>   (enum-jabber, enum-docker, ...)
        for host_dir in sorted(p for p in svc_dir.iterdir() if p.is_dir()):
            context_path = host_dir / "_task-context.json"
            protocol = ""
            if context_path.is_file():
                try:
                    context = json.loads(context_path.read_text(errors="replace"))
                    target = context.get("target") or {}
                    host = str(target.get("ip", "")).strip()
                    port = str(target.get("port", "")).strip()
                    protocol = str(target.get("proto", "")).strip().lower()
                except Exception:
                    continue
                if not host or not port or protocol not in {"tcp", "udp"}:
                    continue
            else:
                name = host_dir.name
                if "_" in name and name.rsplit("_", 1)[-1].isdigit():
                    host, port = name.rsplit("_", 1)
                else:
                    host, port = name, ""
            for fp in sorted(host_dir.rglob("*")):
                # Containment (OPSEC §9): never read/report a file that resolves
                # outside the scan tree — a symlink or .. inside an untrusted
                # scan dir must not leak host filesystem content into findings.
                # Resolve BEFORE stat/read so a symlink target is never touched.
                try:
                    if _root not in fp.resolve().parents:
                        continue
                except OSError:
                    continue
                if not fp.is_file() or fp.stat().st_size == 0:
                    continue
                # Only scan text-ish files. Skip structured evidence (JSON/XML/PEM):
                # these are machine-readable artifacts (nxc --jsonl, nuclei -json,
                # default-creds.json, _meta.json), not finding text — line-scanning
                # them inflates/duplicates findings against their sibling .txt and
                # makes the broad LOW banner rule fire on JSON keys. (This is what
                # the walker always claimed to do; the filter was missing.)
                if fp.suffix.lower() in _SKIP_SCAN_SUFFIXES:
                    continue
                try:
                    text = fp.read_text(errors="replace")
                except Exception:
                    continue
                for line in text.splitlines():
                    sev = _classify(line, rules)
                    if sev is None:
                        continue
                    yield _structured_finding(
                        host,
                        port,
                        service,
                        sev,
                        line,
                        str(fp.relative_to(out_dir)),
                        service_metadata,
                        protocol,
                    )
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
                yield _structured_finding(
                    "(dispatcher)",
                    "",
                    service,
                    sev,
                    line,
                    str(top_fp.relative_to(out_dir)),
                    service_metadata,
                )


# ---------------------------------------------------- bulk-enum walker
def walk_findings_bulk(out_dir: Path, extra_rules, service_metadata: dict | None = None) -> Iterable[dict]:
    """Walk a bulk-enum output tree. Each top-level subdir is one host. The
    host's output file selects the rule set + service label:
        linenum.txt  -> _BULK_RULES     + service='linenum'  (Linux, J)
        winenum.txt  -> _BULK_RULES_WIN + service='winenum'  (Windows, K)
    A single $OUT can hold both — report.py rolls them up into ONE per-host
    verdict table so a mixed-OS engagement gets one prioritized view."""
    if service_metadata is None:
        service_metadata = _load_service_metadata(out_dir)
    extras = list(extra_rules or [])
    # Fold in the AD-depth / CVE-signal rules so bulk (winenum/linenum) findings —
    # LAPS, ADCS/ESC, PrintNightmare, writable pipes, coercion primitives — actually
    # get graded. They were only wired into the auto-enum classifier path, so a
    # bulk-windows sweep produced ungraded (LOW-looking) AD-depth signals.
    linux_rules = list(_BULK_RULES) + list(_AD_DEPTH_RULES) + extras
    win_rules   = list(_BULK_RULES_WIN) + list(_AD_DEPTH_RULES) + extras
    for host_dir in sorted(p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()):
        meta = host_dir / "_meta.json"
        if not meta.is_file():
            continue
        # ADR-006 D1a-2 integration: a host that AUTH_FAIL'd / was UNREACHABLE /
        # timed out did NOT produce clean enumeration. Without surfacing the
        # per-host status, an empty linenum.txt reads as "no findings = clean",
        # hiding a whole failed sweep. Emit a synthetic finding so the operator
        # sees the host was not (fully) enumerated.
        try:
            _meta_obj = json.loads(meta.read_text())
        except Exception:
            _meta_obj = {}
        _host = str(_meta_obj.get("host") or host_dir.name)
        _port = str(_meta_obj.get("port") or _meta_obj.get("ssh_port") or "")
        _protocol = str(_meta_obj.get("protocol") or "tcp")
        _status = str(_meta_obj.get("status", "")).upper()
        if _status and _status != "OK":
            _reason = str(_meta_obj.get("fail_reason", "") or _status)
            _svc = "linenum" if (host_dir / "linenum.txt").is_file() else "winenum"
            _sev = "medium" if _status in (
                "AUTH_FAIL", "UNREACHABLE", "TIMEOUT", "HOST_TIMEOUT") else "low"
            yield _structured_finding(
                _host, _port, _svc, _sev,
                f"[bulk-enum] host NOT fully enumerated — status={_status} ({_reason})",
                str(meta.relative_to(out_dir)), service_metadata, _protocol)
        for fname, rules, svc in (
            ("linenum.txt", linux_rules, "linenum"),
            ("winenum.txt", win_rules,   "winenum"),
        ):
            evidence = host_dir / fname
            if not evidence.is_file():
                continue
            try:
                text = evidence.read_text(errors="replace")
            except Exception:
                continue
            host = _host
            for line in text.splitlines():
                sev = _classify(line, rules)
                if sev is None:
                    continue
                yield _structured_finding(
                    host,
                    _port,
                    svc,
                    sev,
                    line,
                    str(evidence.relative_to(out_dir)),
                    service_metadata,
                    _protocol,
                )


# ---------------------------------------------------- renderers
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _per_host_verdicts(findings: list[dict]) -> dict[str, dict]:
    """Compute per-host verdict (max severity across findings) for bulk-enum
    reports. Each host's verdict considers both linenum AND winenum findings;
    mixed-OS estates produce a single prioritized table. Returns
    {host: {verdict, n_critical, n_high, n_medium, n_low, os}}."""
    per: dict[str, dict] = {}
    for f in findings:
        if f["service"] not in ("linenum", "winenum"):
            continue
        h = f["host"]
        if h not in per:
            per[h] = {"n_critical": 0, "n_high": 0, "n_medium": 0, "n_low": 0,
                      "verdict": "low", "os": ""}
        per[h][f"n_{f['severity']}"] += 1
        if _SEV_ORDER[f["severity"]] < _SEV_ORDER[per[h]["verdict"]]:
            per[h]["verdict"] = f["severity"]
        # Track OS — if both surfaces produced findings, label "mixed"
        new_os = "linux" if f["service"] == "linenum" else "windows"
        if not per[h]["os"]:
            per[h]["os"] = new_os
        elif per[h]["os"] != new_os:
            per[h]["os"] = "mixed"
    return per


def _summary(findings: list[dict], out_dir: Path | None = None) -> dict:
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
    hosts_with_findings = set(hosts)
    services_with_findings = set(services)
    coverage = _coverage(out_dir, findings) if out_dir is not None else []
    hosts.update(c["host"] for c in coverage if c.get("host"))
    services.update(c["service"] for c in coverage if c.get("service"))
    coverage_counts: dict[str, int] = defaultdict(int)
    for record in coverage:
        coverage_counts[str(record.get("status", "unassessed"))] += 1
    return {
        "hosts": sorted(hosts),
        "services": sorted(services),
        "hosts_assessed": sorted({c["host"] for c in coverage
                                  if c.get("status") in {"confirmed", "assessed_clean"}}),
        "hosts_with_findings": sorted(hosts_with_findings),
        "services_attempted": sorted({c["service"] for c in coverage
                                      if c.get("status") != "unassessed"}),
        "services_with_findings": sorted(services_with_findings),
        "coverage_counts": dict(coverage_counts),
        "coverage": coverage,
        "counts": dict(counts),
        "by_service": {s: dict(v) for s, v in by_service.items()},
    }


def render_markdown(findings: list[dict], summary: dict, run_label: str,
                    redactor: Redactor, per_host: dict | None = None) -> str:
    out = [f"# Findings report — {run_label}", ""]
    out.append(f"_Generated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}_")
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

    # Per-host verdict table — bulk-enum mode only. Shown BEFORE the
    # service breakdown because for bulk-enum the operator's first question
    # is "which hosts should I focus on?".
    if per_host:
        out.append("## Per-host privesc verdict (bulk-enum)")
        out.append("")
        out.append("| Host | OS | Verdict | Critical | High | Medium | Low |")
        out.append("|---|---|---|---:|---:|---:|---:|")
        # Sort: critical hosts first, then high, etc.; alpha within tier.
        ordered = sorted(per_host.items(),
                         key=lambda kv: (_SEV_ORDER[kv[1]["verdict"]], kv[0]))
        for host, v in ordered:
            out.append(f"| {redactor(host)} | {v.get('os', '')} | **{v['verdict']}** | "
                       f"{v['n_critical']} | {v['n_high']} | {v['n_medium']} | {v['n_low']} |")
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
td.medium, td .medium { color: #a60; }
td.low, td .low { color: #060; }
.verdict-critical { background: #fee; }
.verdict-high { background: #ffe; }
.verdict-medium { background: #ffd; }
.verdict-low { background: #efe; }
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

    return (f"<!doctype html><html><head><meta charset='utf-8'><title>aranum report</title>"
            f"<style>{_HTML_STYLE}</style></head><body>" + "\n".join(out) + "</body></html>")


def _inline(s: str) -> str:
    s = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


# ---------------------------------------------------- main
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def _to_sarif(findings: list[dict], label: str) -> dict:
    """Minimal SARIF 2.1.0 subset so findings drop into standard security
    dashboards / CI (GitHub code-scanning, DefectDojo, etc.)."""
    results = []
    for f in findings:
        sev = str(f.get("severity", "low")).lower()
        loc = []
        ev = f.get("evidence_path")
        if ev:
            loc = [{"physicalLocation": {"artifactLocation": {"uri": str(ev)}}}]
        results.append({
            "ruleId": f.get("service", "finding") or "finding",
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": (f.get("title") or f.get("line", "")).strip()[:400]},
            "locations": loc,
            "properties": {
                "host": f.get("host", ""), "port": f.get("port", ""),
                "severity": sev, "finding_id": f.get("finding_id", ""),
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "aranum", "informationUri": "https://github.com/aradex-io/aranum",
                                "version": _FINDINGS_SCHEMA_VERSION, "rules": []}},
            "properties": {"label": label},
            "results": results,
        }],
    }


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
    ap.add_argument("--sarif", action="store_true",
                    help="also write findings.sarif (SARIF 2.1.0 for CI / code-scanning)")
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    if not out_dir.is_dir():
        print(_c(f"[!] not a directory: {out_dir}", "R"), file=sys.stderr)
        return 2

    rules = _load_rules(Path(args.severity_rules) if args.severity_rules else None)
    # D1.5: layer the AD-depth rules on top of the default + operator rules.
    # These are general (apply to both auto-enum and bulk-enum trees).
    rules = list(rules) + list(_AD_DEPTH_RULES)
    service_metadata = _load_service_metadata(out_dir)
    redactor = Redactor(args.redact)
    label = args.label or out_dir.name

    # Auto-detect bulk-enum vs auto-enum layout
    bulk_mode = _is_bulk_enum_dir(out_dir)
    if bulk_mode:
        print(_c(f"[+] bulk-enum layout detected — using linenum-fast.sh rules", "G"))
        findings = finalize_findings(out_dir, walk_findings_bulk(out_dir, rules, service_metadata))
        per_host = _per_host_verdicts(findings)
    else:
        findings = finalize_findings(out_dir, walk_findings(out_dir, rules, service_metadata))
        per_host = None

    summary = _summary(findings, out_dir)

    # Always emit findings.json (machine-readable)
    findings_json = {
        "schema_version": _FINDINGS_SCHEMA_VERSION,
        "label":         label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "redacted":      args.redact,
        "mode":          "bulk-enum" if bulk_mode else "auto-enum",
        "summary":       summary,
        "findings":      findings,
    }
    if per_host:
        # Sort by verdict (worst first), then host name
        findings_json["per_host"] = {
            h: v for h, v in sorted(per_host.items(),
                                    key=lambda kv: (_SEV_ORDER[kv[1]["verdict"]], kv[0]))
        }
    if args.redact:
        # Seed hostname redaction from the discovered scan hosts (pre-redaction).
        redactor.set_known_hosts(summary.get("hosts", []))
        for f in findings_json["findings"]:
            f["host"] = redactor(f["host"])
            f["line"] = redactor(f["line"])
            f["evidence_path"] = redactor(f["evidence_path"])
            f["evidence_paths"] = [redactor(p) for p in f.get("evidence_paths", [])]
            f["title"] = redactor(f["title"])
        for field in ("hosts", "hosts_assessed", "hosts_with_findings"):
            findings_json["summary"][field] = [redactor(h) for h in summary.get(field, [])]
        for record in findings_json["summary"].get("coverage", []):
            record["host"] = redactor(str(record.get("host", "")))
        if per_host:
            findings_json["per_host"] = {redactor(h): v for h, v in findings_json["per_host"].items()}
    (out_dir / "findings.json").write_text(json.dumps(findings_json, indent=2))
    print(_c(f"[+] findings.json written ({len(findings)} findings)", "G"))

    if args.sarif:
        (out_dir / "findings.sarif").write_text(
            json.dumps(_to_sarif(findings_json["findings"], label), indent=2))
        print(_c("[+] findings.sarif written (SARIF 2.1.0)", "G"))

    if args.findings_only:
        return 0

    md = render_markdown(findings, summary, label, redactor, per_host)
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
