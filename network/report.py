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


# ---------------------------------------------------- bulk-enum severity rules
# Patterns specific to linux/linenum-fast.sh output. Operators can extend via
# --severity-rules just like for the network rules. Each entry is
# (compiled regex, severity). First-match wins.
#
# Anchored on what linenum-fast.sh actually prints (see linux/linenum-fast.sh
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
]


# ---------------------------------------------------- Windows bulk-enum severity rules
# Anchored on what windows/Invoke-PrivEscEnum.ps1 actually prints (see that
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
]


# ---------------------------------------------------- AD-depth signal rules (D1.5)
# These layer on top of the default rules and apply to auto-enum.sh output
# tree files (enum-ldap.sh / enum-smb.sh / enum-kerberos.sh produce them).
# Anchored on the literal strings the D1.0-D1.4 commits emit.
_AD_DEPTH_RULES: list[tuple[re.Pattern, str]] = [
    # --- Certipy AD CS ---
    # Certipy's "ESCN (Vulnerable)" header is the canonical hit — and our
    # ADSI-based Get-ADCSMisconfig.ps1 mirrors that format for parity.
    (re.compile(r"ESC([1-9]|1[0-1])\s*\(Vulnerable\)", re.I),                    "critical"),
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
    (re.compile(r"^WRITABLE PIPE:", re.M),                                        "high"),
    # --- D2.1 Linux CVE-check outputs ---
    # pwnkit: polkit < 0.120 banner
    (re.compile(r"polkit\s+\S+\s+<\s+0\.120\s+—\s+PwnKit vulnerable", re.I),       "critical"),
    # looney: glibc in 2.34-2.38 banner
    (re.compile(r"glibc\s+\S+\s+in vulnerable window\s+2\.34-2\.38\s+—\s+Looney", re.I), "critical"),
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
        if not sub.is_dir():
            continue
        if (sub / "_meta.json").is_file():
            if (sub / "linenum.txt").is_file() or (sub / "winenum.txt").is_file():
                return True
    return False


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


# ---------------------------------------------------- bulk-enum walker
def walk_findings_bulk(out_dir: Path, extra_rules) -> Iterable[dict]:
    """Walk a bulk-enum output tree. Each top-level subdir is one host. The
    host's output file selects the rule set + service label:
        linenum.txt  -> _BULK_RULES     + service='linenum'  (Linux, J)
        winenum.txt  -> _BULK_RULES_WIN + service='winenum'  (Windows, K)
    A single $OUT can hold both — report.py rolls them up into ONE per-host
    verdict table so a mixed-OS engagement gets one prioritized view."""
    extras = list(extra_rules or [])
    linux_rules = list(_BULK_RULES) + extras
    win_rules   = list(_BULK_RULES_WIN) + extras
    for host_dir in sorted(p for p in out_dir.iterdir() if p.is_dir()):
        meta = host_dir / "_meta.json"
        if not meta.is_file():
            continue
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
            host = host_dir.name
            for line in text.splitlines():
                sev = _classify(line, rules)
                if sev is None:
                    continue
                yield {
                    "host":          host,
                    "port":          "",
                    "service":       svc,
                    "severity":      sev,
                    "line":          line.strip()[:300],
                    "evidence_path": str(evidence.relative_to(out_dir)),
                }


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
                    redactor: Redactor, per_host: dict | None = None) -> str:
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
    # D1.5: layer the AD-depth rules on top of the default + operator rules.
    # These are general (apply to both auto-enum and bulk-enum trees).
    rules = list(rules) + list(_AD_DEPTH_RULES)
    redactor = Redactor(args.redact)
    label = args.label or out_dir.name

    # Auto-detect bulk-enum vs auto-enum layout
    bulk_mode = _is_bulk_enum_dir(out_dir)
    if bulk_mode:
        print(_c(f"[+] bulk-enum layout detected — using linenum-fast.sh rules", "G"))
        findings = list(walk_findings_bulk(out_dir, rules))
        per_host = _per_host_verdicts(findings)
    else:
        findings = list(walk_findings(out_dir, rules))
        per_host = None

    summary = _summary(findings)

    # Always emit findings.json (machine-readable)
    findings_json = {
        "label":         label,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
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
        for f in findings_json["findings"]:
            f["host"] = redactor(f["host"])
            f["line"] = redactor(f["line"])
        findings_json["summary"]["hosts"] = [redactor(h) for h in summary["hosts"]]
        if per_host:
            findings_json["per_host"] = {redactor(h): v for h, v in findings_json["per_host"].items()}
    (out_dir / "findings.json").write_text(json.dumps(findings_json, indent=2))
    print(_c(f"[+] findings.json written ({len(findings)} findings)", "G"))

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
