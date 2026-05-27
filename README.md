# aranum — Authorized Pentest Enumeration Toolkit

[![License: CC BY-NC-SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](./LICENSE)

`aranum` is an authorized-testing-only collection of privilege-escalation enumeration scripts (Windows + Linux) and a network enumeration orchestrator that consumes nmap output and dispatches per-service authenticated enumeration.

> **Authorization required.** Every script assumes the operator has written authorization to test the target. See [`CLAUDE.md`](./CLAUDE.md) §9 (Safety / OPSEC invariants) for the rules this repo enforces. Read [`LICENSE`](./LICENSE) before use — non-commercial only.

Repo: <https://github.com/aradex-io/aranum>

## Layout

```
aratool/
├── windows/        # PowerShell + batch privesc enumeration
├── linux/          # Bash privesc enumeration (no-deps + extended)
├── network/        # nmap-output parser + service dispatchers
├── graphql/        # GraphQL toolkit (GitLab-tuned)
├── activemq/       # ActiveMQ enum + CVE-2023-46604 PoC (see activemq/README.md)
├── redis/          # Redis quickwin / lateral / RCE helpers (see redis/README.md)
├── smtp/           # SMTP enum + relay / smuggling tests (see smtp/README.md)
├── creds/          # Default-credential sweep + spray scheduler + hash formatter
├── jabber/         # XMPP/Jabber enum + OpenFire CVE-2023-32315 helper (see jabber/README.md)
├── ot/             # Tier 4 — OT/ICS read-side ID (gated; never auto-routed)
├── docs/           # CLAUDE.md governance, ADRs, REVIEW + ROADMAP
└── deps-check.sh   # Verify required tools on attacker box
```

Each subsystem ships its own README documenting the per-tool surface — `activemq/README.md`, `redis/README.md`, `smtp/README.md`, `jabber/README.md`, `ot/README.md`. The tables below cover the auto-enum / privesc fleet; targeted post-discovery helpers (`redis-quickwin.sh`, `redis-lateral.sh`, `redis-rogue-master.py`, `redis-rce-module.sh`, `redis-rce-ssh.sh`, `activemq-quickwin.sh`, `activemq-queues.sh`, `activemq-jolokia-rce.sh`, `smtp-quickwin.sh`, `smtp-relay-test.sh`, `smtp-phish-send.sh`, `smtp-smuggling-test.py`, `smtp-user-enum.sh`, `spf-dmarc-check.sh`) are documented in their respective subdirectory READMEs.

## Windows Scripts

| Script | Purpose |
|---|---|
| `windows/Invoke-PrivEscEnum.ps1` | All-in-one privesc enumerator (services, tasks, tokens, registry, creds) |
| `windows/Get-UnquotedServices.ps1` | Unquoted service paths + write-check on intermediate dirs |
| `windows/Get-ServiceMisconfig.ps1` | Modifiable services (SERVICE_CHANGE_CONFIG / binary perms / registry perms) |
| `windows/Get-ScheduledTasks.ps1` | Scheduled tasks with author, runas, action — flags privileged runas |
| `windows/Get-TokenPrivileges.ps1` | Token privileges + interpretation (SeImpersonate, SeBackup, etc.) |
| `windows/Get-StoredCreds.ps1` | cmdkey, Credential Manager, unattend.xml, sysprep, Group Policy Prefs |
| `windows/Get-AlwaysInstallElevated.ps1` | Registry check for AlwaysInstallElevated MSI privesc |
| `windows/Get-WritablePathDirs.ps1` | Directories in PATH that current user can write to |
| `windows/enum.bat` | No-PS fallback — `systeminfo`, `whoami /all`, `net localgroup`, `schtasks`, `wmic`, `reg query` |
| `windows/Get-LAPSPassword.ps1` (D1.4) | Reads `ms-Mcs-AdmPwd` / `msLAPS-Password` for every computer object the current user can see — cleartext is CRITICAL |
| `windows/Get-ADCSMisconfig.ps1` (D1.4) | Pure-ADSI ESC1/ESC2/ESC4 detection (no-deps fallback when Certipy unreachable from attacker box) |
| `windows/Get-GPPCPassword.ps1` (D1.4) | SYSVOL + GP-History sweep for `cpassword=` in Groups.xml/Services.xml/etc. (AES key is public) |
| `windows/Get-DPAPIBlobs.ps1` (D1.4) | Enumerates DPAPI master keys, vaults, Chrome/Edge/Firefox stores, RDP saved creds — **paths only** |
| `windows/Get-NamedPipes.ps1` (D1.4) | ACL audit of named pipes; flags pipes writable to current user / Everyone / Authenticated Users |
| `windows/Get-PrintNightmare.ps1` (D1.4) | CVE-2021-34527 / CVE-2021-1675 mitigation-state check (Spooler + registry policy combo) |
| `windows/Get-PetitPotamSignals.ps1` (D1.4) | NTLM-relay/coercion signal audit on this host: SMB+LDAP signing, EFS RPC, coerce-vector services |
| `windows/Test-CoercedAuth.ps1` (D1.4) | Local-only precondition check for PrintSpoofer/RoguePotato/GodPotato chains (SE* + Spooler + DCOM + WebDAV) |

## Linux Scripts

| Script | Purpose |
|---|---|
| `linux/linenum-fast.sh` | No-dep one-shot privesc enumerator (SUID, sudo, caps, cron, env, kernel, group) |
| `linux/sudo-enum.sh` | `sudo -l` analysis + version CVE check (Baron Samedit, etc.) |
| `linux/suid-gtfobins.sh` | SUID/SGID binaries cross-referenced against GTFOBins offline list |
| `linux/cron-enum.sh` | System+user cron + writable scripts they invoke |
| `linux/capabilities-enum.sh` | Files with `cap_*` capabilities + exploit hints |
| `linux/group-enum.sh` | Group membership privesc (docker, lxd, disk, video, adm, lxc) |
| `linux/container-detect.sh` | Detect Docker/LXC/k8s and check for socket access, cgroup escapes |
| `linux/writable-files.sh` | World-writable + writable in $PATH + writable /etc/* sensitive |
| `linux/creds-hunt.sh` | Grep filesystem for passwords, API keys, private keys, history files |
| `linux/juicy-files-hunt.sh` | Expanded credential/config/service-file grep for SSH stdin-pipe use or mounted shares |
| `linux/pwnkit-check.sh` (D2.1) | CVE-2021-4034 (polkit `pkexec`) version + setuid check |
| `linux/looney-check.sh` (D2.1) | CVE-2023-4911 (glibc `GLIBC_TUNABLES`) — flags glibc 2.34-2.38 |
| `linux/overlayfs-check.sh` (D2.1) | CVE-2023-0386 — Ubuntu HWE kernel range check + overlayfs/userns prerequisites |
| `linux/io-uring-check.sh` (D2.1) | io_uring availability + restrictions; flags reachable surface for multi-CVE history |
| `linux/namespaces-check.sh` (D2.1) | Unprivileged user-namespace creation (precondition for many recent kernel CVEs) |
| `linux/apt-source-check.sh` (D2.1) | apt-get writable config / hooks (`/etc/apt/apt.conf.d`, `sources.list.d`) — root runs scripts from there on `apt-get install` |

## Credential helpers

| Script | Purpose |
|---|---|
| `creds/default-creds-sweep.py` | Multi-protocol default-credential sweep (SSH/MSSQL/MySQL/Redis/Mongo/…) |
| `creds/spray-scheduler.py` (D2.2) | Lockout-policy-aware wrapper around any spray tool — `--threshold N --interval M` (default 3 attempts / 30 minutes per principal) with persistent state for resume |
| `creds/hash-format.py` (D2.2) | Convert captured NTLMv2 / NTLMv1 / AS-REP / TGS-REP from Responder / impacket / nxc output into `hashcat`- and `john`-ready files + `_index.tsv` |

## Network Enumeration

| Script | Purpose |
|---|---|
| `network/aranum.py` | Unified wrapper CLI for planner, auto-enum, reports, dashboard, queue view, merge, and bulk enum |
| `network/plan.py` | Operator-centric planner: nmap output → priority queue + guidance (`plan.json`, `queue.jsonl`, `guidance.json`) |
| `network/nmap-parse.py` | Parse `.xml`, `.gnmap`, and `.nmap` files → JSON inventory by service |
| `network/auto-enum.sh` | Master orchestrator: nmap output → service buckets → dispatch enum |
| `network/iterative-enum.sh` | Second-pass pivot: `/etc/hosts` entries, HTTP source fingerprints, SMB share spidering/mount grep, default creds, username harvesting, and credentialed filesystem scraping |
| `network/bulk-enum-linux.sh` | **Post-foothold** — pipe `linenum-fast.sh` over SSH to many hosts in parallel; per-host verdicts via `report.py` (J.1) |
| `network/bulk-enum-windows.py` | **Post-foothold** — ship `Invoke-PrivEscEnum.ps1` over WinRM (pywinrm) to many Windows hosts in parallel; same `report.py` rolls up mixed Linux+Windows estates (K.1) |
| `network/enum-smb.sh` | `enum4linux-ng`, `nxc smb --shares --users --pass-pol --spider`, smbclient, rpcclient |
| `network/enum-ldap.sh` | `nxc ldap`, `ldapsearch`, `GetUserSPNs.py`, `GetNPUsers.py` |
| `network/enum-kerberos.sh` | AS-REP roast, SPN enum, `kerbrute userenum` |
| `network/enum-winrm.sh` | `nxc winrm`, command exec test, evil-winrm spray |
| `network/enum-rdp.sh` | `nxc rdp`, `rdp-sec-check`, NLA detection |
| `network/enum-mssql.sh` | `nxc mssql`, `mssqlclient.py`, xp_cmdshell check |
| `network/enum-http.sh` | `whatweb`, `httpx`, `nuclei`, `ffuf` (light wordlist), `nikto` (optional); **C.13 product-fingerprint phase** fans 40+ product-specific probes per live URL — IT products, BMC, VPN, hypervisor/private-cloud, source/CI, artifact registries, platform control planes, storage, and backup APIs; each detector requires a product-specific marker (header pattern, JSON key, or exact body string) before emitting a hit; skippable via `NO_PRODUCT_DETECT=1` |
| `network/enum-ssh.sh` | `ssh-audit`, banner, `nxc ssh` cred spray, key auth probe |
| `network/enum-ftp.sh` | Anonymous, `nxc ftp` cred spray |
| `network/enum-snmp.sh` | `onesixtyone` + `snmpwalk` with common communities |
| `network/enum-nfs.sh` | `showmount -e`, no_root_squash detection |
| `network/enum-dns.sh` | `dig axfr`, `dnsrecon`, reverse lookup |
| `network/enum-redis.sh` | Unauthenticated `INFO`, `CONFIG GET`, key listing |
| `network/enum-jabber.sh` | XMPP server enum — banner, cert+SANs, SASL mechs, XEP-0077 advertised?, disco, MUC, BOSH/WS, admin-API exposure |
| `network/enum-postgres.sh` | trust-auth probe + nxc + `pg_roles` recon |
| `network/enum-mysql.sh` | anon root + nxc + `mysql.user` + `secure_file_priv` |
| `network/enum-mongo.sh` | unauth `listDatabases` + per-collection counts |
| `network/enum-elastic.sh` | `_cluster/state`, `_cat/indices`, `_search` cred-grep, Kibana |
| `network/enum-docker.sh` | 2375/2376 daemon API — **CRITICAL** on unauth 2375 |
| `network/enum-kubernetes.sh` | apiserver 6443/8080 + kubelet 10250 + readonly 10255 |
| `network/enum-ipmi.sh` | 623/udp — cipher-0 + RAKP-3 hash dump hints |
| `network/enum-vnc.sh` | nmap vnc-info + RealVNC CVE-2006-2369 + RFB banner |
| `network/enum-jmx.sh` | nmap rmi-* + JRMI handshake probe + mjet/ysoserial hints |
| `network/enum-rabbitmq.sh` | mgmt API guest:guest + auth probe |
| `network/enum-memcached.sh` | `stats` + key inventory via cachedump |
| `network/enum-couchdb.sh` | _all_dbs + _config + CVE-2017-12635 version signal |
| `network/enum-etcd.sh` | /v2/keys + /metrics — CRITICAL on unauth k8s control-plane KV |
| `network/enum-activemq.sh` | 61616 (OpenWire — CVE-2023-46604 candidate) + 8161 (web console / Jolokia — admin:admin → RCE) + 5672 (AMQP) + 61613 (STOMP) banner + version |
| `network/enum-https.sh` | symlink → `enum-http.sh`; routed by nmap-parse for ssl/http services. No separate logic — auto-enum dispatches via service name |
| `network/enum-unknown.sh` | nmap-parse catch-all for services that did not match any port/regex bucket — banner + HTTP/HTTPS probe, baseline `nmap -sV -sC`, then targeted NSE follow-ups (`http-*`, `ssl-*`, SSH/FTP/SMTP/Redis/VNC/RDP scripts) when the first pass suggests a protocol |
| `network/enum-ajp.sh` | AJP/Tomcat (8009) — nmap ajp-headers/methods/auth by default; set `ENUM_AJP_NSE` for custom script sets; Ghostcat CVE-2020-1938 hints |
| `network/enum-oracle.sh` | Oracle DB (1521/1522/1526) — TNS version, SID brute, optional tnscmd10g |
| `network/enum-pop3.sh` | POP3 (110/995) — CAPA banner, plaintext-auth flag, optional ENUM_USER/PASS probe |
| `network/enum-imap.sh` | IMAP (143/993) — CAPABILITY banner, STARTTLS flag, optional LOGIN probe |
| `network/enum-telnet.sh` | Telnet (23) — nc banner + device-family fingerprint (Cisco/HP iLO/Brother/iDRAC/Juniper/Ubiquiti/DD-WRT) |
| `network/enum-rsync.sh` | rsync daemon (873) — anonymous module listing; flags high-value modules (etc/home/root/backup) |
| `network/enum-mqtt.sh` | MQTT (1883/8883) — anonymous $SYS/# subscribe; broker version from $SYS topic |
| `network/enum-sip.sh` | SIP (5060/5061) — nmap sip-methods/enum-users; vendor fingerprint (Asterisk/FreePBX/CUCM/Avaya/Polycom) |
| `network/enum-ipp.sh` | IPP/CUPS (631) — printer list, admin UI, CUPS version; CVE-2024-47176 chain flag for CUPS < 2.4.10 |
| `network/enum-zookeeper.sh` | ZooKeeper (2181/2182) — 4LW commands (ruok/mntr/srvr/conf); flags imok reachability and config exposure |
| `network/enum-cassandra.sh` | Cassandra (9042/9160) — nmap cassandra-info/brute; optional cqlsh anonymous CQL confirm |
| `network/enum-kafka.sh` | Kafka (9092/9093) — kcat/kafkacat broker metadata; topic count; TLS variant for 9093 |
| `network/enum-neo4j.sh` | Neo4j (7474/7687) — HTTP API version, unauth /db/data/; default-cred gated on `ENUM_NEO4J_DEFAULT_CRED=1` |
| `network/enum-influxdb.sh` | InfluxDB (8086/8088) — /ping version header, unauth SHOW DATABASES, /debug/vars |
| `network/enum-solr.sh` | Apache Solr (8983/8984) — system info, core list; CVE-2019-17558 / CVE-2023-50386 version-range signals |
| `network/enum-consul.sh` | Consul (8500/8501) — agent self, unauth KV dump, service catalog, ACL state |
| `network/enum-vault.sh` | Vault (8200/8201) — seal-status (version/cluster/sealed), init-state; tries http + https |
| `network/enum-msrpc.sh` | MSRPC endpoint mapper (135) — impacket-rpcdump → rpcdump.py → rpcclient → nmap msrpc-enum |
| `network/enum-netbios-ns.sh` | NetBIOS-NS (137/udp) — name table via nbtscan/nmblookup; workgroup mismatch signal (rogue host) |
| `network/enum-ike.sh` | **OPT-IN** IKE/IPsec UDP 500/4500 — IKEv1 main-mode handshake probe; vendor-ID extraction; doubly-gated aggressive-mode PSK hash harvest (`ENUM_IKE_AGGRESSIVE_MODE=1`); requires `--ike` or `--aggressive` |
| `network/enum-slp.sh` | **OPT-IN** SLP UDP 427 — nmap NSE slp-discovery/slp-info; CVE-2023-29552 amplification surface flag; requires `--slp` or `--aggressive` |
| `network/enum-radius.sh` | **OPT-IN** RADIUS UDP 1812/1813 — stdlib-only Access-Request probe; BlastRADIUS (CVE-2024-3596) Message-Authenticator enforcement precondition check; requires `--radius` or `--aggressive` |
| `network/enum-print.sh` | Network print services — JetDirect/PJL (9100) + LPD (515); two-evidence-guarded; reports device model + PJL filesystem follow-up hints (I-K cluster from ROADMAP-001) |
| `network/enum-flexnet.sh` | FlexNet Publisher / FLEXlm license servers (27000–27009) — banner detection + `lmutil lmstat -a` when available; characteristic of MATLAB/Cadence/Synopsys/Ansys/COMSOL/Mentor hosts (I-C) |
| `network/enum-hpc.sh` | HPC schedulers — Slurm slurmctld/slurmd (6817/6818), HTCondor collector (9618), YARN ResourceManager (8088); read-side only — no job submission (I-F) |
| `network/enum-monitoring.sh` | Monitoring / lab-data — Zabbix agent (10050) + server (10051), Nagios NRPE (5666), Splunk mgmt API (8089); read-side metric queries + version fingerprints (I-G) |
| `network/enum-backup.sh` | Backup infrastructure detection — Veeam B&R REST (9392), CommVault (8400/81), Veritas NetBackup (1556), Avamar/PowerProtect (7778/7779), Rubrik/Cohesity/PowerProtect APIs (8543); detection-only — pre-auth CVE links in _hints.txt (I-H) |
| `network/enum-artifact.sh` | Artifact/package/container registries — Docker Registry v2, Nexus, Artifactory, Harbor; read-side status/catalog probes only; no pulls/downloads/writes |
| `network/enum-platform.sh` | Platform control planes — Nomad, Portainer, Rancher, Argo CD; read-side version/inventory probes only; no job submission or cluster mutation |
| `network/enum-storage.sh` | Storage fabric/object-store exposure — iSCSI, Ceph/RADOSGW, Gluster, MinIO; read-side discovery only; no mounts, object downloads, or attaches |

### Tier 4 — OT/ICS read-side identification (`ot/`)

**Auto-enum NEVER routes to these.** They live in `ot/` and require both
`--ics-confirm` and a typed `ICS-CONFIRMED` prompt. Read
[`ot/README.md`](ot/README.md) and
[`docs/ADR-005-22MAY2026-ot-ics-safety-scope.md`](docs/ADR-005-22MAY2026-ot-ics-safety-scope.md)
before invoking. Write-side function codes are hard-prohibited — no override.

| Script | Protocol / Port | Probe |
|---|---|---|
| `ot/ot-enum.sh` | orchestrator | Typed-confirmation gate; routes targets to per-proto dispatchers; throttle floor 500ms; max-parallel ceiling 4 |
| `ot/enum-modbus.sh` | Modbus TCP 502 | FC 17 (Report Slave ID) via `nmap modbus-discover aggressive=false` |
| `ot/enum-s7.sh` | Siemens S7comm 102 | Read SZL via `nmap s7-info` (COTP CR + Job 0x29) |
| `ot/enum-enip.sh` | EtherNet/IP 44818 | List Identity (0x0063) via `nmap enip-info` |
| `ot/enum-bacnet.sh` | BACnet/IP 47808/udp | Who-Is broadcast via `nmap bacnet-info` |
| `ot/enum-opcua.sh` | OPC-UA 4840 | GetEndpoints (no session) via `nmap opcua-info` |
| `ot/enum-dnp3.sh` | DNP3 20000 | link-status request via `nmap dnp3-info` |
| `ot/enum-iec104.sh` | IEC 60870-5-104 2404 | TESTFR (act) APDU via stdlib socket |

## Jabber / XMPP (iteration H)

Authorized-testing-only XMPP helpers in `jabber/`. **Read [`docs/ADR-001-19MAY2026-jabber-scope.md`](docs/ADR-001-19MAY2026-jabber-scope.md) and [`jabber/README.md`](jabber/README.md) before use** — they document scope, safety invariants, and the (mandatory typed-FQDN-confirmed + cleanup-required) gating on the only state-modifying tool.

| Tool | Default behavior | Notes |
|---|---|---|
| `jabber/jabber-user-enum.py` | SASL response-differential username enum (read-only) | NO XEP-0077 conflict-probe (that creates accounts) |
| `jabber/jabber-validate.py` | Single-credential SASL validation (SCRAM-SHA-256 → SHA-1 → PLAIN) | NO spray — one user, one password, one attempt |
| `jabber/jabber-admin-api-probe.sh` | Ejabberd `/api/` + Prosody `mod_admin_telnet` / `mod_admin_web` exposure detection | HEAD/banner only |
| `jabber/openfire-cve-2023-32315.py` | `detect` default (read-only); `exploit` modifies target state, requires typed-FQDN confirm + operator-supplied JSP plugin; `cleanup` reverses | Lab-verify against vulnerable 4.7.4 container before engagement use |

### Opt-in aggressive probes (E4)

Three dispatchers cover high-risk UDP services that can cause operational disruption (account lockouts, DDoS reflection amplification, PSK hash leakage). They are **disabled by default** and require an explicit opt-in:

```bash
# Enable specific aggressive probes
./network/auto-enum.sh -i scan.xml --ike          # IKE/IPsec UDP 500
./network/auto-enum.sh -i scan.xml --slp          # SLP UDP 427
./network/auto-enum.sh -i scan.xml --radius       # RADIUS UDP 1812/1813
./network/auto-enum.sh -i scan.xml --aggressive   # all three

# IKE aggressive-mode PSK hash harvest is doubly-gated within --ike:
ENUM_IKE_AGGRESSIVE_MODE=1 ./network/auto-enum.sh -i scan.xml --ike
```

Manual invocation also requires the env gate — the dispatcher refuses with a reminder:
```bash
ENUM_RUN_IKE=1 bash network/enum-ike.sh --targets targets.txt --output /tmp/out
```

**Safety stance (§9):**
- `--slp` / SLP UDP 427 is a CVE-2023-29552 amplification surface (up to 2200x). Do **not** use against internet-facing or arbitrary addresses — you risk becoming a reflection DDoS source.
- `--radius` probes may interact with NAS-side account-lockout policies. Verify that `aratool-probe` does not match any real account before running.
- `--ike` aggressive mode (`ENUM_IKE_AGGRESSIVE_MODE=1`) sends IKEv1 Aggressive Mode packets which can harvest PSK hashes. The double gate is intentional and load-bearing.
- BlastRADIUS detection (CVE-2024-3596) checks the precondition only (Message-Authenticator enforcement). Full exploitation requires nonce-grinding and an on-path position.

## Usage — Network Auto-Enumeration

```bash
# Drop your nmap output in any of these formats — use ALL of them with nmap -oA:
#   nmap -sS -sV -p- --min-rate 2000 -oA scan 10.10.0.0/16

# Then:
./network/auto-enum.sh \
    --input scan.xml \
    --output ./enum-results \
    --user 'CORP\jay' \
    --password 'P@ssword' \
    --domain CORP.LOCAL \
    --dc-ip 10.10.0.1 \
    --parallel 8

# Or unauthenticated:
./network/auto-enum.sh -i scan.xml -o ./enum-unauth
```

Each service dispatcher writes results into `<output>/<service>/<ip>_<port>/` so re-runs are idempotent and findings are easy to grep.

### Iterative second pass

After the first `auto-enum.sh` run, use `iterative-enum.sh` to turn discovered names, shares, web fingerprints, default credentials, and usernames into the next set of pivots:

```bash
./network/iterative-enum.sh \
    --input scan.xml \
    --enum-output ./enum-results \
    --output ./iter-results \
    --user 'CORP\jay' \
    --password 'P@ssword' \
    --domain CORP.LOCAL \
    --dc-ip 10.10.0.1 \
    --ssh-user jay \
    --ssh-key ~/.ssh/id_rsa
```

Use `--mount-shares` only when you want read-only CIFS mounts under `/mnt/aranum_*`; it requires root/sudo and unmounts after each grep pass. The default run still spiders/list-shares, builds `etc-hosts.add`, runs HTTP source-code product fingerprints, runs the low-rate default-credential catalog, harvests usernames, and writes `next-ideas.txt`.

### Operator plan / queue

For large networks, build the operator queue before scanning:

```bash
python3 ./network/aranum.py plan --input scan.xml --output ./enum-results --profile quick
python3 ./network/aranum.py queue ./enum-results --list

# Planning only through auto-enum.sh:
./network/auto-enum.sh -i scan.xml -o ./enum-results --profile quick --plan-only

# Execute only the planned quick profile targets. Default behavior is unchanged
# when --profile/--phase/--queue are omitted.
./network/auto-enum.sh -i scan.xml -o ./enum-results --profile quick --dry-run
```

Planner outputs:

| File | Purpose |
|---|---|
| `plan.json` | Full deterministic plan with profile, phase, priority, and service metadata |
| `queue.jsonl` | One pending work item per line, sorted by operator priority |
| `guidance.json` | Manual handoffs, gated surfaces, and next-step recommendations for dashboard rendering |

Profiles live in `network/engagement-profiles.json`; service priorities and safety metadata live in `network/service-metadata.json`.

## Unified report (iteration E)

After `auto-enum.sh` finishes, generate the consolidated report:

```bash
python3 ./network/aranum.py run scan01 -report
# shorthand: reads scan01.xml/scan01.gnmap/scan01.nmap, writes ./scan01/,
# then writes report artifacts plus ./scan01-dashboard/

python3 ./network/report.py ./enum-results --label "engagement-name"
# writes findings.json + report.md + report.html into ./enum-results/

# For shareable output (replaces every IP with <TARGET-N>):
python3 ./network/report.py ./enum-results --redact

# Compare two runs (CI-loop friendly: exit 1 iff new findings):
./network/autoenum-diff.sh ./prev-results ./curr-results
```

`auto-enum.sh` also writes a central `run.log` capturing tool versions, per-dispatcher exit codes, and elapsed times; `--resume` skips services with a `.done` marker from a prior run.

## Standalone dashboard (v0.29.0)

For a polished multi-page view of the run — severity tiles, per-host detail, per-service detail, coverage matrix, timeline — generate the dashboard:

```bash
python3 ./network/aranum.py dashboard ./enum-results
# writes ./enum-results-dashboard/ and starts a local report server

# Or auto-pick the newest scan-looking output directory in the current dir:
python3 ./network/aranum.py dashboard

# Export static files only, without starting the server:
python3 ./network/aranum.py dashboard ./enum-results --no-serve
```

By default the report server binds to `127.0.0.1` on the first free port at or above `8765`; use `--bind`, `--port`, or `--open` when needed. The output remains a self-contained directory of HTML pages — no CDN or build step required. Pages:

| Page | Purpose |
|---|---|
| `index.html` | severity tiles + top hosts + top services + **noisiest ports** + recent findings + run summary |
| `inbox.html` | operator inbox sorted by triage status, priority, severity, confidence, and target |
| `guidance.html` | planner guidance from `guidance.json` — manual handoffs, gated services, and coverage gaps |
| `hosts.html` | sortable table of every host (max severity, finding count, severity breakdown, services) |
| `host_<ip>.html` | per-host **port × service** table — every probed port on the host with click-to-expand findings + evidence files inline (no extra page load) |
| `inventory.html` | **master port table** — every `(host, port, service)` row in the engagement, sortable + searchable, with severity state and top-finding preview |
| `services.html` | sortable table of every dispatcher exercised |
| `service_<svc>.html` | per-service detail — host inventory + all findings |
| `severity.html` + `severity_<sev>.html` | filtered findings by severity tier |
| `timeline.html` | chronological events from `run.log` |
| `coverage.html` | dispatch matrix (hosts × services) with severity-coloured cells |
| `data.json` | client-side search payload (consumed by the embedded JS) |

Keyboard shortcuts inside the dashboard: `/` focuses the search box; `Esc` clears it; type `>host 10.0.0` then Enter to jump to a host page; `>svc smb` jumps to a service page. Dark theme by default with a toggle in the top nav.

Pass `--bulk` when generating from a `bulk-enum-linux.sh`/`bulk-enum-windows.py` tree instead of an `auto-enum.sh` tree.

`network/report-dashboard.py` remains the underlying generator for advanced/manual use; `aranum.py dashboard` supplies the default output path and scan-output auto-detection.

### Nmap defaults vs aranum depth

`nmap -sC` is not enough for random HTTP services. It runs NSE `default`
scripts, not every product script, and those scripts only run against ports
nmap scanned and identified well enough. Use a broad port scan plus service
version detection first, then feed XML to aranum:

```bash
nmap -Pn -p- --min-rate 5000 -oA tcp-all <target-or-cidr>
nmap -Pn -sV -sC -p <open-port-list> -oX scan.xml <target-or-cidr>
python3 ./network/aranum.py plan --input scan.xml --output ./enum-results --profile quick
```

`enum-http.sh` deliberately retries HTTP and HTTPS on unknown ports and runs
product-specific marker-gated probes that `-sC` will not cover by default.
For ports that nmap leaves as `unknown`, `enum-unknown.sh` now also performs a
second targeted NSE pass: HTTP-like unknowns get `http-*` scripts, TLS-like
unknowns get `ssl-*`, and obvious protocol banners get matching NSE sets. The
HTTP follow-up uses an explicit aggressive-local script expression with
`default`, `discovery`, `intrusive`, `vuln`, and `http-*`, while excluding
`brute`, `dos`, `external`, and `broadcast`; override with
`ENUM_UNKNOWN_HTTP_NSE`, `ENUM_UNKNOWN_TLS_NSE`, etc. when an engagement calls
for a different script expression. Unknown-port nmap follow-ups are bounded by
`ENUM_NMAP_SCRIPT_TIMEOUT`, `ENUM_NMAP_HOST_TIMEOUT`, and
`ENUM_NMAP_WALL_TIMEOUT` so a slow NSE script cannot stall the whole run.
For large HTTP surfaces, tune curl-based probes with
`ENUM_HTTP_CONNECT_TIMEOUT`, `ENUM_HTTP_MAX_TIME`, and
`ENUM_HTTP_PRODUCT_MAX_URLS`.

To preview without running a live engagement, generate against the committed example fixture:

```bash
python3 network/report-dashboard.py --output docs/examples/dashboard/output docs/examples/dashboard/fixture && xdg-open docs/examples/dashboard/output/index.html
```

See [`docs/examples/dashboard/README.md`](docs/examples/dashboard/README.md) for what the fixture covers.

## Bulk local-enum across many hosts (iteration J)

When you have low-privilege credentials on a 50-500 host internal network and need fast per-host privesc enumeration, `network/bulk-enum-linux.sh` pipes `linux/linenum-fast.sh` over SSH to each target in parallel. The remote enumerator **never lands on the victim's disk** — stdin-pipe means it lives in the SSH session's bash memory and is gone when the session ends. Output streams back over the same authenticated SSH channel. See [`docs/ADR-002-20MAY2026-bulk-enum-design.md`](docs/ADR-002-20MAY2026-bulk-enum-design.md) for the design rationale.

```bash
# 1) Build a targets file — one user@host[:port] per line; '#' comments OK.
cat > prod-hosts.txt <<'EOF'
jay@web01.corp
jay@web02.corp
jay@db01.corp:2222
jay@app03.corp
EOF

# 2) Run bulk-enum. Auth via ssh-agent (recommended), --key, or --pass (sshpass).
./network/bulk-enum-linux.sh \
    --targets prod-hosts.txt \
    -k ~/.ssh/engagement_key \
    --output ./prod-bulk \
    --parallel 8

# Sensitive environments (OT/legacy/lab) — gentle mode:
./network/bulk-enum-linux.sh --targets lab-hosts.txt -u lab --pass 'Hunter2!' \
    --throttle -o ./lab-bulk

# Interrupted? --resume continues from where the prior run stopped:
./network/bulk-enum-linux.sh --targets prod-hosts.txt -k ~/.ssh/engagement_key \
    -o ./prod-bulk --resume

# Preview what would happen without connecting:
./network/bulk-enum-linux.sh --targets prod-hosts.txt -u jay -o /tmp/x --dry-run

# 3) Generate the per-host privesc verdict report.
python3 ./network/report.py ./prod-bulk
#   -> ./prod-bulk/findings.json + report.md + report.html (per-host
#      CRITICAL/HIGH/MEDIUM/LOW verdict + drill-down by host)
```

Per-engagement trust silo: `bulk-enum-linux.sh` writes a per-run `known_hosts` file under `$OUT/known_hosts` (not `~/.ssh/known_hosts`) with `accept-new` semantics so first contact is recorded and re-contact is verified within the engagement — without polluting your global trust store or inheriting a previous engagement's host keys.

Output structure:
```
$OUT/
  run.log              # central timestamped journal
  hosts.txt            # copy of input list (audit)
  known_hosts          # engagement-scoped SSH trust silo
  _summary.tsv         # host  rc  elapsed_s  size_kb
  <host>/
    linenum.txt        # raw stdout from linenum-fast.sh
    linenum.err        # ssh + script stderr
    _meta.json         # rc, timing, ssh args
    .done              # touched iff rc=0 (for --resume)
```

After `report.py` runs, `findings.json` adds a `per_host` map with each host's `verdict` (worst severity across its findings) + per-tier finding counts. `report.html` surfaces a sortable per-host verdict table BEFORE the service breakdown so the operator's first view is "which hosts should I focus on?"

### Windows side — `network/bulk-enum-windows.py` (iteration K, v0.16.0)

Same shape, WinRM transport via `pywinrm`. `Invoke-Command -ScriptBlock` wraps the PowerShell so the script never lands on the victim's disk; output streams back over the same WSMan session. Per [`docs/ADR-003-20MAY2026-windows-bulk-enum-design.md`](docs/ADR-003-20MAY2026-windows-bulk-enum-design.md).

```bash
# Windows hosts file format — same as Linux side (user@host[:port]).
cat > windows-hosts.txt <<'EOF'
CORP\jay@WIN-DC01.corp:5985
CORP\jay@WIN-MEMBER01.corp
CORP\jay@WIN-MEMBER02.corp
EOF

# WinRM HTTP (5985). Auth defaults to NTLM. --pass works for NTLM/Basic/CredSSP.
./network/bulk-enum-windows.py \
    --targets windows-hosts.txt \
    --pass 'P@ssw0rd' \
    --output ./prod-win \
    --parallel 8

# WinRM HTTPS (5986). Cert validation is "ignore" by default for engagement
# reality — flag if your env requires strict verification.
./network/bulk-enum-windows.py --targets windows-hosts.txt --pass '...' \
    --tls -o ./prod-win-tls

# Kerberos (recommended for domain envs) — pre-existing krb5 ticket cache
# (run `kinit` first). pywinrm picks up the cache automatically.
./network/bulk-enum-windows.py --targets windows-hosts.txt --auth kerberos \
    -o ./prod-win-krb5

# Mixed estate — run BOTH orchestrators into the same $OUT. report.py
# rolls them up into ONE per-host verdict table with an `os` column.
./network/bulk-enum-linux.sh   --targets linux.txt   -u jay -k ~/.ssh/k -o ./estate
./network/bulk-enum-windows.py --targets windows.txt --pass '...' --tls -o ./estate
python3 ./network/report.py ./estate    # one report, mixed-OS, worst-first
```

**Authentication reach (read this before you trust the orchestrator at scale).** WinRM as a domain user requires "Remote Management Users" group membership on each target. That's uncommon in real environments — many domains gate WinRM to local Administrators only. If your engagement creds don't have that membership, bulk-enum-windows will fail clean (rc=255 per host with the pywinrm fault in `winenum.err`) and you'll need to fall back to the standalone `windows/*.ps1` scripts via WinRM/SMB transfer or remote desktop. `--use-smb-admin` documents the admin fallback path but the implementation is deferred (refuses with rc=126 + reason) — operators who already have admin should use `impacket-wmiexec` / `-psexec` directly with their engagement scoping.

**Validation gap.** Per ADR-003 "WHAT THIS DOES NOT VALIDATE": this codebase ships on Fedora with no domain-joined Windows host in CI, so the WinRM transport is unverified pre-engagement. Mock-pywinrm unit tests cover everything OUTSIDE the transport (target parsing, IPv6 bracketing, output layout, arg validation, --dry-run, --throttle precedence). The operator's first real run against a known-good Windows VM is the transport validation. The ADR has a verification checklist.

## Dependencies

Run `./deps-check.sh` to see what's installed/missing. Recommended:

- **Required**: python3, nmap, ldapsearch, smbclient, rpcclient, dig, snmpwalk
- **Highly recommended**: netexec (nxc), enum4linux-ng, impacket-scripts, kerbrute, ssh-audit, whatweb, httpx, ffuf, onesixtyone
- **Optional**: nuclei, nikto, evil-winrm, mssqlclient.py, rdp-sec-check, shellcheck (for `make lint`), sshpass (only for `bulk-enum-linux.sh --pass`), pywinrm (only for `bulk-enum-windows.py`; `pip install pywinrm`)
- **AD depth (D1)**: `bloodhound-python` (`pipx install bloodhound-py`), `certipy-ad` (`pipx install certipy-ad`), impacket scripts (`pipx install impacket` provides `GetUserSPNs.py`/`GetNPUsers.py`/`petitpotam.py`/etc.). Each is OPTIONAL — the AD dispatchers detect-and-skip when a tool is missing per [ADR-004](docs/ADR-004-20MAY2026-ad-depth-tool-deps.md) D3.

## Safety / OPSEC

- Network auto-enum defaults to read-side probing; exploit/write helpers are separate and require their documented explicit gates.
- All network scripts respect `--rate` and `--parallel` flags; default is conservative.
- Authentication is passed via env vars or CLI flags — never hardcoded.
- Output writes only to `--output` dir; nothing modifies target systems.
- For lab/CTF/authorized-engagement use only.
