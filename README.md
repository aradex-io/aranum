# Pentest Enumeration Toolkit — 19MAY2026

Authorized-testing-only collection of privilege escalation enumeration scripts (Windows + Linux) and a network enumeration orchestrator that consumes nmap output and dispatches per-service authenticated enumeration.

## Layout

```
aratool/
├── windows/        # PowerShell + batch privesc enumeration
├── linux/          # Bash privesc enumeration (no-deps + extended)
├── network/        # nmap-output parser + service dispatchers
├── graphql/        # GraphQL toolkit (GitLab-tuned)
├── activemq/       # ActiveMQ enumeration + targeted CVE PoC
├── redis/          # Redis quickwin / lateral / RCE helpers
├── smtp/           # SMTP enumeration + relay / smuggling tests
├── creds/          # Default-credential sweep
├── jabber/         # XMPP/Jabber enum + OpenFire CVE-2023-32315 helper
├── docs/           # CLAUDE.md governance, ADRs, REVIEW + ROADMAP
└── deps-check.sh   # Verify required tools on attacker box
```

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
| `network/nmap-parse.py` | Parse `.xml`, `.gnmap`, and `.nmap` files → JSON inventory by service |
| `network/auto-enum.sh` | Master orchestrator: nmap output → service buckets → dispatch enum |
| `network/bulk-enum-linux.sh` | **Post-foothold** — pipe `linenum-fast.sh` over SSH to many hosts in parallel; per-host verdicts via `report.py` (J.1) |
| `network/bulk-enum-windows.py` | **Post-foothold** — ship `Invoke-PrivEscEnum.ps1` over WinRM (pywinrm) to many Windows hosts in parallel; same `report.py` rolls up mixed Linux+Windows estates (K.1) |
| `network/enum-smb.sh` | `enum4linux-ng`, `nxc smb --shares --users --pass-pol --spider`, smbclient, rpcclient |
| `network/enum-ldap.sh` | `nxc ldap`, `ldapsearch`, `GetUserSPNs.py`, `GetNPUsers.py` |
| `network/enum-kerberos.sh` | AS-REP roast, SPN enum, `kerbrute userenum` |
| `network/enum-winrm.sh` | `nxc winrm`, command exec test, evil-winrm spray |
| `network/enum-rdp.sh` | `nxc rdp`, `rdp-sec-check`, NLA detection |
| `network/enum-mssql.sh` | `nxc mssql`, `mssqlclient.py`, xp_cmdshell check |
| `network/enum-http.sh` | `whatweb`, `httpx`, `nuclei`, `ffuf` (light wordlist), `nikto` (optional); **C.13 product-fingerprint phase** fans 9 product-specific probes per live URL (Tomcat Manager, Jenkins including Groovy script console RCE check, GitLab, SonarQube, Grafana, Prometheus, Hadoop NameNode, Spark UI, **VMware vCenter SDK + UI** added in E4); each detector requires a product-specific marker (header pattern, JSON key, or exact body string) before emitting a hit; skippable via `NO_PRODUCT_DETECT=1` |
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
| `network/enum-ajp.sh` | AJP/Tomcat (8009) — nmap ajp-headers/methods/auth/brute; Ghostcat CVE-2020-1938 hints |
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

## Unified report (iteration E)

After `auto-enum.sh` finishes, generate the consolidated report:

```bash
python3 ./network/report.py ./enum-results --label "engagement-name"
# writes findings.json + report.md + report.html into ./enum-results/

# For shareable output (replaces every IP with <TARGET-N>):
python3 ./network/report.py ./enum-results --redact

# Compare two runs (CI-loop friendly: exit 1 iff new findings):
./network/autoenum-diff.sh ./prev-results ./curr-results
```

`auto-enum.sh` also writes a central `run.log` capturing tool versions, per-dispatcher exit codes, and elapsed times; `--resume` skips services with a `.done` marker from a prior run.

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

- Scripts are **enumeration-only** — no exploit payloads. They run standard recon tools.
- All network scripts respect `--rate` and `--parallel` flags; default is conservative.
- Authentication is passed via env vars or CLI flags — never hardcoded.
- Output writes only to `--output` dir; nothing modifies target systems.
- For lab/CTF/authorized-engagement use only.
