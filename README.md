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

## Network Enumeration

| Script | Purpose |
|---|---|
| `network/nmap-parse.py` | Parse `.xml`, `.gnmap`, and `.nmap` files → JSON inventory by service |
| `network/auto-enum.sh` | Master orchestrator: nmap output → service buckets → dispatch enum |
| `network/enum-smb.sh` | `enum4linux-ng`, `nxc smb --shares --users --pass-pol --spider`, smbclient, rpcclient |
| `network/enum-ldap.sh` | `nxc ldap`, `ldapsearch`, `GetUserSPNs.py`, `GetNPUsers.py` |
| `network/enum-kerberos.sh` | AS-REP roast, SPN enum, `kerbrute userenum` |
| `network/enum-winrm.sh` | `nxc winrm`, command exec test, evil-winrm spray |
| `network/enum-rdp.sh` | `nxc rdp`, `rdp-sec-check`, NLA detection |
| `network/enum-mssql.sh` | `nxc mssql`, `mssqlclient.py`, xp_cmdshell check |
| `network/enum-http.sh` | `whatweb`, `httpx`, `nuclei`, `ffuf` (light wordlist), `nikto` (optional) |
| `network/enum-ssh.sh` | `ssh-audit`, banner, `nxc ssh` cred spray, key auth probe |
| `network/enum-ftp.sh` | Anonymous, `nxc ftp` cred spray |
| `network/enum-snmp.sh` | `onesixtyone` + `snmpwalk` with common communities |
| `network/enum-nfs.sh` | `showmount -e`, no_root_squash detection |
| `network/enum-dns.sh` | `dig axfr`, `dnsrecon`, reverse lookup |
| `network/enum-redis.sh` | Unauthenticated `INFO`, `CONFIG GET`, key listing |
| `network/enum-jabber.sh` | XMPP server enum — banner, cert+SANs, SASL mechs, XEP-0077 advertised?, disco, MUC, BOSH/WS, admin-API exposure |

## Jabber / XMPP (iteration H)

Authorized-testing-only XMPP helpers in `jabber/`. **Read [`docs/ADR-001-19MAY2026-jabber-scope.md`](docs/ADR-001-19MAY2026-jabber-scope.md) and [`jabber/README.md`](jabber/README.md) before use** — they document scope, safety invariants, and the (mandatory typed-FQDN-confirmed + cleanup-required) gating on the only state-modifying tool.

| Tool | Default behavior | Notes |
|---|---|---|
| `jabber/jabber-user-enum.py` | SASL response-differential username enum (read-only) | NO XEP-0077 conflict-probe (that creates accounts) |
| `jabber/jabber-validate.py` | Single-credential SASL validation (SCRAM-SHA-256 → SHA-1 → PLAIN) | NO spray — one user, one password, one attempt |
| `jabber/jabber-admin-api-probe.sh` | Ejabberd `/api/` + Prosody `mod_admin_telnet` / `mod_admin_web` exposure detection | HEAD/banner only |
| `jabber/openfire-cve-2023-32315.py` | `detect` default (read-only); `exploit` modifies target state, requires typed-FQDN confirm + operator-supplied JSP plugin; `cleanup` reverses | Lab-verify against vulnerable 4.7.4 container before engagement use |

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

## Dependencies

Run `./deps-check.sh` to see what's installed/missing. Recommended:

- **Required**: python3, nmap, ldapsearch, smbclient, rpcclient, dig, snmpwalk
- **Highly recommended**: netexec (nxc), enum4linux-ng, impacket-scripts, kerbrute, ssh-audit, whatweb, httpx, ffuf, onesixtyone
- **Optional**: nuclei, nikto, evil-winrm, mssqlclient.py, rdp-sec-check

## Safety / OPSEC

- Scripts are **enumeration-only** — no exploit payloads. They run standard recon tools.
- All network scripts respect `--rate` and `--parallel` flags; default is conservative.
- Authentication is passed via env vars or CLI flags — never hardcoded.
- Output writes only to `--output` dir; nothing modifies target systems.
- For lab/CTF/authorized-engagement use only.
