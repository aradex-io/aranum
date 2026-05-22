# ROADMAP-002 — Tier 1 + Tier 2 Network Enumeration Expansion

**Date:** 2026-05-22
**Author:** plan-on-Opus / execute-on-Sonnet (CLAUDE.md §2)
**Iterations:** E1 (Tier 1, v0.19.0) → E2 (Tier 2a, v0.20.0) → E3 (Tier 2b http product-detect, v0.21.0) → E4 (Tier 2c UDP/specialty, v0.22.0)

---

## Motivation

`nmap-parse.py` already routes 8 service categories (`ajp`, `oracle`, `pop3`, `imap`, `telnet`, `rsync`, `mqtt`, `sip`) for which `auto-enum.sh` has **no dispatcher** — they fall through silently. Tier 1 closes that gap. Tier 2 adds high-yield enterprise services (Solr, Consul, Vault, Zookeeper, etc.) not currently routed at all.

---

## E1 — Tier 1: 8 dispatchers, categories already in SERVICE_MAP

| # | Dispatcher | Port(s) | Primary checks | Required deps |
|---|---|---|---|---|
| 1 | `enum-ajp.sh` | 8009 | `nmap --script ajp-headers,ajp-methods,ajp-auth,ajp-brute`; banner; _hints points at Ghostcat PoC repos (no PoC shipped — see §Notes) | nmap |
| 2 | `enum-oracle.sh` | 1521/1522/1526 | `nmap --script oracle-tns-version,oracle-sid-brute,oracle-brute-stealth` | nmap |
| 3 | `enum-pop3.sh` | 110/995 | `CAPA`; plaintext-auth flag; `nmap --script pop3-capabilities,pop3-brute`; openssl s_client for 995 | nc, openssl, nmap |
| 4 | `enum-imap.sh` | 143/993 | `CAPABILITY`; STARTTLS-required check; `nmap --script imap-capabilities,imap-brute`; openssl s_client for 993 | nc, openssl, nmap |
| 5 | `enum-telnet.sh` | 23 | Banner grab; device-family detection (Cisco/HP/Brother/Dell-iDRAC); `nmap --script telnet-encryption,telnet-ntlm-info,banner` | nc, nmap |
| 6 | `enum-rsync.sh` | 873 | `rsync rsync://$ip/` for module list; recursive top-level listing of each module; flag HIGH if `etc`, `home`, `backup`, `var`, `srv`, `root` exposed | rsync |
| 7 | `enum-mqtt.sh` | 1883/8883 | `mosquitto_sub -t '$SYS/#' -W 5` anonymous (rc ∈ {0,27} = success); `nmap --script mqtt-subscribe`; TLS variant via `--insecure` on 8883 | mosquitto-clients |
| 8 | `enum-sip.sh` | 5060 | `nmap -sU/-sT --script sip-methods,sip-enum-users`; optional SIPVicious `svmap`/`svwar` if installed | nmap |

### Cross-cutting work per dispatcher

For each new dispatcher:
1. Drop file in `network/enum-<svc>.sh` following the `enum-memcached.sh` template (set -uo pipefail, source _lib.sh, parse_common_args, throttle_sleep where appropriate, emit `_hints.txt`).
2. Add severity rule(s) to `network/report.py` so emitted `UNAUTH:` and version-banner lines are graded.
3. Update `deps-check.sh` for any new external tool.
4. Update top-level `README.md` "Network enumeration" section.
5. Update `CHANGELOG.md` `[Unreleased]` → `Added`.

### Notes

- **AJP / CVE-2020-1938 (Ghostcat):** there is no first-party nmap NSE that does the actual file-read PoC. Do **not** claim Ghostcat detection in `enum-ajp.sh`. Run the available scripts (`ajp-headers/methods/auth/brute`), then in `_hints.txt` point operators at the known Python PoC (`AjpShooter.py` / `00theway/Ghostcat-CNVD-2020-10487`) for verification.
- **MQTT `mosquitto_sub`:** when `-W <secs>` fires after a successful subscribe, exit code is **27** — that's the success case for anonymous-broker confirmation. Treat `rc ∈ {0, 27}` as success; `rc ∈ {5, 14}` as auth-required.
- **Throttle awareness:** `enum-rsync.sh` and `enum-sip.sh` can hammer; call `throttle_sleep` between hosts.

---

## E2 — Tier 2a: 11 new categories + dispatchers

### SERVICE_MAP additions (`network/nmap-parse.py`)

```python
"ipp":         ({631},                 r"^(ipp|cups)"),
"zookeeper":   ({2181, 2182},          r"^zookeeper"),
"cassandra":   ({9042, 9160},          r"^(cassandra|apani1)"),
"kafka":       ({9092, 9093},          r"^kafka"),
"neo4j":       ({7474, 7687},          r"^neo4j"),
"influxdb":    ({8086, 8088},          r"^influxdb"),
"solr":        ({8983, 8984},          r"a^"),  # fingerprints as http
"consul":      ({8500, 8501},          r"a^"),  # fingerprints as http
"vault":       ({8200, 8201},          r"a^"),  # fingerprints as http/https
"msrpc":       ({135},                 r"^(msrpc|ms-rpc|epmap)"),
"netbios-ns":  ({137},                 r"^netbios-ns"),
```

> Tests: `tests/test_nmap_parse.py` must add fixtures for each new category. ref obs 8802 (last time, a SERVICE_MAP add broke routing tests because dispatch() entries needed manual decoration).

### Dispatcher checklist

| Dispatcher | Probe |
|---|---|
| `enum-ipp.sh` | `curl http://$ip:631/printers`; CUPS-Browsed UDP 631 probe; CVE-2024-47176 banner-version compare |
| `enum-zookeeper.sh` | 4-letter words: `echo mntr` / `echo srvr` / `echo conf` / `echo ruok` via `nc` |
| `enum-cassandra.sh` | `cqlsh $ip 9042 -e "SELECT release_version FROM system.local"`; nmap `cassandra-info` |
| `enum-kafka.sh` | `kafkacat -L -b $ip:9092` (anonymous broker metadata + topic list) |
| `enum-neo4j.sh` | HTTP `GET /db/data/`; default `neo4j/neo4j` cred probe (single attempt, locks itself); Bolt 7687 reachability |
| `enum-influxdb.sh` | `curl http://$ip:8086/ping` for version header; `SHOW DATABASES` via `query` API |
| `enum-solr.sh` | `curl http://$ip:8983/solr/admin/cores?wt=json`; CVE-2019-17558 / CVE-2023-50386 version compare |
| `enum-consul.sh` | `curl http://$ip:8500/v1/agent/self`; `/v1/kv/?recurse` (ACL-disabled = unauth dump) |
| `enum-vault.sh` | `curl http://$ip:8200/v1/sys/seal-status`; `/v1/sys/health`; `/v1/sys/init` |
| `enum-msrpc.sh` | `rpcdump.py @$ip` (impacket); `rpcclient -U '' -N $ip` if sambacli installed |
| `enum-netbios-ns.sh` | `nbtscan -r $ip/32` or `nmblookup -A $ip` |

---

## E3 — Tier 2b: HTTP product detectors (extend `enum-http.sh` only)

Add a "product-detect" phase that fans these probes per http target:
- Tomcat manager `/manager/html`, `/host-manager/text/list`
- Jenkins `/api/json`, `/asynchPeople/api/json`, `/script` (POST 403 check)
- GitLab `/api/v4/version`, `/api/v4/users` (auth)
- SonarQube `/api/server/version`
- Grafana `/api/health`, `/api/datasources`
- Prometheus `/api/v1/status/config`, `/-/healthy`
- Hadoop NameNode `/dfshealth.html`, `/jmx`
- Spark UI `/api/v1/applications`

No new dispatchers, no SERVICE_MAP changes.

---

## E4 — Tier 2c: UDP / specialty (opt-in via flags)

- IKE 500/udp via `ike-scan` — gated by `--ike` flag (noisy, aggressive-mode PSK harvest)
- SLP 427 via `slpd`/`openslp-tools` — gated by `--slp` flag
- RADIUS 1812/1813 — `eapmd5pass` precondition / BlastRADIUS CVE-2024-3596 reachability — gated by `--radius` flag
- VMware vCenter (5480/902) — folds into E3 https product-detect, not a separate dispatcher

---

## Tier 4 — ICS (deferred)

Modbus 502 / S7 102 / EtherNet/IP 44818 / BACnet 47808 require a separate spec doc and `--ics` flag with an explicit confirmation prompt. Tracked separately; do not include in E1–E4.

---

## Sonnet Execution Brief (E1 only)

See accompanying message — separate brief generated for direct hand-off.
