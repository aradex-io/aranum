---
service: solr
title: Apache Solr
ports: 8983, 8984
aliases: solr
---

# Apache Solr — quick wins

**When you see it:** 8983/tcp open and `/solr/admin/info/system` returns JSON without auth →
an unauthenticated Solr admin API. Solr has a rich RCE history: the Velocity template RCE
(CVE-2019-17558), the ConfigSet/backup RCE (CVE-2023-50386), plus config-API SSRF and an XXE.

> Authorized testing only. Triage is read-only. Enabling params / config changes and the RCE
> chains (marked ✏️) modify the target — get sign-off; they toggle `params.resource.loader`
> and write config.

## Triage (read-only)
```sh
curl -s "http://H:8983/solr/admin/info/system?wt=json" | python3 -m json.tool | grep -i version
curl -s "http://H:8983/solr/admin/cores?wt=json"                 # core list
curl -s "http://H:8983/solr/admin/collections?action=LIST&wt=json"
curl -s "http://H:8983/solr/CORE/config?wt=json"                 # per-core config
```

## Quick wins

### Enumerate cores / collections
```sh
curl -s "http://H:8983/solr/admin/cores?wt=json" | python3 -m json.tool
```
*Why:* names the indexes and their config/schema — the target set for data queries and the
core name you need for the RCE chains below.

### Data query / secret hunting
```sh
curl -s "http://H:8983/solr/CORE/select?q=*:*&rows=20&wt=json"
curl -s "http://H:8983/solr/CORE/select?q=password:*+OR+secret:*&wt=json"
```
*Why:* `q=*:*` dumps documents; Solr indexes application data that frequently includes PII,
tokens, and credentials in fields.

### VelocityResponseWriter RCE — CVE-2019-17558 ✏️
```sh
# 1) enable params resource loader on the core (config API), then
# 2) request a Velocity template that runs a command. Public PoCs / Metasploit
#    (exploit/multi/http/solr_velocity_rce) automate both steps.
```
*Why:* Solr 5.0–8.3.1 lets the config API turn on `params.resource.loader.enabled`, after which
a crafted `v.template` in a query executes Java/OS commands — unauth RCE. Command-level only;
use the public module.

### ConfigSet / backup-restore RCE — CVE-2023-50386
```sh
# upload a malicious ConfigSet (with a lib/ jar) via the backup/restore or
# configset upload API, then load it — public advisories detail the steps.
```
*Why:* Solr ≤ 8.11.2 / 9.x < 9.4.1 lets an attacker smuggle executable code through ConfigSet
upload + backup/restore → RCE. Also note CVE-2017-12629 (RunExecutableListener RCE + XXE) on
old 5.x/6.x and CVE-2021-27905 (replication-handler SSRF).

## aranum helpers
- `aranumtoolkit/network/enum-solr.sh` — dispatcher (system info, core list; CVE-2019-17558 / CVE-2023-50386 version-range signals).

## Gotchas
- Solr's Admin UI is unauthenticated by default — auth (BasicAuthPlugin) is opt-in and often absent, which is exactly why these RCEs land.
- CVE-2019-17558 needs the config API reachable to flip the Velocity loader — locked-down cores where config edits are blocked defeat it.
- 8984 is a common second node/replica; check both.
- `RunExecutableListener` (CVE-2017-12629) is disabled by default in later 6.x/7.x — version-gate before trying.

## Sources
- CVE-2019-17558 / CVE-2023-50386 / CVE-2017-12629 / CVE-2021-27905 advisories; HackTricks `8983-pentesting-apache-solr`; Metasploit `solr_velocity_rce`.
