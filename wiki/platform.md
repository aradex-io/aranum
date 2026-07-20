---
service: platform
title: Platform Control Planes (Nomad / Portainer / Rancher / Argo CD)
ports: 4646, 9000, 9443, 8080
aliases: nomad, portainer, rancher, argocd
---

# Platform control planes — quick wins

**When you see it:** a Nomad (4646), Portainer (9000/9443), Rancher (443), or Argo CD
(8080/443) endpoint — orchestration control planes that schedule containers/jobs across a
fleet. An unauthenticated Nomad or a fresh Portainer (no admin set) is direct cluster-wide
RCE. aranum probes read-side version/inventory only — no job submission or cluster mutation.

> Authorized testing only. Triage is read-only. Job/stack creation (marked ✏️) runs
> containers on the cluster = RCE across nodes — explicitly out of aranum scope; only with
> written exploitation sign-off.

## Triage (read-only)
```sh
curl -s http://H:4646/v1/status/leader                 # Nomad — leader (unauth?)
curl -s http://H:4646/v1/jobs                          # Nomad job list
curl -sk https://H:9443/api/status                     # Portainer status (+ /api/users/admin/check)
curl -sk https://H:443/v3/settings/server-version      # Rancher version
curl -sk https://H:8080/api/version                    # Argo CD version
```

## Quick wins

### Nomad — unauth job read (RCE surface)
```sh
curl -s http://H:4646/v1/status/leader
curl -s http://H:4646/v1/jobs
curl -s http://H:4646/v1/nodes                         # every client node + address
```
*Why:* Nomad with ACLs disabled (default) answers these unauthenticated. The same API's
`PUT /v1/jobs` with a `raw_exec`/`docker` task is the well-known unauth RCE — confirming the
read surface is open confirms the exploit surface is too (out of scope to fire here).

### Portainer — uninitialized admin ✏️
```sh
curl -sk https://H:9443/api/users/admin/check          # 404 = no admin yet (seizable)
# if 404: POST /api/users/admin/init to set your own admin password
```
*Why:* a freshly deployed Portainer with no admin lets the first caller to `/api/users/admin/init`
set the admin password and take the whole Docker/Swarm/K8s environment it manages.

### Rancher / Argo CD — default creds + version
```sh
curl -sk https://H:443/v3/settings/server-version
# Argo CD initial admin password = the argocd-server pod name (if not rotated)
curl -sk https://H:8080/api/version
```
*Why:* the version endpoints are unauthenticated and map to known control-plane CVEs; Rancher
historically shipped `admin:admin`, and Argo CD's initial admin password is the server pod
name — both are frequent first-blood creds that grant fleet-wide control.

## aranum helpers
- `aranumtoolkit/network/enum-platform.sh` — dispatcher (Nomad/Portainer/Rancher/Argo CD version + inventory, read-side only; no job submission or cluster mutation).

## Gotchas
- Nomad ACLs, when enabled, return 403 with `Permission denied` — a leaked `X-Nomad-Token` re-opens the API.
- Portainer's `admin/check` returning 204/`true` means an admin already exists — pivot to default/guessed creds instead.
- These planes usually manage Docker/K8s underneath — success here chains straight to `wiki/docker.md` / `wiki/kubernetes.md`.
- 9000 (Portainer) collides with MinIO and others — require the product marker before trusting the hit.

## Sources
- HashiCorp Nomad API docs (ACL/`raw_exec`); Portainer `admin/init` writeups; Rancher/Argo CD default-credential notes; aranum `enum-platform.sh`.
