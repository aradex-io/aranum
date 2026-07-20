---
service: backup
title: Backup Infrastructure
ports: 9392, 8400, 1556, 7778, 8543
aliases: veeam, commvault, netbackup, avamar, rubrik
---

# Backup infrastructure — quick wins

**When you see it:** a Veeam B&R REST (9392), CommVault (8400/81), Veritas NetBackup (1556),
Avamar/PowerProtect (7778/7779), or Rubrik/Cohesity (8543) endpoint — backup servers hold
credentials to *every* system they protect, so a single pre-auth bug here is domain-wide.
aranum is **detection-only**; pre-auth CVE links land in `_hints.txt`.

> Authorized testing only. Triage is read-only. Exploitation of these products is high-impact
> and destructive-adjacent (they can restore/delete data) — get explicit sign-off and stay at
> the version-confirm level unless the engagement scopes exploitation.

## Triage (read-only)
```sh
curl -sk https://H:9392/api/v1/serverInfo           # Veeam B&R REST — version banner
curl -sk https://H:81/SearchSvc/CVWebService.svc/    # CommVault web service
nmap -sV -p 1556,13724 H                             # Veritas NetBackup PBX/vnetd
curl -sk https://H:8543/api/v1/cluster/me            # Rubrik cluster info
curl -sk https://H:8543/irisservices/api/v1/public/cluster   # Cohesity cluster info
```

## Quick wins

### Veeam B&R — version → known pre-auth CVEs
```sh
curl -sk https://H:9392/api/v1/serverInfo | python3 -m json.tool
```
*Why:* the unauth `serverInfo` banner discloses the exact build; map it to CVE-2023-27532
(credential decrypt via the backup service), CVE-2024-40711 (unauth deserialization RCE in
12.1.2 and below), or CVE-2025-23120. Confirm version before touching anything else.

### CommVault — CVE-2025-34028 / path traversal
```sh
curl -sk "https://H:81/SearchSvc/CVWebService.svc/GetCVSPInfo"
```
*Why:* the CommVault Command Center exposes unauthenticated endpoints; recent CVEs
(CVE-2025-34028 pre-auth SSRF→RCE, CVE-2025-3928 webshell) target this surface — the banner
tells you if the build is in range.

### NetBackup / Avamar service fingerprint
```sh
nmap -sV --script banner -p 1556,13724,7778,7779 H
```
*Why:* NetBackup PBX (1556) and Avamar/PowerProtect (7778/7779) rarely expose a web UI;
banner + port profile confirms product and version for offline CVE lookup — no live exploit
from the read side.

### Rubrik / Cohesity API version leak
```sh
curl -sk https://H:8543/api/v2/about
curl -sk https://H:8543/irisservices/api/v1/public/cluster
```
*Why:* both expose an unauthenticated `about`/`cluster` endpoint with the software version and
node topology — enough to scope the appliance and check for known auth-bypass CVEs.

## aranum helpers
- `aranumtoolkit/network/enum-backup.sh` — dispatcher (Veeam/CommVault/NetBackup/Avamar/Rubrik/Cohesity detection + version, read-only; CVE links in `_hints.txt`).

## Gotchas
- These are the crown jewels — coordinate tightly; a mistimed "restore test" can overwrite production data.
- Many appliances present a generic nginx/IIS front — rely on the product-specific API path, not the server header.
- Ports overlap with unrelated services (81 = alt-HTTP, 8543 = many appliances); require the product marker before believing the hit.
- Veeam creds, once decrypted, unlock every guest OS credential stored for backup jobs — treat as a full-network pivot.

## Sources
- CVE-2023-27532 / CVE-2024-40711 (Veeam); CVE-2025-34028 (CommVault); vendor security advisories;
  ROADMAP-001 iteration I-H notes.
