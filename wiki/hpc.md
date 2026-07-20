---
service: hpc
title: HPC Schedulers (Slurm / HTCondor / YARN)
ports: 6817, 6818, 9618, 8088
aliases: slurm, slurmctld, condor, yarn
---

# HPC schedulers — quick wins

**When you see it:** Slurm `slurmctld` (6817) / `slurmd` (6818), HTCondor collector (9618),
or Hadoop YARN ResourceManager (8088) — cluster schedulers that run arbitrary jobs across
many nodes. An unauthenticated YARN RM is a well-known unauth-RCE-via-job-submission surface.
aranum is **read-side only** — it never submits a job.

> Authorized testing only. Triage is read-only. Job submission = code execution on cluster
> nodes; it is explicitly out of aranum scope — only run it with written exploitation sign-off.

## Triage (read-only)
```sh
curl -s http://H:8088/ws/v1/cluster/info           # YARN RM — Hadoop version, HA state
curl -s http://H:8088/ws/v1/cluster/apps           # running/finished applications
nmap -sV -p 6817,6818,9618 H                        # Slurm/HTCondor banners
nc -nv -w 4 H 9618                                   # HTCondor collector reachability
```

## Quick wins

### YARN ResourceManager — unauth cluster read
```sh
curl -s http://H:8088/ws/v1/cluster/info | python3 -m json.tool
curl -s http://H:8088/ws/v1/cluster/nodes          # every NodeManager + address
curl -s http://H:8088/ws/v1/cluster/apps           # app history, users, queues
```
*Why:* when the RM REST API is unauthenticated (default in stock Hadoop), you read the whole
cluster — versions, node inventory, running users, and app configs. The same API's
`/apps/new-application` + submit is the RCE primitive (out of scope here, but confirm the
surface is open).

### Slurm cluster state (read commands)
```sh
sinfo -M all                    # partitions, node states (needs slurm client + reachable ctld)
scontrol show config | grep -Ei "version|AuthType|SlurmUser"
```
*Why:* `scontrol show config` reveals the Slurm version and `AuthType` (`munge` vs none). No
munge / shared munge key = the door to job submission; version maps to known slurmctld CVEs.

### HTCondor collector query
```sh
condor_status -pool H:9618        # daemons, slots, versions (needs condor client)
```
*Why:* the collector answers pool-wide status queries; it discloses every startd/schedd, its
version, and slot layout — reconnaissance for a `condor_submit` foothold.

## aranum helpers
- `aranumtoolkit/network/enum-hpc.sh` — dispatcher (Slurm 6817/6818, HTCondor 9618, YARN 8088; read-side only, no job submission).

## Gotchas
- Slurm auth is `munge`-based — without the shared `/etc/munge/munge.key` you cannot submit; the read-side `scontrol` may still answer.
- YARN clusters with `yarn.acl.enable` / Kerberos return 401 — check for the plain HTTP RM before assuming it's locked.
- 8088 is also generic alt-HTTP; require the `ws/v1/cluster` marker before calling it YARN.
- Job submission on any of these executes on worker nodes as the scheduler/job user — treat as RCE and gate accordingly.

## Sources
- Hadoop YARN ResourceManager REST API docs; SchedMD Slurm `scontrol`/`sinfo` reference; HTCondor manual; aranum iteration I-F.
