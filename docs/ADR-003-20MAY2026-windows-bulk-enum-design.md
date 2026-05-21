# ADR-003 — Windows bulk-enum (iteration K)

| | |
|---|---|
| **Status** | Accepted (2026-05-20) |
| **Iteration** | K (introduced 2026-05-20) |
| **Tag** | `v0.16.0` |
| **Supersedes** | none |
| **Related** | [ADR-002](ADR-002-20MAY2026-bulk-enum-design.md), CLAUDE.md §9 |

## Context

[ADR-002](ADR-002-20MAY2026-bulk-enum-design.md) shipped Linux bulk-enum
(`network/bulk-enum-linux.sh`) over SSH stdin-pipe at v0.15.0. ADR-002 D6
explicitly deferred the Windows orchestrator to a follow-up iteration. This
ADR records the Windows-side design.

The operator's stated workflow is unchanged: with low-privilege credentials
on a 50-500 host internal network, run `windows/Invoke-PrivEscEnum.ps1`
against every reachable Windows host in parallel and roll up per-host
verdicts via `report.py`. The transport must respect CLAUDE.md §9 invariants
1, 2, 4, 5 (no auto-mutation, no exfil, no persistence, no detection-evasion).

## Decisions

### D1 — WinRM (`pywinrm`) is the default and only transport

**Decision:** `network/bulk-enum-windows.py` connects via WinRM (port 5985 HTTP
or 5986 HTTPS) using the `pywinrm` Python package. The remote script is sent
inside an `Invoke-Command -ScriptBlock { ... }`-equivalent payload and stdout
streams back over the same WinRM session.

**Reason:**
1. **Symmetric to ADR-002 D1.** Like SSH stdin-pipe, WinRM PSRP keeps the
   script in the remote process's memory — `Invoke-Command -ScriptBlock`
   never writes the script to disk on the target. Same OPSEC property:
   no on-disk forensic trail, no AV/EDR signature target on disk.
2. **One protocol, one set of failure modes.** Operators who run
   `bulk-enum-linux.sh` already understand the SSH-fails-cleanly model;
   WinRM with `pywinrm` gives them the same shape. SMB+wmiexec, RDP+xfreerdp,
   evil-winrm with file upload — each has its own quirks. Picking one
   transport reduces the operator-cognitive surface.
3. **The realistic low-priv reach.** For a domain user account, WinRM access
   requires "Remote Management Users" group membership. We document this
   explicitly (D6 below) — operators must know the constraint before
   trusting bulk-enum-windows to cover every Windows host.

### D2 — `--use-smb-admin` opt-in, gated by `--exploit`-style explicit consent

**Decision:** When the operator has admin creds (Domain Admins / local
Administrator) and wants higher reach, they can pass `--use-smb-admin`. That
flag tells bulk-enum-windows to fall back to `impacket-wmiexec` for hosts
where the WinRM probe fails. **The flag must be passed explicitly — no
auto-fallback.**

**Reason:** mirrors the G.8 explicit-write-gate pattern. SMB+wmiexec is
materially different from WinRM:
- It requires admin (escalation surface much larger).
- It drops a temporary service binary on ADMIN$ (visible to host-side EDR
  as a known wmiexec signature).
- It writes to the Windows event log (4624 logon-type-3, 7045 service
  creation).

The operator should be making the conscious choice each time — not
discovering after the fact that wmiexec was used because WinRM was down.
If the operator chooses `--use-smb-admin` they accept the larger
side-effect surface and the requirement that they're authorized to
operate at admin level.

`--use-smb-admin` without admin-grade creds (the WinRM-style
"Remote Management Users" user) is refused at arg-parse time with a
clear error. impacket must be installed; deps-check.sh flags this.

### D3 — Output layout identical to ADR-002 D5, filename swap only

**Decision:** Per-host output uses the same `$OUT/<host>/` shape as Linux,
just with `winenum.txt` / `winenum.err` instead of `linenum.txt` /
`linenum.err`.

```
$OUT/
  run.log
  hosts.txt
  _summary.tsv
  <host>/
    winenum.txt        # raw stdout from Invoke-PrivEscEnum.ps1
    winenum.err        # WinRM faults + script warnings
    _meta.json         # rc, timing, transport (winrm|smb-admin), session details
    .done              # rc=0 marker for --resume
```

**Reason:** `report.py`'s `_is_bulk_enum_dir()` is extended to look for
EITHER `linenum.txt` OR `winenum.txt`. The same per-host verdict logic
runs on both. An operator running mixed Linux+Windows engagements gets
ONE report.html with both groups in the verdict table, sorted worst-first
across the whole estate.

This also means `bulk-enum-linux.sh` and `bulk-enum-windows.py` can write
into the SAME `$OUT` dir — one for Linux hosts, one for Windows hosts.
`report.py` rolls up both sides into a unified picture.

### D4 — Python orchestrator, not bash

**Decision:** `network/bulk-enum-windows.py` is Python. `pywinrm` is the
canonical WinRM client; bashing it (calling `python -c` from bash) adds
no value.

**Reason:** consistent with `graphql/gql.py`, `smtp/smtp-smuggling-test.py`,
`creds/default-creds-sweep.py`, `jabber/jabber-validate.py`,
`activemq/activemq-cve-2023-46604.py`, `redis/redis-rogue-master.py` —
when Python is the obvious tool, this repo uses Python.

The CLI flag parity with `bulk-enum-linux.sh` is preserved (`--targets`,
`--user`, `--pass`, `--output`, `--parallel`, `--throttle`, `--dry-run`,
`--resume`). Operators who learn one orchestrator know the other.

### D5 — Concurrency model: `concurrent.futures.ThreadPoolExecutor`

**Decision:** Parallelism is implemented with a thread pool sized at
`--parallel` (default 4, cap 16 — same as bulk-enum-linux.sh). Each
worker holds one WinRM session; results are written per-host as they
complete.

**Reason:** pywinrm's `Session` object is not async; threads are the
simplest concurrency for I/O-bound HTTP calls. The cap-at-16 reasoning
from ADR-002 D7 applies identically: above ~16 sessions the operator's
local-side process / file-descriptor / TLS-context count starts to
matter more than the per-target throughput, and connection-pool
exhaustion at the target's IIS/WinRM listener is increasingly likely.

### D6 — `--throttle` parity with the SSH side

**Decision:** `--throttle` collapses parallelism to 1 and adds an
`ENUM_THROTTLE_DELAY` sleep between hosts. Operator-explicit `--parallel`
wins over `--throttle` defaults (G.7 precedence rule).

**Reason:** the same OT/legacy/lab justification as ADR-002 D4 — and
arguably stronger on the Windows side because old IIS/Wsman listeners
have been known to deadlock under concurrent PSRP sessions. The shared
flag name keeps the operator-cognition surface flat.

### D7 — Authentication negotiation order

**Decision:** Try NTLM by default (the broadest-supporting option). If
the operator passes `--auth kerberos`, use Kerberos via GSSAPI (requires
a valid local krb5 ticket cache; the operator usually runs `kinit` first).
If `--auth basic`, force Basic over HTTPS (refused over HTTP — Basic over
HTTP sends the password in clear). If `--auth credssp`, use CredSSP for
the second-hop scenarios. NEVER auto-fall-back from one auth method to
another — that produces confusing error messages and risks accidentally
sending a hashed cred to a different listener than the operator intended.

**Reason:** explicit > implicit. The operator is responsible for the
ticket cache, the proxy chain, and the listener configuration. We expose
the choice and refuse on auth failure rather than silently retrying.

### D8 — Read-only by default; gate flag vocabulary already covers it

**Decision:** bulk-enum-windows runs `Invoke-PrivEscEnum.ps1` only. The
script is enumeration-only (verified by the G.8 audit). No write
operations on the target beyond the WinRM session's own logging.

If the operator wants to ship something OTHER than `Invoke-PrivEscEnum.ps1`
they pass `--script PATH` — but the operator-supplied script falls
under operator responsibility. We document this as "the operator must
verify the supplied script is enumeration-only before passing
`--script`" in `--help` and in the README.

`Invoke-PrivEscEnum.ps1` is the documented-and-vetted default. There is
no `--exploit` flag in bulk-enum-windows itself — exploitation lives in
the per-CVE helpers (`jabber/openfire-cve-2023-32315.py --exploit`,
`activemq/activemq-cve-2023-46604.py --exploit`, etc.) which carry their
own gates per G.8.

## What this ADR DOES NOT validate

**The WinRM transport is unverified pre-engagement.** This codebase ships
on Fedora Linux with no domain-joined Windows hosts available for testing.
The bulk-enum-windows orchestrator's transport layer has been validated by:

1. Unit tests with `pywinrm` mocked at the `Session.run_ps` level.
2. Synthetic `Invoke-PrivEscEnum.ps1` output as report.py fixtures.
3. `--dry-run` end-to-end (no actual WinRM connections).

**Before relying on it in an engagement, the operator MUST:**

- Spin up a Windows VM (Server 2019+ or Windows 10/11), join it to a test
  domain, add a non-admin test user to "Remote Management Users", and run
  `bulk-enum-windows.py --targets <vm-ip> --user testuser --pass ...
  --dry-run` first.
- Then a real (non-dry-run) execution against that same VM and verify the
  per-host `winenum.txt` contains the expected sections from
  `Invoke-PrivEscEnum.ps1`.
- Capture any pywinrm exception classes that arise (timeout, auth fail,
  WSMan fault, kerberos ticket expired) and verify they're caught
  cleanly with `rc != 0` per-host and a useful `winenum.err`.

If any of these fail, an issue against this repo (or a fix-it commit)
must land BEFORE the orchestrator is used at scale. **CI cannot validate
the WinRM path; the operator's first engagement is the validation.**

## Open questions recorded for v0.17.0+

- **Mixed-OS engagements:** when an operator runs both `bulk-enum-linux.sh`
  and `bulk-enum-windows.py` into the SAME `$OUT` dir, the per-host
  verdict table merges naturally. Should we add a `host_os` field
  (`linux` / `windows`) to `_meta.json` so report.py can also group by
  OS? Decision: yes, but it can land alongside the first iteration that
  produces a mixed report — not pre-emptively.
- **Kerberos pre-auth flow:** does the operator want bulk-enum-windows
  to invoke `kinit` itself or insist on a pre-existing ticket cache?
  Recommendation: pre-existing only; the operator's `klist` is the
  source of truth. If they want auto-kinit they can wrap our tool.
