# ADR-007 — `--local` access layer: one orchestrator over every access pathway, by capability tier

| | |
|---|---|
| **Status** | Accepted (2026-10-26) — S4 of PLAN-001 |
| **Plan** | [`docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md`](../../docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md) §S4 (G17, G18, G20) |
| **Related** | [ADR-002](ADR-002-20MAY2026-bulk-enum-design.md), [ADR-003](ADR-003-20MAY2026-windows-bulk-enum-design.md), [ADR-006](ADR-006-28JUL2026-bulk-enum-overhaul.md), CLAUDE.md §9 |

## Context

An operator often holds credentials for many machines, across several protocols.
They want each machine's privesc and hardening posture, using whatever pathway
works. The user chose the following pathways:

| OS | Pathways |
|---|---|
| Windows | ssh, winrm, rdp, vnc, plus wmiexec, smbexec or psexec (operator's choice) |
| Linux | ssh, rdp, vnc |

The engines that already exist cover part of this:
- `bulk-enum-linux.sh` covers Linux ssh.
- `bulk-enum-windows.py` covers Windows winrm and ssh, plus the wmiexec-backed
  `smb` transport (ADR-006).

Three things are missing. The local machine has no pathway at all. Nothing chooses
a pathway per host. And `aranum run` has no way to continue from a network scan
into host enumeration.

## Decision D1 — `local-enum.py`, a thin orchestrator that delegates (Option A)

`aranumtoolkit/network/local-enum.py` resolves each host's OS, plans its pathways,
and hands full enumeration to the proven engines:

| Pathway | Tier | Engine |
|---|---|---|
| `local` (`--self`) | full | runs the collectors directly on this machine |
| Linux `ssh` | full | `bulk-enum-linux.sh --with-posture` |
| Windows `winrm`, `ssh` | full | `bulk-enum-windows.py --transport winrm,ssh --with-posture [--ad]` |
| Windows `wmiexec` / `smbexec` / `psexec` | compact | the compact probe (D4) |
| `rdp`, `vnc` | desktop | S5. In S4, asking for them is refused with an explicit "not yet available" |

**Option B (not taken):** reimplement every transport inside the orchestrator.
That would duplicate tested code and void the ADR-006 auth-mode and status
coverage.

**What would flip it:** an engine that cannot take per-host credentials. Today
the orchestrator runs each engine once per credential group (D3), which keeps
delegation cheap.

## Decision D2 — `--transport` *selects* pathways; tiers always run richest-first

The plan said `--transport` sets the order. That is refined here. `--transport`
is a comma list over `local, ssh, winrm, exec, rdp, vnc` that *selects* which
pathways are allowed. `exec` means the method named by `--win-exec`.

Within a host, pathways run in a fixed order:
- **Windows:** winrm, then ssh, then the exec method, then desktop.
- **Linux:** ssh, then desktop.

A pathway only runs when every richer one failed to authenticate.

**Why:** an operator can never trade the full collector for a compact probe by
accident. A host that answers on winrm gets the whole collector, even if exec
was listed first.

**What would flip it:** a lab-measured case where a richer pathway is
unacceptable but authenticates — for example, winrm that is heavily logged. The
operator already has a remedy: leave it out of `--transport`.

## Decision D3 — Inputs, credentials, OS resolution, and the dry-run plan contract

### Targets

There are two sources, and they can be combined:
- `--targets FILE`, one line per host: `[user@]host[:port] [os=linux|windows] [via=ssh,winrm,...] [user=...]`
- `--from-inventory inventory.json`, from auto-enum.

From inventory, a host is a candidate when any of 22, 5985/5986, 445, 3389 or
5900–5910 is open. The open ports bound its `via` set.

### OS resolution

The first rule that applies wins:
1. An explicit `os=` hint.
2. Port and product evidence from the inventory:
   - **Windows:** any of 445, 135, 139, 3389, 5985 or 5986 is open, or the product says Windows/Microsoft.
   - **Linux:** only 22 is open, with no Windows evidence.
3. The SSH banner, read at run time only. `OpenSSH_for_Windows` means Windows; anything else means Linux.

A dry run never opens that socket, so the plan shows the OS as `unknown`.

### Credentials

Credentials come only from the operator:
- `-u`, `-p`, `--key` and `-H`, used as the defaults for every host.
- `--creds FILE`, with lines of the form `host|* user secret`:
  - A `secret` that is an existing file is treated as an SSH key.
  - `nt:<32 hex>` is an NT hash, used only by the exec methods.
  - Anything else is a password.
  - The file should be mode 0600. The tool warns if it is not.

A host with no usable credential for any of its pathways is **skipped**. It is
listed in the plan as `skip:no-credentials`, and no host directory is written.
This is deliberate: a credential-less candidate from an inventory would
otherwise add an `AUTH_FAIL` "not fully enumerated" finding per host. That would
be manufactured noise, the exact class S1 removed.

Credentials discovered during a run are access candidates only. They are never
used automatically.

### The dry-run plan contract

`--dry-run` prints one machine-readable row per planned (host, pathway), then
stops. It opens no socket and spawns no engine.

```
PLAN|<host>|<os>|<pathway>|<tier>|<engine>|<note>
```

The M8 harness and the tests read these rows.

## Decision D4 — The compact probe: verbatim checks, a measured ceiling, and refusal over truncation

The exec methods run one command line through their own mechanism and return
its stdout the same way. No relay, listener, upload endpoint or target-side
fetch is involved. The full collectors are 20 KB and 46 KB, so they cannot ride
these methods. Over these methods, **full enumeration is declared unsupported**.

### Ceilings

These are recorded from the impacket 0.13.1 source. They have not yet been
measured on a live host; the S5 Windows lab verifies them.

| Method | Mechanism (impacket 0.13.1) | Declared ceiling for our command |
|---|---|---|
| wmiexec | `Win32_Process.Create` running `cmd.exe /Q /c <cmd> 1> \\127.0.0.1\ADMIN$\__<ts> 2>&1`; cmd.exe caps a line at 8191 | **8000** (the existing `_smb_admin_run` constant) |
| smbexec | a service whose `lpBinaryPathName` is `%COMSPEC% /Q /c echo <cmd> ^> \\%COMPUTERNAME%\C$\__output_X 2^>^&1 > %SYSTEMROOT%\X.bat & %COMSPEC% /Q /c %SYSTEMROOT%\X.bat`, still under cmd.exe's 8191 after expansion | **7800** |
| psexec | the RemCom named-pipe message `Command` field, `'4096s'` | **4000** |

impacket 0.13.1's `smbexec.py` has no command argument; it is a shell that reads
commands from stdin. The orchestrator therefore writes the command and then
`exit` to its stdin. `wmiexec.py` and `psexec.py` take the command as an
argument.

### What the probe carries

Each command is `powershell.exe -NoProfile -NonInteractive -EncodedCommand <UTF-16LE base64>`.
It is never compressed or packed (§9 and the plan constraints forbid packed
stagers), so the script budget is roughly ceiling × 3/8 characters. The script
contains, in order:

1. A compact restatement of the collector's framing helpers. They keep the same
   names and the same semantics as `Invoke-HostPosture.ps1`: `Write-PostureLine`
   splitting and stripping, `Invoke-PostureCheck` grading a thrown error as ERR,
   `Get-RegValue` returning absent only on `ItemNotFound`, and `Get-RegPolicy`
   rejecting any value outside its domain.
2. `whoami.exe /priv`, a raw privilege list that the existing `winenum` rules
   grade (SeImpersonate and the rest).
3. Host checks in a fixed priority order. Each `Invoke-PostureCheck '<ID>' { … }`
   block is **extracted verbatim from `Invoke-HostPosture.ps1` at build time**,
   with only the indentation and full-line comments stripped. The registry-path
   variables it needs (`$lsa`, `$sys`, `$lmSrv`, `$lmWks`) are extracted the
   same way.

   Only blocks that need nothing else are eligible. A block that reads
   `$Context` (OS build, DC role) is not. So the probe can never drift from the
   collector's grading. The *parity gate* test enforces this: it runs the probe
   and the full collector under the same stubbed registry and requires identical
   POSTURE lines.

### Building to the ceiling

The core is the helpers, the privilege list and the first check.
- If the core does not fit the chosen method's ceiling, the builder **refuses**.
  It names the method and tells the operator to use winrm or ssh for full
  enumeration.
- Otherwise it adds checks greedily in priority order while they fit.

The command is never truncated onto the wire, and no check is ever dropped
silently:
- Every host check the probe did not carry is recorded in `_meta.json` under
  `probe_omitted`.
- Each omitted check is also appended to `winenum.txt` under a marked
  `== aranum local-enum annotations ==` section, as
  `POSTURE|<id>|NA|not carried by the <method> compact probe (use winrm/ssh for this check)`.

So the posture matrix shows the gap as NA rather than hiding it.

**Option not taken:** chunk the collector across many command lines in one
session. That would give near-full coverage, but it means many process or
service creations per host, and the plan fixed a single command line. It is
recorded as a follow-up if the S5 lab shows the per-command cost is acceptable.

### Erratum (26OCT2026) — measured exec-tier capacity

The ceilings above are still impacket-source figures, unverified on a live host
(S5). What *is* now measured, from the dry-run planner on the S4 code, is how
much the compact probe actually carries once the core (helpers + `whoami /priv`
+ the first priority check) is assembled:

| Method | Ceiling | Core (chars) | Checks carried | Plan row |
|---|---|---|---|---|
| wmiexec | 8000 | 7982 | **2** | `fits=yes chars=7982/8000 checks=2 omitted=39` |
| smbexec | 7800 | 7146 | **1** | `fits=yes chars=7146/7800 checks=1 omitted=40` |
| psexec  | 4000 | 7146 | **0** | `fits=no refuse (core 7146 > ceiling 4000; use winrm or ssh)` |

Consequences, recorded so the thinness is not mistaken for a bug:

- **psexec carries no posture at all.** The core alone (7146 chars) is ~1.8× the
  psexec ceiling, so the builder refuses before the first check — exactly the
  "refuse over truncate" path of *Building to the ceiling*, now exercised. psexec
  remains a valid *access* pathway; it is simply not a *posture* pathway, and the
  planner routes the operator to winrm/ssh for this host. A second skip row
  (`psexec:probe-too-large`) records why no fallback was planned.
- **The exec tier is deliberately thin.** wmiexec gets two host checks, smbexec
  one; the remaining ~39–40 checks are emitted as `NA` in `winenum.txt` and
  `probe_omitted`. This is why D2 orders richest-first: winrm and ssh carry the
  whole collector, and exec is the fallback that proves privilege + one or two
  high-value checks, never a full posture.
- **M8 benefit (PLAN-001) therefore tops out at compact 2/3**, with psexec a
  correct FAIL, not a regression. The pre-registered M8 target for S4 is full
  4/4 + compact 2/3 = **6/9**; desktop 0/2 is S5 scope.

The live ceilings (and whether per-command chunking could lift coverage) remain
the S5 Windows-lab item under *What this does not validate*.

## Decision D5 — Output layout, bulk roots, and the mixed tree

`local-enum.py -o OUT` writes the existing bulk layout under an OS root:
`OUT/linux/<endpoint>/{_meta.json,linenum.txt,linenum.err}` and the same under
`OUT/windows/...`.

**Bulk roots.** It writes the marker file `_aranum_bulk_root` (JSON naming the
writer and OS) at each OS root.
- `report.collect()` treats a marked top-level directory as a **bulk root**,
  walked by the bulk walker with evidence paths rebased to `windows/<host>/...`.
- Every other top-level directory is a service directory.
- A tree with both kinds is `mode: "mixed"`. A tree with only marked roots is
  `bulk-enum`. Unmarked trees behave exactly as before.

**Engine runs.** Each engine run (one per credential group) writes to
`OUT/<os>/_engine/<group>/`, and its host directories are then moved up into
`OUT/<os>/`. The engine's logs, `_payload.*` and `known_hosts` stay under
`_engine/`. That directory has no `_meta.json`, so neither walker reads it.

**Local host.** The local host is filed as `host="localhost"`,
`transport="local"`, in `OUT/<os>/localhost/`. The posture collector runs first
and the privesc collector second, under one wall-clock `--host-timeout`
(default 600 s). On timeout the partial output is kept and the status is
`HOST_TIMEOUT`.

Why posture runs first: on a large root filesystem the privesc collector's
SUID walk can run for many minutes. It was measured at over 10 minutes on the
development host, while the posture collector took 2.75 s.

**Exec probes.** A host that ran the exec probe has `_meta.json` fields
`transport=<method>`, `capability="compact-probe"`, `probe_checks`,
`probe_omitted`, `probe_chars` and `probe_ceiling`. Its `transports_attempted`
keeps the failed full-tier attempts.

**Missing tools.** A missing tool gives status `DEP_MISSING`, with a clear
`fail_reason` and a non-zero host status, and the run continues. The report
grades that as a low "not fully enumerated" finding.

## Decision D6 — `aranum` wiring

**`aranum local [args] [-report|-serve]`** runs `local-enum.py`. The output
defaults to `outputs/<session>/raw`, and the report and dashboard chain is the
same as `aranum run`.

**`aranum run <scan> --local [args]`** runs auto-enum, then
`local-enum.py --from-inventory <raw>/inventory.json` into the same raw
directory, then the report and dashboard over the mixed tree.

**Argument routing.** Arguments are partitioned by a declared table:
- Local-only flags reach only `local-enum.py`: `--local`, `--self`, `--targets`,
  `--creds`, `--key`, `--transport`, `--win-exec`, `--use-smb-admin`, `--ad`,
  `--host-timeout`, `--connect-timeout`, `--linux-script`, `--windows-script`
  and `--desktop-ok`.
- Credentials and `-P`/`--dry-run` go to both.
- Everything else goes to auto-enum, as today.

auto-enum never receives a flag it rejects. If auto-enum fails, the local stage
does not run.

## §9 analysis

1. **No target write without an explicit flag.**
   - local, ssh and winrm write nothing to the target. They pipe or carry the
     script in memory, as in ADR-002 and ADR-006.
   - The exec methods do write, through **their own mechanism**:
     - wmiexec writes an output file to ADMIN$.
     - smbexec creates a service and writes a `.bat` file and an output file.
     - psexec uploads the RemCom service binary to ADMIN$ and creates a service.

     Each is torn down by the method itself. All three require **both**
     `--win-exec <method>` and `--use-smb-admin`, which is the ADR-003 D2 and
     ADR-006 explicit-consent flag. The `--help` text for that flag states these
     writes, and none of them is ever added automatically. They do not have the
     no-on-disk-artifact property that winrm and ssh keep; this ADR and `--help`
     say so plainly.
2. **No exfiltration or phone-home.** There is no listener, relay, fetch server
   or upload endpoint. Output returns only through the transport that carried the
   command.
3. **Outputs only under `-o`.** Engine work directories and the probe build stay
   under `OUT/`.
4. **No persistence.** Services created by smbexec and psexec are deleted by the
   method. Nothing is scheduled or registered.
5. **No evasion.** The probe is plain, readable PowerShell, encoded only because
   `-EncodedCommand` is the transport-safe way to pass `|` and quotes through
   cmd.exe. It is not compressed, packed or obfuscated, and it has no AMSI or ETW
   handling.

## What this does not validate

There is no live Windows host, impacket install or nxc install in this repo's
test environment. CI and the S4 tests verify:
- planning
- the dry-run contract
- probe assembly against each ceiling
- refusal past a ceiling
- parity with the collector, under pwsh with a stubbed registry
- the exec argv for each method, with the tool stubbed on PATH
- outcome classification
- the mixed-tree collector
- a real local self-scan on this Linux host

The first live run of each exec method, and the measured ceilings, are S5 Windows
lab items, as are N1, N4 and N6 from S3.
