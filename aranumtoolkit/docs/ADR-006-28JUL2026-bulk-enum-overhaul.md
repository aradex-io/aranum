# ADR-006 — Bulk-enum overhaul: fix, harden, expand (Linux SSH, Windows multi-transport, SSH triage, on-host thick-client enum)

| | |
|---|---|
| **Status** | Proposed (2026-07-28) |
| **Iteration** | 28JUL toolkit push |
| **Related** | [ADR-002](ADR-002-20MAY2026-bulk-enum-design.md), [ADR-003](ADR-003-20MAY2026-windows-bulk-enum-design.md), CLAUDE.md §9 |
| **Delivery** | Fixes land on canonical `dev/aranum` (`dev/28jul-bulk-enum-overhaul`); an offline-packaged snapshot is produced under `dev/28julytoolkit/aranum/` with a pip wheelhouse. |

## Context

Operator report + code audit surfaced one hard bug and four capability gaps. This
ADR records the design for all of them so implementation can be fanned out to
per-workstream implementers without colliding.

Everything here is **enumeration + credential-validation** tooling for authorized
testing. Nothing added persists on a target, exfiltrates, evades detection, or
mass-targets beyond an operator-supplied host list. CLAUDE.md §9 invariants hold.

---

## Workstream 1a — FIX: bulk SSH enum reports all FAILS even with valid creds (CRITICAL)

### Root cause (confirmed by audit)

`bulk-enum-linux.sh` sets `-o BatchMode=yes` on **every** SSH invocation
(`ssh_base_args`, line ~176), including the `--pass` path which authenticates via
`sshpass` (lines ~257–263). `BatchMode=yes` disables the interactive password
**prompt**. `sshpass` works by injecting the password into that prompt on the
allocated PTY. With no prompt, `sshpass` has nothing to answer → ssh never sends
the password → every host fails `Permission denied (publickey,password)` and the
summary shows `FAIL` for all hosts. The header comment (line ~87, "BatchMode=yes
— auth must work on first try") enshrines the mistaken assumption.

The key/agent path is unaffected (pubkey auth is non-interactive and works under
BatchMode). So the bug manifests specifically — and totally — when `--pass` is used.

### Decision D1a-1 — split SSH option builder by auth mode

`ssh_base_args` takes an auth-mode argument. Password mode (`--pass`) drops
`BatchMode=yes` and instead sets:
- `PreferredAuthentications=keyboard-interactive,password`
- `PubkeyAuthentication=no` (don't waste RTT / trip `MaxAuthTries` offering agent keys first)
- `NumberOfPasswordPrompts=1`
- keep `StrictHostKeyChecking=accept-new`, `UserKnownHostsFile=$OUTDIR/known_hosts`,
  `ConnectTimeout`, `LogLevel=ERROR`.

Key/agent mode keeps `BatchMode=yes` and adds `PreferredAuthentications=publickey`.
`sshpass -e` continues to feed `SSHPASS`.

### Decision D1a-2 — classify failures instead of one flat FAIL

SSH exit 255 = transport/auth-level failure; any other non-zero = the remote
`bash -s` (linenum) exited non-zero but auth succeeded. Post-run summary gains a
`status` column derived from rc + a grep of `linenum.err`:
`OK | AUTH_FAIL | UNREACHABLE | TIMEOUT | REMOTE_ERR`. `_meta.json` gains
`"status"` and `"fail_reason"`. This turns "everything failed" into an
actionable per-host triage.

### Decision D1a-3 — preflight + honest reporting

- On `--pass`, if `sshpass` missing → hard error (already present; keep).
- Add an optional one-host **preflight**: before fanning out, run auth against the
  first reachable host and, if it AUTH_FAILs, print a loud warning
  (`[!] auth failed against first host — check creds/transport before burning the list`)
  but continue (operator may have per-host creds). Gate behind default-on
  `--preflight/--no-preflight`.

### Decision D1a-4 — hardening/expansion (in scope, non-breaking)

- `--key` + `--pass` may both be given (try key, fall back to password) via
  `PreferredAuthentications=publickey,keyboard-interactive,password` +
  `BatchMode=no`.
- `--retries N` (default 1) with backoff for TIMEOUT/UNREACHABLE only (never
  retry AUTH_FAIL — avoids lockout).
- `--jump HOST` convenience wrapping `-o ProxyJump=` (ProxyJump already reachable
  via `--ssh-opt`; add the shorthand).
- Accept per-line inline creds in the targets file is **out of scope** here (see
  1b for the OS-aware dispatcher which owns richer target formats).

### Tests (T1)

`tests/test_bulk_enum_linux_auth.py`: a fake `ssh`/`sshpass` shim on `$PATH` that
asserts (a) password mode never passes `BatchMode=yes`, (b) key mode does,
(c) status classification maps rc 255→AUTH_FAIL/UNREACHABLE and rc 1→REMOTE_ERR,
(d) `_summary.tsv` has the new `status` column. No live SSH.

**Files owned by T1:** `aranumtoolkit/network/bulk-enum-linux.sh`,
`aranumtoolkit/network/_lib.sh` (only if a shared helper is added),
`tests/test_bulk_enum_linux_auth.py`. **Must NOT edit:** `aranum.py`, `CHANGELOG.md`,
`README.md`, `VERSION`, `deps-check.sh` — report those edits in the integration manifest.

---

## Workstream 1c — Windows bulk enum: verify + multi-transport (HIGH)

`bulk-enum-windows.py` exists (WinRM + opt-in SMB/wmiexec fallback) but the WinRM
path is unverified and single-transport-brittle.

### Decision D1c-1 — pluggable transport layer

Introduce `--transport {auto,winrm,ssh,smb}` (repeatable / comma-list; `auto`
tries in order winrm→ssh→smb until one authenticates):
- **winrm** — existing pywinrm path (5985/5986), keep ntlm/basic/kerberos/credssp.
- **ssh** — Windows OpenSSH Server (port 22): ship the PS script over stdin to
  `powershell -NoProfile -NonInteractive -Command -` exactly like the Linux
  stdin-pipe. Reuses the 1a-fixed SSH option logic (no on-disk artifact). This is
  the most-requested addition: many hardened Windows fleets expose OpenSSH, not WinRM.
- **smb** — impacket `wmiexec`/`smbexec`-style exec of a base64-encoded PS payload
  (already partially present as `--use-smb-admin`); formalize as a transport,
  admin-only, opt-in, clearly labeled.

Each transport is a small class with a uniform `run(target, script) -> HostResult`
interface so `report.py` sees the same `winenum.txt`/`_meta.json` layout regardless.
`_meta.json` records which transport actually succeeded.

### Decision D1c-2 — graceful dependency degradation

Missing `pywinrm`/`impacket` disables only that transport with a clear
`[?] transport 'winrm' unavailable (pywinrm not installed) — skipping` message;
`auto` skips to the next. `--help`/`--dry-run` never import-fail (already the case).

### Decision D1c-3 — parity + honesty

Mirror 1a's status classification (`OK/AUTH_FAIL/UNREACHABLE/REMOTE_ERR`) and the
per-host summary. Document plainly in the module docstring which transports are
CI-verifiable vs. require an operator's known-good Windows VM.

### Tests (T2)

`tests/test_bulk_enum_windows_transports.py`: transport selection/ordering,
`auto` fallthrough, dependency-absent messaging, spec parsing, base64 PS wrapping,
status classification — all with mocked transports (no live Windows, no live pywinrm).

**Files owned by T2:** `aranumtoolkit/network/bulk-enum-windows.py`,
`aranumtoolkit/network/enum-winrm.sh` (if touched), new transport module if split
out, `tests/test_bulk_enum_windows_transports.py`. **Must NOT edit** the shared files.

---

## Workstream 1b — OS-aware SSH sweep dispatcher (LOWER priority)

Operator has a list of open-22 hosts (or the stdout of an `nxc ssh` sweep) and
wants the tool to decide Windows vs Linux per host and dispatch the right enum.

### Decision D1b-1 — `ssh-triage` dispatcher (new)

New `aranumtoolkit/network/ssh-triage.sh` (+ `aranum.py` subcommand `ssh-triage`):
1. **Input flexibility** (CLAUDE.md "take nmap outputs, run from a list"): accept
   `--targets FILE` (host list), `--nmap FILE` (xml/gnmap → hosts with 22 open via
   the existing `nmap-parse.py`), or `--nxc FILE`/stdin (parse `nxc ssh` output
   lines — they include the OS banner nxc prints).
2. **OS classification** per host, cheapest signal first:
   - SSH banner (`SSH-2.0-OpenSSH_for_Windows_*` ⇒ Windows; most Linux daemons
     ⇒ Linux; drop-in banners like `dropbear`/`ROSSSH` ⇒ appliance/other).
   - If ambiguous and creds present, one authenticated probe command
     (`uname -s || ver`) classifies definitively.
   - `nxc ssh` already prints `(Windows|Linux)` — trust it when parsing `--nxc`.
3. **Dispatch**: Linux hosts → `bulk-enum-linux.sh`; Windows hosts →
   `bulk-enum-windows.py --transport ssh`; unknown → report, don't guess.
   Writes a `classification.tsv` (host, os, signal, confidence) and one combined
   output tree.

### Decision D1b-2 — reuse, don't reinvent

OS classification helpers extend the banner logic already in `enum-ssh.sh`; the
dispatcher shells out to the two bulk tools rather than duplicating their SSH logic.

### Tests (T3)

`tests/test_ssh_triage.py`: banner→OS mapping table, `nxc` output parsing, nmap
input path (reuse fixtures), dispatch routing (mock the two bulk tools), unknown
handling. No live hosts.

**Files owned by T3:** new `aranumtoolkit/network/ssh-triage.sh`,
`aranumtoolkit/network/enum-ssh.sh` (extend banner→OS helper only),
`tests/test_ssh_triage.py`. Reports the `aranum.py` subcommand registration in the
integration manifest. **Must NOT edit** shared files.

---

## Workstream 1d — On-host enum for thick clients / workstations + SSH-key triage (HIGH)

"Move through many workstations with various GUI/custom apps; piles of unknown SSH
keys." Two deliverables.

### Decision D1d-1 — thick-client / workstation app enumeration (additive to on-host scripts)

Extend the self-contained on-host scripts (they must stay `source`-free per
ADR-002 D1 so bulk-enum can stdin-pipe them):
- **Windows** (`standalones/windows/Get-ThickClientEnum.ps1`, folded into
  `Invoke-PrivEscEnum.ps1`'s dispatch): enumerate installed apps (uninstall
  registry keys + `Program Files`), running GUI processes with window titles,
  per-app config/creds at rest — PuTTY/WinSCP/pageant saved sessions & keys,
  RDP `.rdp` + cached creds, OpenVPN/AnyConnect profiles, browser saved-login DBs
  (presence only, no decryption), Electron `app.asar`/config, `.config`/AppData
  connection strings & `*.ini/*.xml/*.json` credential patterns, DPAPI blobs
  (already `Get-DPAPIBlobs.ps1`), unquoted-path/writable custom-app services
  (reuse existing checks). **Read-only enumeration; presence + path + why-it-matters.**
- **Linux/thick-client** (`standalones/linux/thickclient-hunt.sh`, folded into
  `linenum-fast.sh`): GUI app configs under `~/.config`, `~/.*rc`, Electron apps,
  saved VPN/DB/SSH client configs, keyring presence, `.desktop` custom launchers,
  hardcoded creds in app config trees.

All findings go to stdout in the existing linenum/winenum shape so `report.py`
ingests them unchanged. Extend `service-metadata.json`/report categorization if a
new finding class is added.

### Decision D1d-2 — `ssh-key-triage` (new tool) — "which key is good for what?"

New `aranumtoolkit/network/ssh-key-triage.py` (stdlib + already-present
`paramiko`/`cryptography`; degrade to `ssh-keygen` shell-out if paramiko absent).
Given a directory/glob of unknown private keys and a host list:
1. **Inventory** each key: type (rsa/ed25519/ecdsa/dsa), bit size, fingerprint
   (SHA256 + MD5), encrypted? (and whether a passphrase from `--passwords` unlocks
   it), derive the public key, PEM/OpenSSH format, comment.
2. **Match**: for each key × host, attempt a **non-destructive auth probe**
   (`ssh -i key -o BatchMode=yes -o PreferredAuthentications=publickey
   -o PasswordAuthentication=no <user>@host true`) and record accept/reject. Build a
   **key→hosts→users acceptance matrix** ("this key opens hosts A,C as root; that
   key opens nothing we can see"). Honors `--targets/--nmap`, `--users` list,
   parallelism cap, per-engagement known_hosts — same conventions as bulk-enum.
3. **Output**: `key-triage.json` + a human matrix (`key-triage.md`) + optional
   `authorized-pairs.txt` (key,user,host) ready to feed `bulk-enum-linux.sh`.

This is authorized-testing triage of operator-held key material against
operator-authorized hosts — pure auth validation, no spraying of passwords, no
writes. It respects `MaxAuthTries` (one key per connection, `IdentitiesOnly=yes`).

### Tests (T4)

`tests/test_ssh_key_triage.py`: key inventory/fingerprinting against generated
test keys (ed25519/rsa, encrypted + not), passphrase-unlock, acceptance-matrix
assembly with a mocked ssh probe, output schema. `tests/test_thickclient_enum.*`:
PS/bash static lint + a smoke run of the Linux script on the runner (self-target).

**Files owned by T4:** `standalones/windows/Get-ThickClientEnum.ps1`,
`standalones/windows/Invoke-PrivEscEnum.ps1` (dispatch hook), `standalones/linux/
thickclient-hunt.sh`, `standalones/linux/linenum-fast.sh` (dispatch hook),
`aranumtoolkit/network/ssh-key-triage.py`, the T4 tests. **Must NOT edit** shared files.

---

## Workstream 5 — Offline packaging into `dev/28julytoolkit/aranum/` (after 1a–1d land)

Per operator decision "our scripts + python wheelhouse only" (assume nmap/nxc
present on the operator box; kit must `pip install --no-index` offline):
1. Snapshot the fixed `dev/aranum` tree into `dev/28julytoolkit/aranum/` (exclude
   `.git`, `outputs/`, `__pycache__`, engagement data).
2. Build `dev/28julytoolkit/aranum/wheelhouse/` via
   `pip download` for the runtime Python deps: `pywinrm`, `impacket`, `paramiko`,
   `cryptography`, `requests` (+ their transitive deps), for the operator's
   platform (Linux x86_64, cp311). Pin versions in `requirements-offline.txt`.
3. `install-offline.sh`: `python3 -m venv .venv && .venv/bin/pip install
   --no-index --find-links wheelhouse -r requirements-offline.txt`.
4. `README-OFFLINE.md`: what's bundled, what's assumed present (nmap, nxc/netexec,
   sshpass, ssh, optionally evil-winrm), size, and the offline install/run flow.
5. Enforce the **4GB total** cap; wheelhouse is the only heavy item (~tens of MB) —
   if for any reason over, drop lowest-priority (1b) content first per operator rule.

**Files owned by T5:** everything under `dev/28julytoolkit/aranum/` only. Does not
modify canonical `dev/aranum`.

---

## Integration (owned by the orchestrator, not the implementers)

Shared files are edited centrally to avoid merge conflicts. Each implementer
returns an **integration manifest**: new `aranum.py` subcommands + dispatch-table
entries, `CHANGELOG.md` lines (Keep-a-Changelog groups), `README.md` snippet, new
deps for `deps-check.sh`/`requirements-optional.txt`, new files. The orchestrator
applies them, wires `aranum.py`, runs the full suite (`make test` / pytest), and
commits per aranum CLAUDE.md §3 (Conventional Commits, one logical change per
commit, CHANGELOG in-commit) on `dev/28jul-bulk-enum-overhaul`. No push, no PR
(not requested). Version: MINOR bump (new subcommands/transports/auth mode) →
target `v0.33.0`.

## Model triage (per RepoTemplate AGENTS.md)

Planning/design (this ADR) + review = Opus. T1 (auth-mode bug, subtle) and T4
(design-heavy new tool) = Opus-class implementation. T2/T3/T5 = Sonnet execution
against this brief. Whole-file mechanical edits and packaging = Sonnet.

## Risks

- **Live-auth tests forbidden in CI** → all tests use shims/mocks; the module
  docstrings state plainly what only an operator VM can validate (honesty rule).
- **Windows transports unverifiable here** → shipped clearly labeled; SSH transport
  reuses the (tested) 1a option logic to minimize new untested surface.
- **ssh-key-triage touching real hosts** → default-safe: `BatchMode`, publickey-only,
  `IdentitiesOnly`, one key/connection, `--dry-run` prints the plan.
- **Parallel implementers on one tree** → strict file ownership + central shared-file
  edits; conflicts structurally impossible on owned files.

## Post-review revisions (resolving the 3 blockers)

**Resolves BLOCKER 1 — three explicit SSH auth modes (supersedes D1a-1/D1a-4 option
details).** The option builder takes an explicit `mode` and the `-i`/BatchMode/
PubkeyAuthentication choices follow the mode, never the mere presence of `SSH_PASS`:

| Mode | Trigger | `-i key` | Key opts | Password opts |
|---|---|---|---|---|
| `KEY` | `--key` and/or agent, no `--pass` | yes (if `--key`) | `BatchMode=yes`, `PreferredAuthentications=publickey`, `IdentitiesOnly=yes` (if `--key`) | — |
| `PASS` | `--pass`, no `--key` | no | `PubkeyAuthentication=no` | `BatchMode=no`, `PreferredAuthentications=keyboard-interactive,password`, `NumberOfPasswordPrompts=1` |
| `KEY_THEN_PASS` | both `--key` and `--pass` | yes | `IdentitiesOnly=yes` (only offer the given key) | `BatchMode=no`, `PreferredAuthentications=publickey,keyboard-interactive,password`, `NumberOfPasswordPrompts=1`; **do NOT set `PubkeyAuthentication=no`** |

Only pure `PASS` mode sets `PubkeyAuthentication=no`. `KEY_THEN_PASS` keeps pubkey
on so the key is tried first and password is the fallback. `sshpass -e` wraps ssh
whenever `--pass` is set (PASS and KEY_THEN_PASS). Non-blocking note honored: if
`--key` is passphrase-encrypted, sshpass would answer the *passphrase* prompt not a
login password — T1 documents this and recommends `ssh-agent` for encrypted keys.

**Resolves BLOCKER 2 — `report.py` + `service-metadata.json` are now orchestrator-owned
shared files.** Added to the central shared-file set (with `aranum.py`, `CHANGELOG.md`,
`README.md`, `VERSION`, `deps-check.sh`, `requirements-optional.txt`). No implementer
edits them. The orchestrator makes two integration edits: (i) teach `report.py`'s
bulk walk to read the new `_meta.json` `status`/`fail_reason` and surface
`AUTH_FAIL/UNREACHABLE/REMOTE_ERR` (today it treats a present-but-empty
`linenum.txt` as "clean", hiding auth failures); (ii) extend the report finding
rules / `service-metadata.json` for any new 1d thick-client finding class. T1/T4
return the exact `status` strings and finding-class names they emit so the
orchestrator wires them.

**Resolves BLOCKER 3 — one canonical SSH-option spec both languages implement.**
The table above is the single source of truth. The bash builder (1a) and every
Python SSH argv builder (1c Windows-SSH transport, 1d ssh-key-triage) MUST emit
options consistent with it. Each such implementer MUST include a unit assertion on
the built argv: password paths assert `BatchMode=yes` is ABSENT and
`NumberOfPasswordPrompts=1` present; key-probe paths (key-triage) assert
`BatchMode=yes`, `PubkeyAuthentication` not disabled, `IdentitiesOnly=yes`, and
`PasswordAuthentication=no` present. This makes the 1a bug impossible to re-ship in
another language.

**Sequencing (non-blocking rec honored):** 1a lands FIRST as its own atomic `fix`
commit (with its regression test incl. a KEY_THEN_PASS case) before the additive
workstreams. ssh-key-triage adds lockout hygiene: `--max-per-user N` cap +
`--throttle` inter-attempt delay, one key per connection. SMB transport (1c)
documents that it breaks ADR-002 D1's no-on-disk-artifact guarantee (base64 payload
executes via the service control manager) — labeled and opt-in only.

## Appendix: Plan Review

**Reviewer:** plan-reviewer (Opus) · 2026-07-28 · read-only adversarial pass over the plan + `bulk-enum-linux.sh`, `_lib.sh`, `enum-ssh.sh`, `bulk-enum-windows.py`, `report.py`, `linenum-fast.sh`, ADR-002/003.

### Verdict: **APPROVE WITH CHANGES**

The 1a root cause is confirmed and the core fix is correct. Three integration/correctness gaps must be closed before implementation fans out; none is a redesign.

### Blocking issues

1. **Three-way auth mode is under-specified and will silently break the D1a-4 key+pass fallback.** The dispatch branch selects `sshpass` purely on `[ -n "$SSH_PASS" ]` (`bulk-enum-linux.sh:257`), and `ssh_base_args` unconditionally injects `-i "$SSH_KEY"` whenever a key is set (`:184`). If D1a-1's "password mode" sets `PubkeyAuthentication=no`, then a `--key --pass` invocation still enters the `SSH_PASS` branch, gets `PubkeyAuthentication=no`, and the key is dead — the opposite of D1a-4. The plan describes pass-only and key+pass as different option sets but never reconciles that both flow through the same `SSH_PASS` branch. **Require:** `ssh_base_args` take an explicit 3-valued mode (`key` | `pass` | `keypass` | agent-default); gate both the `-i` injection and `PubkeyAuthentication=no` by mode; document the selection precedence (`key&&pass → keypass`, else `pass`, else `key`, else agent).

2. **`report.py` and `service-metadata.json` are shared files that TWO workstreams need, but the plan lists neither as owned or centrally-edited** (the enumerated shared set is only `aranum.py`/`CHANGELOG`/`README`/`VERSION`/`deps-check.sh`). Two concrete collisions: (a) **1a's "honest reporting" never reaches the report.** `walk_findings_bulk` only checks that `_meta.json` exists, then classifies `linenum.txt` lines (`report.py:892-920`); it never reads `rc`/`status`. An AUTH_FAIL host has an *empty* `linenum.txt`, so it renders as "no findings / clean", not FAIL — the new `_meta.json` `status`/`fail_reason` fields are inert until `report.py` is taught to consume them. (b) **1d's new finding classes render ungraded/LOW** unless `_BULK_RULES`/`_BULK_RULES_WIN` are extended — the identical problem the code comment at `report.py:886-889` already records for AD-depth rules. **Require:** add `report.py` + `service-metadata.json` to the centrally-edited shared-file set, and assign the status-surfacing edit (1a) and the new-rule edits (1d) explicitly. (Note in mitigation: the `_summary.tsv` extra `status` column is report-safe — `report.py` does not parse that file.)

3. **"Reuse the 1a-fixed SSH option logic" (D1c-1, 1d-2) is not mechanically possible across languages.** 1a's fix is bash inside `bulk-enum-linux.sh`; 1c's Windows-OpenSSH transport and 1d's `ssh-key-triage.py` are Python and each build their own ssh argv, in parallel workstreams that cannot see T1's diff. Nothing forces the fix to propagate, so 1c's password-over-SSH path can re-ship the exact `BatchMode`+`sshpass`/password bug. **Require:** capture the fixed password-auth option set as a language-neutral spec in this ADR (the four `-o` values + the "no BatchMode on password" rule), have both Python paths implement it, and add the same shim-argv assertion (T1-style) to T2/T4.

### Non-blocking recommendations

1. **sshpass + encrypted key in the key+pass fallback misfires.** With `BatchMode=no` and a passphrase-protected key, ssh prompts `Enter passphrase for key …`; sshpass matches `assword` by default, so it will not answer the passphrase (hang/timeout) or, worse, feed the login password to the wrong prompt. Document the limitation and prefer agent-loaded keys for the fallback case.
2. **SMB transport breaks the "no on-disk artifact" guarantee.** impacket `wmiexec`/`smbexec` retrieve output via a transient file on `ADMIN$` — unlike the SSH/WinRM stdin-pipe paths (ADR-002 D1). This is acceptable behind the admin-only `--transport smb` opt-in, but it must be stated plainly rather than implied to share the memory-only property; confirm the payload path leaves nothing behind.
3. **`ssh-key-triage` lockout hygiene.** Pubkey auth *failures* still increment PAM `pam_tally`/AD bad-password counters on some configs regardless of `MaxAuthTries`. Add a per-user attempt cap, conservative default parallelism, honor `--throttle`, `--dry-run` prints the plan, and a loud lockout warning. The `-o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no … true` probe is otherwise appropriately non-destructive.
4. **Test the regression from blocking-issue 1.** T1 must add a `--key --pass` case asserting `-i` is present AND `PubkeyAuthentication` is *not* `no`; likewise T4 should assert the key-triage argv actually carries `IdentitiesOnly`/publickey-only (the safety-critical part), not just matrix assembly.
5. **Land 1a first, on its own.** 1a is a self-contained `fix` (file-owned: script + test). Do not gate the CRITICAL fix behind the Windows-transport/new-tool integration pass and the WS5 offline packaging. Commit/merge it independently; the rest can follow into the same MINOR `v0.33.0`.
6. **Minor:** xargs-spawned child shells inherit exported *functions* (`export -f`) but not `set -uo pipefail`; helper code added to `_lib.sh` for T1 runs without nounset/pipefail in the per-host subshell. Not a fail cause, but re-assert options inside `run_one_host` if new pipelines are added.

### Root-cause confirmation

**Confirmed.** `ssh_base_args` hardcodes `-o "BatchMode=yes"` (`bulk-enum-linux.sh:176`) into the array consumed by *every* invocation, including the password branch `SSHPASS=… sshpass -e ssh "${ssh_args[@]}" …` (`:250,257-259`); the header comment enshrines the wrong assumption (`:87`). `BatchMode=yes` suppresses the interactive password prompt that `sshpass` exists to answer, so on `--pass` ssh never emits a password and every host returns 255 `Permission denied` → uniform FAIL. The key/agent path is genuinely unaffected (pubkey is non-interactive under BatchMode). The proposed fix — split the option builder by mode, drop BatchMode for password, set `PreferredAuthentications=keyboard-interactive,password`, `PubkeyAuthentication=no`, `NumberOfPasswordPrompts=1` — is correct and sufficient for the pass-only path (sshpass drives the password via the controlling pty, independent of ssh's file-redirected stdin, so the stdin script pipe is unaffected), and `NumberOfPasswordPrompts=1` is a lockout-positive. I checked for a second latent universal-FAIL cause and found none: `linenum-fast.sh` ends on an `echo` and exits 0 (so D1a-2's REMOTE_ERR is a real-but-secondary classification improvement, not a hidden all-FAIL source), and the `bash -s -- -v` stdin invocation is well-formed (`-v` reaches the script as `$1`). The BatchMode/sshpass bug is the sole universal-FAIL cause — but see blocking-issue 3: the same bug can be reintroduced verbatim in the parallel Python transports.
