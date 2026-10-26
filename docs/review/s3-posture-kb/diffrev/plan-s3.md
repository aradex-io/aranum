## S3 — Host posture collectors + posture model (G16, G21–G23)

### D3.1 Collector output contract — strict ASCII framing

Each check emits exactly one line:

```
POSTURE|<check-id>|<PASS|FAIL|WARN|INFO|NA|ERR>|<detail>
```

- **Framing is ASCII and escaped.** `check-id` and `status` are `[A-Z0-9-]` only. `detail` is a single physical line: the collectors replace any `|`, CR or LF in a detail value with ` ` (space) before emitting, so the field count is always exactly 4 and a detail can never inject a field or a line. The parser splits on the first three `|` only (`split("|", 3)`), so a stray `|` that somehow survives stays inside `detail`.
- **The parser is strict and anchored** (`^POSTURE\|[A-Z0-9-]+\|(PASS|FAIL|WARN|INFO|NA|ERR)\|`). A line that starts `POSTURE|` but fails the anchor, or whose `check-id` is unknown to the KB, or whose `check-id` repeats within one host, is **quarantined as a diagnostic** (`collect().diagnostics`, surfaced in Run health) — never dropped silently and never turned into a finding. `ERR` means the check could not run (permission, missing binary); it is never PASS.

**Option not taken:** JSON output. The collectors must also be readable on screen and must survive PS transcripts; a strict pipe line is grep-friendly and transcript-safe.

### D3.2 Collectors — read-only; host checks are localhost-only, AD checks are consent-gated DC queries

The header is corrected from the round-1 draft: **host** posture is localhost-only, but **AD domain** checks necessarily query the host's own domain controller over authenticated read-only LDAP. That is inherent to AD enumeration and is gated behind an explicit consent flag; it is not "no network beyond localhost." Both collectors are standalone and self-contained (no dot-sourcing) so bulk transports can stdin-pipe them.

**`standalones/linux/host-posture.sh`.** Pure POSIX tools, ~30–35 localhost checks: kernel EOL + pending security updates (read package cache only, never refresh); sysctl (ptrace_scope, kptr_restrict, dmesg_restrict, unprivileged_bpf, unprivileged userns, ASLR, suid_dumpable, ip_forward); LSM mode; firewall present; sshd_config (PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, ciphers); accounts (extra UID-0, empty-password — shadow only if readable else ERR, sudoers NOPASSWD count, umask, aging); mounts (/tmp, /dev/shm nosuid/noexec); logging (auditd, syslog); secure boot (`mokutil --sb-state` if present); world-writable PATH dirs, core dumps, cron/at perms, time sync, failed units (INFO); AD membership (sssd/realm/winbind joined = INFO, readable keytab = FAIL).

**`standalones/windows/Invoke-HostPosture.ps1`.** ~35–45 localhost checks, registry/CIM/native read-only: firewall profiles; Defender (RTP, tamper, signature age — read only); BitLocker, Secure Boot; SMB (SMBv1, server/client signing); name resolution (LLMNR, NBT-NS, WPAD); PowerShell (v2 engine, script-block logging, transcription); RDP (enabled, NLA); credential protection (RunAsPPL, Credential Guard, WDigest, LmCompatibilityLevel, CachedLogonsCount); elevation (EnableLUA/ConsentPrompt, LocalAccountTokenFilterPolicy, AlwaysInstallElevated); local Administrators (INFO + count), Guest; patching (last hotfix age, build EOL); spooler (WARN on DC), WinRM HTTP-only listener; LAPS client policy, AutoLogon password (FAIL).

**AD domain checks are consent-gated end-to-end (reviewer round-2 D3.2).** The gate is one logical flag threaded through every delivery layer, off by default:
- `Invoke-HostPosture.ps1` takes a `-AdChecks` switch; absent it, every `AD-*` check emits `POSTURE|AD-...|NA|ad checks not requested` and no DC query runs.
- `bulk-enum-windows.py --with-posture` gains `--ad`; when set, the script-block wrapper (D3.4) invokes the posture block as `& { <posture body> } -AdChecks`.
- `local-enum.py` and `aranum run --local` / `aranum local` gain `--ad`, forwarded to `bulk-enum-windows.py` and to the `--self` Windows collector. `--ad` is in `_LOCAL_ENUM_VALUE_FLAGS`-adjacent boolean handling (D4.4) and never auto-enabled.
- The Linux collector's AD-membership checks are localhost-only (sssd/realm/keytab) and issue **no** DC query, so they need no flag; only the Windows ADSI DC queries are gated.

**When `-AdChecks` is set and the host is domain-joined and FullLanguage:** read-only LDAP against the host's own DC, selected via `RootDSE` (`defaultNamingContext`, `dnsHostName`), with **bounded paging (page size 1000) and a per-query timeout**, so a large directory cannot hang the collector. Checks: domain password policy (min length, lockout threshold, max age); `krbtgt pwdLastSet` age (signed `LargeInteger` → FILETIME conversion); counts of kerberoastable users (SPN set, not computer, enabled), AS-REP users (`DONT_REQ_PREAUTH`, enabled), non-DC unconstrained-delegation computers, `adminCount=1` users, Domain Admins members (recursive); Protected Users count, `ms-DS-MachineAccountQuota`; **domain and forest functional level**; **LDAP signing / channel-binding requirement** (read from the DC's policy via `rootDSE`/registry where remotely readable, else `NA` with a note — not a false PASS); trusts (INFO); LAPS schema attribute present. Every AD line is tagged `domain=<dns>` in `detail` and carries an observer tag so D3.3 can roll up without double counting. Roastable/AS-REP/delegation filters and the `LargeInteger`→age and COM/ADSI→plain-object conversions are factored into **named helper functions** so they can be unit-tested off a Windows box with fixture inputs (reviewer D3.2 testability).

### D3.3 Parser and model — structured domains, no double count

`report.py`:

- New strict `_POSTURE_RE` (D3.1). Posture lines bypass the regex rules entirely.
- FAIL and WARN become findings with `service="posture"`. Severity comes from the KB check entry (`sev_fail`/`sev_warn`). The finding carries `posture_check`, `posture_status`, `kb_id`, `category`.
- PASS, INFO, NA, ERR are not findings; they live in **`posture.json`** beside findings.json: `{hosts: {host: {os, source, checks: {id: {status, detail}}}}, domains: {name: {checks: {id: {status, detail, observed_from: [...]}}}}}`.
- **AD/domain checks never become per-host findings.** They are parsed into the `domains` map keyed by domain identity. Each `(domain, check)` yields **one canonical finding** for KPIs, so three domain-joined hosts reporting the same policy produce one finding, not three (reviewer D3.3 double-count).
- **Per-observer evidence is preserved, not flattened (reviewer round-2 D3.3).** `observed_from` is a list of **records** `{host, status, detail}`, one per reporting host — not a list of bare hostnames — so a host reporting PASS and another reporting ERR (or FAIL) are both retained and visible; no observer's status/detail is lost.
- **The canonical status lattice is total over all six statuses (reviewer round-3 added `INFO`).** Partition into *determined* `{FAIL, WARN, PASS, INFO}` ranked `FAIL > WARN > PASS > INFO` (INFO is a real domain status — e.g. the trusts check emits it — and is the least-severe determined value), and *undetermined* `{ERR, NA}`. The canonical `(domain,check)` status is the **worst determined** status across all observers if any observer determined it (so one real FAIL beats any number of PASS/INFO/ERR; an INFO-only check stays INFO); if **no** observer determined it, the canonical status is `ERR` when any observer reported `ERR`, else `NA`. An undetermined status never outranks a determined one, so the ordering is total. A `detail` string on the canonical record notes a conflict when observers disagree among determined statuses (e.g. `conflict: host-a=PASS host-b=FAIL`).
- findings.json `summary.posture` gains additive `{hosts, pass, fail, warn, err}`; `summary.domains` gains `{count, worst_by_check}`.

### D3.4 Delivery — PowerShell script-block wrapper (5.1-safe)

- `bulk-enum-linux.sh` and `bulk-enum-windows.py` gain `--with-posture`.
- **Linux:** bash concatenation of the privesc script then the posture script over the SSH stdin stream (both are plain scripts; order fixed; `linenum-fast.sh` must not `exit` before the appended part — verified, no early exit today, re-checked in the sprint).
- **Windows:** the two advanced scripts are **not text-concatenated** (that breaks PS 5.1, where `[CmdletBinding()]`/`param()` must be the first statement of a script). Instead the transport emits a wrapper that invokes each collector body inside its own script block — `& { <privesc body> }` then `& { <posture body> }` — because `param()` *is* valid as the first statement of a script block. The combined payload is parsed under the 5.1 parser (dual-encoding + AST, the gotcha-doc method) in the test before it is ever shipped (reviewer D3.4).
- Output stays in `linenum.txt`/`winenum.txt`, so the existing walker and layout are untouched. S4's `local-enum.py` always enables posture.

### D3.5 Dashboard

- A **Posture** page: a host × category matrix of pass/fail/warn counts with a score, then a per-check table across hosts.
- The host detail gains a **Posture** card: checks grouped by category with status chips and KB test/fix expanders.
- The AD page gains a **Domain posture** table fed by `collect().domains`, and (per D2.2) upgrades the S2 "uncorrelated signals" hints to confirmed chains where a domain identity now ties them together.

### S3 test plan

- **(a)** The manifest at the S3 base.
- **(b) Linux collector.** Runs for real on this Linux host; assert ≥ 30 POSTURE lines, every id known to the KB, no `ERR` a non-root user could have satisfied. Hermetic fixtures set `ARANUM_POSTURE_ROOT=<tmp tree>` (the `apt-source-check.sh` pattern) and assert specific PASS/FAIL for sshd_config, login.defs, `/proc/sys` sysctls, and a fake `mounts`.
- **(b) Windows collector.** No Windows box: dual-encoding parse (UTF-8 + CP1252); PSScriptAnalyzer 5.1-profile rules; AST scan for 7-only syntax; **extract the AD helper functions via the AST and unit-test them** against fixtures — a disabled roastable account is excluded, a DC is excluded from delegation counts, recursive Domain Admins membership is counted once, a signed `LargeInteger` krbtgt age converts correctly, and a channel-binding value that is not remotely readable yields `NA` not PASS; run under pwsh on Linux and assert every `WIN-*`/`AD-*` check emits `NA|not windows` and exit 0; and assert that **absent `-AdChecks`** every `AD-*` check emits `NA|ad checks not requested` with no LDAP/ADSI call (the AD helper is AST-extracted and invoked with the switch off).
- **(b) Parser.** On fixture winenum/linenum with POSTURE lines: FAIL → finding at KB severity; PASS → only in posture.json; a malformed `POSTURE|` line → quarantined diagnostic, not a finding; the same domain check from two hosts → **one canonical finding** whose `observed_from` holds two `{host,status,detail}` records; a PASS-from-host-a + ERR-from-host-b pair yields canonical `PASS` (determined beats undetermined) with both records preserved; a PASS + FAIL pair yields canonical `FAIL` with a `conflict:` detail; an ERR + NA pair (no determined observer) yields canonical `ERR`.
- **(c) New gate:** the posture-KB coverage test — every check id emitted by either collector has a KB check entry with test+fix (ids extracted statically). RED: add a fake id to a temp copy of a collector → fail. Asserts ≥ 30 ids extracted (no vacuous pass). A second gate asserts the strict parser rejects a crafted field-injection detail (`a|b|c` inside detail) — RED by relaxing the split cap.

---

