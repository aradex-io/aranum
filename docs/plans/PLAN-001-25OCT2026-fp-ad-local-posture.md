# PLAN-001 — 25OCT2026 — findings fidelity, AD analysis, `--local` posture enumeration, posture dashboard

Gap analysis and triage: `docs/research/GAP-ANALYSIS-25OCT2026-fp-ad-local-posture.md` (IDs G01–G23, PRE1–3, B1).
Base: `main` @ `69fec13` (v0.34.0). Path: full cycle. Target release: **v0.35.0** (MINOR: new subcommand, flags, transports and collectors; findings-schema changes are additive only).

## Constraints (settled, not re-litigated)

- **§9 OPSEC invariants hold for every sprint:**
  - No target write without an explicit flag.
  - No exfiltration or third-party phone-home.
  - Outputs only under the operator-passed path.
  - No persistence.
  - No AMSI/ETW/EDR evasion, and no obfuscated or packed stagers.
  - Credentials are only those the operator supplies. Credentials discovered during a run are reported as *access candidates*, never auto-used.
- **Code style:**
  - Python 3.9+ stdlib-only in core.
  - Optional tools (nxc, impacket, pywinrm, vncdotool, sshpass) degrade with a clear `[!] <tool> not installed` and a non-zero per-host status. They never silently no-op.
  - PowerShell must run on Windows PowerShell 5.1: ASCII-only, `[CmdletBinding()]`, no inline `if` as a hashtable value, no `$IsWindows`, and no assignment to automatic variables.
- **findings.json stays schema `"2"`.** Every new key is additive. `finding_id` derivation is unchanged: `service|host|port|protocol|severity|sha256(clean line)`. Ids change only where attribution fixes a wrong host or port, and the CHANGELOG notes it under "Changed".
- **The user chose the transports:**
  - Windows: ssh, winrm, rdp, vnc, and an operator choice of wmiexec, smbexec or psexec.
  - Linux: ssh, rdp, vnc.
  - The flag is `--local`.
- **Out-of-scope classes:** see the gap analysis. Repeat them in every peer prompt.

## Sprint map

| Sprint | Band | Items | Branch | Ships |
|--------|------|-------|--------|-------|
| S1 | P0 | G01–G09, PRE1 | `dev/findings-fidelity` | Negative/progress guard, rule-order fix + shadow audit, endpoint attribution, echo dedup, new rules, shared collector |
| S2 | P1 | G10, G12–G15 | `dev/finding-kb-ad-view` | Finding knowledge base (category, how-to-test, how-to-fix), categories, AD page, run-health panel, report.md/html remediation |
| S3 | P1 | G16, G21–G23 | `dev/host-posture` | `host-posture.sh` + `Invoke-HostPosture.ps1` (incl. AD domain checks), POSTURE parser, posture.json, Posture page + host posture card |
| S4 | P1/P2 | G17, G18, G20 | `dev/local-access` | `local-enum.py` orchestrator, `aranum run --local` / `aranum local`, local + ssh + winrm pathways and operator-chosen Windows exec method, mixed-tree report |
| S5 | P2 | G19 | `dev/desktop-transports` | rdp and vnc interactive pathways (both OS, incl. Linux xrdp), `--desktop-ok` gate |

Each sprint branches from the integrated tip of the previous sprint: S2's KB attaches to S1's cleaned findings, S3 extends S2's KB, and so on. Each sprint captures its own baseline pair at its real base SHA, so Rule 3 is deferred for S2–S5. Each sprint gets its own PR, merged by squash when green.

## Benefit metrics (pre-registered 25OCT2026, before any edit)

Harness: `docs/test-strategy/harness/emission_audit.py <repo>` and `tp_labels.json`. Plus the fixture run:

```
cp -r aranumtoolkit/docs/examples/dashboard/fixture $T && python3 aranumtoolkit/network/report.py $T --findings-only
```

| Metric | Baseline @69fec13 | Target | Sprint |
|---|---|---|---|
| M1 `neg_graded` (miss/log emissions graded) | 18 | 0 | S1 |
| M2 `crit_ungraded` | 1 | 0 | S1 |
| M3 `tp_recall` / 25 | 3 | >= 23 | S1 |
| M3b `tp_sev_exact` / 25 | 0 | >= 20 | S1 |
| M4 fixture `(dispatcher)` findings | 4 / 11 | 0 | S1 |
| M5 fixture duplicate findings (same fact twice) | 4 | 0 | S1 |
| M6 graded findings with a KB test + remediation block (fixture after S1) | 0 % | 100 % of non-low | S2 |
| M7 posture checks per OS with KB test + remediation | Linux 0 / Windows 0 | >= 30 / >= 35 | S3 |
| M8 access pathways runnable via `aranum run --local` | 0 (separate commands, 2 pathways) | Windows 7 + Linux 3 + local | S4/S5 |

Rows M6–M8 measure capability rather than noise. Their baselines are measured by grep (gap analysis G12, G17, G19).

## Regression baseline (S1; S2–S5 capture their own at their base SHA)

Raw output: `docs/test-strategy/raw/baseline-69fec13/`. Manifest: `manifest.json`, with 1138 per-test identities built by `docs/test-strategy/raw/manifest.py`. Commands:

```
python3 -m unittest discover -s aranumtoolkit/tests -v      > unittest.log   # 331 ok, 4 skipped
python3 -m pytest aranumtoolkit/tests -v -rA                > pytest.log     # 413 PASSED (ids), 5 SKIPPED, 1 FAILED (PRE1)
bash aranumtoolkit/tests/smoke.sh                           > smoke-tagsfetched.log  # 384 PASS, 0 FAIL, 1 SKIP
git ls-files '*.sh' | xargs shellcheck -S warning -e SC1091 -e SC2046 -f gcc   # clean
python3 aranumtoolkit/tests/data_audit.py                                       # rc=0
```

---

## S1 — Findings fidelity (G01–G09, PRE1)

**Problem.** The classifier grades negative and progress lines. Rule order misgrades criticals. `(dispatcher)` lines fail endpoint attribution. Dispatcher echoes duplicate per-host evidence. About 22 true emissions are ungraded. All of these are in `aranumtoolkit/network/report.py`. The dashboard re-implements collection and diverges.

### D1.1 Negative and progress guard (G01, G02)

**Option A (chosen).** A pre-classification guard in a new `_classify_line(line, rules)`. Every walker switches to it, and `_classify` stays as the raw-rule primitive for compatibility. The guard returns None when the ANSI-stripped line matches any of:

- `_lib.sh` miss marker: `^\s*\[-\]\s`.
- `_lib.sh` log marker: `^\s*\[\d{2}:\d{2}:\d{2}\]\s`.
- NetExec failure column: `^\S+\s+\S+\s+\d{1,5}\s+\S+\s+\[-\]\s`.
- Explicit negation: `\bNOT VULNERABLE\b` (case-insensitive) or `STATUS_(LOGON_FAILURE|ACCESS_DENIED|ACCOUNT_DISABLED)`.

**Exemption list (deliberate negatives):** `Privilege \(disabled - can still be enabled\)` (Invoke-PrivEscEnum.ps1:121 prints the medium-graded disabled-privilege hit through `Miss`).

**Option B (not taken).** Per-rule negative lookbehinds. They need about 150 edits, are fragile, and a new rule would re-open the class. Evidence that would flip the choice: a dispatcher that legitimately prints a positive finding via `miss`/`log`. The M3 label set and a grep of `log "` lines carrying `CRITICAL:`/`UNAUTH:` show none (`emission_audit.py`: all 13 graded log lines are progress text).

**Failure mode.** A future `[-]`-prefixed positive would be silenced. The mitigation is a test asserting the exemption list is honored, and a dispatcher-contract note that `miss`/`log` never carry findings.

### D1.2 Rule order and a shadow audit (G03, G09)

Move the specific critical HTTP product rules above the generic `EXPOSED`/`UNAUTH` rules: Tomcat Manager and host-manager, the Jenkins API, and the Jenkins Groovy console. Fix the backup regex to match the emission (`(Rubrik|Cohesity|Dell PowerProtect Data Manager) backup API detected:` and the legacy form).

New **shadow-audit gate** (`tests/test_rule_shadowing.py`). For every graded emission in the static corpus, and every labeled TP:

1. Collect all matching rules.
2. The first-match severity must equal the severity of the *most specific* matching rule, measured by longest literal pattern text, unless the pair is on an explicit allowlist with a reason.
3. The test fails on any unlisted shadow.

The corpus extractor moves from the docs harness into `aranumtoolkit/tests/_emission_corpus.py`, so the harness and the test share one extractor. The docs harness keeps its own frozen copy, so the benefit harness stays fixed. **Option not taken:** rule priorities/weights, a data-structure change to every rule-list consumer, `--severity-rules` included. Evidence that would flip it: allowlist growth past about 10 entries.

### D1.3 Endpoint attribution (G04, G05)

1. **Fold port-less records.** In `_inventory_endpoints`, a post-pass drops a port-less record `(host, "", "", svc)` whenever a port-specific record exists for the same `(host, svc)`.
2. **Infer scheme default ports.** In `_endpoint_in_text`, before matching, normalise `scheme://host` URLs without an explicit port to the scheme default for matching only (http 80, https 443, ldap 389, ldaps 636, ftp 21). The evidence text is unchanged.
3. **Host-level fallback.** If every match shares one host but the ports are ambiguous, attribute `host` with `port=""` and `attribution="host"`. One known host is better than `(dispatcher)`.
4. **Explicit run scope.** A line still unattributed keeps `host="(dispatcher)"`, documented in SCHEMA.md and used by merge-results.py and the interop README. It gains additive `scope:"run"`. Attributed findings get `scope:"endpoint"` or `scope:"host"`. The dashboard shows run-scope findings in a collapsed **Unattributed** panel and excludes them from host tables and severity KPIs.

**Option not taken:** renaming `(dispatcher)`, which breaks merge-results, recce interop and consumers. **Failure mode:** wrong-host attribution. Guards: the existing token-delimited matcher `_line_mentions_endpoint` is unchanged, and the new tests cover `10.0.0.1` vs `10.0.0.10` and multi-host lines.

### D1.4 Echo dedup (G06)

After attribution, merge a finding from a top-level `_*` dispatcher file into a per-host finding on the same `(host, service)` when it is the same fact. "Same fact" is decided on normalised texts: strip markers, timestamps and the `UNAUTH:` prefix, lowercase, and collapse whitespace. The two are the same fact if either:

- **(a)** One normalised text contains the other, and the shorter is >= 16 characters.
- **(b)** The Jaccard similarity of word stems is >= 0.75. Alphabetic words are stemmed to their first 4 letters. Tokens containing digits, `/`, `\`, `.` or `:` are kept whole, so paths, IPs and versions stay distinct.

**The merge.** The survivor keeps the higher severity and its line. Its primary `evidence_path` prefers the per-host file. `evidence_paths` is unioned and additive `merged_ids` lists the absorbed ids. Merging happens **only across the dispatcher-echo boundary**. Two per-host lines are never fuzzy-merged, which protects linenum/winenum SUID and path lines from collapsing.

**Option not taken:** global fuzzy dedup, which over-merges distinct per-host facts. **Failure mode:** two distinct dispatcher facts about one host merging into one per-host fact. Test: two dispatcher lines with different whole tokens (paths, ports) stay separate.

### D1.5 Rules (G07, G08)

Add or adjust rules so every `tp_labels.json` entry grades at its labeled severity:

- `admin:admin WORKS` → critical.
- `OPEN RELAY CANDIDATE` → high.
- `VRFY enabled` → medium.
- NFS exports: `no_root_squash` (critical, in the default rules), `no_all_squash` (medium), `insecure` (low).
- `POTENTIAL CRED LEAK` → high.
- JWT HMAC → medium.
- Terrapin (ssh-audit) → medium.
- Read-only kubelet → high.
- `BloodHound collection:` → high.
- RMI registry, KIBANA API → medium.
- Product "detected:" fingerprints (Jenkins, GitLab, SonarQube, Grafana, Prometheus) → medium.
- `Vault reachable` → low.
- Generic `^\s*\[!!\]` → critical, as the last critical fallback. All 12 `crit` call sites are criticals (grep).

### D1.6 Shared collector (consistency)

New `report.collect(out_dir, rules_path=None, *, diagnostics=None) -> list[dict]`. It runs bulk detection, walks with the right rules and service metadata, and finalizes. Both `report.main` and `report-dashboard.build_index` call it. The dashboard's dead `known_hosts` re-attribution block goes. The `(dispatcher)` checks in the dashboard become `scope == "run"` checks, with a host-string fallback for older findings.json.

### PRE1 (adopted ride-along)

Fix the test fixture: `chmod 0o555` on the `apt.conf.d` directory, restored in teardown. No tool change. Recorded here because it is a test defect present at base.

### S1 test plan

- **(a) Regression.** Rerun the full manifest. Every base PASS must still pass. The PRE1 FAIL becomes PASS. Tests asserting old wrong behaviour may only change if listed here; the sweep is at Phase 7.
- **(b) New behaviour.** New `tests/test_findings_fidelity.py`:
  - The guard on each G01/G02 sample, plus the exemption.
  - The rule order on the Tomcat and Jenkins samples.
  - Attribution on the fixture: zero `(dispatcher)`, iLO → 10.0.0.30:443, SMB → 10.0.0.5:445.
  - Echo dedup on the fixture: one Jenkins, one SMB signing, one guest.
  - The distinct-path non-merge case.
  - The host-level fallback.
  - run-scope for a line with no known host.
  - Dashboard <-> report count parity on the fixture.
  - Every `tp_labels` entry at its labeled severity.
- **(c) New gate.** The shadow audit. RED proof: run it at the pre-fix commit, where it must flag the Jenkins and Tomcat shadows. Then a mutation, moving the generic UNAUTH rule back above the Tomcat rule in a disposable worktree, must go RED. Its absence check also asserts that the corpus is non-empty (>= 500 emissions) and that the Tomcat sample exists in it.
- **Benefit.** M1–M5 re-measured with the frozen harness.

**Blast radius:** report.py, report-dashboard.py, findings.json content, dashboard counts. **Rollback:** revert the S1 squash commit. There is no data migration, because findings are regenerated from raw trees.

---

## S2 — Finding knowledge base, categories, AD view, run health (G10, G12–G15)

### D2.1 KB format and location

New `aranumtoolkit/network/finding-kb.json`, registered in `data-sources.json` with a reviewed date and owner. Shape:

```
{"schema": 1,
 "categories": {"ad": {"title": "Active Directory", "order": 1}, ...},
 "classes": [{"id": "ad.smb-signing-not-required", "category": "ad",
   "match": ["\\bsigning disabled\\b", "signing enabled but not required"],
   "services": ["smb"], "title": "...", "why": "...",
   "test": [{"label": "Confirm with NetExec", "cmd": "nxc smb <host> --gen-relay-list relay.txt"}],
   "fix":  [{"label": "Require SMB signing (GPO)", "text": "... 'Microsoft network server: Digitally sign communications (always)' = Enabled"},
            {"label": "PowerShell", "cmd": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"}],
   "refs": ["https://learn.microsoft.com/..."]}]}
```

**Option A (chosen): KB regexes matched against the finding line**, first class wins, with service as a tie-break. **Option B: tag each severity rule with a KB id.** That changes the `(regex, severity)` tuple contract used by `--severity-rules` files, and couples two lists. Evidence that would flip the choice: more than 10 % of graded fixture findings matching two KB classes with different categories (measured by a test).

- **Category fallback** when no class matches: a service → category map in the same file (e.g. `ldap`/`kerberos` → ad, `http` → web, `redis`/`mongo` → data). `smb` falls back to `ad` only when the host also exposes 88 or 389, otherwise `network`.
- **Findings gain additive keys:** `category`, `kb_id`, `kb_match` (`"class"` or `"service-default"`).
- **Commands are templates.** `<host>`/`<port>` are filled at render time from the finding. Nothing executes; the dashboard shows copyable text only.

**Coverage target (M6).** Every critical, high and medium rule in `_DEFAULT_RULES`, `_AD_DEPTH_RULES` and `_BULK_RULES(_WIN)` maps to a class with >= 1 test and >= 1 fix entry. The gate test computes this from rule samples in the emission corpus plus a samples file `tests/fixtures/kb-samples.txt`, one sample per rule. The gate fails if any non-low rule sample has no class.

### D2.2 Presentation

- **report.md and report.html:** a "Top risks" section grouped by category. Each finding shows Why, How to test and How to fix.
- **Dashboard:**
  - An **Active Directory** page. It shows domain controllers (inventory hosts with 88+389 or 88+445), then AD findings grouped by attack-path family: relay and coercion, roasting, AD CS, delegation, credential exposure (GPP/LAPS/SYSVOL), and policy and hygiene. Each family gets a "chain" hint, for example signing-not-required + coercion + ESC8 = relay-to-ADCS path.
  - A **Categories** page.
  - The finding card gains "How to test" and "How to fix" expanders with copy buttons. The existing dashboard.js handles copy for code blocks; reuse it.
  - A **Run health** panel on the index and coverage pages. It parses `[!]` lines from every `_dispatcher.log` that no rule grades (tool missing, refused, timeout, error), grouped by service, with counts (G10).
- **Option not taken:** a JS single-page application. The dashboard stays static HTML with no external assets (the existing contract).

### S2 test plan

- **(a)** The manifest from the S2 base.
- **(b)**
  - KB schema validation (ids unique, categories exist, regexes compile, every class has test+fix).
  - Fixture findings carry `category`/`kb_id`.
  - The AD page lists the fixture SMB-signing finding under relay.
  - Run health lists a seeded nuclei-timeout line.
  - report.md contains "How to fix".
- **(c) New gate:** the KB coverage test. RED proof: delete one class from a temp copy of the KB and point the test at it (an `ARANUM_FINDING_KB` env override for tests), so it must fail naming the uncovered rule. Its absence check also asserts that the samples file has >= N lines and that the known sample exists.

**Rollback:** revert. The new keys are additive, and consumers ignore unknown keys.

---

## S3 — Host posture collectors + posture model (G16, G21–G23)

### D3.1 Collector output contract

Each check emits exactly one line:

```
POSTURE|<check-id>|<PASS|FAIL|WARN|INFO|NA|ERR>|<detail single line>
```

Check ids are stable, e.g. `LNX-SSH-ROOTLOGIN` and `WIN-SMB1`. `ERR` means the check could not run (permission, missing binary). It is never PASS. **Option not taken:** JSON output. The collectors must also be readable on screen when run by hand, and the existing transports carry plain text; a pipe-delimited line is grep-friendly and survives PS transcripts.

### D3.2 Collectors (read-only; no writes, no network beyond localhost queries)

Both are standalone and self-contained (no dot-sourcing), so bulk transports can stdin-pipe them.

**`standalones/linux/host-posture.sh`.** Pure POSIX tools, about 30–35 checks:

- Kernel and patching: kernel EOL heuristic, pending security updates (read the package cache only, never refresh it).
- sysctl: ptrace_scope, kptr_restrict, dmesg_restrict, unprivileged_bpf, unprivileged userns, ASLR, suid_dumpable, ip_forward.
- LSM: SELinux/AppArmor mode.
- Firewall: nft/iptables/ufw/firewalld rules present.
- sshd_config: PermitRootLogin, PasswordAuthentication, PermitEmptyPasswords, X11Forwarding, MaxAuthTries, protocol and ciphers.
- Accounts: UID-0 accounts besides root, empty-password accounts (shadow only if readable, else ERR), sudoers NOPASSWD count, default umask, password aging (login.defs).
- Mounts: /tmp and /dev/shm nosuid/noexec.
- Logging: auditd, syslog daemon.
- Secure boot: `mokutil --sb-state` if present.
- Other: world-writable dirs on PATH, core dumps, cron and at permissions, time sync, failed systemd units (INFO).
- AD membership: sssd/realm/winbind joined (INFO), plus keytab files readable by the current user (FAIL).

**`standalones/windows/Invoke-HostPosture.ps1`.** About 35–45 checks, registry/CIM/native only, read-only:

- Firewall profiles enabled.
- Defender: real-time protection, tamper protection status, signature age. Status read only.
- BitLocker OS volume, Secure Boot.
- SMB: SMBv1 enabled, SMB server signing required, SMB client signing.
- Name resolution: LLMNR disabled, NBT-NS per adapter, WPAD autodetect.
- PowerShell: v2 engine present, script-block logging, transcription.
- RDP: enabled, NLA required.
- Credential protection: LSA RunAsPPL, Credential Guard, WDigest, LmCompatibilityLevel >= 5, CachedLogonsCount.
- Elevation: UAC EnableLUA/ConsentPrompt, LocalAccountTokenFilterPolicy, AlwaysInstallElevated.
- Local Administrators members (INFO + count), Guest enabled.
- Patching: last hotfix age, OS build EOL.
- Spooler running (WARN on a DC), WinRM listener HTTP-only.
- LAPS client policy present, AutoLogon password present (FAIL).
- **When domain-joined and FullLanguage, AD checks via ADSI (read-only LDAP):**
  - Domain password policy: min length, lockout threshold, max age.
  - krbtgt `pwdLastSet` age.
  - Counts of kerberoastable users (SPN set, not computer), AS-REP users (DONT_REQ_PREAUTH), non-DC unconstrained-delegation computers, adminCount=1 users, Domain Admins members.
  - Protected Users member count, ms-DS-MachineAccountQuota, domain functional level.
  - Trusts (INFO), and LAPS schema attribute present.
  - These emit `POSTURE|AD-...` lines tagged with `domain=<dns name>` in the detail.

### D3.3 Parser and model

`report.py`:

- New `_POSTURE_RE`. Posture lines bypass the regex rules entirely, because the guard and rules never see them.
- FAIL and WARN become findings with `service="posture"`. Severity comes from the KB check entry (`sev_fail`/`sev_warn`). The finding carries `posture_check`, `posture_status`, `kb_id` and `category`.
- PASS, INFO, NA and ERR are not findings. They are recorded in **`posture.json`**, written beside findings.json: `{host: {os, source, checks: {id: {status, detail}}}, domains: {name: {checks..., observed_from: [hosts]}}}`.
- AD-* checks are rolled up per domain: the worst status across observing hosts, with every observer listed.
- findings.json `summary.posture` gains additive `{hosts, pass, fail, warn, err}`.

### D3.4 Delivery

- `bulk-enum-linux.sh` and `bulk-enum-windows.py` gain `--with-posture`. It appends the posture collector to the shipped stream: bash concatenation for Linux, PS script-block concatenation for Windows.
- `linenum-fast.sh` and `Invoke-PrivEscEnum.ps1` must not `exit` before the appended part runs. Verify their tails and change them if needed.
- Output stays in `linenum.txt`/`winenum.txt`, so the existing walker and layout are untouched.
- S4's `local-enum.py` always enables posture.

### D3.5 Dashboard

- A **Posture** page: a host x category matrix of pass/fail/warn counts with a score (pass / (pass+fail+warn)), then a per-check table across hosts.
- The host detail gains a **Posture** card: checks grouped by category with status chips, and KB test/fix expanders.
- The AD page gains a **Domain posture** table.

### S3 test plan

- **(a)** The manifest at the S3 base.
- **(b) Linux collector.** `host-posture.sh` runs for real on this Linux host; assert >= 30 POSTURE lines, every id known to the KB, and no `ERR` that a non-root user could have satisfied. Hermetic fixture tests set `ARANUM_POSTURE_ROOT=<tmp tree>` (the pattern `apt-source-check.sh` already uses) and assert specific PASS and FAIL results for sshd_config, login.defs, sysctl via `/proc/sys` under the root, and mounts via a fake `mounts` file.
- **(b) Windows collector.** Five checks that need no Windows box:
  - Parse it under pwsh 7 with the dual-encoding parse (UTF-8 and CP1252).
  - Run PSScriptAnalyzer compatibility rules against the 5.1 profile.
  - AST-scan for 7-only syntax.
  - Extract functions via the AST and unit-test the pure classification helpers with stubbed inputs.
  - Run it under pwsh on Linux. The non-Windows path must emit `POSTURE|WIN-*|NA|not windows` for every check and exit 0.
- **(b) Parser.** On a fixture winenum and linenum with POSTURE lines: FAIL → finding with the KB severity, PASS → only in posture.json, and a domain rollup across 2 hosts.
- **(c) New gate:** the posture-KB coverage test, where every check id emitted by either collector has a KB check entry with test+fix. The ids are extracted statically from the scripts. RED: add a fake id to a temp copy of the collector. The test asserts >= 30 ids were extracted, so an extractor regression cannot pass vacuously.

---

## S4 — `--local` access layer (G17, G18, G20)

**New ADR-007 records the access-layer design and its §9 analysis before code.** Every delivery note below is enumeration-only; the invariants in the Constraints section bind this sprint in full.

### D4.1 Orchestrator

New `aranumtoolkit/network/local-enum.py` (stdlib) and the CLI entries `aranum local ...` plus `aranum run ... --local`.

**Inputs:**
- `--targets FILE` with lines `host[:port] [os=linux|windows] [via=ssh,winrm,...] [user=...]`, **or** `--from-inventory <inventory.json>`. The latter auto-builds access candidates from open 22, 5985/5986, 445, 3389 and 5900-5910, using nmap OS/service hints for the OS guess.
- Credentials (operator-supplied only): `-u/-p/--key` defaults; `--creds FILE` with lines `host|* user pass-or-key-path` (file mode must be 0600, else a warning); `-H` NT hash for the impacket and nxc families.
- `--transport` order, `--win-exec {wmiexec,smbexec,psexec}`, `--lhost`/`--lport`, `--self`, `--desktop-ok` (S5), `-P`, `--dry-run`, `-o`.

**Per-host flow.** Resolve OS (hint, then port heuristic, then banner over the chosen transport); try transports in order until one authenticates (existing ADR-006 fall-through); run privesc enumeration plus the posture bundle; write the bulk layout `<out>/{linux,windows}/<host>/_meta.json` + `linenum.txt`/`winenum.txt`, with `_meta.json` carrying host, port, protocol, user, transport, os, status, fail_reason, artifact_id.

Default transport order:
- Windows: winrm → ssh → the chosen `--win-exec` method (only when `--win-exec` is given) → rdp/vnc (only with `--desktop-ok`).
- Linux: ssh → rdp/vnc (only with `--desktop-ok`).

**Delegation (Option A, chosen).** Delegate to the proven per-OS engines so tested transports are reused:
- Linux ssh → `bulk-enum-linux.sh` (KEY/PASS/KEY_THEN_PASS, ADR-006) `--with-posture`.
- Windows winrm and ssh → `bulk-enum-windows.py --transport winrm,ssh --with-posture`.
- `local-enum.py` implements only the *new* pathways: the local self-scan, the operator-chosen Windows exec method, and (S5) the desktop transports.

**Option B (not taken):** reimplement every transport in local-enum.py — duplicates tested code and voids ADR-006 coverage. Evidence that would flip it: delegation forcing more than two per-host process round-trips, or output-layout conflicts.

### D4.2 Local self-scan (G20)

`--self` (and `aranum local --self`) runs the matching posture + privesc collector for the current OS directly, with no transport, and files the result in the bulk layout as `host="localhost"`, `transport="local"`. This is the cheapest provable pathway and the backbone of the S4 end-to-end test, because it needs no credentials and no second host.

### D4.3 Operator-chosen Windows exec method (G18)

The three impacket-family methods (wmiexec, smbexec, psexec) are offered because the default enumeration script is far larger than any of their command-line limits (measured: 8545-char minified+gzip stager vs the ~8000-char WMI ceiling and the far smaller psexec ceiling). The design keeps the on-the-wire command short and the large enumeration body off the command line, delivered through an operator-hosted, loopback-bound aranum relay rather than inline.

**Design decisions, recorded here and in full in ADR-007:**
- **Method is explicit and consent-gated.** `--win-exec` must be chosen by the operator; none of the three is ever added to the auto order silently. The existing `--use-smb-admin` consent and admin-cred requirement are preserved.
- **The relay (`aranumtoolkit/network/_relay.py`, stdlib `http.server`) binds an explicit `--lhost`.** There is no wildcard default; an unspecified lhost is refused with guidance. It issues one single-use 128-bit token per host, serves the enumeration body for that token at most twice (one retry) inside a bounded window, accepts exactly one result upload per token capped at 64 MiB, writes it under the operator's `-o`, and 404s every other request. It never serves arbitrary files from disk, only the in-memory enumeration body. It shuts down when all tokens complete or `--relay-timeout` (default 600 s) elapses.
- **No on-disk-artifact parity claim.** The ADR-003/006 SMB CAVEAT is restated: these methods transit a service and/or an ADMIN$ output file, so they do not carry the no-on-disk-artifact property that winrm and ssh keep. This is stated plainly to the operator in `--help` and the ADR, not implied as parity.
- **§9 compliance.** The relay transfers the read-only enumeration body only; it stages no payload to the target, and the service/process it uses is the method's own transient mechanism, torn down by the method itself. No persistence is created. The body is the same reviewed collector shipped over winrm/ssh. There is no obfuscation or evasion. Discovered credentials are reported as access candidates, never reused.

### D4.4 CLI wiring

- `_COMMANDS` gains `local` (runner `local-enum.py`).
- `_AUTO_ENUM_VALUE_FLAGS` gains the new value flags so session arg-splitting stays correct.
- `--local` on `aranum run` runs auto-enum first, then `local-enum.py --from-inventory <raw>/inventory.json`, then the shared report+dashboard over the combined tree.
- A run that mixes network service dirs with `linux/`/`windows/` bulk dirs reports both. The report learns a "mixed" layout: service dirs use the auto walker, and the two bulk dirs use the bulk walker, unified into one findings list and one dashboard.

### S4 test plan

- **(a)** The manifest at the S4 base.
- **(b)**
  - Target-file and `--from-inventory` parsing → correct per-host OS, transport order, and candidate build (fixture inventory.json).
  - `--dry-run` prints the plan and opens no socket (assert no connections, via a no-network sandbox).
  - **The local self-scan runs for real on this host** and produces a valid bulk tree that `report.py` ingests into findings + posture with no `(dispatcher)` noise.
  - Relay unit tests (loopback only): single-use token, the one-retry cap, the upload size cap, 404 on every other path, refusal without `--lhost`, and teardown on timeout.
  - The exec-method argv builder for each of wmiexec/smbexec/psexec is asserted by string, with the tool stubbed on PATH. No real connection.
  - Mixed-layout report parity: a fixture with one service dir and one `windows/` host yields one unified findings list and a dashboard that renders both.
  - Dependency-absent degradation: with the tool absent, the host records a non-zero status and a clear message, and the run continues.
- **(c) New gate:** the relay-safety test — asserts the on-the-wire command length is under the method ceiling, the relay refuses a wildcard bind, and a second GET past the retry cap or a second upload is rejected. RED: raise the body past the ceiling, or allow a wildcard bind, in a temp copy; each must fail.

**Blast radius:** a new orchestrator, a new relay, CLI dispatch, and the report's mixed-layout handling. **Rollback:** revert the squash; the new command and flag are additive, and existing commands are unchanged.

---

## S5 — Desktop transports (G19)

**Problem.** Some hosts expose only RDP or VNC, and the user requires those pathways on both OSes (Linux via xrdp/VNC too). These are interactive GUI channels, so non-interactive enumeration is best-effort.

### D5.1 Approach

- **`--desktop-ok` gate.** RDP and VNC are never in the auto order without this flag, because they disconnect or lock an interactive session and are noisier than winrm/ssh. The flag is the operator's explicit acceptance.
- **RDP command pathway (Option A, chosen for Windows targets).** Use `nxc rdp <host> -x <cmd>` (NetExec RDP command execution, beta since 2025) to run the same short relay-fetch command as S4, so the enumeration body again travels over the relay rather than the GUI. Expose `--cmd-delay`/`--clipboard-delay` passthrough for slow targets. If nxc or its RDP support is absent, degrade with a clear message. **Option not taken:** screen-scraping the RDP framebuffer with OCR — brittle and slow; reserved as a last resort, not built now.
- **VNC pathway (both OSes).** Use `vncdotool` to open a terminal and type a one-line relay-fetch command, then wait for the relay upload. VNC has no auth context for command execution, so this is explicitly best-effort and gated behind `--desktop-ok`. Keystroke scripting is read-only in intent (it runs the same reviewed enumeration body) and types nothing that writes to the target beyond launching the read-only collector.
- **Linux RDP (xrdp).** `nxc rdp` targets Windows RDP semantics; for a Linux xrdp host, fall through to the VNC pathway or ssh. Record this limitation in ADR-007.
- **Assisted mode.** When no non-interactive desktop path succeeds, emit a ready-to-paste operator command (the short relay-fetch line) plus the relay URL, so the operator can run it by hand in the GUI session. This keeps the pathway useful without the tool driving the GUI blindly.

### D5.2 §9 and safety

All S4 relay invariants hold unchanged. The desktop transports only launch the same read-only enumeration body; they stage nothing, persist nothing, and use no evasion. The GUI keystrokes are confined to opening a shell and invoking the collector. `--desktop-ok` and the relay's loopback bind remain mandatory.

### S5 test plan

- **(a)** The manifest at the S5 base.
- **(b)**
  - The RDP argv builder (nxc rdp -x with the relay command and the delay passthrough) asserted by string, tool stubbed.
  - The VNC keystroke script builder asserted by content, `vncdotool` stubbed.
  - `--desktop-ok` gating: without it, rdp/vnc are absent from the resolved order; the test asserts the refusal.
  - Assisted-mode output: the printed operator command is present and well-formed when both automated paths are stubbed to fail.
  - Tool-absent degradation for both.
- **(c) New gate:** the desktop-gate test — rdp/vnc must not appear in any resolved transport order unless `--desktop-ok` is set. RED: drop the gate check in a temp copy; the test must fail.

**Blast radius:** new transports in the S4 orchestrator, new CLI flags. **Rollback:** revert the squash.

---

## Effort-wide benefit (after S5)

Re-measure M1–M8 on the same harnesses. Run the full example fixture plus a local self-scan end-to-end and confirm: zero `(dispatcher)` noise, an AD page, a posture matrix, and a test + remediation block on every non-low finding and every failing posture check. Record the deltas and the merge SHAs here, and write errata against this plan if any pre-registered target is missed.

## Peer review (Phase 5 gate)

This whole plan goes to a second, independent Tier-2-cyber model (codex Daybreak Blue, `-c model_reasoning_effort=xhigh`, read-only, file handoff) before S1 code. Findings are answered by class with a recorded sweep each. The out-of-scope classes above are repeated verbatim in the prompt.
