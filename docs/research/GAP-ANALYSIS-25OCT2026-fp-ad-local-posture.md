# GAP-ANALYSIS — 25OCT2026 — false positives, AD analysis, `--local` posture enumeration, posture dashboard

Base: `main` @ `69fec13` (v0.34.0). Governing contract: `CLAUDE.md` (§3 commits, §5 semver, §6 changelog, §9 OPSEC invariants).
Path: **full cycle** (multi-item, cross-module, additive findings-schema fields, judged by target metrics).
Provenance labels: **measured** (run this session, raw output under `docs/test-strategy/raw/baseline-69fec13/`),
**recorded** (cited artifact), **inferred** (reasoned, not observed).

## Objective

1. **Fidelity.** Every graded finding is a real positive, attributed to a real endpoint, and listed once.
   Targets, measured with `docs/test-strategy/harness/emission_audit.py` and the dashboard example fixture:
   - Negative or progress lines graded as findings (`neg_graded`): 18 → **0**.
   - `CRITICAL`/`[!!]` emissions left ungraded (`crit_ungraded`): 1 → **0**.
   - Labeled true-positive recall (`tp_recall`): 3/25 → **≥ 23/25**. Exact-severity agreement: 0/25 → **≥ 20/25**.
   - `(dispatcher)`-host findings on the fixture: 4/11 → **0**. Duplicate findings on the fixture: 4 → **0**.
2. **Capability.** `aranum run … --local` runs local Linux and Windows posture enumeration on every host the operator has access to:
   - Linux transports: ssh, rdp, vnc. Windows transports: ssh, winrm, rdp, vnc, plus an operator-chosen wmiexec, smbexec or psexec.
   - The dashboard shows each host's posture, with categories including Active Directory, and a test and a remediation example for every failing check.
   - Acceptance: an end-to-end fixture run produces a posture matrix, an AD page, and per-finding test and remediation blocks.

## Inventory

| ID | Type | Item | Evidence | Prov. |
|----|------|------|----------|-------|
| G01 | Bug | `[-]` miss lines graded as findings. Examples: "default creds rejected" (high), "skipping unauth probe" (high), "no UNAUTH Redis" (critical). | `emission_audit.py`: 5 miss emissions graded. Classifier probe at the base SHA: `_classify("[-] no UNAUTH Redis on …")` returns `critical`. | measured |
| G02 | Bug | `[HH:MM:SS]` progress (`log`) lines graded. Example: "nuclei (severity high,critical; …)" graded **critical**. | `emission_audit.py`: 13 log emissions graded (enum-http.sh:267, enum-https.sh:267, enum-mongo.sh:39, enum-vnc.sh:16, …). | measured |
| G03 | Bug | First-match-wins ordering shadows specific rules. The generic `UNAUTH` and `EXPOSED` → high rules precede the critical Jenkins API, Tomcat Manager and host-manager rules, so those grade **high**. | Classifier probe: "UNAUTH: Tomcat Manager exposed:" returns `high`. Rule order at `report.py:271-279` vs `report.py:333-336`. | measured |
| G04 | Bug | `(dispatcher)` attribution fails when a host has both a port-specific record (from `_targets_*.txt`) and the port-less host-directory record. `_endpoint_in_text` sees 2 "unique" endpoints and returns None. | Fixture: "SMB signing disabled at 10.0.0.5", "UNAUTH SMB shares at 10.0.0.5" and "guest:guest … 10.0.0.7" stay `(dispatcher)`. Cause at `report.py:888-899` and `report.py:950-960`. | measured |
| G05 | Bug | A URL without an explicit port (`https://10.0.0.30`) is not mapped to its scheme default (443), so a multi-port host stays ambiguous. | Fixture: "BMC HPE iLO detected: https://10.0.0.30" stays `(dispatcher)`. | measured |
| G06 | Bug | The same fact appears twice. A per-host evidence line and the dispatcher echo of it differ only in marker prefix and/or severity, so dedup (keyed on exact evidence hash and severity) keeps both. | Fixture: 11 findings, of which 4 duplicate another (Jenkins ×2, SMB signing ×2, guest ×2, the SMB-shares echo). | measured |
| G07 | Gap | 22 of 25 labeled true-positive emissions are never graded. Examples: `admin:admin WORKS`, `OPEN RELAY CANDIDATE`, `VRFY enabled`, NFS `no_root_squash`/`no_all_squash`/`insecure`, `POTENTIAL CRED LEAK`, JWT HMAC, Terrapin, read-only kubelet, product fingerprints. | `emission_audit.py` M4: `tp_recall=3/25`, `tp_sev_exact=0/25`. Labels pre-registered in `harness/tp_labels.json`. | measured |
| G08 | Bug | `crit()` (`[!!]`) emissions are not anchored. The NFS `no_root_squash` crit is ungraded because its rule lives only in `_BULK_RULES`. | `crit_ungraded=1` (enum-nfs.sh:20). | measured |
| G09 | Bug | The backup rule text does not match the emission. The rule expects `Backup (Rubrik\|…) API detected:`; enum-backup.sh emits `Rubrik backup API detected:`. | enum-backup.sh:145/154/163 vs `report.py` backup rule. | measured |
| G10 | Issue | Operational errors are invisible: tool not installed, "refuses to run", wall-clock timeouts. They are correctly not findings, but nothing surfaces them, so an operator cannot tell a clean host from an unprobed one. | 13 ungraded `err` emissions (e.g. enum-http.sh:276 nuclei timeout, enum-ike.sh:29). `grep` of report-dashboard.py for "health"/"run note" finds none. | measured |
| G11 | Issue | The broad low banner rule `(OpenSSH\|nginx\|Apache\|MySQL\|PostgreSQL\|Redis)` fires once per raw-tool output line. Expected result: many low findings per endpoint. | `report.py:445`. Not measured on a live tree (no live run data on disk; `outputs/*/raw` empty). | inferred |
| G12 | Gap | No remediation guidance exists anywhere in findings, reports, dashboard or wiki. | `grep -il "remediat\|mitigat" wiki/*.md` = 0 files. `report.py` only has `next_actions` labels (`report.py:80-85`). The dashboard has no remediation renderer (`grep -n remediat report-dashboard.py` = 0). | measured |
| G13 | Gap | No per-finding testing or verification example. The wiki has per-service triage commands but nothing at the finding-class level. | Wiki TEMPLATE sections: Triage, Quick wins, helpers, Gotchas, Sources. Finding dicts carry no `test` key (`_structured_finding`, `report.py:202-242`). | measured |
| G14 | Gap | No finding category taxonomy (AD, credentials, web exposure, privesc, hardening …). Tags are only severity and service. | `_compose_tags` (`report.py:182`). Service metadata has no category entries (`service-metadata.json` keys). | measured |
| G15 | Gap | No Active Directory analysis view. AD signals from enum-smb, enum-ldap, enum-kerberos, AD-depth rules and winenum are scattered across service pages. There is no domain rollup. | `NAV_ITEMS` (`report-dashboard.py:59`) has no AD entry. `grep "Active Directory" report-dashboard.py` = 0. | measured |
| G16 | Gap | AD checks missing from local Windows enumeration: password/lockout policy, krbtgt password age, kerberoastable and AS-REP-roastable account counts, unconstrained delegation on non-DCs, adminCount/privileged group size, Protected Users, domain/forest functional level, trusts, LDAP signing / channel binding (on a DC), SMB signing (local). | AD DEPTH section (`Invoke-PrivEscEnum.ps1:300-340`) covers only MachineAccountQuota, LAPS readability and WebClient. Network-side has 1 hit each for `ldap signing`/`channel binding` (enum-ldap.sh). | measured |
| G17 | Gap | No `--local` run item. `aranum run` never performs local posture enumeration. `bulk-linux`/`bulk-windows` exist as separate commands and are not wired into a session run or its report. | `grep -n "\-\-local" aranum.py auto-enum.sh` = none. `_run_auto_enum` (`aranum.py:635`) chains auto-enum → report → dashboard only. | measured |
| G18 | Gap | Windows exec choice is incomplete. Only impacket-wmiexec exists (`smb` transport). There is no smbexec and no psexec, and the wmiexec path cannot carry the default script: the encoded command exceeds 8000 characters, and even gzip+base64 of the minified script is 8545 characters. | `bulk-enum-windows.py:408-460`. Size probe this session: raw 20724 B, minified-gzip stager 8545 chars. | measured |
| G19 | Gap | No RDP or VNC access pathway for posture enumeration, on either OS. | `grep -n "rdp\|vnc\|xfreerdp\|vncdo" bulk-enum-windows.py bulk-enum-linux.sh` = none. | measured |
| G20 | Gap | No `local` transport, meaning enumerate the box aranum runs on, inside the session layout and report. | Standalones run by hand only. `aranum.py` `_COMMANDS` has no such entry. | measured |
| G21 | Gap | Linux posture coverage is privesc-only. No hardening/posture checks inline: sysctl/LSM status, firewall, pending security updates, sshd_config posture, UID-0 accounts, empty-password accounts, auditd/logging, mount options, umask. Some exist in separate standalones (`proc-hardening-check.sh`) but are not delivered by bulk. | `linenum-fast.sh` `hdr` list (SYSTEM … THICK-CLIENT). | measured |
| G22 | Gap | Windows posture coverage gaps: firewall profiles, Defender real-time status, BitLocker, SMBv1, SMB signing (local server), LLMNR/NBT-NS, WPAD, PowerShell v2 engine, script-block/transcription logging, RDP NLA, local Administrators membership, cached logons count, last hotfix date, Spooler, LAPS client present. Some are printed as raw values with no grading (RunAsPPL, LmCompatibilityLevel, CredGuard). | `Invoke-PrivEscEnum.ps1:274-297` prints RunAsPPL/LmCompat/CredGuard via `Write-Host` with no `Hit`. Other items: none (grep). | measured |
| G23 | Gap | No per-host posture view merging network findings and local posture into one card. | `render_host_detail` lists findings only. No posture model. | measured |
| PRE1 | Pre-existing failure | `test_r2_host_predicates.py::test_apt_no_writable_surface_emits_only_clean_conclusion` fails at the base SHA. The fixture directory is created owner-writable, so the checker correctly reports WRITABLE. This is a test-fixture defect, not a tool defect. | `pytest.log:443-455` (baseline). | measured |
| PRE2 | Pre-existing env failure | smoke `git: latest released tag v0.34.0 MISSING` occurs only because local tags were not fetched. It passes after `git fetch --tags` (384 pass / 0 fail / 1 skip). | `smoke.log` vs `smoke-tagsfetched.log`. | measured |
| PRE3 | Env | shellcheck was absent, so lint degraded to `bash -n`. After `pip install shellcheck-py` (0.11.0), `shellcheck -S warning` is clean at base. | `lint.log`, `shellcheck.log`. | measured |
| B1 | Blocked (live) | No live Windows or Linux lab hosts. No nxc, impacket, pywinrm, vncdotool, xfreerdp locally. Live transport validation is impossible here, so transports are proven by argv/flow tests, a local `local` transport run, and a loopback relay test. | `deps-check` / `which` this session. | measured |

## Out-of-scope classes (declared up front, repeated in every delegated prompt)

- Hardening of aranum itself beyond what the new code needs (tool-security findings), and compliance-control nits.
- Any write-to-target, persistence, credential-use beyond operator-supplied credentials, or detection evasion (§9). Specifically excluded:
  - AMSI/ETW bypass and obfuscated stagers.
  - Auto-use of credentials discovered during a run. These are reported as access candidates only.
- Redesigning existing dispatchers' probes. Fidelity is fixed in the classifier and emission corpus, not by rewriting probes.

## Triage

Relevance (R) and complexity (C) are scored 1–5. P-tier follows the triage-rubric matrix. The impact override applies to every wrong-result item (R=5).

| ID | R | C | Tier | Lane | Sprint |
|----|---|---|------|------|--------|
| G01 | 5 | 2 | P0 | now | S1 |
| G02 | 5 | 2 | P0 | now | S1 |
| G03 | 5 | 1 | P0 | now | S1 |
| G04 | 5 | 2 | P0 | now | S1 |
| G05 | 4 | 1 | P0 | now | S1 |
| G06 | 5 | 3 | P0 | now | S1 |
| G07 | 5 | 2 | P0 | now | S1 |
| G08 | 5 | 1 | P0 | now | S1 |
| G09 | 4 | 1 | P0 | now | S1 |
| PRE1 | 2 | 1 | P3 | now (adopted ride-along, recorded) | S1 |
| G10 | 4 | 2 | P1 | now | S2 |
| G12 | 5 | 3 | P1 | now | S2 |
| G13 | 5 | 3 | P1 | now | S2 |
| G14 | 4 | 2 | P1 | now | S2 |
| G15 | 5 | 3 | P1 | now | S2 |
| G21 | 5 | 3 | P1 | now | S3 |
| G22 | 5 | 3 | P1 | now | S3 |
| G16 | 5 | 3 | P1 | now | S3 |
| G23 | 5 | 3 | P1 | now | S3 |
| G17 | 5 | 4 | P1 | now | S4 |
| G18 | 5 | 3 | P1 | now | S4 |
| G20 | 3 | 1 | P2 | now (promoted: the cheapest provable transport, unblocks the S4 E2E test) | S4 |
| G19 | 5 | 4 | P2 | now | S5 |
| G11 | 3 | 3 | P2 | later (needs live tree data to size; R=3, C=3) | — |
| PRE2 | 1 | 1 | P3 | document-and-move-on (environment, not code) | — |
| PRE3 | 1 | 1 | P3 | document-and-move-on (environment) | — |
| B1 | — | — | — | spike-equivalent: offline proof strategy in each sprint test plan | S4/S5 |

Plan: `docs/plans/PLAN-001-25OCT2026-fp-ad-local-posture.md`.
