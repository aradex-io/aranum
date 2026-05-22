# Changelog

All notable changes to **aratool** will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

See `CLAUDE.md` §6 for the entry style guide.

## [Unreleased]

### Added

### Changed

### Fixed

---

## [v0.22.0] — 2026-05-22

**Opt-in aggressive UDP probes + VMware vCenter detector (E4).** Three new dispatchers (IKE, SLP, RADIUS) covering UDP service-discovery surface with significant operational risk; disabled by default and double-gated (auto-enum flag + env var). Plus a vCenter detector folded into `enum-http.sh` C.13.

### Added
- `network/enum-ike.sh` — IKE/IPsec UDP 500 main-mode probe; aggressive-mode hash harvest doubly-gated on `ENUM_IKE_AGGRESSIVE_MODE=1`.
- `network/enum-slp.sh` — SLP UDP 427 discovery via nmap NSE; CVE-2023-29552 amplification flag.
- `network/enum-radius.sh` — RADIUS UDP 1812/1813 reachability + BlastRADIUS (CVE-2024-3596) Message-Authenticator-enforcement precondition check.
- `network/enum-http.sh` — VMware vCenter SDK (`/sdk/vimServiceVersions.xml`) + UI (`/ui/`) detection in C.13 product-detect block (9th product family).
- `network/auto-enum.sh` — `--ike`, `--slp`, `--radius`, `--aggressive` flags. Aggressive services are stripped from the auto-derived service list unless explicitly opted in; opt-in also sets `ENUM_RUN_X=1` env vars so dispatchers double-gate against accidental manual invocation.
- `network/nmap-parse.py` — SERVICE_MAP routes 3 new aggressive categories (`ike`, `slp`, `radius`).
- `network/report.py` — 11 severity rules for E4 hit patterns (CRITICAL: PSK hash harvest, SLP amplification, RADIUS bogus-accept; HIGH: BlastRADIUS precondition, vCenter SDK; MEDIUM: SLP registry, vCenter UI; LOW: RADIUS reachable, IKE endpoint, IKE vendor).
- `tests/tp-server.py` — vCenter SDK/UI TP stub on port 19024 (base+14).
- `tests/fp-harness.sh` — FP sweep expanded to 22 dispatchers × 4 scenarios = 88 cells; new ENV-GATE TEST block verifies the 3 aggressive dispatchers refuse to run without their env var (0/3 expected failures); TP block adds vCenter (7 total TP checks).
- `deps-check.sh` — E4 OPT-IN AGGRESSIVE PROBES section checks `ike-scan` (required for `--ike`), `nmap` (confirmed for SLP NSE), `python3` (confirmed for RADIUS stdlib probe).

**Notes:**
- E4 dispatchers are AGGRESSIVE: IKE aggressive-mode is a known historical PSK-hash leak; SLP is a CVE-2023-29552 amplification surface (do not fire indiscriminately); RADIUS probes may interact with NAS lockout policies. The double-gate (auto-enum flag + ENUM_RUN_X env var) is intentional and load-bearing — do not weaken without operator request.
- `slptool` direct-target mode is unreliable across distros; the SLP dispatcher uses nmap NSE (`slp-discovery,slp-info`) instead.
- BlastRADIUS detection here is the precondition only (Message-Authenticator enforcement check). Full exploit requires nonce-grinding + on-path position.

---

## [v0.21.0] — 2026-05-22

**HTTP product detectors (E3).** `enum-http.sh` now fingerprints 8 common product families on live HTTP targets, emitting product+version findings only when product-specific markers are present.

### Added
- `network/enum-http.sh` — C.13 product-fingerprint phase covering Tomcat Manager, Jenkins (including Groovy script console RCE check), GitLab, SonarQube, Grafana, Prometheus, Hadoop NameNode, Spark UI. Skippable via `NO_PRODUCT_DETECT=1`.
- `network/report.py` — 12 severity rules for the product-detect hit patterns (CRITICAL for Tomcat-Manager-UNAUTH and Jenkins-Groovy-script-console; HIGH for the rest; MEDIUM for Spark).
- `tests/tp-server.py` — Jenkins / Grafana / Prometheus TP stub servers on 19020-19022.
- `tests/fp-harness.sh` — TP block exercises the three product-detect stubs end-to-end.

**Notes:**
- `enum-http.sh` is intentionally NOT added to the dispatcher FP sweep — it depends on optional external tools (httpx, whatweb, nuclei, ffuf, nikto) and its target shape differs (alive-URLs not raw ip:port). Per-product TP stubs cover the product-detect logic specifically.
- The product detectors carry forward v0.20.1's "two-evidence" discipline: every detector requires a product-specific marker (header pattern OR JSON-key combination OR exact body string), never just "HTTP 200 on the canonical path".

---

## [v0.20.2] — 2026-05-22

**CHANGELOG hygiene + AJP behavioral note.** No code changes — pure documentation cleanup.

### Changed
- `CHANGELOG.md` v0.20.1 — folded the non-standard `Known gaps` section into a `Notes:` paragraph under `Fixed`, per Keep a Changelog 1.1.0.
- `CHANGELOG.md` v0.20.1 — documented the AJP two-evidence guard's false-negative tail under tight timing.

---

## [v0.20.1] — 2026-05-22

**Dispatcher FP fixes + in-tree regression harness.** Three confirmed false-positive bugs in network dispatchers corrected; in-tree FP/TP harness added so this class of regression cannot reappear silently.

### Fixed
- `network/enum-ajp.sh` — required two-evidence service fingerprint (nmap `ajp13` fingerprint line AND at least one `| ajp-*:` script-result line) before emitting AJP findings. Previously, `grep -qi 'AJP'` matched nmap's own NSE preamble ("NSE: Loading scripts: ajp-headers, …"), causing a false `UNAUTH:` hit on any open port.
- `network/enum-telnet.sh` — required nmap telnet fingerprint OR IAC option-negotiation byte (0xFF 0xFB–0xFE) in the banner before emitting "Telnet open". Previously emitted a hit unconditionally after `nc` connected, regardless of protocol.
- `network/enum-rsync.sh` — gated module parsing on `rsync` exit code 0 instead of regex-filtering error lines. Previously the regex `^(@|rsync:)` skipped `@RSYNCD:` and `rsync:` error lines but not `rsync error: …` lines (no colon immediately after "rsync"), so the token "rsync" was parsed as a module name.

### Added
- `tests/fp-harness.sh` — in-tree regression harness: runs all 19 dispatchers × 4 wrong-service scenarios (HTTP-200, SSH-banner, accept-silent, TCP-echo) and 3 TP markers (rsync stub, telnet IAC stub, AJP fixture). Returns rc=0 iff 0 FPs and 0 TP regressions.
- `tests/fp-server.py` — multi-flavor wrong-protocol server (HTTP-200, SSH-banner, accept-silent, TCP-echo); `--port-base` flag for collision avoidance.
- `tests/tp-server.py` — true-positive stub servers: rsync daemon with full handshake + module list, telnet IAC option-negotiation; `--port-base` flag.
- `tests/fixtures/ajp-real-nmap.txt` — canonical `nmap --script ajp-headers` output fixture used by the AJP TP check in `fp-harness.sh`.
- `tests/smoke.sh` — section 13 runs `fp-harness.sh` as part of the smoke suite.

**Notes:**
- The AJP two-evidence guard is conservative — a real AJP service whose `ajp-*` nmap scripts time out (aggressive `--throttle` mode, lossy network, very busy backend) will be silently skipped. If AJP findings disappear after upgrade against a target you previously saw on v0.20.0, re-run with `--script-timeout 60` or higher.
- The FP harness scenarios use plain HTTP / SSH / echo / silent servers — cross-service false positives (e.g. an HTTP server returning JSON containing both "sealed" and "neo4j_version") are out of scope for the harness. The 4 scenarios cover the user-reported "open port, wrong service" class; specifically-crafted evil servers could still trigger FPs. Future expansion candidate.

---

## [v0.20.0] — 2026-05-22

**Iteration E2** of ROADMAP-002 — Tier 2a network enumeration dispatchers. Covers 11 SERVICE_MAP categories: high-yield infrastructure and data-store services.

### Added
- `network/enum-ipp.sh` — IPP / CUPS (631) — printer enum + CVE-2024-47176 version hint.
- `network/enum-zookeeper.sh` — Zookeeper (2181/2182) — 4LW enumeration.
- `network/enum-cassandra.sh` — Cassandra (9042/9160) — cluster info, anonymous CQL.
- `network/enum-kafka.sh` — Kafka (9092/9093) — anonymous broker metadata + topic list.
- `network/enum-neo4j.sh` — Neo4j (7474/7687) — version + opt-in default-cred check (gated on ENUM_NEO4J_DEFAULT_CRED=1).
- `network/enum-influxdb.sh` — InfluxDB (8086/8088) — version, unauth query API.
- `network/enum-solr.sh` — Apache Solr (8983/8984) — cores, version + CVE-2019-17558 / CVE-2023-50386 hints.
- `network/enum-consul.sh` — Consul (8500) — agent self, KV dump.
- `network/enum-vault.sh` — Vault (8200) — seal-status, init-state probe.
- `network/enum-msrpc.sh` — MSRPC endpoint mapper (135) — rpcdump / rpcclient / nmap msrpc-enum.
- `network/enum-netbios-ns.sh` — NetBIOS-NS (137/udp) — name-table dump via nbtscan/nmblookup.
- `network/nmap-parse.py` — SERVICE_MAP routes 11 new tier-2a categories.
- `network/report.py` — severity rules for tier-2a dispatchers.

### Changed
- `deps-check.sh` — checks tier 2a tooling (kafkacat, cqlsh, nbtscan, impacket-rpcdump, etc.).
- `tests/test_nmap_parse.py` — REQUIRED_CATEGORIES extended with the 11 new keys.

---

## [v0.19.0] — 2026-05-22

**Iteration E1** of ROADMAP-002 — Tier 1 network enumeration dispatchers. Covers 8 SERVICE_MAP categories that routed to targets but had no dispatcher scripts.

### Added
- `network/enum-ajp.sh` — AJP / Tomcat (8009) — nmap ajp-headers/methods/auth/brute scripts + Ghostcat CVE-2020-1938 hints in _hints.txt. Flags `UNAUTH:` when ajp-auth output does not include `Authentication: Required`.
- `network/enum-oracle.sh` — Oracle DB (1521/1522/1526) — TNS version, SID brute (oracle-sid-brute NSE), oracle-brute-stealth. Discovered SIDs written to sids_<port>.txt. Optional tnscmd10g version probe.
- `network/enum-pop3.sh` — POP3 (110/995) — CAPA banner grab (nc for plain, openssl s_client for POP3S), plaintext-auth flag (USER present + STLS absent on port 110), optional ENUM_USER/ENUM_PASS probe via nc.
- `network/enum-imap.sh` — IMAP (143/993) — CAPABILITY banner grab, STARTTLS flag (LOGIN present + STARTTLS absent on port 143), optional LOGIN cred probe via nc.
- `network/enum-telnet.sh` — Telnet (23) — nc banner grab + optional nmap telnet-encryption/telnet-ntlm-info/banner. Device-family fingerprint regex (Cisco, HP iLO, Brother, Dell iDRAC, Juniper, Ubiquiti, DD-WRT). Per-family default-cred shortlist in _hints.txt — no auto-attempt performed.
- `network/enum-rsync.sh` — rsync daemon (873) — anonymous module listing via rsync://. Per-module directory listing (up to 10 modules). Flags high-value modules (etc, home, root, backup, var, srv, www) exposed without auth.
- `network/enum-mqtt.sh` — MQTT (1883/8883) — anonymous $SYS/# subscribe via mosquitto_sub (50-message/5-second cap). rc 0 and rc 27 (timeout-after-success) treated as success; rc 5 (auth required) and rc 14 (unreachable) produce no finding. Records broker version from $SYS topic.
- `network/enum-sip.sh` — SIP (5060/5061) — nmap sip-methods/sip-enum-users (UDP + TCP). Vendor fingerprint from Server:/User-Agent: lines (Asterisk, FreePBX, Cisco CUCM, Avaya, Polycom). Optional svmap (SIPVicious) probe.
- `network/report.py` — 8 explicit HIGH severity rules anchored on E1 dispatcher hit strings (AJP unauthenticated, Oracle TNS/SIDs, POP3 plaintext-auth/AUTH SUCCESS, IMAP plaintext-auth/AUTH SUCCESS, Telnet open/device, rsync HIGH-VALUE module, MQTT UNAUTH broker, SIP service). Rules inserted after generic UNAUTH rule to document intent.
- `docs/ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md` — Opus-authored plan mapping E1-E4 iteration scope.

### Changed
- `deps-check.sh` — added E1 TIER-1 DISPATCHERS section: rsync (required), mosquitto_sub (recommended), tnscmd10g (optional), svmap/sipvicious (optional), kafkacat/kcat (optional, reserved for Tier 2a).

---

## [v0.18.0] — 2026-05-20

**Iteration D2** of ROADMAP-001 — Linux CVE checks + creds enhancements. Second half of bundled-D per the option-2 sequencing. Closes REVIEW-001 §2.8 and §2.9.

### Added
- **D2.1 — 6 Linux CVE / privesc-surface check scripts:**
  - `linux/pwnkit-check.sh` — CVE-2021-4034 (polkit `pkexec` memory-corruption local privesc); flags polkit < 0.120.
  - `linux/looney-check.sh` — CVE-2023-4911 (glibc `GLIBC_TUNABLES`); flags glibc 2.34-2.38; lists candidate setuid binaries.
  - `linux/overlayfs-check.sh` — CVE-2023-0386 (overlayfs uid/gid mapping); flags Ubuntu HWE 5.15.0-{60..86} / 6.2.0-{20..32}; checks userns + overlayfs prerequisites.
  - `linux/io-uring-check.sh` — io_uring availability + restrictions across `/proc/sys/kernel/io_uring_disabled` + empirical `io_uring_setup()` reachability via python ctypes. HIGH on user-reachable surface (multi-CVE history).
  - `linux/namespaces-check.sh` — unprivileged user-namespace creation (precondition for CVE-2022-0185 / CVE-2023-32233 / etc.). `unshare -rU -- /bin/true` is the empirical test.
  - `linux/apt-source-check.sh` — apt-get writable config / hooks (`/etc/apt/apt.conf.d`, `sources.list.d`, etc.). Root runs scripts from these dirs on `apt-get install/update` — operator-write to any of them is a privesc path. Debian/Ubuntu only.
  - All 6 no-deps, run as unprivileged user, exit 0 on safe state. `bash -n` + `shellcheck -S warning` clean.
- **D2.2 — `creds/spray-scheduler.py`:** lockout-policy-aware wrapper around any external spray tool (nxc, kerbrute, default-creds-sweep.py, etc.). Per-principal attempt counting with sliding window: max `--threshold N` attempts per user within `--interval M` minutes (defaults 3/30 mirror common AD default). When threshold hit, sleeps until the oldest recent attempt ages out. Persistent state under `.spray-state.json` for resume after Ctrl-C. `--dry-run` does NOT mutate state (otherwise dry-run would lock out the planned set).
- **D2.2 — `creds/hash-format.py`:** converts captured authentication hashes from Responder / nxc smb / impacket GetNPUsers / impacket GetUserSPNs output into hashcat- and john-ready files. Detects: NetNTLMv2 (mode 5600), NetNTLMv1 (5500), Kerberos AS-REP (18200), Kerberos TGS-REP RC4 (13100). Writes per-type `hashcat-*.txt` + `john-*.txt` + `_index.tsv`.

### Enhanced
- **D2.3 `network/report.py`:** `_AD_DEPTH_RULES` extended with seven new severity rules anchored on the D2.1 script output strings — CRITICAL on `polkit < 0.120 — PwnKit vulnerable`, `glibc 2.34-2.38 — Looney`, Ubuntu HWE CVE-2023-0386 hits, apt writable config / sources.list; HIGH on io_uring user-reachable surface and `unshare -rU succeeded`.
- **D2.3 README** — Linux Scripts table extended with 6 new rows for D2.1; new "Credential helpers" section listing `default-creds-sweep.py` (pre-existing) + the two D2.2 additions.
- **D2.3 `tests/smoke.sh`** — section 11i (D2.1 syntax + real-data run on this host) + section 11j (D2.2 hash-format synthetic-Responder NTLMv2+ASREP extraction + spray-scheduler 9-attempt dry-run with no spurious lockout sleep).

### Real-data validation (this release)
The 6 D2.1 scripts all ran against this Fedora 6.19 attacker box with the expected verdicts:
- pwnkit-check: polkit 126 → patched (correct: Fedora 42 ships polkit 126)
- looney-check: glibc 2.41 → outside vulnerable window 2.34-2.38 (correct)
- overlayfs-check: kernel 6.19.14-104.fc42.x86_64 → outside Ubuntu HWE ranges (correct: this is Fedora)
- io-uring-check: io_uring reachable → HIGH (verbatim — `/proc/sys/kernel/io_uring_disabled=0`)
- namespaces-check: `unshare -rU` succeeded → HIGH (verbatim — Fedora ships unprivileged userns enabled)
- apt-source-check: apt-get not present → not applicable (correct: not Debian/Ubuntu)

report.py against the stitched output (treating as a bulk-enum host) correctly classified the io_uring + namespaces findings as HIGH. The D2.3 severity rules are anchored on real string outputs from this run, not synthetic guesses.

D2.2 helpers validated against synthetic Responder dump (2 NTLMv2 + 1 AS-REP + 1 TGS-REP correctly extracted; `_index.tsv` tabulates each) and 3×3 spray dry-run (9 [DRY] lines emitted, no lockout sleep triggered after the dry-run-vs-state fix).

## [v0.17.0] — 2026-05-20

**Iteration D1** of ROADMAP-001 — Windows/AD remote depth + Windows local AD scripts. First half of the bundled D (per the option-2 sequencing the operator chose); D2 (Linux CVE checks + creds enhancements) follows as v0.18.0. Per [ADR-004](docs/ADR-004-20MAY2026-ad-depth-tool-deps.md).

### Added
- **D1.0 [ADR-004](docs/ADR-004-20MAY2026-ad-depth-tool-deps.md):** records the seven AD-tool integration decisions — bloodhound-python is the BloodHound ingestor; Certipy for AD CS ESC1-11; graceful skip-when-tool-missing is mandatory (every optional integration checks `command -v` and emits a one-line install hint); never auto-escalate to admin; coerce probes are detection-only with operator-gated next-step hints; raw tool output preserved + report.py rules parse signals; Windows PS1 scripts ship standalone (not folded into Invoke-PrivEscEnum).
- **D1.4 Eight Windows AD-depth PowerShell scripts** under `windows/`:
  - `Get-LAPSPassword.ps1` — reads `ms-Mcs-AdmPwd` / `msLAPS-Password` / `msLAPS-EncryptedPassword` for every computer object the current user can see. Cleartext readable → CRITICAL; encrypted blob → HIGH (DPAPI extraction needed).
  - `Get-ADCSMisconfig.ps1` — pure-ADSI ESC1 / ESC2 / ESC4 detection. The no-deps Linux-attacker fallback for when Certipy can't reach the target box. Output format mirrors Certipy so `report.py` rules pick up either source uniformly.
  - `Get-GPPCPassword.ps1` — SYSVOL + GP-History sweep for `cpassword=` matches across the six canonical GPP XML files (Groups, Services, ScheduledTasks, DataSources, Printers, Drives). Includes the openssl decryption one-liner since the AES key is public.
  - `Get-DPAPIBlobs.ps1` — enumerates DPAPI master keys, credential vaults, Chrome/Edge/Firefox stores, RDP saved creds, Outlook PST/OST. **Paths only — no decryption attempted** (per CLAUDE.md §9 invariant 1).
  - `Get-NamedPipes.ps1` — ACL audit of every named pipe; flags pipes writable to current user / Everyone / Authenticated Users. Combined with SeImpersonate on the local user, these are impersonation primitives if the server runs as SYSTEM.
  - `Get-PrintNightmare.ps1` — CVE-2021-34527 / CVE-2021-1675 mitigation-state check across Spooler service status + `RestrictDriverInstallationToAdministrators` + `NoWarningNoElevationOnInstall` + `DisableWebPnPDownload`.
  - `Get-PetitPotamSignals.ps1` — NTLM-relay/coercion-signal audit for this host across SMB+LDAP signing, channel binding, and the four coerce-vector services (EFS / DfsR / Dfs / Spooler). Includes the operator-next-step commands for the attacker-box-side `impacket-ntlmrelayx` + `petitpotam.py` / `dfscoerce.py` / `printerbug.py` chains.
  - `Test-CoercedAuth.ps1` — local-only precondition check for PrintSpoofer / RoguePotato / GodPotato chains: SE* token-privilege ENABLED state + Spooler status + DCOM reachability + WebDAV redirector status. Never fires the actual coercion (per REVIEW-001 §2.7 design note).
  - All 8 syntax-validated via `pwsh [Parser]::ParseFile` AST check.
- **D1.6 tests/fixtures/ad-signals/** — six synthetic AD-output fixtures (certipy-esc1, bloodhound-zip, gpp-cpassword, laps-readable, delegation-uncons, pn-exploitable) anchoring the D1.5 severity-rule classifications.
- **D1.6 tests/test_ad_signals.py** — 7 stdlib-`unittest` tests across the per-fixture severity-count assertions plus end-to-end report.py CLI integration against a synthesised auto-enum layout containing the Certipy fixture.
- **D1.6 tests/smoke.sh** sections 11g (AD-signal fixture classifications) and 11h (pwsh AST parse on every windows/Get-*.ps1 + Test-CoercedAuth.ps1, skipped gracefully when pwsh absent).

### Enhanced
- **D1.1 `network/enum-smb.sh`:** PetitPotam coerce next-step hint (`_petitpotam_hint.txt`) emitted when relay-candidate hosts exist AND `--dc-ip` is set; detects whether `petitpotam.py` is on PATH and adjusts the hint accordingly. Shadow Credentials viability hint (`_shadow_creds_hint.txt`) with pywhisker + certipy follow-up commands when `--user` + `--dc-ip` are present. Neither hint auto-fires; per ADR-004 D5, coerce probes are detection-only.
- **D1.2 `network/enum-ldap.sh`:** four new sections — bloodhound-python full graph collection (Default method, no Session — opt-in via manual re-run); Certipy `find` for AD CS ESC1-11 (text+JSON output, CRITICAL on any ESC* finding); Kerberos delegation enumeration via single ldapsearch query per host (unconstrained / constrained / RBCD; HIGH on non-zero unconstrained count); pre-2000 computer-account candidate listing (workstation-trust-account UAC flag) with a "DO NOT spray without authz" hint file.
- **D1.3 `network/enum-kerberos.sh`:** bulk Kerberoast mode — `GetUserSPNs.py -request -outputfile` pulls every kerberoastable account in one pass (`_kerberoast_hashcat.txt`, hashcat -m 13100); AS-REP roast cross-linked from upstream dispatchers' user output (harvested from nxc rid-brute results + ldap users.txt + legacy `_users.lst`); writes `_asrep_hashcat.txt` (hashcat -m 18200). Both honour `ENUM_THROTTLE` from G.7.
- **D1.5 `network/report.py`:** new `_AD_DEPTH_RULES` layered on top of default + operator rules — CRITICAL on Certipy `ESC[1-11] (Vulnerable)`, `GPP cpassword=` matches, `READABLE (LAPSv1/v2)` hits, kerberoastable / AS-REP-roastable bulk-capture lines, `lsarpc anonymous reachable on DC`, PrintNightmare exploitable config, SeImpersonate + Spooler → PrintSpoofer chain viable. HIGH on `BLOODHOUND_ZIP:` signal, LAPS encrypted-blob, unconstrained / RBCD delegation, PetitPotam coerce chain availability, writable named pipes, SeImpersonate + DCOM → RoguePotato candidate.
- **D1.7 `README.md`:** Windows Scripts table extended with 8 new rows for the D1.4 PS1 files; Dependencies gains an "AD depth (D1)" bullet cross-linking to ADR-004 D3.
- **D1.7 `deps-check.sh`:** new "AD DEPTH (iteration D1 — optional)" section checks bloodhound-python, bloodhound.py, certipy, certipy-ad, petitpotam.py, and pwsh.

### Real-data validation (this release)
On a Fedora attacker box with no domain controller available, the new dispatchers all handle missing AD tooling per ADR-004 D3:
- `enum-ldap.sh` against localhost:389 with full env (`ENUM_USER`/`ENUM_PASS`/`ENUM_DOMAIN`/`ENUM_DC_IP`) → "[skip] bloodhound-python not installed" + "[skip] certipy not installed"; ldapsearch sections silently no-op (`have ldapsearch` returns false); existing impacket GetUserSPNs/GetNPUsers paths still attempt their normal work. `ldap dispatcher done.` rc=0.
- `enum-smb.sh` against localhost with `ENUM_DC_IP=10.0.0.1` → produces `_petitpotam_signal.txt` + `_shadow_creds_hint.txt` (D1.1) alongside the pre-existing artifacts; relay-candidates list empty so PetitPotam hint correctly not emitted.
- `enum-kerberos.sh` against localhost:88 → "[skip] AS-REP cross-link: no users harvested from smb/ldap dispatchers yet" (D1.3 cross-link logic works when given an empty upstream user set).
- 8 PS1 scripts: AST-parsed via `pwsh -NoProfile [Parser]::ParseFile` — all 8 OK. Functional behaviour against real AD remains engagement-time validation per ADR-004 "DOES NOT VALIDATE".

## [v0.16.0] — 2026-05-20

**Iteration K** of ROADMAP-001 — Windows side of bulk-enum, completing the post-foothold orchestration story across both platforms. Per [ADR-003](docs/ADR-003-20MAY2026-windows-bulk-enum-design.md).

A single `$OUT` directory can now hold output from BOTH `bulk-enum-linux.sh` (J, v0.15.0) and `bulk-enum-windows.py` (K). `report.py` auto-detects the mixed layout and emits ONE per-host verdict table covering the whole estate, sorted worst-first with an `os` column.

### Added
- **K.0 [ADR-003](docs/ADR-003-20MAY2026-windows-bulk-enum-design.md):** records the eight Windows-bulk-enum design decisions — WinRM-only default transport (`pywinrm`, no fallback parade); `--use-smb-admin` opt-in only, gated like the G.8 exploit flags (implementation deferred with explicit reason); output layout identical to ADR-002 D5 (filename swap only); Python orchestrator (pywinrm is canonical); `ThreadPoolExecutor` concurrency model; `--throttle` parity with the SSH side; explicit auth-method negotiation with no auto-fallback; read-only by default. Includes an explicit "WHAT THIS ADR DOES NOT VALIDATE" section flagging that the WinRM transport is unverified pre-engagement on this codebase's CI, with the operator's first-run verification checklist.
- **K.1 `network/bulk-enum-windows.py`:** Python orchestrator using `pywinrm`. Flag parity with `bulk-enum-linux.sh`: `--targets`/`--user`/`--pass`/`--port`/`--connect-timeout`/`--script`/`--output`/`--parallel` (cap 16)/`--throttle`/`--dry-run`/`--resume`. New: `--auth {ntlm,basic,kerberos,credssp}` (default ntlm), `--tls` (HTTPS:5986 with cert-validation=ignore by default), `--use-smb-admin` (per ADR-003 D2, documented but rc=126'd with the reason). Arg-validation refusals at rc=2: basic-over-HTTP (clear-text password), `--use-smb-admin` without `--pass`, `-P > 16`, pywinrm missing on a non-dry-run. IPv6 endpoint URLs bracketed correctly. Output to `$OUT/<host>/{winenum.txt, winenum.err, _meta.json, .done}`, with `run.log` + `hosts.txt` + `_summary.tsv`.
- **K.2 `network/report.py` Windows rules + mixed-OS verdicts:** `_BULK_RULES_WIN` anchored on what `windows/Invoke-PrivEscEnum.ps1` actually prints (formatting from its Section/Sub/Hit functions is stable across runs). CRITICAL: `AlwaysInstallElevated ENABLED`, `Se{Impersonate,AssignPrimaryToken,Debug,Tcb,CreateToken,LoadDriver}Privilege (ENABLED)` (literal `\(ENABLED\)` parens, no re.I — anchors away from the disabled-hint false positive), `WRITABLE BINARY:` (service binary the user can overwrite), `DefaultPassword=` (AutoLogon disclosure), membership in Domain/Enterprise/Schema Admins / Administrators / Backup/Server Operators / Hyper-V Administrators, GPP cpassword XML files, Unattend/sysprep on disk. HIGH: `Se{Backup,Restore,TakeOwnership,ManageVolume,Security}Privilege (ENABLED)`, unquoted service path with spaces under Program Files, writable PATH directory, Account/Print Operators / DnsAdmins membership, scheduled task running as SYSTEM / NETWORK SERVICE / Administrators, SCCM naa-credential path. MEDIUM: `Se*Privilege (disabled — operator can still enable)`, Remote Desktop / Remote Management Users membership, password/secret/api_key/token patterns in user files, EOL Windows (7 / Server 2008 / 2012). Layout detector (`_is_bulk_enum_dir`) and walker (`walk_findings_bulk`) extended: a subdir with `_meta.json` and EITHER `linenum.txt` OR `winenum.txt` qualifies; rules selected per file type. `_per_host_verdicts` gains an `os` field per host (`linux` / `windows` / `mixed` if both surfaces produce findings). Per-host verdict table in `report.md` / `report.html` gains an OS column.
- **K.3 fixtures + unit + smoke:**
  - `tests/fixtures/bulk-enum/win-{svc-imperson,backup-op,old-rdp}/` — three Windows fixtures anchoring CRITICAL / HIGH / MEDIUM verdict tiers. Named with lowercase hyphenated tokens to avoid colliding with the default `\bCRITICAL\b` severity rule (initial naming using "WIN-CRITICAL" was false-positiving on the host name itself — fixed during fixture testing).
  - `tests/test_bulk_enum_report.py` extended to cover all 7 fixtures + an `EXPECTED_OS` map and a regression test that disabled-hint Se* privileges do not false-positive critical.
  - `tests/test_bulk_enum_windows.py` (new): 14 stdlib-`unittest` tests covering `parse_spec`, WinRM endpoint URL construction (IPv6 bracketing, HTTPS scheme), and end-to-end orchestrator behaviour via mocked `winrm.Session.run_ps` — dry-run produces per-host dirs + run.log, `--throttle` precedence, the four arg-validation refusals, and a mocked-Session non-dry-run that writes winenum.txt + `_meta.json` correctly.
  - `tests/smoke.sh` section 11e extended for the Windows fixtures (now copies winenum.txt alongside linenum.txt); new section 11f exercises bulk-enum-windows.py --dry-run + arg-validation paths.

### Enhanced
- **K.4 top-level `README.md`:** new Windows subsection of the bulk-enum quickstart — WinRM HTTP / HTTPS / Kerberos flows, the mixed-estate single-`$OUT` pattern (one `report.py` rolls both sides up), the "Remote Management Users" auth-reach caveat, the `--use-smb-admin` documented-but-deferred status, and the explicit "WHAT THIS DOES NOT VALIDATE" callout per ADR-003. Network table gets a `bulk-enum-windows.py` row.
- **K.4 `deps-check.sh`:** pywinrm Python-package check added (same shape as the iteration-H stdlib check + defusedxml). Reports installed version or pip-install hint when absent.
- IPv6 bracketing fix in `bulk-enum-linux.sh` (caught by the advisor's review of v0.15.0): the ssh destination spec now brackets bare IPv6 hosts (`user@[2001:db8::1]` instead of `user@2001:db8::1`) — older OpenSSH otherwise treats the trailing `:N` of the v6 address as a port. Mirrors A.5's `ldap_url()` pattern from the network dispatchers.

### Real-data validation (this release)
`nmap -sV --top-ports 1000 -oA localhost-scan 127.0.0.1` → `nmap-parse.py` produced 4 open ports across http/redis/jmx categories → `auto-enum.sh --only redis,unknown` executed dispatchers end-to-end → `report.py` emitted `findings.json` (`mode=auto-enum`) + `report.md` + `report.html` from 7 findings on 127.0.0.1. `bulk-enum-linux.sh` against localhost (no local sshd) produced the expected rc=255 + populated `_meta.json` + `linenum.err` per host, and `report.py` then correctly detected bulk-enum layout (`mode=bulk-enum`).

## [v0.15.0] — 2026-05-20

**Iteration J** of ROADMAP-001 — bulk local-enum at scale (Linux). Fills the remote→local handoff gap: with low-privilege credentials on a 50-500 host network, run `linux/linenum-fast.sh` against every target in parallel via SSH stdin-pipe (no on-disk artifact on the victim) and roll up per-host CRITICAL/HIGH/MEDIUM/LOW verdicts via `report.py`. Per [ADR-002](docs/ADR-002-20MAY2026-bulk-enum-design.md).

### Added
- **J.0 [ADR-002](docs/ADR-002-20MAY2026-bulk-enum-design.md):** records the seven design decisions for bulk-enum — stdin-pipe transport vs scp (no on-disk artifact, one round-trip per host, atomic semantics, output channel = input channel); no bundler (linenum-fast.sh is already the aggregator); per-engagement `known_hosts` silo (`$OUT/known_hosts` with `StrictHostKeyChecking=accept-new`, prevents cross-engagement trust contamination); `--throttle` parity with `auto-enum.sh`; verdict logic in `report.py` not the scanner; Windows orchestration deferred to v0.16.0 (iteration K — needs ADR-003); 50-500 host scale tuning (default parallel=4, capped at 16; `BatchMode=yes`, `ConnectTimeout=10`, `ServerAliveInterval=15`).
- **J.1 `network/bulk-enum-linux.sh`:** orchestrator with full flag parity to `auto-enum.sh` (`--targets`, `--user`, `--key`, `--pass` via sshpass, `--port`, `--connect-timeout`, `--ssh-opt` (repeatable), `--parallel` capped at 16, `--throttle`, `--dry-run`, `--resume`). Per-engagement `known_hosts` written at `$OUT/known_hosts`. Each target gets `$OUT/<host>/{linenum.txt, linenum.err, _meta.json, .done}`. Run.log centralized journal + `_summary.tsv` post-run + failure tally listing each failed host. xargs-based parallel dispatch. Subshell-safe via persisted `.ssh_extra_opts` file (avoids env-var serialization gymnastics).
- **J.3 fixtures + tests:**
  - `tests/fixtures/bulk-enum/` — four synthetic per-host directories anchoring each verdict tier (web01=CRITICAL via NOPASSWD sudo; db02=CRITICAL via cap_setuid + perl SUID; app03=HIGH via writable systemd + cred-in-history; old04=MEDIUM via non-gtfobin SUID + old kernel). README documents the fixture contract.
  - `tests/test_bulk_enum_report.py` — 9 stdlib `unittest` tests: layout detection (bulk vs auto-enum vs empty), walker output shape (every required field, evidence_path relative), per-host verdict assignment (anchored on fixture expectations), end-to-end CLI run (findings.json mode + per_host worst-first ordering, report.md + report.html written, HTML contains the per-host verdict surface).
  - `tests/smoke.sh` sections **11d + 11e**: bulk-enum-linux.sh dry-run path (target-file parsing for bare host vs user@host:port, run.log + known_hosts + hosts.txt artifacts, throttle precedence operator-`-P`-wins, `-P 64` parallel-cap-at-16 refusal); report.py against fixtures (rc=0, all three outputs written, verdict per fixture, HTML contains the per-host surface).

### Enhanced
- **J.2 `network/report.py` bulk-enum mode:** auto-detects bulk-enum output layout (via `_is_bulk_enum_dir()` — checks for `_meta.json` + `linenum.txt` markers) and runs the appropriate walker. No new CLI flag; `python3 network/report.py $OUT` works for either layout. `findings.json` gains a `mode` field (`"auto-enum"` or `"bulk-enum"`) so downstream consumers can branch. In bulk mode: a `per_host` section is added with each host's `verdict` (max severity across findings) + per-tier finding counts, sorted worst-first. `report.md` and `report.html` add a "Per-host privesc verdict (bulk-enum)" table BEFORE the service breakdown (operator's first question is "which hosts should I focus on?"). New severity rules anchored on `linenum-fast.sh` output: CRITICAL on NOPASSWD / `(ALL:ALL) ALL` / dangerous capabilities (cap_setuid / cap_dac_read_search / cap_sys_admin / cap_sys_ptrace / cap_sys_module / cap_chown / cap_net_admin with `+ep`) / SUID matching one of 47 known GTFOBins / world-writable /etc/{passwd,shadow,sudoers} / `Privileged: true` container / `LD_PRELOAD` or `LD_LIBRARY_PATH` in sudo `env_keep`; HIGH on sudo version matching known-CVE ranges / `cap_net_raw`/`cap_kill`/`cap_sys_rawio` with `+ep` / writable systemd or cron / `no_root_squash` in NFS exports / `docker.sock` readable / password/api_key/token=value patterns in history; MEDIUM on non-gtfobin SUID / Linux kernel 2.x/3.x/4.x/5.x ≤ 5.15. HTML adds `.verdict-{critical,high,medium,low}` CSS classes for operator extension.
- **J.4 top-level `README.md`:** new "Bulk local-enum across many hosts (iteration J)" section — quickstart for standard / `--throttle` / `--resume` / `--dry-run` flows, output-tree layout, per-engagement `known_hosts` silo explanation, `report.py` verdict reference, Windows-on-K (v0.16.0) callout. `bulk-enum-linux.sh` row added to the Network Enumeration table. Optional dependencies updated.
- **J.4 `deps-check.sh`:** `sshpass` added under OPTIONAL (only required for `--pass` auth; ssh-agent / `--key` are preferred).

## [v0.14.0] — 2026-05-20

**Iteration G** of ROADMAP-001 — tests + hardening.

### Added
- **G.1 service banner fixtures:** `tests/fixtures/services/` — five synthetic nmap-XML fixtures exercising routing for every category in `SERVICE_MAP` (`all-services.xml`), IPv6 bracketing semantics (`ipv6-host.xml`), the documented dual-routing of openfire-admin on 9090 vs the generic http category (`openfire-vs-http-collision.xml`), closed/filtered port filtering (`closed-and-filtered.xml`), and the unknown-bucket fallthrough (`unknown-service.xml`). All synthetic — no real-target captures.
- **G.2 nmap-parse unit tests:** `tests/test_nmap_parse.py` — 19 stdlib-`unittest` tests across `SERVICE_MAP` completeness, `categorize()` precedence (the openfire/http collision regression case is explicit), full XML-routing through `dispatch()`, IPv6 bracketed-target output, closed-port exclusion, XXE / billion-laughs rejection (anchored on the A.2 hardening), the `--list-categories` / `--unknown` / `--json` CLI surface, and XML-vs-gnmap parser parity. `tests/__init__.py` added so `python3 -m unittest tests.test_nmap_parse` resolves the module.
- **G.3 gql.py pure-function tests:** `tests/test_gql_internals.py` — 28 stdlib-`unittest` tests across seven internal functions chosen for testability without HTTP: `cache_key` (the A.3 identity-expansion fix — distinct cookies / job-tokens / PATs produce distinct cache files; anon path stable), `_check_range_size` (the A.4 bound check — `LOOP_HARD_CAP` boundary, inverted-range exit code, `--allow-huge` bypass), `type_str` (NON_NULL / LIST / nested `[String!]!` reconstruction), `unwrap` (wrapper stripping), `type_by_name` (schema lookup hit / miss / None-input), `parse_kv_args` (only the first `=` splits — base64 values survive; bad input exits 2), and `build_selection` (auto-selection generation for scalar / object / unknown / required-arg-field-skipped cases). Cache dir redirected via `GQL_CACHE_DIR` so tests don't pollute `graphql/.cache/`.
- **G.4 `Makefile`:** convenience targets `test` (lint + unittest + smoke), `lint` (shellcheck), `unittest` (`unittest discover`), `smoke` (`tests/smoke.sh`), `deps-check`, `clean`, `help`. `make help` is the default target.
- **G.5 GitHub Actions CI:** `.github/workflows/ci.yml` — on push + PR to `main`. Installs Python 3.11 + shellcheck (apt) + defusedxml, then runs `make lint && make unittest && make smoke`. `fetch-tags: true` so the smoke test's `git tag` presence check works on CI.

### Enhanced
- **G.7 `--throttle` mode for sensitive environments:** `network/auto-enum.sh --throttle` sets gentle defaults for OT/legacy/lab targets — `ENUM_PARALLEL=1`, `NUCLEI_RATE=20`, `NO_FFUF=1`, `NO_NIKTO=1`, and exports `ENUM_THROTTLE=1` so dispatchers can opt in. **Operator CLI args win over `--throttle` defaults** — `--throttle -P 8` keeps `-P 8` and prints a "operator-explicit; --throttle did not override" line so the precedence is visible. `--throttle --dry-run` previews the effective environment without scanning (the smoke-test interface). `network/_lib.sh`: new helpers `throttle_delay()` (returns the inter-host pause in seconds, default 1, override via `ENUM_THROTTLE_DELAY`), `throttle_sleep()` (no-op when off), and `throttle_nmap_args()` (returns `-T2` under throttle, empty otherwise — use as `nmap $(throttle_nmap_args) ...`).
- `tests/smoke.sh`: extended with throttle-precedence stanza (11b) and write-gate dry-run assertions for every helper that gained a gate in G.8 (11c).
- `deps-check.sh`: added `shellcheck` under OPTIONAL — install via `pip install shellcheck-py` or distro package.

### Security
- **G.6 shellcheck-clean baseline:** every `.sh` file now passes `shellcheck -S warning -e SC1091`. Library files (`network/_lib.sh`, `activemq/_activemq_lib.sh`, `redis/_redis_lib.sh`, `smtp/_smtp_lib.sh`) carry a `# shellcheck shell=bash` directive so the lint scope is unambiguous. Genuine bugs fixed: `SC2069` redirect-order in `network/enum-smtp.sh` and `smtp/smtp-quickwin.sh` (the `2>&1` was before the file redirect, so stderr leaked); `SC2155` declare+assign masking return values in `network/auto-enum.sh` and `smtp/smtp-user-enum.sh`; missing `|| exit` after `cd` in `tests/smoke.sh`. Two unused colour vars (`G`, `C`) dropped from `network/autoenum-diff.sh`. Intentional state vars (`REACHABLE`, `AUTH_REQUIRED`, `REDIS_VERSION`, `RCMD_RC`) in `_redis_lib.sh` and word-splitting `$(curl_auth)` callsites in `_activemq_lib.sh`/`activemq-quickwin.sh` carry targeted `# shellcheck disable=…` directives with reasons. Three parsed-but-unwired flags (`MAX_MSGS`, `PASS_LIST`, `KEEPALIVE`) annotated with TODO reasons rather than silently dropped.
- **G.8 write-gate audit + fixes:** every exploitation helper now honours CLAUDE.md §9 invariant 1 (default = enumeration; mutation requires an explicit gate flag). Audit findings + remediation captured in [REVIEW-002](docs/REVIEW-002-20MAY2026-write-gate-audit.md). Six helpers were in violation at audit start and were fixed in this iteration:
  - `activemq/activemq-cve-2023-46604.py`: added `--exploit` gate (previously default-fired the OpenWire RCE chain on first invocation).
  - `activemq/activemq-jolokia-rce.sh`: added `--exploit` gate (previously default-loaded the MBean and ran the command).
  - `redis/redis-rce-module.sh`: added `--exploit` gate (previously default-chained CONFIG SET + REPLICAOF + MODULE LOAD).
  - `redis/redis-rce-ssh.sh`: added `--write` gate (previously default-dropped `authorized_keys` via CONFIG SET + SAVE). Gate name is `--write` rather than `--exploit` because the primitive is a file write, not an RCE.
  - `smtp/smtp-phish-send.sh`: added `--send` gate (previously default-delivered the spoofed message).
  - `smtp/smtp-smuggling-test.py`: added `--send` gate (previously default-transmitted DATA payloads including the smuggled second-message).
  Every gate prints a dry-run summary and exits 0 when omitted — no env-var bypass. Per-tool READMEs updated to show the new gate flag in the quickstart examples.

---

## [v0.13.0] — 2026-05-19

**Iteration E** of ROADMAP-001 — reporting + ergonomics.

### Added
- `network/report.py` (E.1+E.8+E.9): walks an auto-enum output tree and emits `findings.json` (machine-readable, severity-tagged), `report.md` (Markdown summary + per-host CRITICAL/HIGH detail), and `report.html` (single-file HTML, embedded CSS, no external deps). Severity heuristics anchored on the literal markers dispatchers emit. `--redact` produces a stable `<TARGET-N>` mapping for shareable output. `--severity-rules FILE` lets operators add custom JSON-line rules. Stdlib-only.
- `network/autoenum-diff.sh` (E.2): compares two output trees via their `findings.json`. Surfaces NEW hosts, NEW (host, service) pairs, NEW findings (grouped by severity), and DROPPED findings. Auto-runs `report.py --findings-only` when `findings.json` is missing in either tree. Exit 1 iff any new findings — CI-loop friendly.

### Enhanced
- `network/auto-enum.sh` (E.3+E.4+E.10): central `run.log` under `$OUTDIR` capturing timestamp + auth-presence flags + per-tool versions + per-dispatch begin/end with elapsed seconds and rc. New `--resume` flag honors per-service `.done` markers from prior runs (skip-and-log). Final summary now reports `OK=N FAIL=N SKIP=N` and lists the failed dispatchers; closing hint points at `report.py`.
- `network/_lib.sh` (E.5+E.6): new `curl_ua()`, `curl_proxy_arg()`, `curl_extra_args()` helpers. `ENUM_USER_AGENT` env honored (defaults to the same Chrome-stable string `gql.py` adopted in F.8 — consistent suite fingerprint). `ENUM_PROXY` parallels `GQL_PROXY` for explicit `-x` override; curl's native `*_PROXY` env honor remains the no-config default.
- `network/enum-http.sh`: per-URL header probe now sets `-A "$(curl_ua)"`. Other curl callsites can adopt incrementally.
- `deps-check.sh` (E.7): new `version_floor()` helper using `sort -V`. Floors applied to `nxc`, `netexec`, `kerbrute`, `nuclei`, `ffuf`, `httpx`, `redis-cli`, `mongosh`, `impacket`. Output uses `>=` (green) / `<` (red — upgrade) / `?` (unparseable, manual check).

---

## [v0.12.0] — 2026-05-19

**Iteration F** of ROADMAP-001 — GraphQL depth probes + transport-layer extras.

### Added
- `graphql/gql.py suggest` (F.1): field-name harvest from "Did you mean X?" error messages. Walks a 32-guess built-in corpus or `--corpus FILE`. Useful when introspection is disabled — many resolvers still leak schema structure via suggestion errors.
- `graphql/gql.py apq-probe` (F.3): two-step Apollo Persisted Queries enforcement check. Confirms APQ is implemented, then sends body + forged `sha256Hash` — if server returns data, persisted-query whitelist is bypassable (CRITICAL).
- `graphql/gql.py csrf-probe` (F.5): `GET /graphql?query={__typename}`. Spec-compliant servers reject (400/405). Servers that accept GET combined with cookie auth = one img/iframe away from arbitrary-query CSRF.

### Enhanced
- `graphql/gql.py call --batch N` (F.2): send the same body in a JSON array of length N. Tests batched-body gateways for per-request authz / shared-resolver state leakage.
- `graphql/gql.py call --alias-dos-check --confirm` (F.6): DETECT-ONLY latency growth measurement with N=1,2,4,…,16 aliases of `__typename`. Super-linear growth = missing alias normalization = DoS-amplification surface. Refuses to run without `--confirm`.
- `graphql/gql.py diff --directive-bypass` (F.4): wraps every field in `@skip(if:$gqlSkip)`; reference profile sets it `false`, others `true`. Detects authz checks that key on AST-presence rather than resolver-execution.
- `graphql/gql.py raw --batch N` (F.2): same batched-POST semantics for the literal-query subcommand.
- `graphql/gql.py --proxy URL` (F.7): HTTP/HTTPS/SOCKS proxy via urllib's `ProxyHandler`. Env fallback `GQL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`. SOCKS via `socks5h://` requires PySocks (not a hard dependency).
- `graphql/gql.py --user-agent / --ua-rotate / GQL_UA` (F.8): default User-Agent changed from `gql.py/1.0` to a Chrome-stable string. `--user-agent gql` re-enables legacy UA; `--user-agent <literal>` overrides; `--ua-rotate FILE` picks a random UA per request.

### Refactored
- `graphql/gql.py`: `http_post()` now uses `_opener()` (builds urllib opener with proxy + TLS context); `http_get()` added for the CSRF probe. All existing subcommands inherit the new transport behavior unchanged.
- `tests/smoke.sh`: extended with `v0.12.0` tag check + suggest/apq-probe/csrf-probe smoke against unreachable target.
- `docs/ROADMAP-001-...`: iteration F marked complete (tag v0.12.0). Overall iteration table reordered to match real ship order (A→H→B→C→F, with E/G/D/I still ⬜). Iteration I added as placeholder for the new user milestone (engineering/science facility internal-pentest protocols — industrial/OT, remote-support, license servers, BMC, hypervisor mgmt, HPC schedulers, lab data services, backup, source/CI, VPN concentrators, print). 40+ candidate protocols listed; ADR-002 required before any code lands.

---

## [v0.11.0] — 2026-05-19

**Iteration C** of ROADMAP-001 — P1 service coverage + HTTP-depth bug-class checks + SMB/SSH extras. Fifteen sub-items shipped (C.0–C.14).

### Added
- `network/enum-vnc.sh` (C.1): nmap `vnc-info`/`vnc-title`/`realvnc-auth-bypass` (CVE-2006-2369 raises CRITICAL) + raw RFB banner.
- `network/enum-jmx.sh` (C.2): nmap `rmi-dumpregistry`/`rmi-vuln-classloader` across 1099/9999/9010/11099/7199 + JRMI handshake probe. Hints document mjet/ysoserial/msf follow-ups; never auto-run.
- `network/enum-rabbitmq.sh` (C.3): mgmt-API probe with default `guest:guest` and optional `ENUM_USER`/`ENUM_PASS`. Pulls users/vhosts/exchanges/queues/connections/permissions on auth.
- `network/enum-memcached.sh` (C.4): `stats` / `stats slabs` / `stats items` / `stats sizes` / `stats settings` + cachedump enumeration of first 5 slabs × 50 keys. Memcrashed amplification warning in hints.
- `network/enum-couchdb.sh` (C.5): `_all_dbs`/`_users/_all_docs`/`_config`/`_membership`/`_node/_local/_config`. Version-range signal for CVE-2017-12635 (pre-1.7.0 / pre-2.1.1).
- `network/enum-etcd.sh` (C.6): `/version`/`/v2/keys/?recursive=true`/`/metrics` across HTTP and HTTPS. Unauth v2 keys response = full k8s control-plane secret-store read = CRITICAL.
- `network/nmap-parse.py` (C.0): four new categories — `rabbitmq` (5672/15672/5671/15671), `memcached` (11211), `couchdb` (5984/6984), `etcd` (2379/2380). `vnc` (5800/5900-5902) and `jmx` (1099/9999/9010/11099) were already present.

### Enhanced
- `network/enum-http.sh` (C.7–C.12): six new probes gated on at-least-one-live-URL —
  - **C.7 JWT extraction**: greps response bodies for the three-part `eyJ...` shape, decodes header, raises err() on `alg=none`, hit() on HS* (hashcat -m 16500). `_jwts.txt` aggregates findings.
  - **C.8 CORS misconfig**: `Origin: https://attacker.example.invalid` reflected back + `Access-Control-Allow-Credentials: true` = CRITICAL.
  - **C.9 exposed VCS/sensitive paths**: `.git/HEAD`, `.git/config`, `.svn/entries`, `.svn/wc.db`, `.hg/store`, `.DS_Store`, `.env*`, `web.config`, `wp-config.php.bak`, `config.json`, `server-status`, `server-info`.
  - **C.10 vhost-fuzz seed**: aggregates collected SAN domains into `_all_sans.txt`; hints document the ffuf command.
  - **C.11 cert+SAN collection**: `openssl s_client -showcerts` per HTTPS URL; per-URL SANs feed C.10.
  - **C.12 high-value path micro-wordlist**: `/api/swagger.json`, `/swagger.json`, `/openapi.json`, `/actuator/health`/`env`/`heapdump`, `/wp-json/wp/v2/users`, `/admin`, `/phpmyadmin/`, `/manager/html` (folded into C.9's HEAD sweep).
- `network/enum-smb.sh` (C.13): parses existing nmap-smb-vuln output for "signing enabled but not required" / "enabled: false"; aggregates relay candidates to `_relay_candidates.txt` and raises CRITICAL with host count. PetitPotam signal via rpcclient `\pipe\lsarpc` anonymous reachability when `ENUM_DC_IP` is set. Does NOT run impacket coerce tools.
- `network/enum-ssh.sh` (C.14): parses `auth_methods.txt` from phase 3 — `publickey` advertised AND no `password`/`keyboard-interactive` → `_key_only_<port>.txt` (refuse spray hint). Parses OpenSSH version from `banner.txt`; < 7.7 raises CVE-2018-15473 candidate signal.

### Refactored
- `tests/smoke.sh` extended to cover all 13 new dispatchers + `v0.11.0` tag check.
- `README.md` network table extended with six new C.0-C.6 dispatcher rows.

---

## [v0.10.0] — 2026-05-19

**Iteration B** of ROADMAP-001 — P0 service-coverage expansion. Adds 7 new network dispatchers + 2 new nmap-parse categories. Auto-routed by `auto-enum.sh` based on the new categories. Version is `v0.10.0` (not the originally-reserved `v0.3.0`) because semver requires monotonic increase and iteration H already shipped at `v0.9.0`; the roadmap's iteration→tag mapping is corrected to reflect actual chronology.

### Added
- `network/enum-postgres.sh` (B.1): trust-auth probe (no-pwd attempts as `postgres`/`admin`/`app`) + `nxc postgres` cred check + `psql` authenticated recon dumping `pg_roles` + database list + version. Hints cover post-auth escalation: `COPY ... TO PROGRAM`, untrusted PL languages, `lo_import`/`lo_export`, `dblink`.
- `network/enum-mysql.sh` (B.2): anonymous + root-no-pwd probes (`root`/`admin`/`mysql`) + `nxc mysql` + auth recon dumping `mysql.user`, `secure_file_priv`, `local_infile`, `SHOW GRANTS`. Hints cover `INTO OUTFILE`, UDF RCE, `LOAD DATA LOCAL INFILE`.
- `network/enum-mongo.sh` (B.3): `mongosh`-preferred-or-`mongo`-legacy unauthenticated `listDatabases` probe + per-database collection enumeration (capped at 10 dbs × 50 collections each). IPv6-aware connection-URI construction (per MongoDB URI spec). Auth recon via `usersInfo` + `rolesInfo`. nmap mongodb-info/mongodb-databases NSE.
- `network/enum-elastic.sh` (B.4): `curl`-based probes of `_cluster/health`, `_cluster/state`, `_cat/indices?v`, `_cat/nodes?v`, `_security/user`. Cred-leak sweep via `_search?q=password*|passwd*|secret*|api_key*|token*` with hit-count parsing. Kibana 5601 `/api/status` detection. TLS-insecure by default (engagement targets).
- `network/enum-docker.sh` (B.5): **CRITICAL when triggered.** Remote Docker daemon API probe — `/version`, `/info`, `/containers/json`, `/images/json`, `/networks`, `/volumes` against 2375 (plaintext — dangerous) and 2376 (TLS). Unauth 2375 success raises an `err()`-tagged alert with the explicit "host-equivalent RCE via `docker run -v /:/mnt --privileged`" warning text. **Never invokes `docker run`** — the operator decides.
- `network/enum-kubernetes.sh` (B.6): TLS apiserver 6443 + insecure apiserver 8080 (raises CRITICAL when present — deprecated, full cluster control) + kubelet 10250 (`/pods`, `/stats/summary`, `/metrics`, `/healthz`) + readonly kubelet 10255 + kube-proxy 10256. Optional `K8S_TOKEN` env for operator-supplied Bearer token. Captures apiserver `gitVersion`.
- `network/enum-ipmi.sh` (B.7): `nmap -sU -p623` with `ipmi-version`, `ipmi-cipher-zero`, `ipmi-brute` NSE scripts. Cipher-0 hits raise CRITICAL alert via parsed nmap output. Hints document the manual `msfconsole auxiliary/scanner/ipmi/ipmi_dumphashes` and `ipmitool sol activate` follow-ups — never auto-executes msf.
- `network/nmap-parse.py` (B.8): two new categories — `docker` (ports 2375, 2376) and `kubernetes` (6443, 8080, 10250, 10255, 10256). Both use the canonical never-match regex `a^` because nmap fingerprints them as generic `http`/`ssl/http`; the dispatchers handle product detection. Synthetic-XML routing verified: `docker → {2375}`, `kubernetes → {6443, 10250}`, no false positives on port 80.

### Refactored
- ROADMAP-001: iteration B marked complete; tag-mapping note added clarifying that iteration ordering (H before B) determined actual tag order (`v0.9.0` then `v0.10.0`), not the original aspirational mapping.

---

## [v0.9.0] — 2026-05-19

**Iteration H** of ROADMAP-001 — Jabber/XMPP pentesting tooling per [ADR-001](docs/ADR-001-19MAY2026-jabber-scope.md). Iteration H jumps the version from v0.2.0 to v0.9.0 to match the roadmap's tag plan (B–G iterations are not yet shipped; their tag slots are reserved).

### Added
- `jabber/README.md`: complete tool index + workflow for iteration H. Opens with safety summary (read first), documents the `--cleanup`-before-`--exploit` discipline for the OpenFire CVE helper, walks the typical workflow (discover → enum-jabber → user-enum → validate → optional Openfire detect/exploit/cleanup), gives the JSP plugin manifest template, and explicitly lists what the iteration does NOT do and why (no spray, no XEP-0077 conflict-probe, no Cisco UC, no bundled webshell, no Openfire persistence variant). (ROADMAP-001 H.7)
- `deps-check.sh`: new `JABBER / XMPP` section verifying `nc`, `openssl`, and the Python stdlib modules the jabber/ helpers depend on (`socket`, `ssl`, `base64`, `hashlib`, `hmac`, `urllib.request`, `xml.etree.ElementTree`). No new external deps required by iteration H. (ROADMAP-001 H.8)
- `README.md`: layout tree updated to reflect every top-level dir (was missing `graphql/`, `activemq/`, `redis/`, `smtp/`, `creds/`, `docs/`). New `jabber/` row added. New `enum-jabber.sh` row added under network dispatchers. New "Jabber / XMPP (iteration H)" section with the four jabber/ tool descriptions and ADR pointer. (ROADMAP-001 H.9)
- `jabber/jabber-admin-api-probe.sh`: read-only detection of exposed Ejabberd / Prosody admin surfaces — Ejabberd HTTP commands API at `/api/status` over ports 5280/5281/80/8088 (HEAD-classified: 200/400/405 = EXPOSED, 401/403 = auth-required, 404 = module not enabled), Prosody `mod_admin_telnet` banner probe on TCP 5582, Prosody `mod_admin_web` at `/admin/` on 5280/5281. Sends only HTTP HEAD/GET and a single TCP banner read. Per-finding evidence files written to `--out` dir; one-line INFO/HIT/MISS per probe to stdout. Wired into `enum-jabber.sh` as phase 7 (de-duped per host so multi-port targets don't re-probe). (ROADMAP-001 H.6)
- `jabber/openfire-cve-2023-32315.py`: detect / exploit / cleanup helper for the Openfire admin-console auth-bypass path traversal (per ADR-001 D3). **Default behavior (`detect`)** probes `/setup/setup-/%u002e%u002e/log.jsp`, classifies VULNERABLE / NOT_VULNERABLE / UNKNOWN based on HTTP status + admin-console markup, and prints the server version banner. **No state change.** **`exploit`** prompts the operator to type the target FQDN/IP literally (no `--yes-i-mean-it` short-circuit), then performs the DWR-based `userService.createUser` call via the bypass, then multipart-uploads an operator-supplied JSP-plugin JAR (`--plugin-jar`), then prints the resulting webshell URL and writes a log file for `cleanup`. **`cleanup`** consumes the log and reverses the changes via the legitimate admin interface. Cleanup is currently a **scaffold** with documented manual procedure — the legitimate-login-then-delete flow varies enough by Openfire version that we will not ship untested removal code. Stdlib-only (per ADR-001 D4). The full chain is written per the public CVE advisory PoC pattern and explicitly flagged REQUIRES_LAB_VERIFICATION against a known-vulnerable Openfire 4.7.4 container before any engagement use. (ROADMAP-001 H.5)
- `jabber/jabber-validate.py`: stdlib-only single-credential XMPP SASL validation (per ADR-001 D2 — no spray). Tries mechanisms in order (default: `scram-sha-256,scram-sha-1,plain`), only those advertised by the server, with the stream re-opened between each failed attempt (the SASL state machine treats `<failure/>` as terminal). SCRAM-SHA-1 and SCRAM-SHA-256 implemented inline via stdlib `hashlib.pbkdf2_hmac` + `hmac` — verified against the RFC 5802 §5 reference vector byte-for-byte. Reads password from `--password` or `JABBER_PASSWORD` env. Exit codes: 0 = AUTH_OK, 1 = AUTH_FAIL (with reason), 2 = pre-auth protocol/connect error. (ROADMAP-001 H.4)
- `jabber/jabber-user-enum.py`: stdlib-only XMPP user enumerator using the SASL PLAIN response differential (read-only — no account creation). For each candidate username, opens a stream, optionally negotiates STARTTLS, attempts SASL PLAIN with a deliberately bogus password, and classifies the `<failure/>` XML per RFC 6120 §6.5 — `<not-authorized/>` → USER_EXISTS, `<account-disabled/>` → EXISTS_DISABLED, `<credentials-expired/>` → EXISTS_EXPIRED, `<invalid-authzid/>` → INVALID_FORMAT, etc. Per-user response time recorded as a timing-side-channel fallback for servers that return identical `<not-authorized/>` for every name. Per-user JSONL output via `--out`, summary table at end. Deliberately does NOT use the XEP-0077 IBR conflict-error trick (it creates accounts when the conflict path doesn't fire — violates ADR-001 D2). (ROADMAP-001 H.3)
- `network/enum-jabber.sh`: XMPP/Jabber enumeration dispatcher, auto-routed from the `xmpp` category. Seven phases — raw TCP banner, STARTTLS feature probe + cert/SANs collection (extracts domain from cert SAN when `ENUM_XMPP_DOMAIN` not set), SASL-mechanism inventory, XEP-0077 in-band-registration advertisement check (no actual register call), server `disco#info` + `disco#items`, MUC discovery on `conference.<domain>`, BOSH/WebSocket endpoint detection on 5280/5281. All probes are read-only; tools gracefully no-op when `nc`/`openssl`/`curl` absent. Output per-host per-port under `$OUT/<ip>_<port>/`. (ROADMAP-001 H.2)
- `network/nmap-parse.py`: two new service categories — `xmpp` (ports 5222/5223/5269/5280/5281/5298/7777; service-name regex matching `xmpp`/`jabber`/`xmpp-client`/`xmpp-server`) and `openfire-admin` (ports 9090/9091, port-only — uses the canonical never-match regex `a^` so HTTP service names on other ports don't accidentally tag as openfire-admin). Verified: 9090 routes to both `http` (intentional overlap) and `openfire-admin`; port 80 does NOT route to `openfire-admin`. (ROADMAP-001 H.1)
- `docs/ADR-001-19MAY2026-jabber-scope.md`: Architecture Decision Record locking in scope for iteration H (Jabber/XMPP tooling). Records four decisions: XMPP-only surface (Cisco UC, SIP/voice, modern team chat deferred), no spray (enum + single-cred validation only), OpenFire CVE-2023-32315 ships as detect-default / `--exploit` full-chain / `--cleanup` reverse with typed-FQDN confirm, stdlib-only Python.
- `docs/ROADMAP-001-...`: iteration H placeholder replaced with full per-item plan (H.1–H.9), commit cadence, and acceptance criteria all bound to ADR-001.

### Refactored
- ROADMAP-001 iteration A marked complete (tag `v0.2.0` shipped); iteration H marked complete (all nine sub-items, this release).

---

## [v0.2.0] — 2026-05-19

**Iteration A** of ROADMAP-001 — bug fixes from REVIEW-001 §3 (5 of 10 items addressed; the remaining 5 are lower-severity tracked items not blocking later iterations) plus the governance artifacts that established the repo's commit/changelog/versioning discipline.

### Security
- `network/_lib.sh` + `network/enum-{smb,ldap,mssql,winrm,rdp}.sh`: replaced shell-string credential concatenation (`NXC_ARGS+=" -u $ENUM_USER"`) with bash arrays via new `nxc_creds_array` helper. Closes the shell-injection footgun where credentials containing quotes, spaces, or shell metacharacters could break tooling or — given a hostile credential — execute arbitrary commands. Verified end-to-end with a payload-style credential (`al'ice"bob; rm -rf /tmp/X`) — no shell expansion, no rm execution. (REVIEW-001 §3.1)
- `network/nmap-parse.py`: hardened XML parsing against XXE / billion-laughs. Prefers `defusedxml.ElementTree` when installed; falls back to stdlib with a regex pre-scan of the prolog that rejects `<!ENTITY` declarations and `SYSTEM`/`PUBLIC` external references inside DOCTYPE. Benign nmap output (which always emits `<!DOCTYPE nmaprun>` with no internal subset) parses byte-identically. Verified: `tests/fixtures/malicious_xxe.xml` and `tests/fixtures/billion_laughs.xml` rejected under both backends with clean stderr messages. (REVIEW-001 §3.2)

### Fixed
- `network/enum-ldap.sh`: IPv6 LDAP server addresses are now bracketed in the `ldap://` URL via new `ldap_url()` helper. Previously `ldap://2001:db8::1` would be parsed ambiguously by `ldapsearch`'s URL handler. v4 callsites unchanged. (REVIEW-001 §3.6)
- `graphql/gql.py`: `cache_key()` now includes `Cookie` and `JOB-TOKEN` headers (in addition to `PRIVATE-TOKEN` and `Authorization`) in the per-identity cache hash. Two cookie-based or job-token-based sessions against the same URL no longer collide on a single cache file. Anonymous calls still share a single cache entry. (REVIEW-001 §3.3)

### Enhanced
- `graphql/gql.py`: added `--insecure` / `-k` flag and `GQL_INSECURE=1` env var to bypass TLS certificate verification (mirrors `curl -k`). Default behavior (verify) unchanged. Affects every subcommand that hits the network (`introspect`, `ls`, `describe`, `call`, `loop`, `diff`, `raw`).
- `graphql/gql.py loop`: `--range` and `--gid-range` now materialize values lazily via generators. A new `LOOP_HARD_CAP = 1_000_000` ceiling refuses unbounded sweeps (the prior code would build a 10-billion-element Python list and OOM before the first request fired). Pass `--allow-huge` to override. Inverted ranges (hi < lo) now produce a clean error instead of a silent zero-iteration loop. Verified: 2M-element generator stays under 25 MB RSS for partial consumption. (REVIEW-001 §3.4)

### Added
- `network/_lib.sh`: `nxc_creds_array <ARRAY_NAME>` helper using bash namerefs (4.3+) to populate credential argv safely.
- `network/_lib.sh`: `ldap_url <ip> [port] [scheme]` helper to construct LDAP URLs that respect IPv6 bracketing.
- `tests/fixtures/malicious_xxe.xml` + `tests/fixtures/billion_laughs.xml`: regression fixtures for `nmap-parse.py` XML hardening.
- `deps-check.sh`: detect `defusedxml` Python package; lists `pip3 install defusedxml` under install hints.
- `CLAUDE.md`: agent mandates covering scope, model split (Opus plan / Sonnet execute), commit format, semver, changelog discipline, code style, safety invariants.
- `CHANGELOG.md`: this file.
- `.gitignore`: excludes `__pycache__/`, `.cache/`, `enum-results/`, `*.so`, local secrets.
- `docs/REVIEW-001-19MAY2026-thoroughness-audit.md`: collection-wide audit identifying coverage gaps and hardening opportunities.
- `docs/ROADMAP-001-19MAY2026-thoroughness-execution.md`: living, dated execution plan sequencing all REVIEW-001 items across 7 iterations (A–G) tied to MINOR release tags `v0.2.0`–`v0.8.0`. Iteration H (Jabber/XMPP/comp pentesting) added 2026-05-19 as user-requested milestone targeting `v0.9.0`.

### Refactored
- Repo re-initialized as a standalone git repository (was previously untracked).

---

## [v0.1.0] — 2026-05-19

Initial inventory of the toolkit (pre-versioning baseline). Documented in `README.md`. No formal release tag was cut; this entry exists so future releases have a numeric anchor.

### Added
- `windows/` — PowerShell privesc enumeration (services, tasks, tokens, registry, creds, AlwaysInstallElevated, writable PATH dirs) plus `enum.bat` no-PS fallback.
- `linux/` — bash privesc enumeration (SUID, sudo, capabilities, cron, containers, writable files, group, creds hunt) and `linenum-fast.sh` one-shot.
- `network/` — `nmap-parse.py` (XML/gnmap/nmap → JSON inventory), `auto-enum.sh` orchestrator, and per-service dispatchers for SMB, LDAP, Kerberos, WinRM, RDP, MSSQL, HTTP(S), SSH, FTP, SNMP, NFS, DNS, Redis, SMTP, ActiveMQ, plus an `enum-unknown.sh` catch-all.
- `graphql/gql.py` — stdlib-only GraphQL toolkit (introspect / ls / describe / call / loop / diff / raw), GitLab catalog fallback when introspection is disabled.
- `redis/` — quickwin, lateral, RCE-via-SSH-key, RCE-via-module, rogue-master scripts and Redis module source.
- `activemq/` — CVE-2023-46604 PoC, Jolokia RCE, queue dump, quickwin.
- `smtp/` — quickwin, user enumeration, relay test, SMTP smuggling test, SPF/DMARC check, phishing send.
- `creds/` — default-credentials sweep (JSON catalog of vendor defaults).
- `deps-check.sh` — verify presence of required / recommended / optional tools.
