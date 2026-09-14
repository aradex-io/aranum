# Aranum Comprehensive Quality Review — Sprint 2

Date: 13 September 2026
Baseline: `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
Sprint: Network and Host Enumeration Effectiveness
Review mode: read-only product review; only this report was added
Explicit exclusion: security of aranum itself

## Outcome

Sprint 2 found 22 reproducible or source-demonstrable effectiveness and quality issues: 11 high, 10 medium, and 1 low severity. The highest-impact themes are loss of endpoint identity in bulk and protocol dispatch, stale success markers that suppress failed reruns, multi-port evidence being overwritten and then attributed to the wrong service, implicit-TLS endpoints being treated as plaintext, and Windows/AD checks whose parsers or predicates make advertised coverage incomplete or inaccurate.

These are candidate findings for the required independent validation pass. No product code was changed during this sprint.

| Severity | Count |
|---|---:|
| High | 11 |
| Medium | 10 |
| Low | 1 |
| Total | 22 |

## Findings

### S2-01 — Dispatcher output-directory creation failures are discarded

- **Category:** Failure semantics / evidence loss
- **Severity:** High
- **File and line:** `aranumtoolkit/network/_lib.sh:23-32`; representative caller `aranumtoolkit/network/enum-x11.sh:7-21`
- **Background/details:** `parse_common_args()` runs `mkdir -p "$OUT"` but then unconditionally returns success. All 73 `enum-*.sh` dispatchers share this helper. Many dispatchers also deliberately tolerate individual probe/redirection failures, so an invalid output path can survive to the normal “done” path.
- **Impact on tool effectiveness:** A campaign can report a successful dispatcher even though no evidence could be written. This is especially damaging when `auto-enum.sh` or an external scheduler treats the dispatcher return code as the coverage result.
- **Evidence/reproduction:** With the existing regular file `README.md` used as the output and the checked-in empty `aranumtoolkit/tests/__init__.py` used as targets, `parse_common_args` printed `mkdir: ... File exists` and returned `0`. `enum-x11.sh` then failed to write `README.md/_hints.txt`, printed `x11 dispatcher done.`, and returned `0`.
- **Proposed remediation:** Make `mkdir -p "$OUT" || { err "cannot create output directory: $OUT"; return 1; }` part of the shared contract. Extend `test_dispatcher_contract.py` with a regular-file output, an unwritable parent where portable, and a failed-redirection case across the dispatcher fleet.

### S2-02 — Bulk host output identity omits user and port, causing collisions and overwrites

- **Category:** Endpoint identity / evidence integrity
- **Severity:** High
- **File and line:** `aranumtoolkit/network/bulk-enum-linux.sh:348-370`, `aranumtoolkit/network/bulk-enum-linux.sh:380-386`; `aranumtoolkit/network/bulk-enum-windows.py:143-163`, `aranumtoolkit/network/bulk-enum-windows.py:588-597`
- **Background/details:** Both bulk tools parse targets as `(user, host, port)` but derive the result directory from `host` alone. Two accounts on one host, or two SSH/WinRM endpoints on different ports, write the same `linenum.txt`/`winenum.txt`, `_meta.json`, and `.done` files. Parallel mode makes the overwrite nondeterministic.
- **Impact on tool effectiveness:** Evidence for one valid endpoint can replace another endpoint's output, metadata can describe the wrong run, and resume state cannot distinguish which account/port was successfully assessed.
- **Evidence/reproduction:** A Linux dry run with `alice@127.0.0.1:22` and `bob@127.0.0.1:2222` printed both plans pointing to the same `/127.0.0.1/linenum.txt`; the output tree contained only one host directory. The Windows implementation constructs the same host-only key before writing all per-target artifacts.
- **Proposed remediation:** Define one canonical endpoint ID containing host, port, and user (or a readable prefix plus stable hash), use it for directories, summaries, and state, and include transport where it changes semantics. Add concurrent same-host/different-user and same-host/different-port regression fixtures.

### S2-03 — A failed non-resume rerun leaves a prior `.done` marker valid

- **Category:** Resume state / false completion
- **Severity:** High
- **File and line:** `aranumtoolkit/network/bulk-enum-linux.sh:388-390`, `aranumtoolkit/network/bulk-enum-linux.sh:449-470`; `aranumtoolkit/network/bulk-enum-windows.py:601-603`, `aranumtoolkit/network/bulk-enum-windows.py:636-653`
- **Background/details:** Each bulk tool creates `.done` only on success, but neither clears an existing marker before a normal rerun. A successful run followed by a failed non-resume run therefore leaves the success marker next to evidence and metadata for the failed latest run.
- **Impact on tool effectiveness:** A later `--resume` skips an endpoint whose most recent assessment failed, creating a durable false-completion condition.
- **Evidence/reproduction:** An isolated Windows `run_one_host()` test pre-created `.done`, used `resume=False`, and returned a synthetic `REMOTE_ERR`. The observed result was `latest_status= REMOTE_ERR done_still_exists= True`. The Linux flow has the same marker lifecycle in shell.
- **Proposed remediation:** Remove or atomically invalidate `.done` at the start of every non-resume target execution; write a run-scoped state record and publish the new success marker only after evidence and metadata are complete. Test success→failure→resume for both platforms.

### S2-04 — Invalid zero or negative parallelism bypasses the intended resource contract

- **Category:** Input validation / scale control
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/bulk-enum-linux.sh:163`, `aranumtoolkit/network/bulk-enum-linux.sh:176-180`, `aranumtoolkit/network/bulk-enum-linux.sh:537-540`; `aranumtoolkit/network/bulk-enum-windows.py:728-747`, `aranumtoolkit/network/bulk-enum-windows.py:828-842`
- **Background/details:** Both tools reject only values greater than 16. GNU `xargs -P0` means unlimited parallel processes, so Linux `-P 0` defeats the stated cap. Windows accepts `-P 0` until `ThreadPoolExecutor(max_workers=0)` raises an uncaught `ValueError`; negative values behave similarly.
- **Impact on tool effectiveness:** A typo can either create an unbounded connection burst against a large network or abort Windows enumeration with a stack trace and no controlled summary.
- **Evidence/reproduction:** Linux `--dry-run -P 0` returned `0` and logged `parallel=0`; the Windows equivalent returned `1` with `ValueError: max_workers must be greater than 0` from line 834.
- **Proposed remediation:** Validate a strict integer range `1..16` before any preflight/output creation in both implementations. Add zero, negative, nonnumeric, boundary, and over-cap contract tests.

### S2-05 — Windows-over-SSH loses nondefault ports and emits malformed IPv6 destinations

- **Category:** Transport endpoint correctness
- **Severity:** High
- **File and line:** `aranumtoolkit/network/ssh-triage.sh:382-396`, `aranumtoolkit/network/ssh-triage.sh:460-479`; `aranumtoolkit/network/bulk-enum-windows.py:251-280`, `aranumtoolkit/network/bulk-enum-windows.py:508-516`
- **Background/details:** SSH triage preserves a classified target's actual port in the Windows bucket. `SSHTransport.run()`, however, ignores `target.port` and passes global `args.ssh_port` (default 22) to the argv builder. The same builder emits `user@2001:db8::1` rather than the bracketed `user@[2001:db8::1]` form already used by the Linux and key-triage tools.
- **Impact on tool effectiveness:** Windows OpenSSH on a discovered nondefault port is probed on port 22, while IPv6 Windows SSH targets can fail destination parsing. Correct OS classification therefore still leads to the wrong or unusable endpoint.
- **Evidence/reproduction:** A mocked target with `target.port=2222` recorded `forwarded_ssh_port=22`. Calling `build_ssh_argv()` for `2001:db8::1` produced `alice@2001:db8::1`. Existing transport tests use IPv4 and do not assert that `Target.port` reaches `-p`.
- **Proposed remediation:** Use `target.port` for an explicit target endpoint, reserving `--ssh-port` as the default for bare hosts. Apply the shared IPv6 bracket helper to the destination and add triage→bulk integration tests for port 2222 and bracketed IPv6.

### S2-06 — SSH evidence is host-keyed, so one port's banner is attributed to every SSH port

- **Category:** Cross-port evidence contamination / false positives and negatives
- **Severity:** High
- **File and line:** `aranumtoolkit/network/enum-ssh.sh:39-55`, `aranumtoolkit/network/enum-ssh.sh:70-100`, `aranumtoolkit/network/enum-ssh.sh:109-135`
- **Background/details:** The primary `banner.txt`, `ssh-audit.txt`, and `auth_methods.txt` artifacts are keyed only by IP. Each target port overwrites them. Later loops reread that one shared file while generating port-qualified key-only and CVE signal filenames for every target.
- **Impact on tool effectiveness:** Findings from one SSH service can be duplicated onto another port, while the overwritten service's genuine findings disappear. This directly corrupts multi-service appliances and hosts with administrative SSH on a secondary port.
- **Evidence/reproduction:** Stubbed port 2222 returned `OpenSSH_9.9p1` and port 22 returned `OpenSSH_8.9p1`. After the dispatcher completed, both `_cve-2024-6387_signal_22.txt` and `_cve-2024-6387_signal_2222.txt` claimed `OpenSSH 8.9p1`; the only remaining `banner.txt` was the port-22 banner.
- **Proposed remediation:** Make every primary artifact port-qualified (`banner_<port>.txt`, `ssh-audit_<port>.txt`, `auth_methods_<port>.txt`) and pass the current endpoint artifact through every analysis loop. Add a two-port fixture with deliberately contradictory banners/auth methods.

### S2-07 — LDAP dispatch discards discovered port and TLS semantics

- **Category:** Protocol selection / false-negative coverage
- **Severity:** High
- **File and line:** `aranumtoolkit/network/nmap-parse.py:99`; `aranumtoolkit/network/enum-ldap.sh:9-18`, `aranumtoolkit/network/enum-ldap.sh:34-62`, `aranumtoolkit/network/enum-ldap.sh:144-189`; `aranumtoolkit/network/_lib.sh:113-126`; documented port coverage at `wiki/ldap.md:1-5`, `wiki/ldap.md:104-108`
- **Background/details:** The parser routes 389, 636, 3268, and 3269 to LDAP, but the dispatcher immediately reduces targets to unique IPs. Every `ldapsearch` URL is then built without port or scheme, yielding default `ldap://host`/389. NetExec also receives host-only input. LDAPS and Global Catalog endpoint identity is lost.
- **Impact on tool effectiveness:** A 636-only/3268/3269 service is probed on 389 and can be entirely missed. On hosts exposing multiple LDAP endpoints, evidence cannot say which endpoint was assessed.
- **Evidence/reproduction:** Source tracing from `SERVICE_MAP` into `IPS=$(ips_only "$TARGETS")` shows there is no later access to the parsed port. The shared `ldap_url()` already supports `port` and `scheme`, but all dispatcher calls use only `ldap_url "$ip"`. The wiki explicitly advertises all four ports and notes LDAPS behavior.
- **Proposed remediation:** Iterate canonical `(ip, port)` targets; select `ldaps://` for 636/3269 and appropriate GC bases, and group NetExec calls by actual port/options. Preserve endpoint identity in evidence paths and add 636-only and 3268-only fixtures.

### S2-08 — IMAPS and POP3S capability commands are replaced by `/dev/null`, and TLS credentials are skipped

- **Category:** Protocol implementation / missing authenticated coverage
- **Severity:** High
- **File and line:** `aranumtoolkit/network/enum-imap.sh:25-35`, `aranumtoolkit/network/enum-imap.sh:66-75`; `aranumtoolkit/network/enum-pop3.sh:24-34`, `aranumtoolkit/network/enum-pop3.sh:65-78`
- **Background/details:** Both TLS branches pipe a capability request into `openssl s_client` and also apply `< /dev/null` to the `openssl` command. The explicit input redirection wins, so the piped `CAPABILITY`/`CAPA` and logout commands never reach the server. Both credential branches then explicitly exclude ports 993/995 rather than performing the same operation over TLS.
- **Impact on tool effectiveness:** The dominant implicit-TLS mail endpoints get, at best, a connection/certificate transcript rather than service capabilities, and supplied credentials are never validated on them.
- **Evidence/reproduction:** An `openssl` shim that reported whether it received stdin produced `NO_STDIN` in `banner_993.txt`; the piped IMAP command was absent. POP3 has the identical redirection shape. Static tracing shows `[ "$port" != "993" ]` and `[ "$port" != "995" ]` gate out TLS authentication.
- **Proposed remediation:** Remove `< /dev/null`, use `printf ... | openssl s_client -quiet ...`, bound shutdown with timeout, and implement the tagged/auth reply parsers over the same TLS stream. Add transcript fixtures proving the commands are sent and TLS success/failure is classified.

### S2-09 — POP3 authentication reports success when `PASS` was rejected

- **Category:** Authentication-result parsing / false positive
- **Severity:** High
- **File and line:** `aranumtoolkit/network/enum-pop3.sh:65-76`
- **Background/details:** The implementation comments that the second `+OK` proves `PASS`, but it merely counts all `+OK` lines in the whole conversation. A normal greeting, accepted `USER`, or successful `QUIT` can satisfy the count even when the password response is `-ERR`.
- **Impact on tool effectiveness:** Invalid credentials are promoted as confirmed access, wasting follow-up effort and contaminating credential reuse decisions.
- **Evidence/reproduction:** A safe `nc` transcript of `+OK ready`, `+OK user accepted`, `-ERR invalid password`, `+OK bye` caused the dispatcher to print `POP3 AUTH SUCCESS` because the global count was three.
- **Proposed remediation:** Parse replies sequentially and require the reply immediately corresponding to `PASS` to be `+OK`; preferably stop before `STAT` on failure. Add positive, greeting+USER+PASS-fail, and multiline CAPA transcript tests.

### S2-10 — SMTPS 465 and implicit FTPS 990 are routed but probed as plaintext

- **Category:** Protocol mode mismatch / feature gap
- **Severity:** Medium
- **File and line:** routing at `aranumtoolkit/network/nmap-parse.py:109-110`; `aranumtoolkit/network/enum-smtp.sh:17-37`, `aranumtoolkit/network/enum-smtp.sh:52-57`; `aranumtoolkit/network/enum-ftp.sh:9-19`, `aranumtoolkit/network/enum-ftp.sh:31-36`
- **Background/details:** Port 465 requires TLS before SMTP dialogue, but the dispatcher sends all banner, EHLO, VRFY, and relay probes with raw `nc` and attempts `-starttls smtp` only after plaintext EHLO advertises STARTTLS. FTP 990 likewise uses raw `/dev/tcp` and `ftp://`; its Nmap follow-up is hard-coded to port 21.
- **Impact on tool effectiveness:** Aranum correctly identifies these endpoints for dispatch but first-party probes cannot speak their protocol mode, yielding empty/misleading evidence and missed capability/authentication checks.
- **Evidence/reproduction:** The mismatch is direct in the execution path: both ports exist in `SERVICE_MAP`, while neither dispatcher has an implicit-TLS branch and FTP's Nmap line is `-p21`. The authorized-lab evidence used for S2-12 includes a real `BBL-P003 FTP Server` on 990, showing this is not a theoretical port tuple.
- **Proposed remediation:** Select transport from the actual endpoint: `openssl s_client`/TLS-capable client for 465 and 990, STARTTLS only for upgrade ports, and always pass the discovered port to Nmap. Add implicit-TLS transcript fixtures.

### S2-11 — Port-only X11 classification overrides incompatible detected services

- **Category:** Service classification / false routing
- **Severity:** Medium
- **File and line:** `aranumtoolkit/network/nmap-parse.py:95-96`, `aranumtoolkit/network/nmap-parse.py:149`, `aranumtoolkit/network/nmap-parse.py:233-241`; downstream behavior at `aranumtoolkit/network/enum-x11.sh:10-18`
- **Background/details:** `categorize()` uses unconditional port-or-service matching. Every open port 6000–6009 becomes X11 even when Nmap identifies an incompatible service such as TLS. The X11 dispatcher then runs `x11-access` and derives a display number solely from the port.
- **Impact on tool effectiveness:** Non-X11 services are removed from unknown-service triage and receive a guaranteed-incompatible probe. Genuine product identification opportunities are lost while campaign coverage appears service-specific.
- **Evidence/reproduction:** Importing the current parser produced `categorize(6000, 'ssl') == ['x11']`, `categorize(6000, 'unknown') == ['x11']`, and `categorize(6000, 'x11') == ['x11']`. Authorized-lab observation confirms a TLS/file-transfer service, not X11, on port 6000 of a Bambu-family device.
- **Proposed remediation:** Give positive, incompatible service evidence precedence over port heuristics. Route an uncertain port match to protocol confirmation/unknown until an X11 handshake succeeds; only then compute/display X11 findings. Add a port-6000 `ssl` negative fixture and a real X11 positive fixture.

### S2-12 — Bambu vendor services have no bounded fingerprint or compatible triage path

- **Category:** Product coverage gap / emerging enterprise device identification
- **Severity:** Medium
- **File and line:** absent from `aranumtoolkit/network/nmap-parse.py:95-230` and the `aranumtoolkit/network/enum-*.sh` fleet; conflicting generic routes at `aranumtoolkit/network/nmap-parse.py:106`, `aranumtoolkit/network/nmap-parse.py:109`, `aranumtoolkit/network/nmap-parse.py:126`, `aranumtoolkit/network/nmap-parse.py:149`
- **Background/details:** The repository has no Bambu/`BBL-P003`/`a5a5` fingerprint. Authorized-lab evidence supplied for this review observed the service tuple 990/3000/3002/6000/8883: 990 bannered `BBL-P003 FTP Server`, 3000 used `a5 a5` length-framed JSON rather than HTTP, 6000 was TLS/file transfer rather than X11, and TLS organization/banner evidence identified BBL. A port-only fingerprint would be unsafe, but the combined tuple plus banner/certificate evidence is discriminating.
- **Impact on tool effectiveness:** A recognizable managed/IoT printer family is split across incompatible generic dispatchers, so the operator gets probe failures rather than a coherent device identity and targeted follow-up.
- **Evidence/reproduction:** `rg -ni 'bambu|bbl-p003|a5a5|bambu lab'` returned no product support in the repository. The lab observations are explicitly product evidence, not a generic inference from ports.
- **Proposed remediation:** Add a bounded identification rule requiring multiple independent signals (for example the characteristic endpoint tuple plus `BBL-P003` FTP banner or BBL TLS certificate organization). Emit one vendor-device finding and suppress HTTP/X11 probes when protocol confirmation contradicts them. Keep 3000 payload handling identification-only until a documented safe protocol parser exists.

### S2-13 — Writable apt files are printed but not counted

- **Category:** Standalone output correctness
- **Severity:** Low
- **File and line:** `standalones/linux/apt-source-check.sh:21-37`, contradictory summary at `standalones/linux/apt-source-check.sh:52`
- **Background/details:** Writable files are enumerated through a pipeline into `while read`; Bash executes that loop in a subshell. Its `hits=$((hits + 1))` updates are lost. When files are the only hits, the script prints each positive and then says there is no writable apt surface.
- **Impact on tool effectiveness:** The same standalone output can contain mutually contradictory assessment results, undermining parsers and operator trust.
- **Evidence/reproduction:** ShellCheck emitted SC2030 at line 33 and SC2031 at the next parent-scope use. The variable flow confirms the counter remains zero after the pipeline.
- **Proposed remediation:** Feed the loop with process substitution (`while ...; done < <(find ...)`) or collect/count results in the parent shell. Add a temporary-tree fixture with a writable file and no writable directory.

### S2-14 — Windows service executable parsing truncates valid paths and checks the wrong unquoted candidates

- **Category:** Host-enumeration detection logic / false negatives
- **Severity:** High
- **File and line:** `standalones/windows/Get-ServiceMisconfig.ps1:35-43`; `standalones/windows/Get-UnquotedServices.ps1:25-45`; duplicated aggregate logic at `standalones/windows/Invoke-PrivEscEnum.ps1:90-119`; advertised behavior at `wiki/windows.md:136-140`
- **Background/details:** For a quoted path, `Get-ServiceMisconfig.ps1` first extracts the quoted executable correctly and then immediately applies a second whitespace regex, truncating `C:\Program Files\...` to `C:\Program`. The aggregate duplicates this expression. `Get-UnquotedServices.ps1` similarly sets `$exe` to the first whitespace token and walks only that truncated string, so it never constructs the loader candidates described in its own header (`C:\Program.exe`, `C:\Program Files\Foo.exe`) or tests their containing directories correctly.
- **Impact on tool effectiveness:** Writable binaries in the standard `Program Files` layout are missed, and unquoted-path output lacks the promised actionable writeability determination.
- **Evidence/reproduction:** Applying the chained expression to `"C:\Program Files\Vendor\svc.exe" -d` yields `C:\Program`, which normally fails `Test-Path`; for `C:\Program Files\Foo Bar\app.exe -s`, `$exe` is also only `C:\Program`.
- **Proposed remediation:** Implement and share a Windows-aware service command-line parser: quoted executable ends at the closing quote; unquoted executable resolution should consider progressive `.exe` candidates and arguments. Separately enumerate the Windows loader's unquoted prefix candidates and test ACLs/creatability at their parents. Add Pester fixtures for quoted, unquoted, environment-variable, and no-argument paths.

### S2-15 — Interesting-file credential search uses one literal pipe-delimited string

- **Category:** Host-enumeration predicate / false negatives
- **Severity:** Medium
- **File and line:** `standalones/windows/Invoke-PrivEscEnum.ps1:208-217`
- **Background/details:** `Select-String` is given the regex-shaped pattern `password|passwd|secret|api[_-]?key|token=` together with `-SimpleMatch`. In SimpleMatch mode the pipe and character syntax are literal, so a file containing `password=...` does not match unless it contains that entire combined string.
- **Impact on tool effectiveness:** A major section of the flagship Windows sweep silently finds almost none of the credential material it claims to search for.
- **Evidence/reproduction:** This follows directly from the PowerShell call contract: `-SimpleMatch` disables regular expressions while only one `-Pattern` string is supplied. There is no alternative array of literals.
- **Proposed remediation:** Remove `-SimpleMatch` and use a tested regex, or provide an explicit array of literal patterns if regex behavior is not desired. Add positive/negative Pester fixtures for every advertised term.

### S2-16 — The aggregate SYSVOL path contains the literal text `$env:USERDOMAIN`

- **Category:** Path construction / dead enumeration branch
- **Severity:** Medium
- **File and line:** `standalones/windows/Invoke-PrivEscEnum.ps1:160-165`; working standalone comparison at `standalones/windows/Get-GPPCPassword.ps1:27-30`
- **Background/details:** The aggregate script puts `'\\$env:USERDOMAIN\SYSVOL'` in a single-quoted PowerShell string, which prevents environment-variable interpolation. `Test-Path` therefore checks a server literally named `$env:USERDOMAIN`. The dedicated GPP standalone uses an interpolated path and does not share this mistake.
- **Impact on tool effectiveness:** The default bulk Windows script misses domain SYSVOL GPP files even when they are reachable, despite presenting the section as executed.
- **Evidence/reproduction:** PowerShell single-quote semantics make the path literal; source comparison with the dedicated helper confirms the intended value was dynamic.
- **Proposed remediation:** Use an interpolated UNC based on a validated DNS domain/DC, prefer `$env:USERDNSDOMAIN` or discovered RootDSE context over the NetBIOS domain where appropriate, and report an explicit skip reason when no domain is available. Add joined/unjoined-host fixtures.

### S2-17 — AD CS ESC1 is flagged without proving the caller can enroll

- **Category:** Detection correctness / false positive
- **Severity:** High
- **File and line:** stated predicate at `standalones/windows/Get-ADCSMisconfig.ps1:7-13`; ACL collection at `standalones/windows/Get-ADCSMisconfig.ps1:85-90`; ESC1 decision at `standalones/windows/Get-ADCSMisconfig.ps1:92-97`; broad enrollment used only for ESC2 at `standalones/windows/Get-ADCSMisconfig.ps1:98-105`
- **Background/details:** The script's own definition requires Authenticated Users or another broad principal to have enrollment rights. It collects the DACL, but the ESC1 condition checks only subject-supply, EKU, RA signature, and manager approval. `$broadEnroll` is computed later and applied only to ESC2. A template restricted to administrators can therefore be labeled `ESC1 (Vulnerable)`.
- **Impact on tool effectiveness:** High-priority AD escalation results can be false, sending operators toward a path unavailable to low-privileged principals. This issue was previously recorded in `aranumtoolkit/docs/REVIEW-004-20JUL2026-fable5-toolkit-audit.md:305-310`; approval and per-template exception handling were improved, but enrollment-principal validation remains unresolved.
- **Evidence/reproduction:** The ESC1 `if` expression at lines 94-97 contains no ACL/enrollment variable, despite the required predicate at lines 8-10 and the available `$acl` data.
- **Proposed remediation:** Resolve enrollment extended rights with object-type GUID and principal/SID semantics, calculate effective low-privileged enrollment eligibility, require it in ESC1/ESC2, and consider whether the template is published on an accessible CA. Add admin-only, broad-enroll, manager-approval, and object-specific deny/allow fixtures.

### S2-18 — Windows documentation promises ESC1–ESC8 while the helper implements only ESC1/2/4

- **Category:** Feature gap / documentation accuracy
- **Severity:** Medium
- **File and line:** `standalones/windows/Get-ADCSMisconfig.ps1:1-17`, `standalones/windows/Get-ADCSMisconfig.ps1:31`, `standalones/windows/Get-ADCSMisconfig.ps1:92-125`; claim at `wiki/windows.md:136-150`
- **Background/details:** The script explicitly describes and reports only ESC1, ESC2, and ESC4. The Windows operator wiki calls it an “ADCS ESC1–ESC8” helper. The LDAP-side Certipy path offers wider coverage, but that does not make the host-local helper fulfill the documented contract.
- **Impact on tool effectiveness:** Operators running host-local/bulk Windows enumeration may believe ESC3/5/6/7/8 were assessed when they were not, obscuring a material coverage boundary.
- **Evidence/reproduction:** The only counters and output labels are `$esc1_hits`, `$esc2_hits`, and `$esc4_hits`; no ESC3/5/6/7/8 branch exists. `wiki/windows.md:149` nevertheless promises ESC1–ESC8.
- **Proposed remediation:** Immediately correct the wiki and bulk coverage description to ESC1/2/4. Either extend the helper with well-tested CA/template predicates or explicitly direct operators to the Certipy LDAP path for broader coverage; never infer completion from helper presence.

### S2-19 — OT `--max-parallel` is clamped and logged but never used

- **Category:** Scale feature gap / option contract
- **Severity:** Medium
- **File and line:** `standalones/ot/ot-enum.sh:34-40`, `standalones/ot/ot-enum.sh:48-77`, `standalones/ot/ot-enum.sh:113-128`; representative dispatcher `standalones/ot/enum-modbus.sh:23-61`; contract at `standalones/ot/README.md:20-24`
- **Background/details:** The orchestrator accepts/clamps `--max-parallel`, exports `OT_MAX_PARALLEL` to each dispatcher, and says dispatchers provide internal host parallelism. All seven dispatchers use a serial `while read ...; probe; ot_throttle_sleep; done` loop and none reads `OT_MAX_PARALLEL`.
- **Impact on tool effectiveness:** Large hand-selected inventories run fully serial regardless of the requested safe concurrency. The displayed configuration and docs imply a performance control that has no effect.
- **Evidence/reproduction:** `rg -n 'OT_MAX_PARALLEL' standalones/ot/*.sh` finds consumers only in `_lib.sh`/`ot-enum.sh`; every protocol dispatcher has one serial target loop. The option changes logging but not scheduling.
- **Proposed remediation:** Either implement a bounded worker queue that maintains the non-overridable pacing semantics, or remove the option and document serial execution. Add a shim/timing test proving maximum simultaneous probes and the 500 ms floor.

### S2-20 — SSH key attempt caps are consumed by invalid or unusable encrypted keys

- **Category:** Authentication planning / false-negative coverage
- **Severity:** Medium
- **File and line:** inventory state at `aranumtoolkit/network/ssh-key-triage.py:133-182`, `aranumtoolkit/network/ssh-key-triage.py:191-245`; probe argv at `aranumtoolkit/network/ssh-key-triage.py:254-304`; plan construction at `aranumtoolkit/network/ssh-key-triage.py:552-571`
- **Background/details:** The plan includes every inventory path and applies `--max-per-user` before checking `error`, encryption, or probeability. A locked/invalid key early in sorted order consumes the cap and can exclude a later valid key. Even when `--passwords` proves an encrypted key can be decrypted during inventory, the network probe still passes the original encrypted file to `ssh -i` under `BatchMode=yes`; the discovered passphrase is not made usable by an agent or temporary decrypted identity.
- **Impact on tool effectiveness:** The lockout-hygiene cap can prevent known-valid candidate keys from ever being tested, while planned probes include keys that cannot succeed noninteractively.
- **Evidence/reproduction:** `keys_for = [i["path"] for i in inventory]` is sliced directly; none of `error`, `encrypted`, or `unlocked` participates. `build_probe_argv()` receives only the path and has no passphrase/decrypted-key channel.
- **Proposed remediation:** Define an explicit probeable-key set, record skipped reasons, and apply the cap after filtering. For unlocked encrypted keys, use a protected ephemeral agent/decrypted representation with strict cleanup, or clearly classify them inventory-only instead of spending an attempt. Add an invalid-first/valid-second cap regression.

### S2-21 — `authorized-pairs.txt` is not consumable by the bulk tool it names

- **Category:** Workflow integration / output contract
- **Severity:** High
- **File and line:** promise at `aranumtoolkit/network/ssh-key-triage.py:25-27`; writer at `aranumtoolkit/network/ssh-key-triage.py:454-467`; bulk target grammar at `aranumtoolkit/network/bulk-enum-linux.sh:85-99`, `aranumtoolkit/network/bulk-enum-linux.sh:348-370`; design claim at `aranumtoolkit/docs/ADR-006-28JUL2026-bulk-enum-overhaul.md:211-224`
- **Background/details:** Key triage writes CSV-like `key,user,host` rows and labels them “ready to feed bulk-enum-linux.sh.” The bulk tool accepts only `host`, `host:port`, or `user@host[:port]`, with one global `--key`; it has no per-row key field or CSV parser. Feeding the file directly treats the whole comma-separated row as a hostname.
- **Impact on tool effectiveness:** The core “which key works where → enumerate those pairs” workflow stops at a non-executable artifact, forcing manual regrouping and risking the wrong key/host pairing.
- **Evidence/reproduction:** The writer produces `/keys/id_ed25519,root,127.0.0.1`; `parse_spec()` sees no `@`, assigns the default user, and retains the comma-filled string as the host. Tests verify only that three comma-separated fields exist, not that bulk enumeration can consume them.
- **Proposed remediation:** Either add a documented per-line manifest schema to the bulk tool (key, user, host, port) or emit grouped target files plus exact commands per key. Add an end-to-end key-triage→bulk dry-run test asserting the real host, user, port, and key argv.

### S2-22 — SSH key “inter-attempt” throttling sleeps concurrently and releases a burst

- **Category:** Rate control / behavioral contract
- **Severity:** Medium
- **File and line:** contract at `aranumtoolkit/network/ssh-key-triage.py:20-23`; per-worker sleep at `aranumtoolkit/network/ssh-key-triage.py:323-337`; concurrent submission at `aranumtoolkit/network/ssh-key-triage.py:609-627`
- **Background/details:** The module describes `--throttle` as an inter-attempt delay. Instead, each worker sleeps independently at the start of `probe_one()`. With parallelism greater than one, all workers sleep together and then initiate connections at approximately the same time.
- **Impact on tool effectiveness:** Operators cannot reliably pace authentication attempts; the option delays the initial batch but does not control the rate between attempts as documented.
- **Evidence/reproduction:** All futures are submitted immediately, and the only throttle call is inside each concurrent worker before its own command. There is no shared timestamp, token bucket, or serialized submission interval.
- **Proposed remediation:** Rate-limit task submission or use a thread-safe global limiter that enforces a minimum start interval independently of worker count. Add a timestamping SSH shim test with `parallel > 1` and assert adjacent attempt start times.

## Coverage

The sprint traced discovery input through category selection, target serialization, protocol/transport choice, authentication, evidence naming, standalone collection, and the focused test paths.

| Surface | Read/checked |
|---|---|
| Network dispatchers | All 73 `aranumtoolkit/network/enum-*.sh` files, plus shared `_lib.sh` |
| Discovery/parser integration | `nmap-parse.py`, service fixtures, parser and dispatcher-contract tests |
| Bulk/SSH triage | `bulk-enum-linux.sh`, `bulk-enum-windows.py`, `ssh-triage.sh`, `ssh-key-triage.py`, corresponding tests and ADR-006 |
| Linux standalones | All 19 files under `standalones/linux/` |
| Windows standalones | All 18 files under `standalones/windows/` |
| OT standalones | All 10 files under `standalones/ot/`, including README and shared helper |
| Operator docs | All 76 `wiki/` files included in structural validation; service-corresponding pages were reviewed against implementation, with focused line-by-line review of LDAP, SSH, IMAP, POP3, SMTP, FTP, X11, unknown services, Linux, Windows, Docker, and OT guidance |
| Focused automated tests | Nine focused test modules covering bulk Linux/Windows, transports, SSH triage/key triage, Nmap parsing, dispatcher contracts, new dispatchers, and wiki rendering |

## Commands and results

| Command/check | Result |
|---|---|
| `git rev-parse HEAD` | `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` |
| Focused Pytest command over the nine Sprint 2 modules | `139 passed, 4 skipped, 53 subtests passed in 17.52s` |
| `bash -n` over all network enum scripts, bulk Linux, SSH triage, Linux standalones, and OT standalones | Passed |
| `python3 -m py_compile` on bulk Windows and SSH key triage | Passed |
| PowerShell parser over all `standalones/windows/*.ps1` | `PowerShell parse OK` |
| `PYENV_VERSION=vr shellcheck -x ...` over reviewed shell surfaces | Returned 1 with existing diagnostics; SC2030/SC2031 directly confirmed S2-13. Most remaining messages were dynamic-source SC1091, style notes, or already intentional word splitting |
| `python3` import of `nmap-parse.py`; `categorize(6000, service)` | `ssl`, `unknown`, and `x11` each returned `['x11']` |
| Output-path failure probe with `enum-x11.sh` | `mkdir` and redirection failed; dispatcher still logged done and returned 0 |
| Stubbed two-port `enum-ssh.sh` run | Port 22's 8.9 banner overwrote 2222's 9.9 banner; both port findings claimed 8.9 |
| Stubbed POP3 conversation | `PASS` returned `-ERR`; dispatcher still emitted `POP3 AUTH SUCCESS` |
| Stubbed IMAPS input capture | `banner_993.txt` contained `NO_STDIN`; CAPABILITY request did not reach `openssl` |
| Bulk endpoint dry run | Two users/ports on one IP resolved to one output directory |
| Bulk Windows stale-marker unit probe | Latest status `REMOTE_ERR`; old `.done` remained present |
| Parallel validation probes | Linux `-P 0` returned 0 as unlimited xargs; Windows raised uncaught `ValueError` |
| Repository product search | No Bambu/`BBL-P003`/`a5a5` fingerprint or dispatcher support found |

## Test gaps exposed by the findings

The focused suite is healthy but concentrated on happy-path contracts and mocked single endpoints. The remediation sprint should add cross-component regressions for:

1. output-path creation/redirection failure and propagated nonzero status;
2. same-host multi-user/multi-port evidence identity and concurrent writes;
3. success→failed rerun→resume state transitions;
4. nondefault-port and IPv6 SSH triage into Windows bulk execution;
5. contradictory multi-port SSH banners and auth methods;
6. LDAPS/Global Catalog endpoint preservation;
7. implicit-TLS protocol transcripts and protocol-state-aware authentication parsing;
8. Windows service command-line parsing, AD CS effective enrollment, and aggregate-script predicates;
9. key-triage output consumption, probeable-key filtering, and real inter-attempt timing; and
10. OT concurrency semantics with the hard safety floor intact.

## Scope notes

- The review assessed whether aranum accurately identifies, probes, records, and reports authorized network/host evidence. It did not assess hardening or exploitability of aranum itself.
- Reproduction used local fixtures, static analysis, import-level function calls, and command shims. No unapproved live-network scanning or write-side OT action was performed.
- S2-11 and S2-12 distinguish generic code evidence from the supplied authorized-lab observation. The false X11 route is reproducible solely from the current parser; the vendor gap is proposed only with a bounded multi-signal fingerprint, never a port-only rule.
