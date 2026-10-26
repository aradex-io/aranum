closed: 7, partial: 3, open: 0, new: 1

### R1 — CLOSED

Literal script blocks are generated with a blank line after each block at [bulk-enum-windows.py:624](/srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py:624). `test_bulk_windows_payload_shape_and_ad_flag` pins the exact framing at [test_host_posture.py:760](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:760), while `test_bulk_windows_payload_parses_under_51_rules_and_runs_over_stdin` executes both blocks over stdin under FullLanguage and ConstrainedLanguage at [test_host_posture.py:780](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:780).

### R2 — PARTIAL

The normal policy cases and registry-error propagation are fixed at [Invoke-HostPosture.ps1:220](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:220) and [Invoke-HostPosture.ps1:764](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:764). KB severity, semantics, tests, and guidance were updated at [finding-kb.json:8025](/srv/share/dev/aranum/aranumtoolkit/network/finding-kb.json:8025). `test_windows_ldap_signing_grades_both_policies` pins null/0/1/2 cases at [test_host_posture.py:317](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:317).

Failing scenario: the unconditional fallback at line 240 reports `PASS` for any CBT value other than null, 0, or 1. Directly reproduced: `Resolve-LdapSigningStatus 2 3` and `Resolve-LdapSigningStatus 2 -1` both return `PASS`, contradicting “PASS only when CBT=2.” Require `[int]$ChannelBinding -eq 2`; treat other values as ERR or FAIL, and add invalid-value fixtures.

### R3 — CLOSED

Posture identities are collected from domain, realm, observer, trust, canonical-domain, and quarantined text at [report.py:2239](/srv/share/dev/aranum/aranumtoolkit/network/report.py:2239). Host matching and token lookup are case-insensitive at [report.py:930](/srv/share/dev/aranum/aranumtoolkit/network/report.py:930), and quarantined text is replaced at [report.py:2817](/srv/share/dev/aranum/aranumtoolkit/network/report.py:2817). `test_redact_covers_every_posture_identity` pins all requested identity sources and output formats at [test_host_posture.py:621](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:621).

A collateral redactor regression is reported as NEW-1.

### R4 — CLOSED

`Get-RegValue` now returns null only for a missing key/property and propagates other exceptions at [Invoke-HostPosture.ps1:90](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:90). The two RDP checks preserve a shared read error and rethrow inside their check blocks at [Invoke-HostPosture.ps1:487](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:487).

The distinction is pinned by `test_windows_get_regvalue_separates_absent_from_error` at [test_host_posture.py:333](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:333), and the end-to-end no-false-PASS behavior by `test_windows_registry_access_denied_never_grades_pass` at [test_host_posture.py:352](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:352).

### R5 — PARTIAL

RootDSE now uses `Invoke-LdapSearch` with Base scope and the configured timeout at [Invoke-HostPosture.ps1:284](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:284), threaded from [Invoke-HostPosture.ps1:652](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:652). `test_windows_rootdse_uses_the_bounded_searcher` pins routing and argument propagation at [test_host_posture.py:375](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:375).

Failing scenario: `DirectoryEntry` creation/binding and `FindAll()` remain synchronous at [Invoke-HostPosture.ps1:262](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:262). `ClientTimeout` and `ServerTimeLimit` do not provide an independently enforced wall-clock bound around DC location/ADSI binding. A blackholed locator or bind can therefore exceed `LdapTimeoutSeconds` before any AD result is emitted. The test mocks `Invoke-LdapSearch`, so it does not pin this behavior. Deferral to a Windows lab is reasonable for S5, but it does not close R5.

### R6 — CLOSED

The fallback domain/observer tag is created before both early-exit branches and replaced after RootDSE succeeds at [Invoke-HostPosture.ps1:642](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:642). `test_windows_ad_lines_are_domain_tagged_before_discovery` pins both CLM-NA and RootDSE-ERR output and verifies parser aggregation into a domain at [test_host_posture.py:397](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:397).

### R7 — CLOSED

Scope-aware target generation and labeling are centralized at [report-dashboard.py:217](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:217), used by finding lists and JSON export, and matched by the domain-section anchor at [report-dashboard.py:2783](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2783). `test_domain_findings_link_to_the_domain_not_a_host_page` checks every affected output and the anchor target at [test_dashboard_posture.py:128](/srv/share/dev/aranum/aranumtoolkit/tests/test_dashboard_posture.py:128).

### R8 — CLOSED

The dashboard normalizes host, check, domain, and observer records at the model boundary at [report-dashboard.py:2528](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2528), invoked during model construction at [report-dashboard.py:539](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:539). Malformed records are dropped and unknown statuses become ERR. `test_malformed_posture_structures_do_not_crash` pins malformed siblings, unknown statuses, observers, domains, and all relevant renderers at [test_dashboard_posture.py:174](/srv/share/dev/aranum/aranumtoolkit/tests/test_dashboard_posture.py:174).

### R9 — PARTIAL

The new test configures all three compatibility rules with two PowerShell 5.1 profiles and a three-construct canary at [test_host_posture.py:444](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:444). It passed locally with PSScriptAnalyzer 1.25. The CLM payload execution is also pinned at [test_host_posture.py:780](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:780).

Failing scenario: when PSScriptAnalyzer is absent, the compatibility test explicitly skips at [test_host_posture.py:478](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:478). A PS7-only command parameter such as `Get-Content -AsByteStream` or a PS7-only type can then pass the remaining syntax deny-list. The explicitly required AST extraction is also still absent; helper tests dot-source the entire collector through `_lib()` instead. Make PSScriptAnalyzer 1.25 a required test dependency/fail when missing, and AST-extract the named helpers for their fixture tests.

### R10 — CLOSED

The renderer uses quote-aware escaping at [report-dashboard.py:202](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:202), including posture content at [report-dashboard.py:2642](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2642), observer title attributes at [report-dashboard.py:2771](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2771), and quarantine output at [report-dashboard.py:2801](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2801). `test_hostile_strings_are_escaped_everywhere` scans every generated HTML page and pins content, attribute, domain/quarantine, and observer cases at [test_dashboard_posture.py:219](/srv/share/dev/aranum/aranumtoolkit/tests/test_dashboard_posture.py:219).

### NEW-1 — low

File: [report.py:939](/srv/share/dev/aranum/aranumtoolkit/network/report.py:939)

Failing scenario: the new case-folding assigns `key = m.group(0).lower()` and returns that folded value when a colon-delimited token fails IPv6 validation. Consequently, `Redactor(True)("AA:BB:CC:DD:EE:FF")` returns `aa:bb:cc:dd:ee:ff`. Redacted reports now silently alter uppercase MAC/evidence tokens that are deliberately supposed to remain untouched. The existing regression test only uses an already-lowercase MAC.

Fix: retain both `raw = m.group(0)` and `key = raw.casefold()`. Use `key` for host lookup/token mapping, but return `raw` when the bare-IPv6 candidate is invalid and not a known host. Add an uppercase-MAC assertion.

Verification run: the focused posture/dashboard suite passed, `48 passed in 42.38s`.