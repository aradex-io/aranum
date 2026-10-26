closed: 2, partial: 2, open: 0, new: 0

### R2 — PARTIAL

The original LDAP defect is fixed: both values are range-checked before the sole PASS at [Invoke-HostPosture.ps1:235](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:235), with invalid-value coverage at [test_host_posture.py:321](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:321). `LmCompatibilityLevel` is likewise fixed at [Invoke-HostPosture.ps1:533](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:533).

The claimed sweep is incomplete:

- `LDAPClientIntegrity=3` passes because the condition is `-ge 2` at [Invoke-HostPosture.ps1:459](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:459).
- `ConsentPromptBehaviorAdmin=6` falls through to PASS at [Invoke-HostPosture.ps1:559](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:559), although its defined domain is 0–5. [Microsoft specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)
- `BackupDirectory=4` passes at [Invoke-HostPosture.ps1:603](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:603), despite Windows LAPS allowing only 0, 1, or 2 and treating unsupported values as the disabled default. [Microsoft LAPS documentation](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- `RestrictAnonymous=3` is displayed but never validated at [Invoke-HostPosture.ps1:466](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:466).

The boolean judgment is also applied inconsistently. Under the stated nonzero-is-on rule, negative-sense booleans must test nonzero, but `UseLogonCredential=2`, `EveryoneIncludesAnonymous=2`, `LocalAccountTokenFilterPolicy=2`, and both `AlwaysInstallElevated=2` fall through to PASS at lines [526](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:526), [466](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:466), [564](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:564), and [569](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:569).

Direct reproduction produced PASS for every input above.

### NEW-1 — CLOSED

The redactor now retains the original match separately from its case-folded lookup key and returns `raw` for invalid bare-IPv6 candidates at [report.py:941](/srv/share/dev/aranum/aranumtoolkit/network/report.py:941). The uppercase-MAC regression is pinned at [test_host_posture.py:511](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:511).

Direct verification: `Redactor(True)("AA:BB:CC:DD:EE:FF")` returns the token verbatim.

### R9 — CLOSED

Missing PSScriptAnalyzer now causes `pytest.fail` when `pwsh` is available at [test_host_posture.py:501](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:501).

Rejecting AST extraction is sound. `_lib()` dot-sources the exact shipped collector with `-LibraryOnly` at [test_host_posture.py:178](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:178); the collector defines every function and suppresses only its final invocation at [Invoke-HostPosture.ps1:811](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:811). This parses and loads the complete shipped source before tests invoke those same function definitions, which is stronger than testing extracted copies.

### R5 — PARTIAL

Nothing in this range regressed R5. RootDSE still routes through `Invoke-LdapSearch` at [Invoke-HostPosture.ps1:292](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:292), and the range did not modify that path.

The deferred limitation remains: `DirectoryEntry` construction and synchronous `FindAll()` at [Invoke-HostPosture.ps1:274](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:274) are not independently wall-clock bounded. A blackholed DC locator or stalled ADSI bind can still exceed `LdapTimeoutSeconds`; S5 Windows-lab deferral therefore remains reasonable but does not close R5.

The permitted pytest command could not start because the read-only environment provides no writable temporary directory. Direct PowerShell and Python probes were used for the concrete cases above.