blockers: 0, high: 4, medium: 4, low: 2

### R1 — high

File: [aranumtoolkit/network/bulk-enum-windows.py:624](/srv/share/dev/aranum/aranumtoolkit/network/bulk-enum-windows.py:624)

Concrete failing scenario: On a Windows host enforcing Constrained Language Mode, the declared-deviation wrapper fails before either collector starts because `Encoding.GetString`, `Convert.FromBase64String`, and `ScriptBlock.Create` are prohibited method calls. Consequently, no posture lines are emitted, including the collector’s intended `NA|ConstrainedLanguage` AD results. Reproducing the expression under CLM returns: `Cannot invoke method. Method invocation is supported only on core types in this language mode.`

Suggested fix: Use the literal `& { <body> }` wrappers from D3.4, retaining the empirically required trailing blank line after each complete block. Add an stdin transport test that sets Constrained Language Mode and verifies the host checks run and AD checks emit NA.

### R2 — high

File: [standalones/windows/Invoke-HostPosture.ps1:213](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:213), [aranumtoolkit/tests/test_host_posture.py:217](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:217)

Concrete failing scenario: `Resolve-LdapSigningStatus 2 0` and `Resolve-LdapSigningStatus 2 $null` both return `PASS`. Thus a DC requiring LDAP signing but not channel binding—or whose channel-binding policy is unreadable—is reported fully compliant. The test’s `$null,$null → NA` assertion passes only because the signing value is also missing; it never exercises known signing plus unknown channel binding.

Suggested fix: Return NA when either required policy is unreadable, and grade channel binding explicitly; PASS must require acceptable values for both policies. Add fixtures for `(2,$null)`, `(2,0)`, `(2,1)`, and `(2,2)`.

### R3 — high

File: [aranumtoolkit/network/report.py:2760](/srv/share/dev/aranum/aranumtoolkit/network/report.py:2760), [aranumtoolkit/network/report.py:2237](/srv/share/dev/aranum/aranumtoolkit/network/report.py:2237)

Concrete failing scenario: Redaction is seeded only with metadata hosts and canonical domain keys. With an IP target reporting `domain=corp.local observer=ws01`, the IP and `corp.local` are scrubbed but `ws01` remains in posture details, findings, and `observed_from.detail`. Linux `realm=CORP.EXAMPLE`, AD trust-domain names, differently cased domains, and host/domain names appearing only in quarantined lines likewise remain.

Suggested fix: Build a posture-specific identity set from `domain=`, `realm=`, `observer=`, trust values, and other posture identity fields; redact case-insensitively. For quarantined malformed lines, either sanitize recognized identity tokens or redact the entire untrusted detail portion. Expand the redaction test to cover observers, realms, trusts, case variants, and quarantine entries.

### R4 — high

File: [standalones/windows/Invoke-HostPosture.ps1:90](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:90), [standalones/windows/Invoke-HostPosture.ps1:387](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:387)

Concrete failing scenario: `Get-RegValue` maps every registry exception—missing value, access denied, unavailable provider—to `$null`. Several checks interpret `$null` as PASS. If registry reads fail, examples include `WIN-SMB-V1|PASS`, `WIN-PS-V2|PASS`, `WIN-CRED-NOLMHASH|PASS`, and `WIN-UAC-LUA|PASS`, violating the “could not run → ERR, never PASS” contract.

Suggested fix: Return a structured result distinguishing `present`, `absent`, and `error`. Apply documented defaults only to genuinely absent values; emit ERR on provider or permission failures. Add a fixture where `Get-ItemProperty` throws access-denied and assert none of these checks passes.

### R5 — medium

File: [standalones/windows/Invoke-HostPosture.ps1:268](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:268)

Concrete failing scenario: With `-AdChecks` and an unreachable or stalled DC, the initial `LDAP://RootDSE` property reads have no timeout. The per-query `DirectorySearcher` limits do not cover this call, so the standalone collector can hang before emitting any AD result.

Suggested fix: Perform RootDSE discovery through a bounded LDAP operation, preferably `System.DirectoryServices.Protocols.LdapConnection` with an explicit timeout, and thread `LdapTimeoutSeconds` into it.

### R6 — medium

File: [standalones/windows/Invoke-HostPosture.ps1:619](/srv/share/dev/aranum/standalones/windows/Invoke-HostPosture.ps1:619), [aranumtoolkit/network/report.py:2163](/srv/share/dev/aranum/aranumtoolkit/network/report.py:2163)

Concrete failing scenario: A domain-joined host run directly with `-AdChecks` under Constrained Language Mode emits untagged NA lines. A RootDSE failure similarly emits untagged ERR lines. Since the parser can only add observations to a domain when `domain=` is present, these results never enter the domain lattice; an all-ERR domain incorrectly disappears instead of becoming canonical ERR.

Suggested fix: Construct a fallback `domain=<Context.Domain> observer=<ComputerName>` prefix immediately after confirming domain membership, before the language-mode and RootDSE checks. Replace it with the RootDSE-derived DNS identity after successful discovery.

### R7 — medium

File: [aranumtoolkit/network/report-dashboard.py:486](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:486), [aranumtoolkit/network/report-dashboard.py:1191](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:1191), [aranumtoolkit/network/report-dashboard.py:1431](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:1431)

Concrete failing scenario: A canonical domain finding such as `host="corp.local", scope="domain"` is correctly excluded from `by_host` and no `host_corp.local.html` is generated. However recent-findings, inbox, service, severity, and category tables still label it as a Host and link to that nonexistent host page.

Suggested fix: Centralize scope-aware target rendering. Domain findings should be labeled “Domain” and link to the domain posture section on `ad.html`, while remaining in aggregate finding KPIs.

### R8 — medium

File: [aranumtoolkit/network/report-dashboard.py:2606](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2606), [aranumtoolkit/network/report-dashboard.py:2691](/srv/share/dev/aranum/aranumtoolkit/network/report-dashboard.py:2691)

Concrete failing scenario: A malformed structure such as `{"posture":{"host":{"checks":{"LIN-SYSCTL-ASLR":"bad"}}}}` crashes `render_posture()` with `AttributeError: 'str' object has no attribute 'get'`. Similar non-dict check records crash domain sorting and `_domain_membership`.

Suggested fix: Normalize posture and domain maps at the model boundary: accept dictionaries only, discard malformed check/observer records, coerce keys to strings, and map invalid statuses safely. Add malformed-value tests for hosts, checks, domains, and observer lists.

### R9 — low

File: [aranumtoolkit/tests/test_host_posture.py:317](/srv/share/dev/aranum/aranumtoolkit/tests/test_host_posture.py:317)

Concrete failing scenario: The claimed 5.1 compatibility test uses the installed pwsh parser plus a short deny-list of PS7 AST nodes/tokens. It does not run the required PSScriptAnalyzer 5.1 compatibility profile and does not AST-extract the AD helpers as specified. A PS7-only command parameter or runtime API can therefore pass this test but fail on Windows PowerShell 5.1.

Suggested fix: Run PSScriptAnalyzer with the Windows PowerShell 5.1 compatibility profile, AST-extract and execute the named helpers, and add a CLM execution test for the combined wrapper.

### R10 — low

File: [aranumtoolkit/tests/test_dashboard_posture.py:80](/srv/share/dev/aranum/aranumtoolkit/tests/test_dashboard_posture.py:80)

Concrete failing scenario: `HTMLParser().feed()` is tolerant rather than validating, and the test makes no assertion afterward. Raw posture-derived `</td><script>` or quote-based attribute injection would still pass this “wellformed” test.

Suggested fix: Add hostile detail, host, domain, check-ID, and observer-detail fixtures and assert the raw payload is absent while the correctly escaped text appears in both content and `title` attributes.

### Explicitly checked, no finding

- Strict anchored parser, `split("|", 3)`, quarantine reasons, non-partial quarantine handling, and posture-line regex bypass.
- Domain status lattice, conflict notes, observer preservation, report-level host verdict exclusion, and `summary.hosts` exclusion.
- Collector detail flattening and AutoLogon password suppression.
- Linux target-side read-only/local-only behavior and `(linenum) </dev/null` delivery ordering.
- AD consent gate before RootDSE/search calls, and page size/client/server timeouts for ordinary LDAP searches.
- `--ad` requiring `--with-posture`; default Linux and Windows payload paths remain unchanged.
- HTML/attribute escaping of posture-derived strings when the posture/domain model has the expected structure.