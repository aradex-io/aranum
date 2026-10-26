# S3 round-2 VERIFY-ONLY review (aranum, PLAN-001 S3 host posture)

You reviewed S3 at head 0f80c45 and reported R1-R10 (your report: `daybreak-review.md` in this
folder). The author fixed them in two commits; the full fix diff is `r2-fix.diff` (0f80c45..93ec61e).
The repo is at /srv/share/dev/aranum (read-only for you).

Your task is VERIFICATION ONLY:
1. For each of R1-R10, state CLOSED / PARTIAL / OPEN with the concrete evidence (file:line, and the
   test that pins it). For PARTIAL/OPEN, give the concrete failing scenario.
2. Report any NEW defect the fix diff itself introduces (a regression caused by these changes).
   Only defects in changed lines or directly caused by them count.

Author dispositions to check (the author's claims, not facts):
- R1: literal `& { body }` + blank line per block; CLM runs verified in test_bulk_windows_payload_parses_under_51_rules_and_runs_over_stdin.
- R2: Resolve-LdapSigningStatus: FAIL si<2; FAIL si>=2 with CBT unset/0; WARN CBT=1; PASS only si>=2 AND CBT=2; NA si=$null (non-DC). Unreadable registry throws -> ERR via Invoke-PostureCheck. KB AD-LDAP-SIGNING semantics/sev_warn/guidance updated.
- R3: _posture_identities seeds redaction from domain=/realm=/observer=/trusts= in all posture text incl. quarantined lines; Redactor host matching case-insensitive with case-folded token map; quarantined line text replaced by a length marker.
- R4: Get-RegValue returns $null only on ItemNotFoundException (missing key) or missing property; any other exception propagates -> ERR. The one read outside a check block (fDenyTSConnections) is caught and rethrown inside WIN-RDP-ENABLED and WIN-RDP-NLA.
- R5: PARTIAL by design: RootDSE now goes through Invoke-LdapSearch (DirectorySearcher ClientTimeout/ServerTimeLimit), the bound you accepted for every other query. The author MEASURED that a hard bound is not demonstrable on the Linux test host: S.DS.Protocols LdapConnection.Timeout on Linux/libldap hung >90 s; a runspace WaitOne bound fired at 3 s but left a foreground thread holding the process; Start-Job hung in the sandbox. The bind phase of ADSI is therefore governed by the OS DC locator (inferred), and Windows lab verification is deferred to S5. Judge whether this disposition is acceptable.
- R6: fallback tag `domain=<Context.Domain lower> observer=<host>` set before the CLM and RootDSE branches; replaced by the RootDSE naming context afterwards.
- R7: target_page/target_link helpers; domain findings link to ad.html#domain-<safe>, labelled "domain"; section id added.
- R8: _normalize_posture at the model boundary (dicts only; malformed dropped; unknown status -> ERR).
- R9: PSScriptAnalyzer 1.25 PSUseCompatibleSyntax/Commands/Types with two 5.1 profiles over the collector and the --ad payload, with a 3-construct canary that must trip all three rules.
- R10: hostile-text test across details, domain, observer detail (title attr), and quarantine line.

OUT OF SCOPE (do not report): anything not in the fix diff and not caused by it; the pre-existing
items already recorded (WinRM -EncodedCommand length, duplicate bulk host pages keyed by dir name and
by IP, _AD_FAMILIES substring matching, 5.1 stdin buffering unmeasured, a custom --script calling
`exit`); account-name (`sample=`) redaction (the redaction contract is IPs/hostnames/domains);
style; tool hardening / compliance checklists; generic best-practice suggestions.

Output format: first line `closed: N, partial: N, open: N, new: N`, then one section per R-id, then
any NEW-n sections (severity, file:line, failing scenario, fix).
