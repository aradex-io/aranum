You are the independent Phase-6 diff reviewer for sprint S3 of PLAN-001 in the `aranum` repo (authorized-testing enumeration toolkit; current directory is the repo root). Base SHA 7e62404, head SHA 0f80c45, branch dev/host-posture.

READ (all paths relative to repo root):
- docs/review/s3-posture-kb/diffrev/plan-s3.md — the S3 plan section (contracts D3.1–D3.5 and the test plan). This is the spec.
- docs/review/s3-posture-kb/diffrev/s3-code.diff — code diff: report.py (posture parser/model/posture.json/quarantine/redaction), report-dashboard.py (Posture page, host card, AD domain posture), bulk-enum-linux.sh + bulk-enum-windows.py (--with-posture/--ad delivery), standalones/linux/host-posture.sh, standalones/windows/Invoke-HostPosture.ps1.
- docs/review/s3-posture-kb/diffrev/s3-tests.diff — the new tests and the M7 harness.
You may open any file in the repo to check context (e.g. full report.py around a hunk).

DECLARED DEVIATION FROM PLAN (evaluate it, do not just flag it as "differs from plan"): D3.4 specifies the Windows wrapper as `& { <privesc body> }` then `& { <posture body> }`. The implementation instead sends each body as a single line `& ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('<b64>')))) [-AdChecks]` followed by a blank line. Reason (measured under pwsh 7 on Linux): the ssh transport feeds `powershell -Command -`, which reads stdin like a console and executes a multi-line block only after a trailing blank line; the literal multi-line wrapper produced no output at all without it; 5.1 behaviour could not be measured (no Windows host).

REVIEW FOR (blocker/high/medium/low, each with file:line, a concrete failing input/state, and a suggested fix):
1. Correctness against the D3.1–D3.5 contracts: strict anchor + split cap; quarantine reasons (malformed / unknown id / duplicate id per host / determined domain check without a domain= tag) never become findings and never mark the report partial; the domain lattice (determined FAIL>WARN>PASS>INFO beats undetermined; ERR>NA when nothing determined; conflict note); domain findings excluded from per-host verdicts, summary.hosts, dashboard host tables/pages; posture lines not double-graded by regex rules.
2. Collector read-only/OPSEC properties (CLAUDE.md §9): no writes to the target, no network beyond the opt-in -AdChecks LDAP against the host's own DC, no secret values printed (AutoLogon), detail sanitization (| CR LF control chars), ERR never reported as PASS, -AdChecks consent gate (no LDAP/ADSI call without it), bounded LDAP (page size, timeouts). PowerShell 5.1 compatibility.
3. Delivery: Linux `( linenum ) </dev/null` then posture over `bash -s`; Windows payload as above; --ad requires --with-posture; default payloads unchanged.
4. Redaction: --redact must scrub IPs/hostnames/domain names from posture.json, findings.json posture fields, observed_from, quarantine entries.
5. Dashboard: HTML/attribute escaping of every posture-derived string (detail, check id, host, domain, observer detail in title attributes); robustness to malformed posture/domains structures.
6. Test quality: vacuous assertions, assertions that pass for the wrong reason, missing coverage of a failure mode the plan names.

OUT OF SCOPE — do NOT report: the accuracy of individual KB check remediation texts (separately authored/validated); tool-hardening or compliance-control suggestions for aranum itself beyond §9; the pre-existing bulk-mode duplication of host pages keyed by directory name vs IP (pre-existing, recorded separately); pywinrm/WinRM command-line length limits for large payloads (pre-existing, recorded separately); style/naming; anything in S4/S5 scope (--local, desktop transports).

OUTPUT: Markdown. Start with a one-line verdict (`blockers: N, high: N, medium: N, low: N`). Then one section per finding: ID (R1..), severity, file:line, the concrete failing scenario, suggested fix. Then a short "explicitly checked, no finding" list of what you verified clean. Do not invent findings to fill space; zero findings in a category is a valid answer.
