You are an independent code reviewer. ROUND 3 of 3 (final), VERIFY-ONLY.

Repo: /srv/share/dev/aranum (read-only). Branch dev/host-posture. Range 93ec61e..af45c48.
The diff is in docs/review/s3-posture-kb/diffrev/r3-fix.diff. Your round-2 review is
docs/review/s3-posture-kb/diffrev/daybreak-r2.md.

Verify ONLY these round-2 items against the new code:
- R2 PARTIAL: out-of-domain LDAPServerIntegrity / LdapEnforceChannelBinding must never PASS.
  The author swept the class "enumerated policy with fall-through PASS" across every PASS
  emission in standalones/windows/Invoke-HostPosture.ps1 and also fixed LmCompatibilityLevel;
  boolean DWORDs (EnableLUA, NoLMHash, ...) were judged to follow Windows nonzero-is-on
  semantics and left unchanged. Check the sweep's judgment.
- NEW-1: Redactor must return non-IP colon tokens verbatim (aranumtoolkit/network/report.py).
- R9 PARTIAL: author changed the PSSA test to FAIL (not skip) when pwsh is present and PSSA
  is missing. The author REJECTS the AST-extraction ask: helper tests dot-source the whole
  shipped collector, which defines the same functions (a superset of AST extraction) and
  runs the exact file that ships; say whether that rejection is sound.
- R5 PARTIAL: author accepts it as deferred to the S5 Windows lab (no code change). Just
  confirm nothing in this range regressed it.

Out of scope (do not report): tool-hardening/compliance-control of the tool itself,
deliberate constants, style, anything outside the listed items, new features.
Do not modify files. You may run: python3 -m pytest aranumtoolkit/tests/test_host_posture.py -q

Output format: first line `closed: N, partial: N, open: N, new: N`, then one ### section per
item with CLOSED/PARTIAL/OPEN, file:line evidence, and for non-closed items a concrete
failing input. Any NEW defect introduced by this range: ### NEW-n with severity.
