# aranum design docs — index

Dated design artifacts per CLAUDE.md §7 (`<TYPE>-<NNN>-<DDMONYYYY>-<slug>.md`).
ADRs record decisions, REVIEWs record audits, ROADMAPs record planned work,
TESTPLANs record test campaigns. Newest-first within each type.

## ADR — Architecture Decision Records

| Doc | Date | Topic |
|---|---|---|
| [ADR-005](ADR-005-22MAY2026-ot-ics-safety-scope.md) | 22 May 2026 | OT/ICS read-side safety scope + typed-confirmation gate |
| [ADR-004](ADR-004-20MAY2026-ad-depth-tool-deps.md) | 20 May 2026 | AD-depth (D1) optional-tool dependency / detect-and-skip policy |
| [ADR-003](ADR-003-20MAY2026-windows-bulk-enum-design.md) | 20 May 2026 | Windows bulk-enum (WinRM) design + validation gaps |
| [ADR-002](ADR-002-20MAY2026-bulk-enum-design.md) | 20 May 2026 | Linux bulk-enum (SSH stdin-pipe) design |
| [ADR-001](ADR-001-19MAY2026-jabber-scope.md) | 19 May 2026 | Jabber/XMPP helper scope + safety invariants |

## REVIEW — audits

| Doc | Date | Topic |
|---|---|---|
| [REVIEW-004](REVIEW-004-20JUL2026-fable5-toolkit-audit.md) | 20 Jul 2026 | Fable-5 whole-toolkit audit (gaps/improvements/additions) |
| [REVIEW-003](REVIEW-003-23MAY2026-codebase-audit.md) | 23 May 2026 | Codebase audit |
| [REVIEW-002](REVIEW-002-20MAY2026-write-gate-audit.md) | 20 May 2026 | Write-gate audit |
| [REVIEW-001](REVIEW-001-19MAY2026-thoroughness-audit.md) | 19 May 2026 | Thoroughness audit |

## ROADMAP — planned work

| Doc | Date | Topic |
|---|---|---|
| [ROADMAP-003](ROADMAP-003-22MAY2026-tier4-ics-enumeration.md) | 22 May 2026 | Tier-4 OT/ICS enumeration |
| [ROADMAP-002](ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md) | 22 May 2026 | Tier-1/Tier-2 enumeration coverage |
| [ROADMAP-001](ROADMAP-001-19MAY2026-thoroughness-execution.md) | 19 May 2026 | Thoroughness execution plan |

## Reference

| Doc | Topic |
|---|---|
| [SCHEMA.md](SCHEMA.md) | `findings.json` v2 schema + SARIF export contract |

## TESTPLAN — test campaigns

| Doc | Date | Topic |
|---|---|---|
| [TESTPLAN-001](TESTPLAN-001-07JUN2026-comprehensive-functional-test.md) | 07 Jun 2026 | Comprehensive functional/security test campaign |
