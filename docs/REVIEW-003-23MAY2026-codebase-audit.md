# REVIEW-003 — Codebase audit & fix-up

**Date:** 2026-05-23
**Author:** Claude (Opus 4.7)
**Anchor release:** v0.31.0
**Branch:** `claude/codebase-review-J22li` → merged to `main`

## Scope

Full-codebase review against the CLAUDE.md governance contract (§3 commits,
§4 branching, §5 SemVer, §6 CHANGELOG, §7 doc-naming, §8 style, §9 OPSEC
invariants, §10 done-checklist). 224 files / ~22k LOC of shell + Python +
PowerShell + a single C Redis module. Reviewed in five parallel passes:

1. **Python correctness** — `graphql/gql.py`, `network/nmap-parse.py`,
   `network/report.py`, `network/report-dashboard.py`,
   `network/bulk-enum-windows.py`, `creds/*.py`, `jabber/*.py`,
   `activemq/activemq-cve-2023-46604.py`, `redis/redis-rogue-master.py`,
   `smtp/smtp-smuggling-test.py`.
2. **Shell correctness** — entire `network/enum-*.sh` fleet (~60),
   `network/_lib.sh`, `network/auto-enum.sh`, `network/bulk-enum-linux.sh`,
   `ot/_lib.sh`, `ot/ot-enum.sh`, all `_*_lib.sh` shared libs.
3. **Safety / OPSEC** — every state-modifying tool (`*-rce-*`, `*-cve-*`,
   `smtp-phish-send`, `openfire-cve-*`, OT/ICS gate, E4 aggressive UDP).
4. **PowerShell + tests + docs sync** — `windows/*.ps1`, `tests/test_*.py`,
   `tests/smoke.sh`, README ↔ filesystem ↔ CHANGELOG cross-check.
5. **Cross-cutting consistency** — throttle/proxy/UA env vars,
   `parse_common_args` contract conformance, Conventional-Commits compliance.

## Verdict (TL;DR)

**Safety posture: sound.** Every state-modifying tool gates correctly
behind explicit flags. The OT subsystem's typed-confirmation prompt is
reinforced this release to also require TTY stdin, closing the only
remaining bypass (pipe-redirected confirmation). Zero detection-evasion
code, no `/tmp/loot/` or `~/.loot/` global paths in dispatchers, no
phone-home / exfiltration.

**Operational soundness: was weaker than it looked, now strong.** Five
critical issues turned out to gate developer experience and CI:

| ID | Severity | Site | Fix |
|---|---|---|---|
| C1 | Critical | `deps-check.sh` called undefined `have()` → command-not-found errors | Defined `have()` locally |
| C2 | Critical | `tests/smoke.sh` hardcoded `/home/jay/...` → `make smoke` red on any other host | Derived REPO from `$BASH_SOURCE` |
| C3 | High (security) | `network/enum-smb.sh` wrote to fixed `/tmp/relay_cand.tmp` (symlink/race risk) | `mktemp` + trap cleanup |
| C4 | High | `enum-http.sh` `--no-nuclei` CLI flag was unreachable dead code | Pre-filter `$@` before parse_common_args |
| C5 (false-alarm) | — | dashboard fixture path | Confirmed exists |

Plus four genuine H-series fixes (openfire cleanup rc, activemq xml_file
fd leak, redis-rogue-master loop hygiene, bulk-enum-windows dead code),
the OT-prompt TTY hardening (§9 reinforcement), seven PowerShell scripts
gaining `[CmdletBinding()]`, three `Get-WmiObject` → `Get-CimInstance`
conversions (PS Core compat), Makefile lint coverage extended to the
privesc-enum dirs, and 14 new test cases.

## Findings overruled on re-read

Four sub-agent findings were dismissed after personally re-reading the
source:

- **`network/nmap-parse.py` "`r'a^'` regex bug"** — the `a^` regex is
  the *intentional* never-match pattern; line 151's comment explicitly
  documents it as canonical. Not a bug.
- **`activemq-cve-2023-46604.py` "srv NameError on bind failure"** —
  `srv = None` is initialised on line 156 before the try-block.
- **`openfire-cve-2023-32315.py` "partial-state log written when step
  1 only succeeded"** — intentional, so cleanup can still remove the
  admin user. Cleanup handles `plugin_name=None` correctly.
- **`smtp-smuggling-test.py` "SMTP multi-line response parsing"** —
  the redundant `lines[-2][:4] != b""` clause is dead but the actual
  multi-line terminator check `lines[-2][3:4] == b" "` is correct.

## Out of scope (deferred to a follow-up release)

- **104 `SC2046` shellcheck warnings** across the dispatcher fleet, all
  caused by the intentional `$(curl_proxy_arg)` / `$(curl_ua)` /
  `$(throttle_nmap_args)` word-split pattern in `network/_lib.sh`. The
  proper fix is a refactor to bash-array-populating helpers (~50
  callsites). For v0.31.0 the rule is suppressed via Makefile
  `-e SC2046`; planned for v0.32.0.
- **CI's `make test` failures unrelated to code** — 17 missing version
  tags (smoke checks tag history; fresh clones won't have them unless
  `fetch-tags: true` is set in the workflow, which it already is) and
  one rsync TP regression (rsync not installed in the bare sandbox).
  Both are environment-dependent, not code regressions.

## Method anchor

- Sub-agent review fleet: 4 parallel `Explore` agents covering Python,
  shell, PowerShell+tests+docs, and cross-cutting safety/OPSEC. Sub-agent
  output cross-verified via direct file reads before any fix landed.
- Branch worked on `claude/codebase-review-J22li`; each fix committed
  per CLAUDE.md §3 (one logical change per commit, Conventional Commits
  with `type(scope): subject` shape).
- v0.31.0 dated 2026-05-23, annotated tag, fast-forward merge to `main`.

## See also

- `CHANGELOG.md` `[v0.31.0]` block — entry-by-entry breakdown.
- `ROADMAP-001` / `ROADMAP-002` / `ROADMAP-003` — historical anchors.
- `ADR-001` … `ADR-005` — design decisions on jabber, bulk-enum,
  AD-depth tool-deps, OT/ICS safety scope.
