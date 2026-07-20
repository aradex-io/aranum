# aranum — Agent Mandates

Project instructions for any Claude/agent session operating inside this repo.
**These rules override defaults. Follow them exactly.**

---

## 1. Scope

`aranum` is an authorized-testing-only collection of:
- Privilege-escalation enumeration scripts (Windows + Linux)
- Network service enumeration dispatchers driven from nmap output
- Targeted post-discovery exploitation helpers (ActiveMQ, Redis, SMTP, GraphQL)

Every script here assumes the operator has written authorization to test the target. **Do not add scripts that mass-target, evade detection for malicious purposes, persist on victims, or destroy data.** Enumeration and validated PoCs only.

---

## 2. Model selection (mandatory)

| Phase | Model |
|---|---|
| Plan, architecture, threat model, review, debate trade-offs | **Opus** (`claude-opus-4-7`) |
| Execute the plan: write code, edit files, run scripts, fix mechanical bugs | **Sonnet** (`claude-sonnet-4-6`) |

Rules:
- If a request involves any design judgment (new tool, refactor across files, scoring rubric, security trade-off), **stay on Opus** through the plan, then explicitly hand off to Sonnet for execution.
- Mechanical edits (rename, format, add a flag, fix a typo, run tests) → Sonnet.
- Never use Haiku for anything in this repo — security tooling needs careful reasoning.
- When uncertain whether a task is "plan" or "execute," default to **Opus**.

A hand-off looks like: finish the plan with a "Sonnet execution brief" — bulleted, files-and-line-numbers explicit — then the user (or a sub-agent) runs it on Sonnet.

---

## 3. Commit mandates

Every functional change must be committed. No exceptions.

**Granularity:** one logical change per commit. A new dispatcher = one commit. A bug fix = one commit. Don't pile a feature + an unrelated refactor into the same commit.

**Conventional Commit format** (enforced):

```
<type>(<scope>): <subject>

<body — what changed and why, NOT how>

Refs: <CHANGELOG section, ticket, CVE>
```

`<type>` is one of:
- `feat`     — new tool, new dispatcher, new subcommand
- `fix`      — bug fix in existing tool
- `enh`      — improvement to existing tool (new flag, faster, more thorough)
- `docs`     — README / CLAUDE / CHANGELOG only
- `refactor` — code restructure, no behavior change
- `chore`    — deps, gitignore, build infra
- `test`     — test additions / fixtures (e.g. test.gnmap)
- `sec`      — security hardening of our OWN tools (input validation, etc.)

`<scope>` is the top-level directory: `network`, `windows`, `linux`, `graphql`, `redis`, `activemq`, `smtp`, `creds`, or `repo` for cross-cutting.

**Example:**
```
enh(graphql): add --insecure flag to bypass TLS verification

Engagement targets routinely present self-signed or expired certs.
Match curl -k semantics: opt-in only via --insecure or GQL_INSECURE=1.
Default behavior (verify) unchanged.

Refs: CHANGELOG [Unreleased] / graphql
```

**Never:**
- Skip hooks (`--no-verify`)
- Force-push to `main`
- Amend a pushed commit
- Commit secrets, PATs, captured creds, target IPs, or engagement-specific config

---

## 4. Version control

**Branching:**
- `main` — known-good, every commit must run
- `dev/<topic>` — work-in-progress branches; merge to `main` via fast-forward or squash when green
- Long-lived feature branches discouraged; rebase onto `main` frequently

**Tagging:**
- Tag every release on `main`: `v0.2.0`
- Annotated tags only: `git tag -a v0.2.0 -m "release: ..."`

---

## 5. Semantic versioning

`MAJOR.MINOR.PATCH` — applied to the repo as a whole (single CHANGELOG, single tag).

| Bump | When |
|---|---|
| **MAJOR** | Breaking CLI change in any tool (renamed flag, removed subcommand, output format change consumers parse) |
| **MINOR** | New tool, new dispatcher, new subcommand, new bug class covered, new auth method |
| **PATCH** | Bug fix, doc fix, dependency tightening, hardening that doesn't change interface |

Pre-1.0 (current): treat MINOR bumps as the working unit. Don't ship a MAJOR until interfaces are stable.

---

## 6. CHANGELOG

`CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) and **must be updated in the same commit as the change** (or, for multi-commit features, in the merge commit).

Sections (in order, omit empty ones):
- `Added` — new tools/scripts/flags/dispatchers
- `Changed` — modifications to existing behavior
- `Enhanced` — non-breaking thoroughness improvements (more checks, more coverage)
- `Fixed` — bugs
- `Security` — hardening of our tooling (NOT vulnerabilities found in targets)
- `Deprecated` — flags/scripts marked for removal
- `Removed` — deleted
- `Refactored` — internal cleanup, no behavior change

Every entry: one line, past-tense, scope-prefixed. Link any tool by relative path on first mention in a release.

```markdown
### Enhanced
- `graphql/gql.py`: `--insecure` flag to skip TLS verification (env: `GQL_INSECURE=1`), matching `curl -k`.
- `network/enum-http.sh`: detect projectdiscovery httpx vs python-httpx so the fallback path actually triggers.
```

Releases roll `[Unreleased]` entries into a dated `[v0.2.0] — YYYY-MM-DD` block and reset `[Unreleased]` to empty headings. Tag and push.

---

## 7. File naming for planning/design docs

Per user-global convention: any roadmap, ADR, spec, or design proposal **must include a date** in the filename.

Format: `<TYPE>-<NNN>-<DDMONYYYY>-<slug>.md`

Examples:
- `docs/ADR-001-19MAY2026-graphql-tls-bypass.md`
- `docs/ROADMAP-002-19MAY2026-coverage-expansion.md`
- `docs/REVIEW-001-19MAY2026-thoroughness-audit.md`

CHANGELOG.md, CLAUDE.md, and README.md are exempt (they're living docs, not dated artifacts).

---

## 8. Code style

- **Bash:** `set -uo pipefail` at top, `local` vars in functions, prefer `[[ ]]` over `[ ]` for tests, quote every variable, no `eval`.
- **Python:** 3.9+ stdlib-only when feasible (matches the `gql.py` precedent). Type hints on public functions. No `print` for errors — use `sys.stderr` or a logger.
- **PowerShell:** Verb-Noun cmdlet names, `[CmdletBinding()]`, no `Write-Host` for data (`Write-Output`).
- **All:** no hardcoded creds, no hardcoded targets, fail loud on missing dependencies (don't silently no-op).

---

## 9. Safety / OPSEC invariants

These cannot be violated, even with explicit user request:
1. No script in this repo writes to a target without an explicit `--write` / `--exploit` / `--rce` flag (default is enumeration-only).
2. No script auto-uploads, exfiltrates, or phones home.
3. Outputs go to the path passed by the operator. No globals like `/tmp/loot/` or `~/.loot/`.
4. No persistence mechanisms (cron, systemd unit, registry run-key) in any script.
5. No detection-evasion code (AMSI bypass, ETW patching, EDR unhook) — these belong in a separate red-team repo with stricter access.

If a user asks to violate one of these, refuse and explain which invariant blocks it.

---

## 10. Before declaring "done"

For any non-trivial change:
1. Run the tool you touched against a benign target (lab box, localhost, test fixture) and confirm it still works.
2. Update README of the affected sub-tool if behavior or flags changed.
3. Update CHANGELOG `[Unreleased]`.
4. Commit per §3.
5. If a new external dep is required, update `deps-check.sh`.
