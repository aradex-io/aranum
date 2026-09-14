# Aranum Comprehensive Quality Review Sprint Plan

Date: 13 September 2026
Baseline: `0ee9bc851cad4fbad25a2469386d3a21eca2f2d5` (`v0.33.0`)
Branch: `feat/bulk-enum-fix-expand`

## Objective

Review the complete aranum repository for functional bugs, logic errors, false-positive/false-negative causes, feature gaps, operational failure modes, and general quality issues that reduce its effectiveness as a large-network defensive assessment toolkit. Security weaknesses in aranum itself are explicitly out of scope.

The review is read-only except for dated review and planning artifacts. No product remediation is performed in this review cycle.

## Common Review Method

Each sprint will:

1. Read every in-scope source, test, configuration, data, and relevant documentation file in full.
2. Trace representative production paths from CLI input through tool invocation, evidence capture, classification, and reporting.
3. Compare implementation, tests, metadata, help text, and operator documentation for contract drift.
4. Run focused static and dynamic checks against local fixtures or benign local inputs where practical.
5. Report only evidence-backed issues. Each item must contain a category, severity, exact file and line, behavior/background, impact on aranum's effectiveness, and a concrete remediation.
6. Exclude vulnerabilities in aranum itself and avoid speculative findings that cannot be tied to an observable contract or realistic operator workflow.

## Sprint 1: Orchestration, Data Flow, and Reporting

Focus: the end-to-end framework path that turns scan inputs into actionable findings.

Primary scope:

- `aranum.py`
- `aranumtoolkit/network/{auto-enum.sh,iterative-enum.sh,plan.py,nmap-parse.py,merge-results.py,report.py,report-dashboard.py,wiki.py,autoenum-diff.sh,_lib.sh}`
- `aranumtoolkit/network/{engagement-profiles.json,service-metadata.json}`
- `aranumtoolkit/interop/`
- Directly corresponding tests, fixtures, CLI docs, schemas, and examples

Target questions:

- Are targets, services, credentials, options, exit statuses, and session paths propagated correctly?
- Can valid nmap data or dispatcher evidence be silently lost, misclassified, duplicated, or assigned the wrong priority?
- Do merge, queue, diff, report, dashboard, and interop paths preserve the same semantics?
- Are partial failures observable and resumable at enterprise scale?

## Sprint 2: Network and Host Enumeration Correctness

Focus: service dispatch, protocol-specific checks, bulk enumeration, SSH triage, and host-side collection quality.

Primary scope:

- All `aranumtoolkit/network/enum-*.sh` dispatchers
- `aranumtoolkit/network/{bulk-enum-linux.sh,bulk-enum-windows.py,ssh-triage.sh,ssh-key-triage.py}`
- Network fixture files and directly corresponding tests
- `standalones/linux/`, `standalones/windows/`, and `standalones/ot/`
- Corresponding wiki/operator documentation

Target questions:

- Do service identification, protocol selection, auth handling, and probes match realistic network behavior?
- Are important checks skipped, over-triggered, mislabeled, or rendered unusable by dependency/OS/version assumptions?
- Do bulk transports and on-host scripts produce stable, parseable, comparable evidence?
- Do safety gates preserve useful read-only coverage without accidental no-ops?

## Sprint 3: Specialist Tools, Tests, Build, and Product Gaps

Focus: specialist standalones and the repository systems intended to keep behavior reliable and discoverable.

Primary scope:

- `standalones/{activemq,creds,graphql,jabber,redis,smtp,tomcat}/`
- `.github/workflows/ci.yml`, `Makefile`, `deps-check.sh`, optional requirements, version/release metadata
- All remaining tests and fixtures
- Top-level and subsystem documentation, changelog, ADRs, roadmaps, prior reviews, wiki coverage, and data provenance

Target questions:

- Are specialist tools internally coherent, accurately documented, and integrated where operators would expect?
- Do CI and test commands actually exercise the claimed suites and platform-specific behavior?
- Which high-value defensive workflows, protocols, evidence models, or scale controls are absent or disconnected?
- Where do documentation, dependency checks, datasets, or version metadata mislead operators?

## Independent Validation Gate

After all three sprint lists are complete, a separate review agent will validate every item against the current checkout. It may approve, revise, merge, downgrade, or reject items. Approval requires:

- a reproducible or source-demonstrable behavior;
- a valid in-scope impact on effectiveness or quality;
- an exact current file/line anchor;
- no duplication of another finding; and
- a remediation that addresses the root cause.

The consolidated report will distinguish approved findings, rejected candidates, systemic themes, coverage limitations, and test evidence.

## Remediation Planning Gate

Only independently approved findings will enter a second dated three-phase remediation plan. That plan will group work by dependency/order, specify tests and acceptance evidence, identify compatibility risks, and remain unexecuted until separately authorized.
