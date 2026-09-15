# aranum v0.34.0 release notes

Date: 2026-09-14

## Summary

aranum v0.34.0 closes all 72 findings accepted by the comprehensive quality
review: 38 High, 30 Medium, and 4 Low. This release focuses on correctness,
result integrity, coverage, and operator trust. Security hardening of aranum
itself was explicitly excluded from the review and from this release scope.

## Three remediation components

### R1 — orchestration, artifacts, and quality gates

Campaign scheduling, queue state, reports, merges, diffs, Recce exports, and
bulk-enumeration artifacts now preserve canonical endpoint and run identity.
Failure, skip, assessed-clean, and unassessed outcomes remain distinct, and
dispatcher failures propagate to the process result. CI now runs the complete
declared unit, pytest, smoke, lint, and data-audit inventory.

### R2 — endpoint, transport, and host-detection correctness

Discovery-to-probe paths retain user, host, port, and protocol information.
Implicit-TLS services use the appropriate transport, protocol replies are
classified at the decisive stage, Windows and AD predicates match their stated
requirements, and concurrency/rate controls are enforced. The release adds a
conservative, parser-only Bambu Lab correlation and performs no device probe.

### R3 — specialist verdicts, lifecycle, and coverage

SMTP, Redis, ActiveMQ, GraphQL, Jabber, and Openfire tools now distinguish
confirmed evidence from normal or indeterminate behavior. Mutation helpers
preflight inputs, verify progress, preserve recovery state, and require proved
cleanup. Specialist semantic fixtures and manifest-driven offline-data audits
are part of the standard release gate.

## Verification evidence

The integrated candidate at commit `1c1025286582e465806d37669020a4df7dd145d8`
recorded the following results before the release-only version and gate changes:

- Full pytest: 416 passed, 5 skipped; 100 subtests passed.
- Full unittest: 364 passed, 5 skipped.
- Smoke: 380 passed, 0 failed, 1 skipped.
- Data audit: all seven manifest entries passed, including the dynamically
  discovered 78-file CVE/version family.
- Tracked Python, shell, and JSON syntax sweeps passed.
- The complete `make test` gate passed using the documented `bash -n` fallback
  because ShellCheck was unavailable on the validation host.

The release commit additionally exercises the focused tag-gate policy: an
absent `v0.34.0` tag is accepted only in GitHub `pull_request` CI when `VERSION`
matches the latest release block. Push/main CI and local runs remain strict.

## Validation limitations

- No live Windows or domain-joined AD end-to-end environment was available.
- No live Redis or Openfire mutation-and-cleanup end-to-end run was performed.
- No live Bambu device was re-probed; its new correlation uses bounded parser
  evidence and performs no network action.
- Security of aranum itself was out of scope.

These limitations are intentionally separate from the deterministic protocol,
state-machine, syntax, and integration evidence used to gate this release.
