# `findings.json` schema (v2)

`report.py` and `merge-results.py` emit `findings.json` — the machine-readable
finding list consumed by the dashboard, `autoenum-diff.sh`, and external tooling.
This documents the stable contract.

## Stability

`schema_version` is a string (currently `"2"`). Per CLAUDE.md §5 the version bumps
**MAJOR** on any breaking change to these fields (renamed/removed key, or a type
change consumers parse). Additive keys do **not** bump it. Pin on
`schema_version` and ignore unknown keys.

## Top-level object

| key | type | notes |
|---|---|---|
| `schema_version` | string | `"2"` |
| `label` | string | run label (`--label`, else dir name) |
| `generated_utc` | string | ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `mode` | string | `"auto-enum"`, `"bulk"`, or `"merged"` |
| `redacted` | bool | true when `--redact` masked hosts; merged output derives this from every source |
| `redaction_state` | string | (merge) `"unredacted"`, `"redacted"`, or `"mixed"` |
| `complete` | bool | (merge) false when any referenced evidence could not be copied |
| `summary` | object | findings plus assessed coverage; see below |
| `findings` | array | see below |
| `per_host` | object | (bulk mode) `{host: {verdict, counts:{sev:n}}}` |
| `warnings` | array | (merge) missing/failed evidence copies; a non-empty list makes the merge partial (exit 3) |

`summary.hosts` and `summary.services` are the assessed inventory, including clean
endpoints with no findings.  `hosts_with_findings` and `services_with_findings`
are the affected subsets.  `coverage` contains one record per assessed endpoint
with `host`, `port`, `protocol`, `service`, and `status`; status is one of
`confirmed`, `assessed_clean`, `failed`, `skipped`, or `unassessed`.
Queue-backed records also carry additive `execution_authority: "queue"`.
When that authority is present, endpoints absent from the selected task state
remain `unassessed` even if a service-wide marker or stale evidence exists.
`coverage_counts` aggregates those states. A failed or skipped dispatcher is
never clean coverage.

Queue execution writes `queue.state.jsonl` atomically beside both the output and
an externally supplied queue. Each selected record retains `task_id`, `service`,
`phase`, `risk`, `priority`, the exact `{ip,port,proto}` target, status, rc,
reason, run ID, and timestamp. Dispatch evidence is task-scoped under
`<service>/task-<id-hash>/`; its dispatcher-authored `_task-context.json`
records the same task constraints. A service-level `.done` file is not queue
completion authority. Report generation uses the output-local queue state
exclusively when present; the parent/external copy is a legacy fallback only
when the local copy is absent. `run-state.json` carries `execution_mode` and
`queue_authoritative`; when it also provides a run ID, only queue records with
that exact ID may affect coverage.

`service-metadata.json` is the queue execution-capability authority. Services
declared `task_execution: "phased"` produce one task for each independently
implemented phase. The default `"monolithic"` services produce one canonical
`phase: "all"` task per endpoint; staged phase records for those services are
rejected before dispatch. Task IDs retain endpoint, protocol, service, and the
canonical phase, and risk/priority fields are unchanged.

## Finding object

| key | type | notes |
|---|---|---|
| `finding_id` | string | stable `AR-2-<sha1[:14]>` over logical endpoint + severity + complete evidence identity; relocation does not change it |
| `host` | string | IP or hostname (or `<TARGET-N>` when redacted; `(dispatcher)` for run-level) |
| `port` | string | may be empty |
| `protocol` | string | `tcp`, `udp`, or empty only when the source cannot disambiguate it |
| `service` | string | dispatcher/category (e.g. `redis`, `linux`) |
| `severity` | string | `critical` \| `high` \| `medium` \| `low` |
| `line` | string | the matched evidence line (normalized, ≤300 chars) |
| `evidence_path` | string | path to the evidence file, relative to the output dir |
| `evidence_paths` | array[string] | all source paths consolidated into this logical finding |
| `evidence_identity` | string | SHA-256 identity of the complete normalized evidence line |
| `title` | string | human summary |
| `confidence` | string | `high` \| `medium` \| `low` (derived from severity + metadata) |
| `priority` | string | `P0`–`P3` (P0=critical … P3=low) |
| `tags` | array[string] | severity + service + metadata tags |
| `next_actions` | array[string] | suggested triage steps |
| `triage_status` | string | `new` (operator-mutable downstream) |

## SARIF export (`--sarif`)

`report.py --sarif` also writes `findings.sarif` — a minimal **SARIF 2.1.0** subset
(one `run`, `tool.driver.name = "aranum"`, `results[]` with `ruleId` = service,
`level` = error/warning/note mapped from severity, `message`, `locations` from
`evidence_path`, and host/port/severity/finding_id in `properties`). This drops
into GitHub code-scanning, DefectDojo, and other SARIF consumers.

## Example

```json
{
  "schema_version": "2",
  "label": "acme",
  "generated_utc": "2026-07-20T14:18:49Z",
  "mode": "auto-enum",
  "redacted": false,
  "summary": {"hosts": ["10.0.0.5"], "services": ["redis"], "hosts_with_findings": ["10.0.0.5"], "counts": {"critical": 1}},
  "findings": [
    {
      "finding_id": "AR-2-1a2b3c4d5e6f70",
      "host": "10.0.0.5", "port": "6379", "protocol": "tcp", "service": "redis",
      "severity": "critical", "line": "UNAUTH Redis 10.0.0.5:6379 — redis_version:7.0.15",
      "evidence_path": "redis/10.0.0.5/info_6379.txt",
      "evidence_paths": ["redis/10.0.0.5/info_6379.txt"],
      "evidence_identity": "1b94a39a0f43…",
      "title": "REDIS: UNAUTH Redis 10.0.0.5:6379",
      "confidence": "high", "priority": "P0",
      "tags": ["critical", "redis", "triage:high"],
      "next_actions": ["validate", "contain", "remediate", "track"],
      "triage_status": "new"
    }
  ]
}
```
