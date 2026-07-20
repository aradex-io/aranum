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
| `redacted` | bool | true when `--redact` masked hosts |
| `summary` | object | `{hosts:[], services:[], counts:{sev:n}, by_service:{svc:{sev:n}}}` |
| `findings` | array | see below |
| `per_host` | object | (bulk mode) `{host: {verdict, counts:{sev:n}}}` |
| `warnings` | array | (merge) non-fatal issues (missing evidence, …) |

## Finding object

| key | type | notes |
|---|---|---|
| `finding_id` | string | stable `AR-2-<sha1[:14]>` over (service,host,port,severity,evidence,line) |
| `host` | string | IP or hostname (or `<TARGET-N>` when redacted; `(dispatcher)` for run-level) |
| `port` | string | may be empty |
| `service` | string | dispatcher/category (e.g. `redis`, `linux`) |
| `severity` | string | `critical` \| `high` \| `medium` \| `low` |
| `line` | string | the matched evidence line (normalized, ≤300 chars) |
| `evidence_path` | string | path to the evidence file, relative to the output dir |
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
  "summary": {"hosts": ["10.0.0.5"], "services": ["redis"], "counts": {"critical": 1}},
  "findings": [
    {
      "finding_id": "AR-2-1a2b3c4d5e6f70",
      "host": "10.0.0.5", "port": "6379", "service": "redis",
      "severity": "critical", "line": "UNAUTH Redis 10.0.0.5:6379 — redis_version:7.0.15",
      "evidence_path": "redis/10.0.0.5/info_6379.txt",
      "title": "REDIS: UNAUTH Redis 10.0.0.5:6379",
      "confidence": "high", "priority": "P0",
      "tags": ["critical", "redis", "triage:high"],
      "next_actions": ["validate", "contain", "remediate", "track"],
      "triage_status": "new"
    }
  ]
}
```
