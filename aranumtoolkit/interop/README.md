# aranum ↔ recce interop

One-directional bridge: **aranum output → recce engagement workbook.**

Run aranum for its wide/deep active enumeration + exploitation, then hand the
results to [`recce`](https://github.com/dloucks01/Python) (its `recce/`
subfolder) so **every discovered host, port and service — and every finding —**
populates recce's coverage-tracking spreadsheets (Checklist, Services,
Vulnerabilities, Overview, ...).

## `aranum_to_recce.py`

Reads aranum's machine-readable `findings.json` (schema v2, produced by
`aranumtoolkit/network/report.py`) **plus the full service/port inventory aranum
discovered**, and writes them into a recce SQLite datastore (`results.sqlite`),
then regenerates recce's `enumeration.xlsx` / `.md` / `.csv`.

### Full service/port coverage

To guarantee *all* services and ports land in recce — not just the ones that
produced a finding — the exporter merges every available port source:

| Source | Flag | What it contributes |
|---|---|---|
| nmap scan XML | `--nmap scan.xml` | native recce parse: OS + per-port product/version + NSE scripts (richest) |
| aranum inventory | `--inventory inventory.json` | every open `(ip, port, service)` from `nmap-parse --json` |
| raw output tree | `--raw-dir raw/` | `<service>/<ip>_<port>/` (and bare `<ip>/`) leaves |
| findings | *(always)* | ports embedded in findings; a **portless** finding is pinned to its service's canonical port via aranum's own `SERVICE_MAP`, so no service is ever dropped |

Point it at an aranum **session dir** (`outputs/<session>/`) and it
auto-discovers the `findings.json`, the scan XML under `inputs/`, and the `raw/`
tree — no flags needed. Disable with `--no-autodiscover`.

### Usage

Via the unified CLI (preferred):

```bash
# auto-discovers findings + scan + raw tree from the session dir:
aranum export-recce outputs/acme -o ./acme-recce --recce-path ~/tools/recce

# explicit sources:
aranum export-recce outputs/acme/reports/findings.json \
    --nmap outputs/acme/inputs/scan.xml -o ./acme-recce --label "ACME internal"
```

Or directly:

```bash
python3 aranumtoolkit/interop/aranum_to_recce.py outputs/acme/reports/findings.json \
    --inventory inventory.json -o ./acme-recce --recce-path ~/tools/recce
```

Open `./acme-recce/enumeration.xlsx`, or refresh later straight from recce:

```bash
python3 -m recce report -o ./acme-recce
```

### Requirements

`recce` (MIT) must be importable — `pip install` it, put it on `PYTHONPATH`, or
pass `--recce-path /path/to/recce` (the directory that contains the `recce/`
package). No aranum code is copied into recce or vice-versa; only *data* crosses
the boundary, so aranum's CC-BY-NC-SA and recce's MIT license stay independent.

### Mapping

| aranum `findings.json` field | recce model |
|---|---|
| `host` (or first IP in `line` for `(dispatcher)` buckets) | `Host.ip` (+ `/24` `subnet`) |
| `port` (or `:PORT` / `PORT/tcp` from `line`; else `SERVICE_MAP` canonical port) | `Port.portid` (marked `vuln_scanned`) |
| `service` | `Port.service`, and `Vuln.script_id = aranum:<service>` |
| `severity` | `Vuln.severity` (same critical/high/medium/low/info vocab) |
| `title` / `line` | `Vuln.title` / `Vuln.output` |
| CVEs in `line` | `Vuln.ids` |
| `evidence_path`, `priority`, `next_actions` | folded into `Vuln.output` (recce has no such fields) |
| `confidence` | `Vuln.confidence` |
| inventory `product` / `version` | `Port.product` / `Port.version` |
| — | `Vuln.source = "aranum"` (provenance; never collides with recce's own NSE/version-db vulns) |

### Behavior notes

- **Re-runnable.** recce's `upsert_host` merges by host and dedups vulns by key,
  so re-ingesting the same engagement never duplicates rows and never wipes the
  operator's spreadsheet ticks. Port sources are merged (union), never doubled.
- **Every open port is marked `vuln_scanned`.** aranum's per-service dispatchers
  *are* the vuln pass, so recce's Checklist reflects that.
- **Unattributable findings** (no IP anywhere) are counted and skipped rather
  than filed under a junk host.
- **`SERVICE_MAP` is loaded live** from `../network/nmap-parse.py`, so the
  service→port table stays in lockstep with aranum's own routing; if it can't be
  loaded, portless findings simply stay portless (the export still runs).

### Tests

`aranumtoolkit/tests/test_interop_recce.py` covers the recce-independent
translation logic always; the end-to-end `ingest()` test runs when recce is
importable (`RECCE_PATH=/path/to/recce python3 -m unittest ...`).
