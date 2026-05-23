# Examples

Small, self-contained example inputs for aratool tooling. Each subdirectory
has a `fixture/` (committed) and an `output/` (gitignored — regenerated on
demand). Run the command in each example's README to populate `output/`.

| Example | Tool | One-liner |
|---|---|---|
| [dashboard](dashboard/) | `network/report-dashboard.py` | `python3 network/report-dashboard.py --output docs/examples/dashboard/output docs/examples/dashboard/fixture && xdg-open docs/examples/dashboard/output/index.html` |

## Adding a new example

1. Create `docs/examples/<tool-name>/fixture/` with a minimal but realistic
   input set (no PII, no engagement-specific identifiers).
2. Add a `docs/examples/<tool-name>/README.md` with the one-line generate +
   view command.
3. Add a row to the table above.
4. `docs/examples/*/output/` is already covered by the top-level
   `.gitignore` — no per-example gitignore needed.
