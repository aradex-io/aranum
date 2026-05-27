# Usage

Use the top-level CLI:

```bash
python3 ./aranum.py run scan.xml --session-name acme -report
python3 ./aranum.py iter --session-name acme
python3 ./aranum.py dashboard --session-name acme
```

If `--session-name` is omitted, `aranum.py` creates a date-based session under:

```text
outputs/<session>/
  raw/       raw scanner, dispatcher, and service output
  inputs/    derived inputs: etc-hosts entries, usernames, loot, Burp scope
  reports/   report.md/html/json plus dashboard files
```

Framework code lives in `aranumtoolkit/`. Self-contained tools live in
`standalones/`.
