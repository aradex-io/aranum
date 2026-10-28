**Verdict: RED** — R2-1 and R2-2 are resolved exactly as dispositioned and every earlier resolution still holds, but the R2-1 fix introduced one high-severity regression (R3-1) that must be fixed before merge. It is a two-line guard per store.

Measured test state (isolated HOME, venv `build/venv-plan002`, no full suite): nine touched modules outside `test_server.py` → 494 passed, 16 skipped. `test_server.py -k credential` → 8 passed. `git diff --check` clean, ruff clean on the five changed files, `runD.diff` checksum OK.

## 1. Resolution of R2-1 / R2-2

| Finding | Disposition | Status | Evidence |
|---|---|---|---|
| R2-1 | fold duplicate tuples into kept row's `metadata.folded_candidates`, delete extras, one transaction per store, idempotent, merge existing metadata, NULL/invalid → `{}`, no raise | **Resolved** (measured) | Probe A (legacy, two admin@CORP + bob): constructs without exception; 1 admin row (`admin-primary`/`password-one`), `folded_candidates=[{name:admin-secondary, password:password-two, hash, hash_type, dcip, dns, metadata:{src:second}, original_id:2}]`; bob row and its metadata untouched; raw table byte-identical after second construction. Probe B (ORM): same outcome, candidate carries the six ORM fields + `original_id:2`; bob `metadata` NULL; idempotent. Both stores assign the same ref `11c7f96b-…`. Cross-store: both pre-P1 stores with the pair → construct + `_load_persisted_data` → 1 row per store + 1 session row, same ref, both passwords recoverable from each store; second start unchanged. `core/database.py:314-390`, `models/database.py:305-388`. Tests: `test_database.py:130` (3 params), `test_credential_models_p1.py:90,160,200` pass. |
| R2-2 | add the `.limit().all() → []` mock line to the three not-found tests, nothing else | **Resolved** (measured) | `test_server.py:203,225,692`; the three tests pass; no product change in the delta. |

## 2. Regression check R-1..R-6, R-8, R-10

The delta touches only the two migration functions and three test files (delta diff: `core/database.py`, `models/database.py`, `test_server.py`, `test_database.py`, `test_credential_models_p1.py`). Re-run results:

- **R-1** (measured): single admin@CORP per pre-P1 store + legacy-only bob → migrate + sync → ORM rows 2, legacy and ORM refs identical (`11c7f96b-…`, `6bc7795f-…`); second start still 2 / session 2. Resolved.
- **R-5/R-6** (measured): `attributes={source_tool:"x", source_id:None}` vs field placement → same id; `from_dict` same; absent vs None still differ; no `_MISSING` in `to_dict`, public value None; pickle/deepcopy equality holds; `json.dumps` ok; caller dict unchanged after construction. Resolved.
- **R-2, R-3, R-4, R-8, R-10** (inferred from unchanged code + measured tests): routes `server.py:410-425` unchanged; `AuthContext()` in package → 0 matches; `session.py:577-588` scope guard + index clamp unchanged; all dedup sites unchanged; their named tests are in the 494 passed. Resolved.

## 3. Sweep: migration/backfill paths that can raise on pre-P1 data

Search: `rg -n 'ALTER TABLE|_migrate\w*\(|CREATE UNIQUE INDEX' purplesploit/` → 11 hits in 3 files. `core/store.py:_migrate` (2) is the job store, untouched by P1 (`git diff --stat` empty). Credential paths: `core/database.py:294-390` and `models/database.py:292-388`.

- Column adds: `ALTER TABLE … ADD COLUMN` only when absent, both stores → cannot raise on pre-P1 schema (measured on three pre-P1 shapes: with/without `metadata`, with/without `hash_type`).
- Grouping/ref: `generate_account_ref` raises only on invalid `scope`; pre-P1 rows have NULL scope (column just added) → unreachable. Identity is JSON-encoded, so distinct tuples cannot collide.
- Fold: `json.loads` on kept/extra metadata guarded for `TypeError/ValueError`; `json.dumps` could raise only on BLOB-typed cells, which no pre-P1 writer produced (inferred). Delete-before-ref-UPDATE ordering means the unique index (legacy: built in `_create_tables` after; ORM: built last inside the transaction) cannot fail.
- Transaction: legacy `with self.conn:` + explicit `BEGIN` at line 315 opens only when no transaction is active (the earlier `targets` ALTER does not start one on Python 3.11) → measured no "transaction within transaction" error.
- Downstream startup: `framework._load_persisted_data` → `get_credentials` → `json.loads(None)` on a NULL-metadata legacy row is pre-existing and not from any writer (noted round 2, unchanged).
- Session restore `import_data` (R-10) unchanged.

Result: no reachable raise on pre-P1 data in either migration (measured for the three schema shapes, inferred for BLOB).

## 4. New defects from this round

**R3-1 · high (must fix) · `core/database.py:387-390`, `models/database.py:378-384`** — measured.
Round C backfilled `account_ref` only `WHERE account_ref IS NULL OR account_ref = ''`. This round dropped that guard: every startup now rewrites every kept row's ref to `generate_account_ref(tuple)` in both stores. Spec §4 calls `account_ref` an "explicit stable key", `CredentialCreate.account_ref` accepts a caller value, and both stores honour it on write. Probe: POST-equivalent with `account_ref="aranum-acct-0001"` in both stores, plus an API-PUT-equivalent rename of `alice`→`alice2` that retains ref `a1250192-…` → after one restart the refs become `3c16d132-…` and `7cf44df0-…` in both stores. Consequences: any external holder of the ref (Aranum, P3 "copies the request's", session save files which persist `account_ref` at `session.py:516`, dashboard rows already rendered) gets 404 on the next `GET/PUT/DELETE /api/credentials/{ref}` after a restart; every API rename rotates the key silently; and both stores issue one UPDATE per row per start (efficiency). Fix: keep the fold unconditional but restore the guard on the ref assignment — `UPDATE credentials SET account_ref = ? WHERE id = ? AND (account_ref IS NULL OR account_ref = '')` (legacy) and the same by `rowid` (ORM); add a test that a P1-era row with an explicit ref and a tuple-renamed row keep their refs across reconstruction. No new collision risk: post-P1 dedup (ref OR tuple) prevents two refs in one group.

**R3-2 · low (may defer, record reason) · `models/database.py:329-376`** — inferred.
ORM-side `folded_candidates` lives in a raw `metadata` column that the `Credential` model cannot map (`metadata` is reserved on SQLAlchemy declarative classes), so the folded passwords are reachable only by raw SQL, never via `get_all_credentials`/the API. Satisfies the ruling's "recoverable from the stores"; defer with that reason or expose via a read-only helper later.

**R3-3 · low (may defer) · cross-store fold choice** — inferred.
Each store keeps its own lowest-id row. If the two stores inserted the pair in different orders, startup sync overwrites the ORM kept row's password/name with the legacy kept row's; the other password survives only in the legacy `folded_candidates`. Legacy is already the sync source of truth, so this is by design; record it.

Not raised: R-7, R-9 (deferred by ruling); P4 derivation; style.
