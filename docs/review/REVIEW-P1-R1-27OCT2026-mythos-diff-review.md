**Verdict: RED** (three high findings: pre-P1 install migration duplicates credentials, dashboard delete silently broken, one pre-existing API test fails; suite is not green as claimed).

Measured test state in this worktree with `build/venv-plan002`: the eight TestClient modules the implementer could not run → **208 passed, 1 failed** (`tests/unit/api/test_server.py::TestCredentialsAPIExtended::test_update_credential_success`); the remainder of `tests/` → 4669 passed, 16 skipped. Net: 4877 passed, 1 failed, 16 skipped.

## Findings

**R-1 · high · migration/data-integrity · `core/framework.py:131-170`, `models/database.py:313-326`, `core/database.py:338-352`, `core/execution.py:81-82`** — measured.
The two migrations backfill `account_ref` independently with `uuid4()` for null-scope rows, so a credential that exists in both pre-P1 stores gets two different refs. `_load_credentials` then upserts the legacy ref into the ORM store; `upsert_credential` (`models/database.py:512-525`) has no fallback for null scope, so it inserts a second row. Reproduced inline: legacy `purplesploit.db` + ORM `credentials.db` each holding `CORP/admin` → after migration + startup sync the ORM store has 2 rows for the same credential (`CORP/admin` with two refs); stable afterwards, so the orphan persists. Every existing install gets one duplicate per pre-existing credential in the dashboard/API list. Fix: backfill deterministically for legacy rows (e.g. uuid5 over `(username, domain, name)` plus a `legacy` marker) in both migrations, or have `_load_credentials` match the ORM row by `(username, domain, display_name)` once when `account_ref` misses and scope is null.

**R-2 · high · API compatibility · `web/static/js/c2-terminal.js:703,711,761` vs `api/server.py:508-516`** — measured by reading.
The spec check "routes keyed by `account_ref` without breaking callers that pass name" fails: the C2 terminal's delete button passes `cred.name` to `DELETE /api/credentials/{…}`, which now filters only on `account_ref` → 404; the JS does not check status and prints "Credential … deleted". The list payload already contains `account_ref`, so either the JS must send it, or `get/update/delete_credential` need a display-name fallback when the ref misses. (`cred-select` at `server.py:1351` and the dashboard form at `web/dashboard.py:174` look up by display name and still work.)

**R-3 · high · test regression · `tests/unit/api/test_server.py:662-683`, `api/server.py:394-405`, `models/database.py:194`** — measured.
`CredentialResponse.account_ref: str` is required; the pre-existing update test's `MagicMock` credential sets name/username/… but not `account_ref` → pydantic ValidationError → 500 → assertion fails. The implementer's report excludes this module and reports the sweep as green. Fix: set `mock_cred.account_ref` in the test (and consider `account_ref: Optional[str]` only if a real row can lack it, which it cannot after R-1's backfill).

**R-4 · medium (owner call on spec reading) · credential dedup · `core/session.py:389-399`, `core/database.py:625-645`, `models/database.py:508-525`; producers `core/auto_enum.py:1290`, `modules/ad/kerbrute.py:501`, `modules/web/wpscan.py:582`, `ui/commands.py:1193`** — behavior measured, intent inferred.
"Null scope never merges" is implemented as "identical null-scope tuples never merge": `generate_account_ref` returns a fresh `uuid4` and the tuple check is skipped when `scope is None`. Scenario: auto-enum re-run (or kerbrute/wpscan re-parse, or `creds add admin:pw` twice) finds `admin/CORP` again → `Framework.add_credential` returns True every time → a new session entry, legacy row and ORM row per discovery. Pre-P1 this was rejected as a duplicate. R-29's wording is "such records stay per host"; a null-safe tuple match `(username, None, domain, local_host)` would keep per-host separation (AC-14 still passes) without unbounded duplication. The edited assertion in `tests/unit/core/test_session_state_consistency.py:258-266` is forced only under the literal reading.

**R-5 · medium · identity stability · `core/execution.py:186-192, 215-219`** — measured.
The report states null-valued promoted provenance is reinserted; it is not: `if value is not None`. Probe: `Observation(attributes={"source_tool":"x","source_id":None,"k":1})` and `Observation(attributes={"k":1}, source_tool="x", source_id=None)` yield different `observation_id`s. Today unreachable for persisted records: every post-diff importer that formerly had null keys passes an explicit id (aranum `:174-180`, cloud `:179-190`, containers `:254-262`, identity `:134-140`, api_surface `:150-157`, host_database `:115-129`) and nmap precomputes over the full legacy dict (`nmap_importer.py:22-38`); AC-19 corpus passes. But the invariant is fragile and undocumented: any importer that switches to field-style construction with generated ids changes ids silently. Fix: use a `MISSING` sentinel default for the five promoted fields so an explicit `None` is reinserted, plus a contract test for old-vs-new construction equivalence.

**R-6 · low · side effect · `core/execution.py:177-180`** — measured.
`__post_init__` pops promoted keys from the caller's `attributes` dict in place (probe: caller dict becomes `{"k":1}`). Pre-P1 construction never mutated inputs. Reachable via `attack_graph.py:375-386` with id-less dict input. Fix: `self.attributes = dict(self.attributes)` before popping.

**R-7 · low · forward compatibility · `core/execution.py:64-69, 173-181`** — measured.
`AuthContext.from_dict` is `cls(**value)`; aranum A3 will emit `account_label`, `scope_basis`, `invocation` → `TypeError`. Because `Observation.__post_init__` auto-promotes `attributes["auth_context"]`, an importer that stores the raw aranum block in attributes will fail at construction. P2b must translate; note it in the P2b brief or accept/ignore extra keys.

**R-8 · low · spec wording · `core/execution.py:367-368`** — inferred.
Normalizer defaults to `AuthContext()` (all-null object) rather than `None` when the request carries none; AC-05 says "null otherwise". Harmless for identity (excluded), and AC-16 as written requires the object; flag so P2b does not treat an all-null object as "stamped".

**R-9 · low · coverage · `tests/fixtures/interop/pre-p1/MANIFEST.json`** — measured.
`uncovered_importers` is `{}` yet the corpus has no `host_database`, `api_surface`, or `attack_formats` cases; all three use explicit ids so no drift, but AC-19 does not prove it.

**R-10 · low · behavior change · `core/database.py:633-645`, `core/session.py:564-576`** — measured by reading.
Legacy `add_credential` now UPDATEs on ref match and writes `metadata = {}` when the caller passes none (`_persist_credential_record` never passes it), wiping legacy metadata on re-persist. `CredentialManager.import_data` now routes through `add`: an invalid `scope` in saved session data raises instead of loading, and declared-scope duplicates collapse, shifting `current_index`.

## Spec checklist

1. **Identity** — persisted ids stable (AC-19 pass, all constructors audited); explicit ids preserved; `auth_context` excluded; old placement read-compatible. Caveat R-5/R-6.
2. **auth_context carry** — every `ExecutionResult` constructor carries it: framework early errors `:403-419`, option/operation failures via `_complete_module_results:464`, `module.py:590-595` (handle completion mutates the same record), agent cancel/exception/normal `:81-103`, coordinator and assessment use `to_dict/from_dict`. No drop found.
3. **No inference** — none; `generate_account_ref` and all stores take scope only as given; AC-16 real.
4. **Stores** — null-safe `IS` matching in SQLite; ORM tuple query uses `==` with `None` → SQLAlchemy renders `IS NULL`, fine; migrations additive and idempotent (re-ran on migrated DB in probe, no growth); name-based upsert removed. Defects: R-1, R-2, R-4.
5. **Test edits** — interop/nmap edits are attribute→field moves of equal strength; xfail removals correct; AC-14/15/16 pass for the real reason (AC-14 supplies explicit refs, generation is covered by the unit tests). The consistency-test flip is R-4.
6. **Not implemented** — `Finding.metadata["source_observation"]` on the aranum projection and offline `account_ref` resolution are correctly deferred to P2b per plan §10; nothing else in §4/§10 P1 is missing.
