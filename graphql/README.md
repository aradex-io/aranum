# gql.py — GraphQL toolkit (GitLab-tuned)

Zero-dependency, stdlib-only Python tool for building and executing GraphQL requests against any GitLab instance — works whether introspection is enabled or not.

## Why this tool

GitLab's GraphQL surface is huge (1000+ operations) and the real bugs are in **authorization** and **field-level data exposure**, not injection. Existing tools (graphqlmap, InQL) either lock you to manual per-field driving, or require Burp Pro. `gql.py` fills the gap with:

- **Schema-aware query construction** — give it an op name and arg values, it figures out valid GraphQL syntax including the selection set
- **Catalog fallback** — works against 20+ pre-defined high-value GitLab operations (`project`, `user`, `runner`, `epic`, `mergeRequest`, `vulnerabilities`, all the major mutations) even when introspection is disabled
- **IDOR sweeping** — vary one argument across a list / integer range / GID range, classify responses by error signature
- **Authz diff** — run the same operation as N identities (admin / regular user / unauth / job-token), diff the responses, flag fields where the low-priv response leaks data the reference doesn't
- **All auth flavors** — PAT, OAuth Bearer, session cookie, CI Job-Token, custom headers

## Install

```bash
# Single file, Python 3.9+. No pip install needed.
chmod +x gql.py
./gql.py --help
```

## Quick start

```bash
# Set common env so you don't repeat them
export GQL_URL='https://gitlab.example.com/api/graphql'
export GQL_TOKEN='glpat-XXXXXXXXXXXXXXXX'

# 1. Pull the schema (cached under .cache/)
./gql.py introspect

# 2. Browse — works against schema OR built-in catalog if no introspection
./gql.py ls --filter 'member|runner|token'
./gql.py describe projectMemberAdd

# 3. Run a query — selection set is auto-generated (all scalar fields, depth 2)
./gql.py call currentUser
./gql.py call project --arg fullPath=my/proj
./gql.py call user --arg username=admin

# 4. IDOR / enumeration sweep
./gql.py loop project --vary fullPath --values-file paths.txt
./gql.py loop user    --vary id --gid-range 'gid://gitlab/User/1-200'
./gql.py loop runner  --vary id --gid-range 'gid://gitlab/Ci::Runner/1-1000' --delay 0.05

# 5. Authorization differential
./gql.py diff project --arg fullPath=private/proj \
        --as admin:PRIVATE-TOKEN=glpat-AAA \
        --as regular:PRIVATE-TOKEN=glpat-BBB \
        --as anon:

# 6. Show me the query you're about to send (don't actually send it)
./gql.py call projectUpdate --arg input=@json:'{"id":"gid://gitlab/Project/1","visibility":"private"}' --show-query only

# 7. Send a literal query string (when you've hand-crafted something specific)
./gql.py raw --query-file payload.graphql --variables '{"id":"gid://gitlab/User/1"}'
```

## How argument values work

`--arg name=value` accepts these value forms:

| Form | Becomes |
|---|---|
| `id=42` | int `42` |
| `id=true` | bool `true` |
| `name=alice` | string `"alice"` |
| `fullPath=group/proj` | string `"group/proj"` |
| `input=@json:{...}` | parsed as JSON (use for input-object args) |
| `body=@file:./body.md` | reads file contents as string |
| `id=null` | null |

Everything is sent as **GraphQL variables**, not interpolated into the query — so you don't have to worry about quoting or escaping.

## How selection works

By default, `gql.py` auto-generates a scalar-only selection set at depth 2:

```graphql
query GqlPy($fullPath: ID!) {
  project(fullPath: $fullPath) {
    __typename id name nameWithNamespace path fullPath description visibility
    archived createdAt lastActivityAt # ... all scalar fields
    namespace { __typename id name fullPath ... }  # one level into objects
  }
}
```

Override with `--select`:

```bash
# Pick specific fields
./gql.py call project --arg fullPath=my/proj --select "id name visibility"

# Full custom subquery
./gql.py call project --arg fullPath=my/proj \
        --select '{ id name members(first: 100) { nodes { user { username email } accessLevel { integerValue } } } }'

# Bump auto-depth for richer responses (warning: GitLab complexity limits)
./gql.py call project --arg fullPath=my/proj --depth 3
```

## Workflows for specific bug classes

### A. IDOR via GID

```bash
# Walk Project IDs 1..1000 with anonymous auth — anything that returns data is an info leak
./gql.py --header 'PRIVATE-TOKEN:' loop project \
        --vary fullPath --values-file probable_paths.txt \
        --select "id name visibility"

# Walk User IDs and watch for emails coming back
./gql.py loop user --vary id --gid-range 'gid://gitlab/User/1-500' \
        --select "id username name publicEmail"
```

The summary at the end groups responses by signature (status + error-message bucket + data-size bucket). Anomalies — signatures appearing only 1–2 times across a sweep of 500 — are your interesting cases.

### B. Authorization differential

The single highest-ROI workflow for GitLab GraphQL.

```bash
# For a private project, diff what each identity sees
./gql.py diff project --arg fullPath=secret-org/internal-tool \
        --as owner:PRIVATE-TOKEN=glpat-OwnerTok \
        --as guest:PRIVATE-TOKEN=glpat-GuestTok \
        --as anon:

# Report flags fields where guest/anon's response contains data NOT in owner's
# (impossible by definition — implies the lower-priv role saw something else)
```

Use against high-value resolvers: `project`, `group`, `mergeRequest`, `note`, `epic`, `runner`, `deployToken`, `vulnerability`, `auditEvent`.

### C. GID type confusion

```bash
# Spec: pass a Project GID where the schema expects a User
./gql.py call user --arg id='gid://gitlab/Project/1'
# Did the resolver: a) reject cleanly, b) return data anyway, c) crash 500?
```

Run that pattern across every `id: ID!`-style arg. The bugs are the ones where (b) or (c) happen.

### D. Token-scope bypass

Generate a minimal-scope PAT (e.g., `read_user` only). Then try every mutation:

```bash
export GQL_TOKEN='glpat-low-scope-token'
./gql.py ls --kind mutation | awk '/M /{print $2}' > all_mutations.txt
while read op; do
    echo "=== $op ==="
    ./gql.py call "$op" 2>&1 | head -5
done < all_mutations.txt
```

The successful ones (or ones returning anything other than "Insufficient scope") are the bugs.

### E. Internal-note / confidential-issue exposure

```bash
# Known patterns: 'internal' notes and 'confidential' issues should be invisible to non-members.
# Probe each issue ID in a public project with anon + low-priv tokens.
./gql.py diff issue --arg id='gid://gitlab/Issue/42' \
        --as member:PRIVATE-TOKEN=glpat-Member --as anon: \
        --select '{ id title confidential notes { nodes { internal body author { username } } } }'
```

### F. Field-suggestion-based recon when introspection is OFF

If `introspect` returns a 400 with `__schema disabled` errors, you can still:

- Use the bundled catalog — `./gql.py ls --no-schema` lists 20+ standard ops
- Use `./gql.py call <op> --no-schema` — sends the request with `String!` typed args. Server type errors will tell you the real expected type, letting you progressively refine.
- Use the GitLab schema reference file (committed in gitlab.com source) as a local map — no live introspection needed.

## Tips

- Set `GQL_CACHE_DIR` to put schema caches outside the repo. Default: `./.cache/`.
- Use `--show-query both` to print the constructed document for any `call` — useful for handing exact queries to Burp Repeater.
- `--raw-response` gives the unmodified JSON for piping into `jq`.
- For pagination-heavy ops (`projects`, `users`, anything `*Connection`), pass `--arg first=100` and walk `pageInfo` cursors yourself via `raw` if needed.

## Files

```
graphql/
├── gql.py                  # the tool
├── gitlab_catalog.json     # fallback operations when introspection is disabled
├── README.md               # this file
├── examples/
│   ├── authz-diff.sh
│   └── idor-sweep.sh
└── .cache/                 # gitignored — per-target schema dumps
```
