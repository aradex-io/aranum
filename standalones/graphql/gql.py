#!/usr/bin/env python3
"""gql.py — flexible GraphQL request builder, tuned for GitLab.

Zero external dependencies (stdlib only). Designed for authorized testing
of self-hosted GitLab where:
  * introspection may or may not be enabled
  * the standard GitLab schema is always assumed to "exist" via a fallback catalog
  * the operator wants to build syntactically-correct requests for arbitrary
    operations (including ones not yet seen) without hand-writing them

Subcommands:
    introspect      Pull and cache the full schema for a target.
    ls              List operations (Query/Mutation), optionally filtered.
    describe        Show one operation's full signature with arg types.
    call            Build + execute one operation. Auto-generates a sane
                    selection set if you don't pass one.
    loop            Vary ONE argument across a list of values (IDOR sweep).
    diff            Run the same operation under N auth profiles and diff.
    raw             Send a literal query string from --query or a file.

Auth (any combination, all subcommands):
    --token TOKEN       sets  PRIVATE-TOKEN: TOKEN          (GitLab PAT)
    --bearer TOKEN      sets  Authorization: Bearer TOKEN   (OAuth/JWT)
    --cookie 'k=v;...'  sets  Cookie: ...                   (session)
    --job-token TOKEN   sets  JOB-TOKEN: TOKEN              (CI job token)
    --header K:V        custom (repeatable)

Conventions:
    --url defaults to env GQL_URL.
    --token defaults to env GQL_TOKEN.
    Default URL path is /api/graphql (GitLab). For non-GitLab targets pass full URL.

Run with -h on any subcommand for details.
"""

from __future__ import annotations
import argparse
import json
import os
import re
import ssl
import sys
import urllib.request
import urllib.error
import urllib.parse
import hashlib
import time
import difflib
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------- paths
SCRIPT_DIR  = Path(__file__).resolve().parent
CACHE_DIR   = Path(os.environ.get("GQL_CACHE_DIR", str(SCRIPT_DIR / ".cache")))
CATALOG_F   = SCRIPT_DIR / "gitlab_catalog.json"

# ---------------------------------------------------------------- color
def _color(s: str, c: str) -> str:
    if not sys.stdout.isatty(): return s
    return {"R": "\033[1;31m", "G": "\033[1;32m", "Y": "\033[1;33m",
            "B": "\033[1;34m", "C": "\033[1;36m", "M": "\033[1;35m", "0": "\033[0m"}.get(c, "") + s + "\033[0m"

# =============================================================== HTTP
# Module-level switch for TLS verification. Set via --insecure / -k or GQL_INSECURE=1.
# Mirrors `curl -k`: when True, presented certs are accepted regardless of CA chain,
# hostname mismatch, expiry, or self-signed status. Default is False (verify).
_INSECURE_TLS = os.environ.get("GQL_INSECURE", "").lower() in ("1", "true", "yes")

# Iteration F.7 — proxy. urllib supports http/https proxies natively via
# ProxyHandler. For SOCKS we shell out to `socks5h://` env vars consumed by
# urllib via HTTP_PROXY/HTTPS_PROXY only if PySocks is importable. We DO NOT
# require PySocks — operators who need SOCKS pivot via ssh -D + an http proxy
# in front (chisel/ligolo provide both).
_PROXY = os.environ.get("GQL_PROXY") or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""

# Iteration F.8 — User-Agent. Default is a Chrome-stable string so we don't
# stand out to WAFs / IDS. `gql.py/1.0` is preserved as an opt-in via
# --user-agent gql or --user-agent <literal>.
_DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
_UA = os.environ.get("GQL_UA") or _DEFAULT_UA
_UA_LIST: list[str] = []     # populated when --ua-rotate is on


def _ssl_context() -> ssl.SSLContext | None:
    """Return an unverified SSLContext when --insecure is active, else None
    (urlopen then uses the platform default verifying context)."""
    if not _INSECURE_TLS:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _opener():
    """urllib opener with proxy handler when --proxy / *_PROXY env is set."""
    if _PROXY:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": _PROXY, "https": _PROXY}),
            urllib.request.HTTPHandler(),
            urllib.request.HTTPSHandler(context=_ssl_context()),
        )
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_context()),
    )


def _pick_ua() -> str:
    """Pick a User-Agent — rotated from _UA_LIST when --ua-rotate, else _UA."""
    if _UA_LIST:
        import random
        return random.choice(_UA_LIST)
    return _UA


def http_post(url: str, payload, headers: dict, timeout: int = 30) -> tuple[int, dict, dict]:
    """POST JSON. Returns (status, response-headers, parsed-body-or-text).
    payload may be a dict (standard GraphQL body) OR a list (batched-query
    body — iteration F.2)."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _pick_ua())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with _opener().open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:    parsed = json.loads(body)
            except: parsed = {"_raw": body}
            return r.status, dict(r.headers), parsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:    parsed = json.loads(body)
        except: parsed = {"_raw": body, "_status": e.code}
        return e.code, dict(e.headers), parsed
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", e)
        # Surface SSL-specific errors with a hint about --insecure so operators
        # don't have to decode the stdlib's noisy SSLCertVerificationError repr.
        hint = ""
        if isinstance(reason, ssl.SSLError) or "certificate" in str(reason).lower() or "ssl" in str(reason).lower():
            hint = "  (TLS error — retry with --insecure / -k or GQL_INSECURE=1 to bypass cert verification)"
        return 0, {}, {"_error": f"connection failed: {reason}{hint}"}


def http_get(url: str, headers: dict, timeout: int = 30) -> tuple[int, dict, dict]:
    """GET (for the CSRF-via-GET probe — iteration F.5). Returns (status, hdrs, parsed)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", _pick_ua())
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with _opener().open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
            try:    parsed = json.loads(body)
            except: parsed = {"_raw": body}
            return r.status, dict(r.headers), parsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:    parsed = json.loads(body)
        except: parsed = {"_raw": body, "_status": e.code}
        return e.code, dict(e.headers), parsed
    except urllib.error.URLError as e:
        return 0, {}, {"_error": f"connection failed: {getattr(e, 'reason', e)}"}


def build_headers(args: argparse.Namespace) -> dict:
    h: dict[str, str] = {}
    if args.token:     h["PRIVATE-TOKEN"] = args.token
    if args.bearer:    h["Authorization"] = "Bearer " + args.bearer
    if args.cookie:    h["Cookie"] = args.cookie
    if args.job_token: h["JOB-TOKEN"] = args.job_token
    for hh in (args.header or []):
        if ":" not in hh:
            print(f"[!] bad header (need K:V): {hh}", file=sys.stderr); sys.exit(2)
        k, v = hh.split(":", 1)
        h[k.strip()] = v.strip()
    return h


# =============================================================== Schema cache
# Every header that materially identifies the calling principal must be folded
# into the cache key — otherwise two sessions that differ only in cookie or
# JOB-TOKEN value collide on the same cached schema (older versions did exactly
# this, defaulting both to the literal string "anon"). Order is fixed so the
# same identity always hashes to the same key.
_CACHE_KEY_HEADERS = ("PRIVATE-TOKEN", "Authorization", "Cookie", "JOB-TOKEN")


def cache_key(url: str, headers: dict) -> Path:
    """Cache per URL + auth-identity. Includes every header that distinguishes
    a principal so cookie / job-token / PAT sessions don't share a cache file."""
    parts = [url]
    found_any = False
    for h in _CACHE_KEY_HEADERS:
        v = headers.get(h)
        if v:
            parts.append(f"{h}={v}")
            found_any = True
    if not found_any:
        parts.append("anon")
    ident_src = "|".join(parts)
    h = hashlib.sha256(ident_src.encode()).hexdigest()[:16]
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"schema_{h}.json"


INTROSPECTION_QUERY = r"""
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description isDeprecated
        args {
          name description type { ...TypeRef } defaultValue
        }
        type { ...TypeRef }
      }
      inputFields {
        name description type { ...TypeRef } defaultValue
      }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated }
      possibleTypes { ...TypeRef }
    }
  }
}
fragment TypeRef on __Type {
  kind name ofType {
    kind name ofType {
      kind name ofType {
        kind name ofType {
          kind name ofType {
            kind name ofType {
              kind name ofType { kind name }
            }
          }
        }
      }
    }
  }
}
"""


def fetch_schema(url: str, headers: dict) -> dict:
    status, _, body = http_post(url, {"query": INTROSPECTION_QUERY}, headers)
    if status != 200:
        raise RuntimeError(f"introspection failed: HTTP {status} — {body}")
    if "errors" in body:
        raise RuntimeError(f"introspection errors: {body['errors']}")
    return body["data"]["__schema"]


def load_schema(url: str, headers: dict, force_refresh: bool = False) -> dict | None:
    """Try cache → live introspection → None (caller decides if it falls back to catalog)."""
    cf = cache_key(url, headers)
    if cf.exists() and not force_refresh:
        try:    return json.loads(cf.read_text())
        except: pass
    try:
        schema = fetch_schema(url, headers)
        cf.write_text(json.dumps(schema, indent=2))
        return schema
    except Exception as e:
        print(_color(f"[!] introspection unavailable: {e}", "Y"), file=sys.stderr)
        return None


def load_catalog() -> dict:
    if not CATALOG_F.exists():
        return {"queries": {}, "mutations": {}}
    return json.loads(CATALOG_F.read_text())


# =============================================================== Type plumbing
def type_str(t: dict) -> str:
    """Reconstruct '[Foo!]!' from the introspection nested ofType chain."""
    if t is None: return ""
    if t.get("kind") == "NON_NULL":
        return type_str(t["ofType"]) + "!"
    if t.get("kind") == "LIST":
        return "[" + type_str(t["ofType"]) + "]"
    return t.get("name") or "?"


def unwrap(t: dict) -> dict:
    """Strip NON_NULL/LIST wrappers, return the inner named type."""
    while t and t.get("kind") in ("NON_NULL", "LIST"):
        t = t.get("ofType") or {}
    return t


def type_by_name(schema: dict, name: str) -> dict | None:
    if not schema: return None
    for t in schema.get("types", []):
        if t.get("name") == name: return t
    return None


def operations(schema: dict, kind: str) -> dict[str, dict]:
    """Return {name: field-def} for Query (kind='query') or Mutation (kind='mutation')."""
    if not schema: return {}
    root_name = (schema.get("queryType") if kind == "query" else schema.get("mutationType") or {}).get("name")
    if not root_name: return {}
    root = type_by_name(schema, root_name)
    return {f["name"]: f for f in (root.get("fields") or [])}


def find_operation(schema: dict | None, catalog: dict, name: str) -> tuple[str, dict] | None:
    """Locate an op in schema, then fall back to catalog. Returns (kind, opdef)."""
    if schema:
        q = operations(schema, "query")
        if name in q: return "query", q[name]
        m = operations(schema, "mutation")
        if name in m: return "mutation", m[name]
    cq = catalog.get("queries", {})
    cm = catalog.get("mutations", {})
    if name in cq: return "query", cq[name]
    if name in cm: return "mutation", cm[name]
    return None


# =============================================================== Selection-set builder
SCALAR_KINDS = {"SCALAR", "ENUM"}

def build_selection(schema: dict | None, return_type: dict, depth: int = 2, _seen: set | None = None) -> str:
    """Auto-generate a selection set for a return type.

    Strategy:
      * Scalar/enum return  ->  '' (no braces needed; caller checks)
      * Object/interface    ->  '{ ' + all scalar/enum fields + (one level of nested object scalars at depth>1) + ' }'
      * Cycles broken via _seen
    """
    if _seen is None: _seen = set()
    base = unwrap(return_type)
    name = base.get("name")
    kind = base.get("kind")

    if kind in SCALAR_KINDS:
        return ""  # scalar — no sub-selection
    if not schema or not name:
        return "{ __typename }"  # unknown — minimal valid
    if name in _seen:
        return "{ __typename }"
    _seen.add(name)

    t = type_by_name(schema, name)
    if not t or not t.get("fields"):
        # Could be a UNION (no direct fields) — must use inline fragments per possibleType. Minimal:
        return "{ __typename }"

    parts: list[str] = ["__typename"]
    for f in t["fields"]:
        if f.get("args"):  # skip fields that REQUIRE args at the top level — would error
            required = [a for a in f["args"] if (a.get("type") or {}).get("kind") == "NON_NULL"]
            if required: continue
        ftype  = unwrap(f.get("type") or {})
        fkind  = ftype.get("kind")
        if fkind in SCALAR_KINDS:
            parts.append(f["name"])
        elif depth > 1 and fkind in ("OBJECT", "INTERFACE"):
            sub = build_selection(schema, f["type"], depth - 1, _seen.copy())
            if sub:
                parts.append(f"{f['name']} {sub}")
    return "{ " + " ".join(parts) + " }"


# =============================================================== Query builder
def build_query(op_kind: str, op_name: str, op_def: dict, args: dict[str, Any],
                schema: dict | None, selection: str | None, depth: int = 2) -> tuple[str, dict]:
    """Compose a parameterised GraphQL document + variables dict.

    args values may be:
      - already-typed JSON-coercible values (int/bool/list/dict)
      - strings (we keep them as strings)
      - a 'gid://...' shape string for ID args
      - JSON literal prefixed with '@json:' (we parse it)
    Anything we don't recognize is passed as a string.

    Returns (query_doc, variables_dict).
    """
    # ---- build variable decl + arg call lines
    var_decls: list[str] = []
    call_args: list[str] = []
    variables: dict[str, Any] = {}

    op_args = {a["name"]: a for a in (op_def.get("args") or [])}

    for k, v in args.items():
        if k not in op_args:
            # Unknown arg — still let user pass it as String (lets you probe schemas we don't know yet).
            # Default to String! so the server complains in a useful way.
            tdecl = "String"
        else:
            tdecl = type_str(op_args[k]["type"])

        var_decls.append(f"${k}: {tdecl}")
        call_args.append(f"{k}: ${k}")

        # Value coercion
        if isinstance(v, str):
            if v.startswith("@json:"):
                try:
                    variables[k] = json.loads(v[6:])
                except json.JSONDecodeError as e:
                    print(_color(f"[!] --arg {k}: invalid JSON in @json: value: {e}", "R"), file=sys.stderr)
                    sys.exit(2)
            elif v.startswith("@file:"):
                try:
                    variables[k] = Path(v[6:]).read_text().rstrip("\n")
                except OSError as e:
                    print(_color(f"[!] --arg {k}: cannot read @file: path: {e}", "R"), file=sys.stderr)
                    sys.exit(2)
            elif v == "true":  variables[k] = True
            elif v == "false": variables[k] = False
            elif v == "null":  variables[k] = None
            elif re.match(r"^-?\d+$", v):     variables[k] = int(v)
            elif re.match(r"^-?\d+\.\d+$", v): variables[k] = float(v)
            else: variables[k] = v
        else:
            variables[k] = v

    # ---- build selection set
    if selection is None:
        sel = build_selection(schema, op_def.get("type") or {}, depth=depth)
    elif selection == "":
        sel = ""           # scalar return — nothing
    elif selection.startswith("{"):
        sel = selection    # already wrapped
    else:
        # treat space-separated list as field names
        sel = "{ " + " ".join(selection.split()) + " }"

    vars_decl = "(" + ", ".join(var_decls) + ")" if var_decls else ""
    args_call = "(" + ", ".join(call_args) + ")" if call_args else ""
    doc = f"{op_kind} GqlPy{vars_decl} {{\n  {op_name}{args_call} {sel}\n}}\n"
    return doc, variables


# =============================================================== Output
def print_response(status: int, body: dict, args: argparse.Namespace) -> int:
    if args.raw_response:
        print(json.dumps(body, indent=2))
        return 0

    if "_error" in body:
        print(_color(f"[!] {body['_error']}", "R")); return 1

    if "errors" in body:
        print(_color(f"[!] HTTP {status} — GraphQL errors:", "R"))
        for e in body["errors"]:
            msg = e.get("message", "?")
            path = e.get("path") or []
            ext  = e.get("extensions") or {}
            print(f"    - {msg}")
            if path: print(f"      path: {'.'.join(map(str, path))}")
            if ext:  print(f"      extensions: {json.dumps(ext)}")

    if "data" in body and body["data"] is not None:
        print(_color(f"[+] HTTP {status} — data:", "G"))
        print(json.dumps(body["data"], indent=2))
        return 0
    if "errors" in body:
        return 1
    print(_color(f"[?] HTTP {status} — unexpected body:", "Y"))
    print(json.dumps(body, indent=2))
    return 1


# =============================================================== Subcommand: introspect
def cmd_introspect(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    print(_color(f"[*] GET schema from {args.url}", "C"))
    try:
        schema = fetch_schema(args.url, headers)
    except Exception as e:
        print(_color(f"[!] {e}", "R")); return 1
    cf = cache_key(args.url, headers)
    cf.parent.mkdir(parents=True, exist_ok=True)
    cf.write_text(json.dumps(schema, indent=2))
    out = args.save or str(cf)
    if args.save:
        Path(args.save).write_text(json.dumps(schema, indent=2))
    qcount = len(operations(schema, "query"))
    mcount = len(operations(schema, "mutation"))
    tcount = len(schema.get("types", []))
    print(_color(f"[+] cached: {out}", "G"))
    print(f"    queries={qcount}  mutations={mcount}  types={tcount}")
    return 0


# =============================================================== Subcommand: ls
def cmd_ls(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    schema  = load_schema(args.url, headers) if args.url else None
    catalog = load_catalog()
    pat     = re.compile(args.filter, re.I) if args.filter else None

    def emit(name: str, op: dict, kind: str, source: str):
        if pat and not pat.search(name): return
        ret = type_str(op.get("type") or {})
        arg_count = len(op.get("args") or [])
        print(f"  {_color(kind[0].upper(), 'C')}  {name:48s}  {ret:36s}  args={arg_count}  [{source}]")

    if args.kind in ("all", "query"):
        if schema:
            for n, op in sorted(operations(schema, "query").items()):
                emit(n, op, "query", "schema")
        else:
            for n, op in sorted(catalog.get("queries", {}).items()):
                emit(n, op, "query", "catalog")
    if args.kind in ("all", "mutation"):
        if schema:
            for n, op in sorted(operations(schema, "mutation").items()):
                emit(n, op, "mutation", "schema")
        else:
            for n, op in sorted(catalog.get("mutations", {}).items()):
                emit(n, op, "mutation", "catalog")
    return 0


# =============================================================== Subcommand: describe
def cmd_describe(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    schema  = load_schema(args.url, headers) if args.url else None
    catalog = load_catalog()
    found   = find_operation(schema, catalog, args.operation)
    if not found:
        print(_color(f"[!] not found in schema or catalog: {args.operation}", "R")); return 1
    kind, op = found
    ret = type_str(op.get("type") or {})
    print(_color(f"{kind} {args.operation}", "C"))
    print(f"  returns: {ret}")
    if op.get("description"):
        print(f"  doc:     {op['description']}")
    if op.get("args"):
        print("  args:")
        for a in op["args"]:
            t = type_str(a.get("type") or {})
            dv = a.get("defaultValue")
            doc = a.get("description") or ""
            line = f"    {a['name']}: {t}"
            if dv is not None: line += f" = {dv}"
            if doc: line += f"   # {doc[:80]}"
            print(line)
    else:
        print("  args:   (none)")
    # Show what selection we'd auto-generate
    if schema:
        sel = build_selection(schema, op.get("type") or {}, depth=2)
        if sel: print(f"  auto-selection: {sel[:200]}{'...' if len(sel)>200 else ''}")
    return 0


# =============================================================== Subcommand: call
_GQL_IDENT_RE = re.compile(r"^[_A-Za-z][_A-Za-z0-9]*$")


def parse_kv_args(kvs: list[str]) -> dict[str, str]:
    """Parse list of 'name=value' into dict. Value is always str at this stage."""
    out: dict[str, str] = {}
    for kv in kvs or []:
        if "=" not in kv:
            print(_color(f"[!] bad --arg (need name=value): {kv}", "R"), file=sys.stderr); sys.exit(2)
        k, v = kv.split("=", 1)
        if not _GQL_IDENT_RE.match(k):
            print(_color(f"[!] bad --arg: invalid GraphQL variable name {k!r} "
                         f"(must match ^[_A-Za-z][_A-Za-z0-9]*$)", "R"), file=sys.stderr)
            sys.exit(2)
        if k in out:
            print(_color(f"[!] duplicate --arg {k!r} — last value wins", "Y"), file=sys.stderr)
        out[k] = v
    return out


def cmd_call(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    schema  = load_schema(args.url, headers) if not args.no_schema else None
    catalog = load_catalog()
    found   = find_operation(schema, catalog, args.operation)
    if not found:
        print(_color(f"[!] not found: {args.operation} — try `introspect` first or check catalog", "R")); return 1
    kind, op = found

    arg_values = parse_kv_args(args.arg)
    doc, variables = build_query(kind, args.operation, op, arg_values, schema, args.select, depth=args.depth)

    if args.show_query:
        print(_color("--- query ---", "M"))
        print(doc)
        print(_color("--- variables ---", "M"))
        print(json.dumps(variables, indent=2))
        if args.show_query == "only": return 0

    # F.6 — alias-DoS detection (detect-only, requires --confirm)
    if getattr(args, "alias_dos_check", False):
        if not getattr(args, "confirm", False):
            print(_color("[!] --alias-dos-check requires --confirm (operator acknowledges this is a", "R"))
            print(_color("    timing-measurement probe and could be noticed as an availability test).", "R"))
            return 2
        n_max = max(1, int(getattr(args, "alias_dos_max", 16)))
        print(_color(f"[*] alias-DoS check — N=1..{n_max}", "C"))
        latencies = _alias_dos_check(args.url, args.operation, op, headers, n_max)
        prev = None
        super_linear = False
        for n, ms in sorted(latencies.items()):
            ratio = (ms / prev) if prev else 1.0
            flag = ""
            if prev and ratio > 2.5:
                flag = _color("  super-linear growth (alias normalization may be missing)", "R")
                super_linear = True
            print(f"  N={n:4d}  {ms:6d}ms  ratio_vs_prev={ratio:.2f}x  {flag}")
            prev = ms
        if super_linear:
            print(_color("[!!] alias normalization appears absent — possible DoS-amplification surface", "R"))
        else:
            print(_color("[+] latency scales linearly with N — server normalizes aliased fields", "G"))
        return 0

    # F.2 — batched-query support
    if getattr(args, "batch", 0) and args.batch > 1:
        payload = [{"query": doc, "variables": variables}] * int(args.batch)
        status, _, parsed = http_post(args.url, payload, headers)
        if isinstance(parsed, list):
            print(_color(f"[+] HTTP {status} — batched response: {len(parsed)} entries", "G"))
            print(json.dumps(parsed, indent=2))
            return 0
        return print_response(status, parsed, args)

    status, _, body = http_post(args.url, {"query": doc, "variables": variables}, headers)
    return print_response(status, body, args)


# =============================================================== Subcommand: loop
# Hard cap on values an unguarded --range / --gid-range will materialize.
# A typo'd 1-9999999999 used to OOM the process before the first request fired.
LOOP_HARD_CAP = 1_000_000


def _check_range_size(lo: int, hi: int, flag_name: str, allow_huge: bool) -> int:
    """Validate bounds + size. Returns count. Exits 2 on bad input."""
    if hi < lo:
        print(_color(f"[!] {flag_name}: hi ({hi}) < lo ({lo})", "R"), file=sys.stderr); sys.exit(2)
    count = hi - lo + 1
    if count > LOOP_HARD_CAP and not allow_huge:
        print(_color(
            f"[!] {flag_name} would expand to {count:,} values (> {LOOP_HARD_CAP:,}). "
            f"Pass --allow-huge if you really mean it.", "R"), file=sys.stderr)
        sys.exit(2)
    return count


def cmd_loop(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    schema  = load_schema(args.url, headers) if not args.no_schema else None
    catalog = load_catalog()
    found   = find_operation(schema, catalog, args.operation)
    if not found:
        print(_color(f"[!] not found: {args.operation}", "R")); return 1
    kind, op = found

    # Read the values for the varying arg. --range / --gid-range produce
    # generators (not lists) so a 100k+ sweep doesn't materialize all values
    # in memory before the first request fires; the bounds check happens
    # before the generator is consumed.
    values: Iterable[str]            # type: ignore[name-defined]
    total: int | None
    if args.values_file:
        try:
            vs = [l.strip() for l in Path(args.values_file).read_text().splitlines()
                  if l.strip() and not l.strip().startswith("#")]
        except OSError as e:
            print(_color(f"[!] --values-file: cannot read file: {e}", "R"), file=sys.stderr); return 2
        values, total = vs, len(vs)
    elif args.values:
        values, total = args.values, len(args.values)
    elif args.range:
        try:    lo, hi = (int(x) for x in args.range.split("-"))
        except Exception:
            print(_color("[!] --range form is <lo>-<hi> (integers)", "R")); return 2
        total = _check_range_size(lo, hi, "--range", args.allow_huge)
        values = (str(i) for i in range(lo, hi + 1))
    elif args.gid_range:
        # e.g.  --gid-range 'gid://gitlab/Project/100-200'
        m = re.match(r"^(.*)/(\d+)-(\d+)$", args.gid_range)
        if not m: print(_color("[!] --gid-range form is <prefix>/<lo>-<hi>", "R")); return 1
        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        total = _check_range_size(lo, hi, "--gid-range", args.allow_huge)
        values = (f"{prefix}/{i}" for i in range(lo, hi + 1))
    else:
        print(_color("[!] one of --values, --values-file, --range, --gid-range required", "R")); return 1

    base = parse_kv_args(args.arg)

    print(_color(f"[*] sweeping {args.operation} with {args.vary}=<value> over {total} values", "C"))
    print(_color(f"    response classifier: status, error message, data size", "C"))
    print()
    seen_signatures: dict[tuple, int] = {}

    for v in values:
        a = dict(base); a[args.vary] = v
        doc, variables = build_query(kind, args.operation, op, a, schema, args.select, depth=args.depth)
        status, _, body = http_post(args.url, {"query": doc, "variables": variables}, headers)

        # Classify the response
        has_data   = bool(body.get("data") and any(body["data"].values()))
        err_msgs   = tuple(sorted({e.get("message","")[:60] for e in (body.get("errors") or [])}))
        data_size  = len(json.dumps(body.get("data") or {}))
        sig = (status, has_data, err_msgs, data_size // 100)   # bucket by 100B for size noise
        seen_signatures[sig] = seen_signatures.get(sig, 0) + 1

        flag = " "
        if has_data: flag = _color("+", "G")
        elif status >= 500: flag = _color("!", "R")
        elif err_msgs and any("authoriz" in e.lower() or "permission" in e.lower() for e in err_msgs): flag = _color("=", "Y")
        elif err_msgs: flag = _color("-", "Y")

        print(f"  [{flag}] {v:50s} status={status} size={data_size:6d}  errs={list(err_msgs)[:1]}")

        if args.delay: time.sleep(args.delay)

    print()
    print(_color("--- response-signature summary ---", "M"))
    for sig, n in sorted(seen_signatures.items(), key=lambda x: -x[1]):
        status, has_data, errs, _ = sig
        marker = "DATA" if has_data else ("ERR" if errs else "?")
        print(f"  ×{n:4d}  status={status} {marker:5s} errs={list(errs)[:1]}")
    print(_color("[*] anomalies = signatures that appear only 1–2 times — investigate those", "C"))
    return 0


# =============================================================== Subcommand: diff
def cmd_diff(args: argparse.Namespace) -> int:
    # Each --as is "label:HEADER=VALUE" (e.g. "alice:PRIVATE-TOKEN=glpat-..." or "anon:")
    if not args.as_ or len(args.as_) < 2:
        print(_color("[!] need at least two --as profiles (e.g. --as alice:PRIVATE-TOKEN=glpat-abc --as anon:)", "R")); return 1

    profiles: list[tuple[str, dict]] = []
    for spec in args.as_:
        label, _, hdr = spec.partition(":")
        h: dict = {}
        if hdr and "=" in hdr:
            k, v = hdr.split("=", 1)
            h[k.strip()] = v.strip()
        # Also fold-in base headers from common flags
        for hh in (args.header or []):
            if ":" in hh:
                k, v = hh.split(":", 1); h[k.strip()] = v.strip()
        profiles.append((label or "anon", h))

    catalog = load_catalog()
    # Use the FIRST profile's identity for schema lookup (highest-priv presumed)
    schema = load_schema(args.url, profiles[0][1]) if not args.no_schema else None
    found  = find_operation(schema, catalog, args.operation)
    if not found:
        print(_color(f"[!] not found: {args.operation}", "R")); return 1
    kind, op = found

    arg_values = parse_kv_args(args.arg)
    doc, variables = build_query(kind, args.operation, op, arg_values, schema, args.select, depth=args.depth)

    print(_color(f"[*] {kind} {args.operation} as {[p[0] for p in profiles]}", "C"))
    print(_color(f"    args: {arg_values}", "C"))
    print()

    results: list[tuple[str, int, dict]] = []
    for i, (label, h) in enumerate(profiles):
        per_vars = dict(variables)
        status, _, body = http_post(args.url, {"query": doc, "variables": per_vars}, h)
        results.append((label, status, body))
        ok = "ERR" if "errors" in body else "OK"
        size = len(json.dumps(body.get("data") or {}))
        print(f"  [{label:10s}] http={status} {ok} data={size}B errs={len(body.get('errors') or [])}")

    print()
    # Pairwise diff between the FIRST profile (presumed reference / high-priv)
    # and each other profile.
    ref_label, _, ref_body = results[0]
    ref_text = json.dumps(ref_body.get("data") or {}, indent=2, sort_keys=True)
    for other_label, _, other_body in results[1:]:
        other_text = json.dumps(other_body.get("data") or {}, indent=2, sort_keys=True)
        print(_color(f"=== diff: {ref_label} vs {other_label} ===", "M"))
        diff = list(difflib.unified_diff(ref_text.splitlines(keepends=True),
                                         other_text.splitlines(keepends=True),
                                         fromfile=ref_label, tofile=other_label, n=2))
        if diff:
            sys.stdout.writelines(diff)
            # Heuristic: low-priv sees something high-priv doesn't = bug
            ref_lines   = set(ref_text.splitlines())
            other_lines = set(other_text.splitlines())
            extra_in_other = other_lines - ref_lines - {""}
            if extra_in_other and other_label != ref_label:
                print(_color(f"\n[!!] {other_label} response contains lines NOT in {ref_label} — possible authz bug:", "R"))
                for l in sorted(extra_in_other)[:20]:
                    print(f"    {l}")
        else:
            print(_color("  (identical) — same authz outcome; not necessarily a bug, but no leak.", "G"))
        print()
    return 0


# =============================================================== Subcommand: raw
def cmd_raw(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    if args.query_file:
        try:
            query = Path(args.query_file).read_text()
        except OSError as e:
            print(_color(f"[!] --query-file: cannot read file: {e}", "R"), file=sys.stderr); return 2
    elif args.query:
        query = args.query
    else:
        print(_color("[!] need --query '...' or --query-file path", "R")); return 1
    if args.variables:
        try:
            variables = json.loads(args.variables)
        except json.JSONDecodeError as e:
            print(_color(f"[!] --variables: invalid JSON: {e}", "R"), file=sys.stderr); return 2
    else:
        variables = {}
    body_dict = {"query": query, "variables": variables}
    # F.2 — batched body: send [body, body, body, ...]. Useful when the gateway
    # processes batches but applies rate-limits per-request, or when authz is
    # checked per-request but a shared resolver leaks state.
    if getattr(args, "batch", 0) and args.batch > 1:
        payload = [body_dict] * int(args.batch)
        status, _, parsed = http_post(args.url, payload, headers)
        if isinstance(parsed, list):
            print(_color(f"[+] HTTP {status} — batched response: {len(parsed)} entries", "G"))
            print(json.dumps(parsed, indent=2))
            return 0
        return print_response(status, parsed, args)
    status, _, body = http_post(args.url, body_dict, headers)
    return print_response(status, body, args)


# =============================================================== Subcommand: suggest (F.1)
# When introspection is disabled but the resolver still returns "Did you mean
# `<field>`?" on a malformed query, walk a corpus of guesses and harvest the
# suggestions to reconstruct the schema. Operator supplies a corpus or we
# use a tiny built-in.
_BUILTIN_SUGGEST_CORPUS = [
    "user", "users", "userById", "currentUser", "me", "viewer", "project",
    "projects", "group", "groups", "issue", "issues", "mergeRequest", "epic",
    "runner", "runners", "deployToken", "deployTokens", "pipeline", "pipelines",
    "vulnerabilities", "vulnerability", "ciConfig", "ciJob", "ciJobs",
    "auditEvent", "auditEvents", "secret", "secrets", "token", "tokens",
    "admin", "settings", "config",
]
_DID_YOU_MEAN_RE = re.compile(r"[Dd]id you mean\s+(?:[`'\"]?)([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_SUGGEST_LIST_RE = re.compile(r"[Dd]id you mean\s+([^?\n]+)\?", re.MULTILINE)


def cmd_suggest(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    corpus: list[str] = list(_BUILTIN_SUGGEST_CORPUS)
    if args.corpus:
        try:
            corpus = [w.strip() for w in Path(args.corpus).read_text().splitlines()
                      if w.strip() and not w.strip().startswith("#")]
        except OSError as e:
            print(_color(f"[!] --corpus: cannot read file: {e}", "R"), file=sys.stderr); return 2
    print(_color(f"[*] field-suggestion harvest against {args.url} ({len(corpus)} guesses)", "C"))
    print(_color("    method: send malformed Query.<guess>; harvest Did-you-mean from errors", "C"))
    print()

    discovered: set[str] = set()
    for guess in corpus:
        doc = f"query GqlPySuggest {{ {guess} {{ __typename }} }}"
        status, _, body = http_post(args.url, {"query": doc, "variables": {}}, headers)
        errs = body.get("errors") or []
        for e in errs:
            msg = e.get("message", "")
            # Pattern: 'Field "foo" doesn\'t exist on type "Query". Did you mean `bar`?'
            for m in _DID_YOU_MEAN_RE.finditer(msg):
                discovered.add(m.group(1))
            # GitLab variant: 'Did you mean foo, bar, baz?'
            for m in _SUGGEST_LIST_RE.finditer(msg):
                for cand in re.split(r"[, ]+|\s+or\s+", m.group(1)):
                    cand = cand.strip(" `'\"")
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cand):
                        discovered.add(cand)
        # If the response had NO errors, the guess was a real field — also a win.
        if status == 200 and "data" in body and not errs:
            discovered.add(guess)
        if args.delay:
            time.sleep(args.delay)

    print(_color(f"[+] harvested {len(discovered)} field name(s):", "G"))
    for name in sorted(discovered):
        print(f"  - {name}")
    if args.out:
        Path(args.out).write_text("\n".join(sorted(discovered)) + "\n")
        print(_color(f"[+] written to {args.out}", "G"))
    return 0


# =============================================================== Subcommand: apq-probe (F.3)
# Apollo Persisted Queries: client sends extensions.persistedQuery = {version:1,
# sha256Hash:<hash>} with no body. Server replies PersistedQueryNotFound, then
# client sends both body + hash, and server caches. Bug class: some gateways
# accept *any* hash if you also send a body — that breaks per-hash whitelist
# enforcement, letting an attacker run arbitrary queries.
def cmd_apq_probe(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    base_query = "{ __typename }"
    fake_hash = "0" * 64
    print(_color(f"[*] APQ probe against {args.url}", "C"))
    print()

    # 1. send the hash-only body (no `query` key) — expected: PersistedQueryNotFound
    body1 = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": fake_hash}}}
    s1, _, r1 = http_post(args.url, body1, headers)
    errs1 = [e.get("message", "")[:80] for e in (r1.get("errors") or [])]
    pqnf = any("PersistedQueryNotFound" in m for m in errs1)
    print(f"  step1 hash-only             HTTP {s1}  errs={errs1[:1]}")
    if s1 == 0 or "_error" in r1:
        print(_color(f"[!] connection failed — cannot determine APQ support: "
                     f"{r1.get('_error', 'unreachable')}", "R"), file=sys.stderr)
        return 1
    if not pqnf:
        print(_color("  [-] no PersistedQueryNotFound — server does not implement APQ", "Y"))
        return 0
    print(_color("  [+] APQ is implemented", "G"))

    # 2. send body + arbitrary hash. If server accepts (200 with data) the hash
    #    isn't being verified -> persisted-query whitelist bypass.
    body2 = {"query": base_query,
             "extensions": {"persistedQuery": {"version": 1, "sha256Hash": fake_hash}}}
    s2, _, r2 = http_post(args.url, body2, headers)
    data2 = r2.get("data") or {}
    errs2 = [e.get("message", "")[:80] for e in (r2.get("errors") or [])]
    print(f"  step2 body+fake-hash        HTTP {s2}  data={bool(data2)}  errs={errs2[:1]}")
    if data2 and not errs2:
        print(_color("[!!] CRITICAL: server returned data with a FORGED sha256Hash + arbitrary body", "R"))
        print(_color("     -> persisted-query whitelist is bypassable; APQ is not enforcing the hash", "R"))
    elif any("provided sha does not match" in m.lower() or "hash mismatch" in m.lower() for m in errs2):
        print(_color("  [+] server rejected the forged hash — APQ enforcement is intact", "G"))
    else:
        print(_color("  [?] indeterminate — inspect raw response below", "Y"))
        print(json.dumps(r2, indent=2)[:600])
    return 0


# =============================================================== Subcommand: csrf-probe (F.5)
# Many GraphQL servers accept queries over HTTP GET when they shouldn't.
# Combined with cookie auth (no CSRF token) this enables a one-click CSRF.
def cmd_csrf_probe(args: argparse.Namespace) -> int:
    headers = build_headers(args)
    # Try GET /graphql?query={__typename}
    test_q = "{__typename}"
    qstring = urllib.parse.urlencode({"query": test_q})  # noqa: F821
    sep = "&" if "?" in args.url else "?"
    get_url = f"{args.url}{sep}{qstring}"
    print(_color(f"[*] CSRF-via-GET probe", "C"))
    print(f"    target: {get_url}")

    s, _, body = http_get(get_url, headers)
    data = body.get("data") or {}
    errs = [e.get("message", "")[:120] for e in (body.get("errors") or [])]
    print(f"  HTTP {s}  data={bool(data)}  errs={errs[:1]}")
    if data and not errs and s == 200:
        print(_color("[!!] CRITICAL: GET /graphql?query=... succeeded — GraphQL CSRF vector", "R"))
        print(_color("     If cookie auth is enabled, an attacker img/iframe loads this URL", "R"))
        print(_color("     and executes arbitrary queries (read or mutation) in the user's session.", "R"))
        # Mutation-via-GET is the more dangerous variant — try a benign one.
        # We use __typename which is universally safe; the test is whether GET
        # is accepted for ANY operation, which it shouldn't be per spec.
    elif s in (400, 405):
        print(_color("  [+] GET correctly rejected (HTTP {})".format(s), "G"))
    else:
        print(_color(f"  [?] indeterminate (status {s}, errs={errs[:1]})", "Y"))
    return 0


# =============================================================== Helper: alias-DoS detection (F.6)
# Build a query with N aliases of the same field and measure the latency
# growth. If latency scales super-linearly with N, the server is not
# normalizing aliased queries (per Apollo cost-analysis best-practice).
# DETECT-ONLY — we never exceed N=16 by default, refuse without --confirm.
def _alias_dos_check(url: str, operation: str, op: dict, headers: dict,
                     n_max: int) -> dict:
    """Run with N=1, 2, 4, 8, ... up to n_max and return a {n: elapsed_ms} map."""
    out: dict[int, int] = {}
    n = 1
    # Build a single field selection using the existing builder; if it's not
    # a scalar return, wrap in __typename.
    while n <= n_max:
        aliases = " ".join(f"a{i}: __typename" for i in range(n))
        doc = f"query GqlPyAliasDos {{ {aliases} }}"
        t0 = time.monotonic()
        status, _, _ = http_post(url, {"query": doc, "variables": {}}, headers)
        elapsed = int((time.monotonic() - t0) * 1000)
        out[n] = elapsed
        if status == 0:                  # connect fail — stop
            break
        n *= 2
    return out


# =============================================================== argparser
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url",       default=os.environ.get("GQL_URL", ""), help="GraphQL endpoint (env: GQL_URL). For GitLab: https://gitlab.example.com/api/graphql")
    ap.add_argument("--token",     default=os.environ.get("GQL_TOKEN", ""), help="GitLab PAT — sets PRIVATE-TOKEN header (env: GQL_TOKEN)")
    ap.add_argument("--bearer",    default="", help="OAuth/JWT — sets Authorization: Bearer")
    ap.add_argument("--cookie",    default="", help="Cookie header (e.g., '_gitlab_session=...')")
    ap.add_argument("--job-token", default="", help="CI Job-Token — sets JOB-TOKEN header")
    ap.add_argument("--header",    action="append", help="custom header K:V (repeatable)")
    ap.add_argument("--raw-response", action="store_true", help="print raw JSON response unmodified")
    ap.add_argument("-k", "--insecure", action="store_true",
                    default=os.environ.get("GQL_INSECURE", "").lower() in ("1", "true", "yes"),
                    help="skip TLS certificate verification (curl -k equivalent; env: GQL_INSECURE=1). Use for self-signed / expired / hostname-mismatch lab targets.")
    # F.7 — proxy
    ap.add_argument("--proxy", default="",
                    help="HTTP/HTTPS/SOCKS proxy URL (e.g. http://127.0.0.1:8080, socks5h://127.0.0.1:1080 — requires PySocks). "
                         "Env fallback: GQL_PROXY, HTTPS_PROXY, HTTP_PROXY.")
    # F.8 — User-Agent
    ap.add_argument("--user-agent", default="",
                    help="override User-Agent (default: a Chrome-stable string). Pass 'gql' for the legacy gql.py/1.0. Env: GQL_UA.")
    ap.add_argument("--ua-rotate",  default="",
                    help="path to a file with one UA per line; each request picks a random one. Useful with --proxy chains.")

    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("introspect", help="fetch and cache schema")
    p.add_argument("--save", help="also write schema JSON to this path")
    p.set_defaults(func=cmd_introspect)

    p = sub.add_parser("ls", help="list operations")
    p.add_argument("--kind", choices=["all", "query", "mutation"], default="all")
    p.add_argument("--filter", help="regex filter on operation name (case-insensitive)")
    p.set_defaults(func=cmd_ls)

    p = sub.add_parser("describe", help="show one operation's signature")
    p.add_argument("operation")
    p.set_defaults(func=cmd_describe)

    p = sub.add_parser("call", help="build and execute one operation")
    p.add_argument("operation")
    p.add_argument("--arg",   action="append", help="argument as name=value (repeatable). Value prefixes: @json:JSON, @file:PATH")
    p.add_argument("--select", help="custom selection (space-separated fields, or '{ ... }' for full subquery). Omit for auto.")
    p.add_argument("--depth", type=int, default=2, help="auto-selection depth (default 2)")
    p.add_argument("--show-query", nargs="?", const="both", choices=["both", "only"], help="print the constructed query (and exit early if 'only')")
    p.add_argument("--no-schema", action="store_true", help="don't pull/use cached schema; build args as String type via catalog/blind")
    # F.2 — batched-query support
    p.add_argument("--batch", type=int, default=0, metavar="N",
                   help="send the same query N times in one batched POST (JSON array). Tests per-request authz and resolver state leakage.")
    # F.6 — alias-DoS detection
    p.add_argument("--alias-dos-check", action="store_true",
                   help="DETECT-ONLY: send N aliases of __typename for N=1,2,4,...,n_max and report latency growth. Requires --confirm.")
    p.add_argument("--alias-dos-max", type=int, default=16, metavar="N",
                   help="cap on --alias-dos-check N (default 16)")
    p.add_argument("--confirm", action="store_true",
                   help="acknowledge that --alias-dos-check is a timing probe")
    p.set_defaults(func=cmd_call)

    p = sub.add_parser("loop", help="IDOR/sweep: vary one arg across many values")
    p.add_argument("operation")
    p.add_argument("--vary", required=True, help="name of the arg to vary")
    p.add_argument("--arg",  action="append", help="other args as name=value")
    p.add_argument("--values", nargs="+", help="inline list of values")
    p.add_argument("--values-file", help="path to file, one value per line")
    p.add_argument("--range", help="integer range, e.g. 1-1000")
    p.add_argument("--gid-range", help="GID range, e.g. 'gid://gitlab/Project/1-1000'")
    p.add_argument("--select", help="custom selection (see `call`)")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--delay", type=float, default=0, help="seconds between requests")
    p.add_argument("--no-schema", action="store_true")
    p.add_argument("--allow-huge", action="store_true",
                   help=f"override the {LOOP_HARD_CAP:,}-value cap on --range / --gid-range")
    p.set_defaults(func=cmd_loop)

    p = sub.add_parser("diff", help="run as multiple identities, diff responses")
    p.add_argument("operation")
    p.add_argument("--as", action="append", dest="as_",
                   help="profile spec 'label:HEADER=VALUE' (e.g. 'alice:PRIVATE-TOKEN=glpat-X', 'anon:'). Repeatable.")
    p.add_argument("--arg", action="append")
    p.add_argument("--select")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--no-schema", action="store_true")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("raw", help="send a literal GraphQL document")
    p.add_argument("--query",      help="inline query string")
    p.add_argument("--query-file", help="path to a .graphql file")
    p.add_argument("--variables",  help="JSON string of variables")
    p.add_argument("--batch", type=int, default=0, metavar="N",
                   help="send the same body N times in one batched POST (JSON array)")
    p.set_defaults(func=cmd_raw)

    # F.1 — suggest subcommand
    p = sub.add_parser("suggest",
                       help="harvest field names from 'Did you mean X?' errors (when introspection disabled)")
    p.add_argument("--corpus", help="path to one-per-line guess list (omit for built-in)")
    p.add_argument("--delay",  type=float, default=0,
                   help="seconds between probes")
    p.add_argument("--out",    help="write the harvested name list to this file")
    p.set_defaults(func=cmd_suggest)

    # F.3 — APQ probe subcommand
    p = sub.add_parser("apq-probe",
                       help="test Apollo Persisted Queries — does the server enforce sha256Hash?")
    p.set_defaults(func=cmd_apq_probe)

    # F.5 — CSRF-via-GET probe
    p = sub.add_parser("csrf-probe",
                       help="GET /graphql?query=... — does the server accept queries via GET? (CSRF surface)")
    p.set_defaults(func=cmd_csrf_probe)

    args = ap.parse_args()
    if not args.url:
        print(_color("[!] --url required (or set GQL_URL env)", "R"), file=sys.stderr); return 2

    # Apply --insecure / GQL_INSECURE to the module-level switch used by http_post.
    global _INSECURE_TLS, _PROXY, _UA, _UA_LIST
    if args.insecure:
        _INSECURE_TLS = True
        if args.url and args.url.startswith("https://"):
            print(_color("[!] TLS verification DISABLED (--insecure). Use only against authorized targets.", "Y"),
                  file=sys.stderr)
    # F.7 — proxy
    if args.proxy:
        _PROXY = args.proxy
        print(_color(f"[*] proxy active: {_PROXY}", "Y"), file=sys.stderr)
    # F.8 — User-Agent
    if args.user_agent:
        _UA = "gql.py/1.0" if args.user_agent == "gql" else args.user_agent
    if args.ua_rotate:
        try:
            _UA_LIST = [l.strip() for l in Path(args.ua_rotate).read_text().splitlines()
                        if l.strip() and not l.strip().startswith("#")]
        except OSError as e:
            print(_color(f"[!] --ua-rotate: cannot read file: {e}", "R"), file=sys.stderr); return 2
        if _UA_LIST:
            print(_color(f"[*] UA rotation: {len(_UA_LIST)} user-agents loaded", "C"), file=sys.stderr)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted"); return 130


if __name__ == "__main__":
    sys.exit(main())
