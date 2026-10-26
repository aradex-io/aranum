#!/usr/bin/env python3
"""Validate one Daybreak posture-KB batch: coverage vs input, schema, single-line
strings, and an OPSEC scan of `test` commands (must be read-only)."""
import json, re, sys
inp = json.load(open(sys.argv[1])); out = json.load(open(sys.argv[2]))
WRITE = re.compile(r"(\btee\b|>>?\s*(?!/dev/null)[/~$A-Za-z]|\bsed\s+-i|\breg\s+add|\bSet-|\bNew-|\bRemove-|\bEnable-|\bDisable-|"
                   r"\bsystemctl\s+(start|stop|restart|enable|disable|mask)|\bchmod\b|\bchown\b|\brm\b|"
                   r"\bsysctl\s+-w|\bauditpol\s+/set|\bnet\s+user\s+\S+\s+/|\bsc(\.exe)?\s+config)", re.I)
probs = []
missing = sorted(set(inp) - set(out)); extra = sorted(set(out) - set(inp))
for cid, e in out.items():
    if not isinstance(e, dict): probs.append(f"{cid}: not object"); continue
    if set(e) != {"why", "test", "fix", "refs"}: probs.append(f"{cid}: keys {sorted(e)}")
    if not isinstance(e.get("why"), str) or not e["why"].strip(): probs.append(f"{cid}: why")
    for k in ("test", "fix"):
        v = e.get(k)
        if not isinstance(v, list) or not v: probs.append(f"{cid}: {k} empty"); continue
        for t in v:
            if not isinstance(t, dict) or "label" not in t or not (("cmd" in t) ^ ("text" in t)) and k == "fix":
                probs.append(f"{cid}: {k} item shape {t}")
            if k == "test" and (not isinstance(t, dict) or "cmd" not in t):
                probs.append(f"{cid}: test item lacks cmd")
            for s in (t.values() if isinstance(t, dict) else []):
                if isinstance(s, str) and ("\n" in s or "\r" in s): probs.append(f"{cid}: newline in {k}")
            if k == "test" and isinstance(t, dict) and WRITE.search(str(t.get("cmd", ""))):
                probs.append(f"{cid}: OPSEC test may write: {t['cmd'][:120]}")
    if not isinstance(e.get("refs"), list) or not all(isinstance(r, str) and r.startswith("http") for r in e["refs"]):
        probs.append(f"{cid}: refs")
print(f"in={len(inp)} out={len(out)} missing={missing} extra={extra} problems={len(probs)}")
for p in probs: print("  -", p)
sys.exit(1 if (missing or extra or probs) else 0)
