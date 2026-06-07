---
service: example
title: Example Service
ports: 1234
aliases: example-alt
---

# Example — quick wins

**When you see it:** one line — the port/banner that produces this finding and the
single condition that makes it interesting (e.g. "unauth = full read/write").

> Authorized testing only. Commands assume you have written authorization for the
> target. Read-only triage first; anything that writes/changes state is marked ✏️.

## Triage (read-only)
```sh
# 2–4 one-liners that confirm the service + grab version/role/config
```

## Quick wins
### <Technique name>
```sh
# the exact commands, smallest working form, placeholders in CAPS (H=host, ATT=your IP)
```
*Why:* one sentence — what this gives you and the precondition.

### <Next technique> ✏️ (writes to target)
```sh
```
*Why:* …

## aranum helpers
- `enum-example.sh` — the dispatcher that produced the finding.
- `standalones/example/...` — repo exploit helper, if one exists (gated behind --write/--exploit).

## Gotchas
- Common reasons a quick win fails (auth, modern-distro perms, protected-mode, etc.).

## Sources
- HackTricks <port>-pentesting-example; <other references by name>.
