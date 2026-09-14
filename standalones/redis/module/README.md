# Redis system-exec module

Minimal Redis module that adds one command:

```
system.exec "<shell command>"  # returns stdout + "\n--exit:<rc>\n"
```

## Offline-ready

`redismodule.h` (from Redis 7.4.0) and `system.c` are checked in and recorded in
`SOURCE.json`. `system.so` is intentionally not distributed: shared objects are
architecture/toolchain-specific. An offline assessment host therefore needs
`make`, Python, and a C compiler. The exploit preflight verifies every vendored
input against `SOURCE.json` before target access and fails before target
mutation when a prerequisite or provenance check fails.

```bash
make                       # offline build from vendored source/header
make rebuild               # force rebuild from checked-in header (no network)
make refresh-header        # refresh redismodule.h from upstream (needs network)
make REDIS_TAG=6.2.14 refresh-header && make rebuild   # build for older API
make clean                 # delete .so only (header preserved)
make distclean             # maintainer-only: delete .so + vendored header
```

Default/runtime builds never fetch from the network. `refresh-header` is an
explicit maintainer action; update its checksum in `SOURCE.json` before the
next verified build. If the vendored header is absent, `make` fails closed.

The Redis module API is **stable across versions ≥ 4.0**, but if you hit symbol-version mismatches on very old targets, rebuild against that target's tag (visible via `INFO server` → `redis_version`).

## Why this module?

The `MODULE LOAD` primitive turns *any* file-write into RCE. Compared to the SSH key drop primitive:

- **No filesystem assumptions** — doesn't care whether Redis runs as root or what homedir layouts exist.
- **No restart needed** — module loads into the running process immediately.
- **Cleaner cleanup** — `MODULE UNLOAD system` removes it from memory; the `.so` on disk is a forensic artifact only.

The module exposes exactly one new command (`system.exec`) and adds nothing else to the Redis namespace.

## Detection

Redis ≥ 7.0 can disable module loading via `enable-module-command no` in config. If your target sets that, the `MODULE LOAD` call will return `ERR ... module-command is disabled`. The detector (`redis-quickwin.sh`) probes for this and downgrades the tier accordingly.
