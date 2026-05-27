# Redis system-exec module

Minimal Redis module that adds one command:

```
system.exec "<shell command>"  # returns stdout + "\n--exit:<rc>\n"
```

## Offline-ready

`redismodule.h` (from Redis 7.4.0) **and** `system.so` (x86_64-linux-gnu) are
**checked in**, so this works without network access.

```bash
make                       # no-op if system.so is up-to-date (default offline)
make rebuild               # force rebuild from checked-in header (no network)
make refresh-header        # refresh redismodule.h from upstream (needs network)
make REDIS_TAG=6.2.14 refresh-header && make rebuild   # build for older API
make clean                 # delete .so only (header preserved)
make distclean             # delete .so + header (next build needs network)
```

The Redis module API is **stable across versions ≥ 4.0**, but if you hit symbol-version mismatches on very old targets, rebuild against that target's tag (visible via `INFO server` → `redis_version`).

## Why this module?

The `MODULE LOAD` primitive turns *any* file-write into RCE. Compared to the SSH key drop primitive:

- **No filesystem assumptions** — doesn't care whether Redis runs as root or what homedir layouts exist.
- **No restart needed** — module loads into the running process immediately.
- **Cleaner cleanup** — `MODULE UNLOAD system` removes it from memory; the `.so` on disk is a forensic artifact only.

The module exposes exactly one new command (`system.exec`) and adds nothing else to the Redis namespace.

## Detection

Redis ≥ 7.0 can disable module loading via `enable-module-command no` in config. If your target sets that, the `MODULE LOAD` call will return `ERR ... module-command is disabled`. The detector (`redis-quickwin.sh`) probes for this and downgrades the tier accordingly.
