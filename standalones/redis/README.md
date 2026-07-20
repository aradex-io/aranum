# Redis Pentesting Toolkit

Authorized testing only. Three quick-win primitives for Redis: detection, SSH key drop, module-load RCE.

## Layout

```
standalones/redis/
├── _redis_lib.sh        # Shared helpers: raw protocol send, auth probe, config save/restore
├── redis-quickwin.sh    # Detection + exploitability classification
├── redis-rce-ssh.sh     # Classic authorized_keys drop
├── redis-rce-module.sh  # MODULE LOAD RCE (direct write + rogue-master modes)
├── redis-rogue-master.py # Fake-master Python helper (for replication-based module upload)
└── module/
    ├── system.c         # Minimal Redis module exposing `system.exec`
    ├── redismodule.h    # Vendored Redis module API header
    ├── Makefile         # Builds module/system.so
    └── README.md        # Module compile notes
```

## Exploitability Tier

The detector (`redis-quickwin.sh`) classifies each host:

| Tier | Conditions | Quick win |
|---|---|---|
| **CRITICAL** | Unauth + `MODULE LOAD` enabled + Redis ≥ 4.0 | `redis-rce-module.sh` → root-equivalent shell in <30s |
| **CRITICAL** | Unauth + Redis runs as root + writable `/root/.ssh` | `redis-rce-ssh.sh` → root SSH |
| **HIGH** | Unauth + writable `/var/lib/redis/.ssh` (or any user homedir) | `redis-rce-ssh.sh` → user shell, then local privesc |
| **HIGH** | Authenticated as default/weak password with above | same |
| **MEDIUM** | Unauth read-only (protected-mode + masterauth blocking writes) | `KEYS *` sampling for tokens/secrets in cached values |
| **LOW** | Auth required, no weak creds | Continue cred spray / move on |

## Quickstart

```bash
# 1. Sweep — feed it ip:port lines, get a tier report
./redis-quickwin.sh --targets ../../outputs/acme/raw/_targets_redis.txt \
                    --output ./quickwin

# 2. Build the module once
( cd module && make )

# 3. Module-RCE the CRITICAL hosts (auto-uses rogue master if direct write fails).
#    Default behaviour is DRY-RUN (prints plan, exits 0). Add --exploit to fire.
./redis-rce-module.sh --target 10.0.0.20:6379 --cmd 'id; uname -a; hostname' --exploit

# 4. SSH key drop on HIGH hosts. Add --write to actually mutate authorized_keys.
./redis-rce-ssh.sh --target 10.0.0.20:6379 --key ~/.ssh/id_rsa.pub --write
```

## OPSEC notes

- Every exploit script **saves the current Redis CONFIG before mutation and restores it on exit** (even on Ctrl-C — `trap` is wired). The persistence file is left at its original path. Note the save/restore round-trips `dir`/`dbfilename`/`appendonly` **only** — it does not snapshot the keyspace, so treat any `--write` action as potentially touching on-disk state and never point these at production data you cannot lose. (`redis-rce-ssh.sh` no longer issues `FLUSHALL`; the pubkey is newline-padded so it stays a valid `authorized_keys` line without wiping the DB.)
- `redis-rce-module.sh` always issues `MODULE UNLOAD` on cleanup. The `.so` file is left on disk so you have audit trail, but the Redis process drops it from memory.
- The fake-master mode (`--rogue`) listens on a chosen port; pick a port your jump host has open inbound. Defaults to `46379`.
- No payload is hardcoded into the C module beyond an `int system(const char *)` wrapper — every command is supplied at runtime via `system.exec "<cmd>"`.

## Version coverage (smoke-tested 2026-05-19)

| Redis | Module-load chain | Notes |
|---|---|---|
| 4.0 – 5.x | ✅ works out of the box | classic target, no hardening |
| 6.x       | ✅ works if `enable-module-command yes` (legacy default) | many distro packages keep it on |
| 7.0+      | ⚠️ partial — `enable-module-command no` blocks load by policy *and* failed RDB sync now deletes the dropped `.so` | needs polyglot RDB+ELF payload, or local file-write primitive obtained another way |

**Smoke-test result against Redis 5.0**: `MODULE LOAD success` → `system.exec 'id'` → `uid=999(redis)`. Full RCE in ~2 seconds.

**Smoke-test result against Redis 7.2**:
- With default config: blocked at policy (`enable-module-command no`). Detector correctly downgrades tier.
- With `enable-module-command yes`: rogue master delivers payload, but Redis 7.x deletes the `.so` after RDB-signature validation fails. The standard rogue-master approach used here is no longer sufficient; a polyglot RDB+ELF payload is required (TODO in `module/README.md`).

## Prereqs

Required: `redis-cli`, `python3`, `nc` (or `ncat`).
Optional: `gcc` + `make` (to compile `module/system.so`), `ssh` (for redis-rce-ssh).
