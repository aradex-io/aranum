---
service: telnet
title: Telnet
ports: 23
aliases: telnetd
---

# Telnet — quick wins

**When you see it:** 23/tcp open — almost always a network device (Cisco router/switch,
HP iLO, Juniper, Ubiquiti AP, DD-WRT) or legacy embedded system. Every byte including
credentials transits in cleartext.

> Authorized testing only. Triage is read-only. Telnet is inherently thin on novel
> attack surface: the wins here are cleartext capture, default credentials, and known
> IoT backdoors — not code-execution exploits.

## Triage (read-only)
```sh
nc -nv H 23                                        # banner — reveals device/OS/version
nmap -Pn -p23 --script telnet-encryption,telnet-ntlm-info,banner H
```

## Quick wins

### Cleartext credential capture (on-path)
```sh
tcpdump -i ETH -A -nn 'tcp port 23 and host H'
```
*Why:* Telnet sends credentials and all session data as plaintext. On a shared segment or
after ARP spoofing, a single `tcpdump` captures the username and password typed by any
user logging into H. No interaction with the target required.

### Default credentials — network gear and IoT
```sh
# Interactive test — try vendor defaults manually from banner recon:
telnet H          # Cisco: cisco/cisco, enable/enable; Juniper: root/''; Ubiquiti: ubnt/ubnt

# Automated sweep:
hydra -L USERS_FILE -P WORDLIST -f telnet://H
# or Metasploit:
msf> use auxiliary/scanner/telnet/telnet_login
msf> set RHOSTS H; set USER_FILE USERS_FILE; set PASS_FILE WORDLIST; run
```
*Why:* the banner tells you the device family; vendor-default credential lists
(`standalones/creds/default-creds.json`) narrow the pairs to try. Most embedded Telnet
exposure is root:root, admin:admin, or the device's serial number as password.

### NTLM banner — Windows telnet service
```sh
nmap -Pn -p23 --script telnet-ntlm-info H
```
*Why:* Windows Telnet Server leaks domain, hostname, and OS version in the NTLM
negotiation banner — useful for AD scoping without authenticating.

## aranum helpers
- `aranumtoolkit/network/enum-telnet.sh` — banner grab via nc, nmap
  `telnet-encryption/telnet-ntlm-info/banner` NSE scripts, service-fingerprint guard to
  avoid false positives on non-telnet TCP 23.
- `standalones/creds/default-creds.json` — vendor default credential pairs; feed into
  hydra `-C` for structured sweeps.

## Gotchas
- Telnet on port 23 is frequently a honeypot on modern internet-facing infrastructure;
  confirm the service is real before spending time on cred spray.
- `telnet-encryption` NSE returning "Telnet encryption NOT supported" is the expected
  finding — it confirms cleartext; it does not indicate a bypass.
- Some embedded firmware uses a proprietary banner with Telnet only as a transport;
  IAC option-negotiation bytes at session start confirm it is real telnetd.
- No write-gate flags here: Telnet enumeration (banner grab, cred spray) aligns with
  standard service access — it is the protocol that is the risk, not a separate exploit.

## Sources
- HackTricks `23-pentesting-telnet`; Hackviser Telnet; Hacking Articles "Penetration
  Testing on Telnet (Port 23)"; enum-telnet.sh inline comments (device family list).
