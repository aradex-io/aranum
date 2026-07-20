---
service: ipp
title: IPP / CUPS
ports: 631
aliases: cups, ipp, printer
---

# IPP / CUPS — quick wins

**When you see it:** 631/tcp open → an IPP print service, usually CUPS. The admin UI may be
unauthenticated, printer attributes leak internal detail, and CUPS < 2.4.10 is vulnerable to
the 2024 `cups-browsed` → `foomatic-rip` RCE chain (CVE-2024-47176 and friends).

> Authorized testing only. Triage is read-only. The CUPS RCE chain executes commands via a
> crafted printer + a print job — it is explicitly beyond aranum's read-side scope; only
> pursue with written exploitation sign-off.

## Triage (read-only)
```sh
curl -s http://H:631/                                 # CUPS web UI present?
curl -sI http://H:631/admin                           # admin UI (401 vs 200)
curl -s http://H:631/printers/                        # printer list
nmap -sU -sT -p 631 --script cups-info,cups-queue-info H   # CUPS version + queues
```

## Quick wins

### CUPS version → CVE-2024-47176 chain flag
```sh
curl -sI http://H:631/ | grep -i "^Server:"           # e.g. "CUPS/2.4.2 IPP/2.1"
```
*Why:* the `Server:` header (and `cups-info` NSE) gives the CUPS version. < 2.4.10 with
`cups-browsed` listening on UDP 631 is the CVE-2024-47176/47076/47175/47177 chain — a crafted
IPP `Get-Printer-Attributes` adds a malicious PPD, then a print job runs `foomatic-rip` code.

### Printer attribute enumeration
```sh
ipptool -tv ipp://H:631/printers/PRINTERNAME get-printer-attributes.test
```
*Why:* `Get-Printer-Attributes` discloses device model, firmware, driver, and default job
options — plus, on the RCE chain, is the very request an attacker's fake printer answers.

### Admin UI / config exposure
```sh
curl -s http://H:631/admin/conf/cupsd.conf            # sometimes served unauth
curl -s http://H:631/jobs/                            # queued jobs (may leak doc names)
```
*Why:* a misconfigured CUPS serves `cupsd.conf` (revealing ACLs, listen addresses, remote
admin) and the job queue, which exposes document titles and submitting users.

## aranum helpers
- `aranumtoolkit/network/enum-ipp.sh` — dispatcher (printer list, admin UI, CUPS version; flags the CVE-2024-47176 chain for CUPS < 2.4.10).
- See also `wiki/print.md` for raw JetDirect/PJL (9100) and LPD (515) on the same host.

## Gotchas
- The CUPS RCE requires `cups-browsed` listening on **UDP** 631 and the target to connect back to your fake printer — a TCP-only 631 (IPP proper) is not the vulnerable component.
- Many embedded printers speak IPP on 631 but are not CUPS — the chain is CUPS/`cups-browsed`-specific; fingerprint first.
- Admin actions require auth by default; unauth `cupsd.conf` disclosure is a misconfig, not the norm.
- IPP over TLS (ipps, 631) needs `ipptool -E` or `curl -k` against `https://`.

## Sources
- CVE-2024-47176 / -47076 / -47175 / -47177 advisories (Simone Margaritelli); HackTricks `631-internet-printing-protocol-ipp`; nmap `cups-*` NSE.
