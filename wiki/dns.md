---
service: dns
title: DNS
ports: 53
aliases: named, bind, unbound, powerdns
---

# DNS — quick wins

**When you see it:** 53/tcp or 53/udp open → zone transfer is the first move; a
permissive server hands you the complete hostname inventory in one query.

> Authorized testing only. DNS recon is entirely read-only — no writes are issued to
> the target. All techniques here are passive enumeration.

## Triage (read-only)
```sh
dig @H version.bind chaos txt +short          # BIND version disclosure
dig @H DOMAIN SOA +short                      # confirms authoritative server
dig @H DOMAIN NS +short                       # name server list
dig @H DOMAIN ANY                             # any-record dump (often rate-limited)
nmap -Pn -sU -p53 --script dns-service-discovery,dns-nsid H
```

## Quick wins

### Zone transfer (AXFR)
```sh
dig axfr @H DOMAIN                            # full zone dump
host -l DOMAIN H                              # alternative if dig not available
dnsrecon -d DOMAIN -n H -t axfr
```
*Why:* a misconfigured server authorises AXFR to any client, returning every hostname,
IP, MX, TXT, and PTR record in the zone in a single query. One zone transfer replaces
days of subdomain bruting. Succeeds on old BIND installs and internal nameservers that
haven't restricted `allow-transfer`.

### Subdomain brute force
```sh
dnsrecon -d DOMAIN -n H -t brt -D WORDLIST
dnsenum --dnsserver H --enum -p 0 -s 0 -f WORDLIST DOMAIN
gobuster dns -d DOMAIN -r H:53 -w WORDLIST -t 50
```
*Why:* when AXFR is blocked, brute force resolves hostnames from a wordlist via the
target resolver. Use SecLists `subdomains-top1million-5000.txt` for broad coverage;
`subdomains-top1million-110000.txt` for deep coverage.

### Any-record dump
```sh
dig @H DOMAIN ANY
dig @H DOMAIN MX +short
dig @H DOMAIN TXT +short                      # SPF, DKIM selectors, cloud tokens
dig @H DOMAIN NS +short
```
*Why:* TXT records frequently contain sensitive data — SPF policy (`include:` chains
reveal third-party mail services), DKIM public keys, Google/Azure verification tokens,
and sometimes internal notes. MX records identify mail infrastructure.

### Cache snooping (non-recursive query)
```sh
dig @H DOMAIN +norecurse
dig @H TARGET_HOSTNAME A +norecurse
```
*Why:* if the resolver has a record cached (TTL < max), it returns it without going
upstream. Absence of a record (NXDOMAIN or TTL=0) on `+norecurse` suggests no recent
lookup — useful for determining whether a domain/host has been recently visited by
clients behind H.

### Reverse PTR sweep
```sh
dnsrecon -r SUBNET/CIDR -n H                  # e.g., 10.10.10.0/24
for i in $(seq 1 254); do dig @H -x 10.10.10.$i +short; done
```
*Why:* PTR records reveal hostnames for IPs you discovered during nmap; often exposes
naming conventions (e.g., `prod-db-01`, `dev-jenkins`) that guide further targeting.

### NSEC zone walking (DNSSEC-signed zones)
```sh
# NSEC: query a non-existent name; AUTHORITY section reveals next valid name in chain
dig @H nonexistent.DOMAIN NSEC +dnssec
ldns-walk @H DOMAIN                           # automated walk if ldns-utils installed
```
*Why:* DNSSEC with NSEC (not NSEC3) creates an ordered linked list of all zone names.
Walking the chain enumerates the full zone without AXFR. NSEC3 obscures names via
hashing but is still brute-forceable offline with hashcat if the iteration count is low
(use `dig @H randomname.DOMAIN +dnssec` to extract salt and iterations from the response).

## aranum helpers
- `aranumtoolkit/network/enum-dns.sh` — `version.bind` probe, AXFR attempt
  (`$ENUM_DOMAIN`), SOA/NS/MX/TXT lookups, dnsrecon `std,axfr,brt` sweep with
  SecLists wordlist when `ENUM_DOMAIN` is set.

## Gotchas
- `dig ANY` is increasingly answered with an empty `ANSWER` section on modern resolvers
  (RFC 8482); query individual record types instead.
- AXFR over UDP is not supported — TCP only. If `dig axfr @H DOMAIN` times out, confirm
  TCP 53 is reachable (`nmap -Pn -p53 -sT H`).
- Internal authoritative servers often allow AXFR from specific subnets only; if you are
  on the correct internal range it may succeed even when internet-facing does not.
- `+norecurse` cache snooping only works against open/recursive resolvers — authoritative-
  only servers will return REFUSED or NXDOMAIN regardless.
- `ldns-walk` requires `ldns-utils`; on Debian/Ubuntu: `apt install ldns`.

## Sources
- HackTricks `53-pentesting-dns`; Hackviser DNS; Pentest Partners "DNSSEC NSEC — the
  accidental treasure map"; PayloadsAllTheThings DNS; dnsrecon / dnsenum documentation.
