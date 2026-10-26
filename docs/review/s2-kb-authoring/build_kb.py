#!/usr/bin/env python3
"""build_kb.py — authoring vehicle for aranumtoolkit/network/finding-kb.json.

Each category batch is authored as a Python dict for readability, then emitted
as the finding-kb.json artifact. Content is hand-authored (AD + local privesc)
or peer-drafted and verified (long-tail services); see docs/review/REVIEW-009.
All `test` commands are READ-ONLY confirmation (OPSEC §9): they confirm the
exposure, they do not write to / exploit the target. Commands are templates;
<host>/<port>/<service> are filled at render time.
"""
import json
from pathlib import Path

CATEGORIES = {
    "ad":       {"title": "Active Directory & Windows Domain", "order": 1},
    "winlocal": {"title": "Windows Local Privilege Escalation", "order": 2},
    "linlocal": {"title": "Linux Local Privilege Escalation", "order": 3},
    "creds":    {"title": "Credential Exposure", "order": 4},
    "web":      {"title": "Web Applications & HTTP Services", "order": 5},
    "data":     {"title": "Databases, Caches & Brokers", "order": 6},
    "devops":   {"title": "CI/CD, Source & Artifact Registries", "order": 7},
    "backup":   {"title": "Backup & Data-Protection Platforms", "order": 8},
    "infra":    {"title": "Virtualization & Out-of-Band Management", "order": 9},
    "network":  {"title": "Network Services & Protocols", "order": 10},
}

# Service -> category fallback for custom/absent rule ids. smb/smb_dc split is
# applied in report._service_category (relay-capable DC vs plain file service).
SERVICE_CATEGORIES = {
    "ldap": "ad", "ldaps": "ad", "kerberos": "ad", "smb_dc": "ad", "smb": "network",
    "msrpc": "ad", "winrm": "ad", "rpc": "ad",
    "http": "web", "https": "web", "http-proxy": "web",
    "redis": "data", "mongodb": "data", "mongo": "data", "mysql": "data",
    "postgresql": "data", "postgres": "data", "mssql": "data", "oracle": "data",
    "cassandra": "data", "elasticsearch": "data", "memcached": "data",
    "ftp": "network", "telnet": "network", "snmp": "network", "ssh": "network",
    "smtp": "network", "ntp": "network", "vnc": "network", "rdp": "network",
    "sip": "network", "tftp": "network",
}

CLASSES: dict = {}

def cls(rule_id, category, title, why, test, fix, refs):
    CLASSES[rule_id] = {"category": category, "title": title, "why": why,
                        "test": test, "fix": fix, "refs": refs}

# ============================================================ AD (33)
cls("kerberoastable-hash-es-captured-aada6591", "ad",
    "Kerberoastable service account(s)",
    "Any domain user can request a Kerberos service ticket (TGS) for an account "
    "with an SPN; the ticket is encrypted with the account's NTLM hash and can be "
    "cracked offline. Weak service-account passwords yield domain credentials.",
    [{"label": "Enumerate SPN accounts (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> --kerberoasting kerb.txt"},
     {"label": "Impacket, list only", "cmd": "GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <host>"}],
    [{"label": "Use Group Managed Service Accounts (gMSA)",
      "text": "Replace SPN-bearing user accounts with gMSAs so Windows manages a 120-char random password that rotates automatically."},
     {"label": "Enforce strong passwords where gMSA is impossible",
      "text": "Set service-account passwords to >=25 random characters and audit SPN accounts with `Get-ADUser -Filter {ServicePrincipalName -like '*'}`."}],
    ["https://attack.mitre.org/techniques/T1558/003/",
     "https://learn.microsoft.com/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview"])

cls("as-rep-roastable-hash-es-captured-5c4e283a", "ad",
    "AS-REP roastable account(s) (no pre-auth)",
    "Accounts with 'Do not require Kerberos preauthentication' let any unauthenticated "
    "attacker request an AS-REP encrypted with the account's key, crackable offline.",
    [{"label": "List no-preauth accounts (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> --asreproast asrep.txt"},
     {"label": "Impacket", "cmd": "GetNPUsers.py <domain>/ -dc-ip <host> -usersfile users.txt -no-pass"}],
    [{"label": "Re-enable Kerberos pre-authentication",
      "text": "Clear 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) on every account; it is rarely required."},
     {"label": "Audit", "cmd": "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth"}],
    ["https://attack.mitre.org/techniques/T1558/004/"])

cls("bunconstrained-delegation-b-d66ecf6e", "ad",
    "Unconstrained Kerberos delegation",
    "A host trusted for unconstrained delegation caches the TGTs of every user who "
    "authenticates to it. Compromising it (or coercing a DC to authenticate to it) "
    "yields a DC TGT and full domain compromise.",
    [{"label": "List unconstrained-delegation hosts (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> --trusted-for-delegation"}],
    [{"label": "Remove unconstrained delegation",
      "text": "Switch to constrained delegation or resource-based constrained delegation; never leave non-DC hosts TRUSTED_FOR_DELEGATION."},
     {"label": "Protect sensitive accounts",
      "text": "Mark privileged accounts 'Account is sensitive and cannot be delegated' and add them to Protected Users."}],
    ["https://attack.mitre.org/techniques/T1558/",
     "https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview"])

cls("bmsds-allowedtoactonbehalfofotheridentity-e73bfbd9", "ad",
    "Resource-based constrained delegation writable (RBCD)",
    "msDS-AllowedToActOnBehalfOfOtherIdentity on a computer object lets the named "
    "principal impersonate any user to that host. If writable (or the attacker can add a "
    "computer via MachineAccountQuota), it is a direct takeover primitive.",
    [{"label": "Read the attribute (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> --query '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' ''"}],
    [{"label": "Restrict write access to computer objects",
      "text": "Audit and remove non-admin write/GenericWrite on computer objects; clear unexpected msDS-AllowedToActOnBehalfOfOtherIdentity values."},
     {"label": "Set MachineAccountQuota to 0",
      "text": "Prevents low-priv users creating the computer account RBCD abuse needs."}],
    ["https://learn.microsoft.com/windows-server/security/kerberos/kerberos-constrained-delegation-overview"])

cls("bms-ds-machineaccountquota-d-d534b185", "ad",
    "ms-DS-MachineAccountQuota > 0",
    "The default MachineAccountQuota of 10 lets any authenticated user create computer "
    "accounts, a precondition for RBCD, noPac, and other privilege-escalation chains.",
    [{"label": "Read the domain attribute",
      "cmd": "nxc ldap <host> -u <user> -p <pass> -M maq"}],
    [{"label": "Set quota to 0",
      "text": "Set ms-DS-MachineAccountQuota=0 on the domain head and delegate machine creation to a dedicated group only."}],
    ["https://learn.microsoft.com/archive/blogs/askds/machineaccountquota-is-useful-sometimes"])

cls("esc-1-9-1-0-6-s-vulnerable-a432e7de", "ad",
    "AD CS template vulnerable (ESC1–ESC16)",
    "A misconfigured certificate template (enrollee-supplies-subject, EDITF_ATTRIBUTESUBJECTALTNAME2, "
    "vulnerable enrollment agent, etc.) lets a low-priv user enroll a cert that authenticates as any "
    "user including Domain Admins.",
    [{"label": "Enumerate vulnerable templates (read-only)",
      "cmd": "certipy find -u <user>@<domain> -p <pass> -dc-ip <host> -vulnerable -stdout"}],
    [{"label": "Remediate per ESC class",
      "text": "Remove enrollee-supplies-subject on auth templates, disable EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA, restrict enrollment rights, and enable manager approval for sensitive templates."},
     {"label": "Enforce strong certificate mapping",
      "text": "Apply the May 2022 KB5014754 certificate-mapping enforcement so SANs cannot be forged."}],
    ["https://posts.specterops.io/certified-pre-owned-d95910965cd2",
     "https://support.microsoft.com/topic/kb5014754"])

cls("besc8-relay-target-b-e9ab15ea", "ad",
    "AD CS ESC8 — HTTP enrollment relay target",
    "The CA web-enrollment endpoint accepts NTLM over HTTP, so a coerced DC authentication can be "
    "relayed to it to obtain a DC certificate — full domain compromise.",
    [{"label": "Confirm the web-enrollment endpoint (read-only)",
      "cmd": "curl -sk https://<host>/certsrv/certfnsh.asp -o /dev/null -w '%{http_code}\\n'"}],
    [{"label": "Enforce HTTPS + EPA / channel binding",
      "text": "Require HTTPS and Extended Protection for Authentication on the certsrv site, or disable web enrollment; enable RPC/LDAP signing and disable NTLM to the CA."}],
    ["https://posts.specterops.io/certified-pre-owned-d95910965cd2"])

cls("gpp-cpassword-in-36f4a9ed", "ad",
    "GPP cpassword in SYSVOL (MS14-025)",
    "Group Policy Preferences stored a password encrypted with a Microsoft-published AES key in "
    "SYSVOL, readable by every domain user and trivially decrypted.",
    [{"label": "Locate cpassword in SYSVOL (read-only)",
      "cmd": "nxc smb <host> -u <user> -p <pass> -M gpp_password"}],
    [{"label": "Remove the GPP password and rotate it",
      "text": "Delete the offending Groups.xml/Services.xml/etc. from SYSVOL, change the exposed account's password, and never store credentials in GPP (use LAPS/gMSA)."}],
    ["https://support.microsoft.com/topic/ms14-025",
     "https://attack.mitre.org/techniques/T1552/006/"])

cls("bcpassword-s-s-e9039ab6", "ad",
    "cpassword value exposed",
    "A GPP cpassword attribute was found. It is AES-encrypted with a public key and decrypts to a "
    "cleartext credential usable across the domain.",
    [{"label": "Confirm the artifact path (read-only)",
      "cmd": "cat '<evidence_path>'"}],
    [{"label": "Rotate and purge",
      "text": "Rotate the exposed credential immediately and remove the cpassword-bearing GPP from SYSVOL."}],
    ["https://support.microsoft.com/topic/ms14-025"])

cls("readable-lapsv-12-d043180c", "ad",
    "LAPS password readable",
    "The Local Administrator Password Solution password is readable by the enumerating principal, "
    "exposing the local admin password of the managed computer.",
    [{"label": "Confirm read access (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> -M laps"}],
    [{"label": "Restrict LAPS read rights",
      "text": "Audit ms-Mcs-AdmPwd / msLAPS-Password read permissions; grant only to tier-0 admins, and remove inherited 'All extended rights' from non-admins."}],
    ["https://learn.microsoft.com/windows-server/identity/laps/laps-overview"])

cls("readable-lapsv-12-d043180c".replace("readable", "encrypted") if False else "encrypted-lapsv2-2540a156", "ad",
    "LAPS v2 encrypted password present",
    "Windows LAPS v2 stores the managed password encrypted; its presence confirms LAPS is deployed. "
    "If the enumerating principal can decrypt it, the local admin password is exposed.",
    [{"label": "Confirm decrypt rights (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> -M laps"}],
    [{"label": "Restrict decryption rights",
      "text": "Ensure only tier-0 principals hold the LAPS encryption/read rights; prefer AES-256 DPAPI-NG encryption scoped to a dedicated group."}],
    ["https://learn.microsoft.com/windows-server/identity/laps/laps-overview"])

cls("blaps-d-computer-object-s-expose-b-e3bda0bf", "ad",
    "LAPS passwords exposed across computer objects",
    "Multiple computer objects expose their LAPS-managed local-admin password to the enumerating "
    "principal — a broad local-admin credential harvest.",
    [{"label": "Count readable LAPS objects (read-only)",
      "cmd": "nxc ldap <host> -u <user> -p <pass> -M laps"}],
    [{"label": "Re-scope LAPS read rights",
      "text": "Remove non-admin read access to ms-Mcs-AdmPwd / msLAPS-Password across all OUs; grant per-OU to tier-appropriate admins only."}],
    ["https://learn.microsoft.com/windows-server/identity/laps/laps-overview"])

cls("printnightmare-configuration-is-exploitable-b4028094", "ad",
    "PrintNightmare exploitable (CVE-2021-34527)",
    "The Print Spooler configuration permits non-admin driver installation / point-and-print, allowing "
    "remote code execution as SYSTEM on the host, including domain controllers.",
    [{"label": "Confirm spooler reachable (read-only)",
      "cmd": "rpcdump.py <host> | grep -i spoolss"}],
    [{"label": "Patch and harden point-and-print",
      "text": "Apply the CVE-2021-34527 updates, set RestrictDriverInstallationToAdministrators=1, and disable the Print Spooler on servers that do not print (especially DCs)."}],
    ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"])

cls("petitpotam-coerce-chain-available-f4420e19", "ad",
    "PetitPotam coercion chain available",
    "MS-EFSRPC lets an attacker coerce a DC/host to authenticate to an attacker machine, which can be "
    "relayed (e.g. to AD CS ESC8) for domain compromise.",
    [{"label": "Confirm EFSRPC reachable (read-only)",
      "cmd": "rpcdump.py <host> | grep -i efsr"}],
    [{"label": "Block the coercion + relay",
      "text": "Apply PetitPotam patches, enable SMB/LDAP signing and EPA, disable NTLM where possible, and filter the MS-EFSRPC named pipes."}],
    ["https://msrc.microsoft.com/update-guide/vulnerability/ADV210003"])

cls("bwebclient-service-running-coercion-b-3bb4dc31", "ad",
    "WebClient service running (coercion via WebDAV)",
    "The WebClient service enables WebDAV coercion (e.g. via PetitPotam/PrinterBug over HTTP), which can "
    "be relayed to AD CS or LDAP for privilege escalation.",
    [{"label": "Confirm WebClient exposure (read-only)",
      "cmd": "nxc smb <host> -u <user> -p <pass> -M webdav"}],
    [{"label": "Disable WebClient where unneeded",
      "text": "Disable the WebClient service via GPO on servers/workstations that do not require WebDAV, and enable EPA on relay targets."}],
    ["https://attack.mitre.org/techniques/T1187/"])

cls("lsarpc-anonymous-reachable-on-dc-4e8a4248", "ad",
    "LSARPC anonymous access on a DC",
    "Anonymous LSARPC access leaks domain SIDs, policy, and user/group names, aiding targeted attacks "
    "and confirming weak null-session restrictions on a domain controller.",
    [{"label": "Confirm anonymous LSA (read-only)",
      "cmd": "nxc smb <host> -u '' -p '' --rid-brute"}],
    [{"label": "Restrict anonymous access",
      "text": "Set 'Network access: Restrict anonymous access to Named Pipes and Shares' and RestrictRemoteSam; audit Everyone/Anonymous in Pre-Windows 2000 Compatible Access."}],
    ["https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares"])

cls("bmsrpc-anonymous-srvinfo-33223179", "ad",
    "MSRPC anonymous srvinfo disclosure",
    "Anonymous MSRPC srvinfo leaks the host OS/version and server role, useful for fingerprinting and "
    "null-session enumeration.",
    [{"label": "Confirm anonymous srvinfo (read-only)",
      "cmd": "rpcclient -U '' -N <host> -c srvinfo"}],
    [{"label": "Restrict anonymous RPC",
      "text": "Apply RestrictRemoteSam / RestrictAnonymous and remove Anonymous Logon from pre-Windows-2000 compatibility groups."}],
    ["https://attack.mitre.org/techniques/T1087/"])

cls("btrust-auth-b-920e530b", "ad",
    "PostgreSQL/host TRUST authentication",
    "A TRUST auth method accepts connections with no password for the matching host, granting the "
    "database/service account without credentials.",
    [{"label": "Confirm passwordless login (read-only)",
      "cmd": "psql -h <host> -p <port> -U postgres -c '\\du'"}],
    [{"label": "Replace trust with scram-sha-256",
      "text": "Edit pg_hba.conf: change `trust` to `scram-sha-256`, restrict host CIDRs, and reload. Never use `trust` outside localhost sockets."}],
    ["https://www.postgresql.org/docs/current/auth-trust.html"])

cls("badmin-admin-works-b-479f083c", "ad",
    "Default credential admin:admin accepted",
    "The service accepts admin:admin, granting administrative access with a trivially guessed default.",
    [{"label": "Confirm the default login (read-only)",
      "cmd": "nxc smb <host> -u admin -p admin"}],
    [{"label": "Change the default credential",
      "text": "Set a unique strong password, disable or rename the default admin account, and enforce an account-lockout policy."}],
    ["https://attack.mitre.org/techniques/T1078/001/"])

cls("bguest-guest-b-34b991e6", "ad",
    "Guest account enabled / guest:guest",
    "The guest account is enabled and accepts guest:guest, exposing anonymous-equivalent access and SMB "
    "enumeration.",
    [{"label": "Confirm guest access (read-only)",
      "cmd": "nxc smb <host> -u guest -p ''"}],
    [{"label": "Disable the Guest account",
      "text": "Disable Guest via GPO ('Accounts: Guest account status' = Disabled) and deny guest network logon."}],
    ["https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status"])

cls("bsigning-disabled-b-bsigning-enabled-but-not-required-b-65edaf46", "ad",
    "SMB signing not required (NTLM relay)",
    "SMB signing is disabled or not enforced, so captured/coerced NTLM authentication can be relayed to "
    "this host for code execution or privilege escalation.",
    [{"label": "Confirm signing state (read-only)",
      "cmd": "nxc smb <host> --gen-relay-list relay.txt"}],
    [{"label": "Require SMB signing (GPO)",
      "text": "Set 'Microsoft network server: Digitally sign communications (always)' = Enabled on servers and clients."},
     {"label": "PowerShell", "cmd": "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force"}],
    ["https://learn.microsoft.com/windows-server/storage/file-server/smb-signing"])

cls("blocalaccounttokenfilterpolicy-1-b-deda8b2f", "ad",
    "LocalAccountTokenFilterPolicy=1 (remote local-admin)",
    "This setting disables UAC remote restrictions, so any local administrator account can authenticate "
    "remotely with a full high-integrity token — ideal for lateral movement with reused local creds.",
    [{"label": "Confirm the registry value (read-only)",
      "cmd": "nxc smb <host> -u <user> -p <pass> -x 'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy'"}],
    [{"label": "Set it back to 0",
      "text": "Remove or set LocalAccountTokenFilterPolicy=0 via GPO; deploy LAPS so local-admin passwords are unique per host."}],
    ["https://learn.microsoft.com/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction"])

cls("bwdigest-uselogoncredential-1-b-909bd9e4", "ad",
    "WDigest UseLogonCredential=1 (cleartext in LSASS)",
    "With UseLogonCredential=1, WDigest caches cleartext passwords in LSASS, so an LSASS dump yields "
    "plaintext domain credentials.",
    [{"label": "Confirm the registry value (read-only)",
      "cmd": "nxc smb <host> -u <user> -p <pass> -x 'reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential'"}],
    [{"label": "Set UseLogonCredential=0",
      "text": "Set it to 0 via GPO, enable Credential Guard, and add privileged users to Protected Users."}],
    ["https://attack.mitre.org/techniques/T1003/001/"])

cls("bnetbios-workgroup-mismatch-high-value-b27dc95e", "ad",
    "NetBIOS workgroup mismatch (high value)",
    "A host advertises a workgroup/domain name inconsistent with the environment, often indicating a "
    "rogue, unmanaged, or legacy system worth targeting.",
    [{"label": "Confirm NetBIOS name (read-only)",
      "cmd": "nmblookup -A <host>"}],
    [{"label": "Investigate and bring under management",
      "text": "Identify the host owner, join it to the correct domain or decommission it, and ensure it is covered by patch/EDR baselines."}],
    ["https://attack.mitre.org/techniques/T1016/"])

cls("bbloodhound-collection-e26e0ea7", "ad",
    "BloodHound collection succeeded",
    "A full BloodHound graph was collected, meaning an authenticated user can map every attack path to "
    "Domain Admins — the data an attacker uses to plan privilege escalation.",
    [{"label": "Re-collect for your own review (read-only)",
      "cmd": "bloodhound-python -u <user> -p <pass> -d <domain> -ns <host> -c All"}],
    [{"label": "Remediate the shortest paths",
      "text": "Import the graph, run the pre-built 'shortest paths to Domain Admins' queries, and remove the risky edges (excess ACLs, stale admin rights, delegation)."}],
    ["https://bloodhound.readthedocs.io/"])

cls("bloodhound-zip-b0e51d91", "ad",
    "BloodHound data archive produced",
    "A BloodHound ZIP of collected domain data exists; it contains the full attack-path graph and should "
    "be treated as sensitive.",
    [{"label": "Inspect the archive (read-only)",
      "cmd": "unzip -l '<evidence_path>'"}],
    [{"label": "Act on the graph and protect it",
      "text": "Use the graph to remediate attack paths, then store/destroy the archive securely — it maps your domain for an attacker."}],
    ["https://bloodhound.readthedocs.io/"])

cls("member-of-domain-admins-enterprise-admins-schema-admins-c3590659", "ad",
    "Principal in a tier-0 privileged group",
    "The assessed principal is a member of a domain-dominant group (Domain/Enterprise/Schema Admins, "
    "Administrators, Backup/Server Operators, Hyper-V Admins) — effective domain compromise if that "
    "principal is obtainable.",
    [{"label": "Confirm membership (read-only)",
      "cmd": "net group \"Domain Admins\" /domain"}],
    [{"label": "Reduce tier-0 membership",
      "text": "Remove standing membership, use time-bound PIM/JIT elevation, and enforce tiered administration so day-to-day accounts are never tier-0."}],
    ["https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model"])

cls("member-of-account-operators-print-operators-dnsadmins-a5c8368a", "ad",
    "Principal in a privilege-escalation group",
    "Account Operators, Print Operators, and DnsAdmins each have documented paths to domain compromise "
    "(e.g. DnsAdmins DLL injection into the DNS service running as SYSTEM on a DC).",
    [{"label": "Confirm membership (read-only)",
      "cmd": "net group \"DnsAdmins\" /domain"}],
    [{"label": "Empty or tightly control these groups",
      "text": "Remove unnecessary members; treat DnsAdmins/Account Operators/Print Operators as tier-0-adjacent and monitor changes."}],
    ["https://attack.mitre.org/techniques/T1069/002/"])

cls("member-of-remote-desktop-users-remote-management-users-b4482fee", "ad",
    "Principal in a remote-access group",
    "Remote Desktop Users / Remote Management Users grants interactive or WinRM access to hosts, enabling "
    "lateral movement and credential harvesting from those sessions.",
    [{"label": "Confirm membership (read-only)",
      "cmd": "net localgroup \"Remote Desktop Users\""}],
    [{"label": "Restrict remote-access groups",
      "text": "Limit membership to required admins, require MFA/network-level authentication for RDP, and segment management access."}],
    ["https://attack.mitre.org/techniques/T1021/001/"])

cls("badfs-sign-on-page-detected-b-120f5ed6", "ad",
    "ADFS sign-on page detected",
    "An exposed ADFS endpoint is a high-value target for password spraying and, if misconfigured, token "
    "forgery (Golden SAML) affecting federated cloud access.",
    [{"label": "Confirm the endpoint (read-only)",
      "cmd": "curl -sk https://<host>/adfs/ls/idpinitiatedsignon.aspx -o /dev/null -w '%{http_code}\\n'"}],
    [{"label": "Harden ADFS",
      "text": "Require Extranet Smart Lockout/MFA, disable IdP-initiated sign-on if unused, protect the token-signing key, and monitor for Golden SAML indicators."}],
    ["https://learn.microsoft.com/windows-server/identity/ad-fs/deployment/best-practices-securing-ad-fs"])

cls("bexchange-endpoint-detected-b-b3d82fbe", "ad",
    "Exchange endpoint detected",
    "On-prem Exchange (OWA/ECP/Autodiscover/EWS) is a recurring RCE/SSRF target (ProxyLogon, ProxyShell) "
    "and a password-spray surface tied to AD identities.",
    [{"label": "Confirm the endpoint + build (read-only)",
      "cmd": "curl -sk https://<host>/owa/ -o /dev/null -w '%{http_code}\\n'"}],
    [{"label": "Patch and reduce exposure",
      "text": "Apply the latest Exchange CU+SU, run the Exchange Health Checker, restrict ECP/management to internal networks, and enable Extended Protection."}],
    ["https://learn.microsoft.com/exchange/plan-and-deploy/post-installation-tasks/security-best-practices/extended-protection"])

cls("bsccm-client-present-b-06b233a7", "ad",
    "SCCM/MECM client present",
    "SCCM/MECM is a high-value lateral-movement and credential surface (Network Access Accounts, PXE, "
    "application deployment to many hosts).",
    [{"label": "Confirm the client (read-only)",
      "cmd": "nxc smb <host> -u <user> -p <pass> -x 'sc query ccmexec'"}],
    [{"label": "Harden SCCM",
      "text": "Remove legacy Network Access Accounts (use Enhanced HTTP), require PXE passwords, enable site-system PKI, and restrict who can deploy applications."}],
    ["https://github.com/subat0mik/Misconfiguration-Manager"])

cls("bwsus-over-http-69eee442", "ad",
    "WSUS served over HTTP",
    "WSUS over cleartext HTTP allows a man-in-the-middle to inject a malicious signed-wrapper update and "
    "achieve SYSTEM-level code execution on clients.",
    [{"label": "Confirm HTTP WSUS (read-only)",
      "cmd": "curl -s http://<host>:<port>/ClientWebService/client.asmx -o /dev/null -w '%{http_code}\\n'"}],
    [{"label": "Require HTTPS for WSUS",
      "text": "Reconfigure WSUS and the client GPO to use HTTPS (8531), or isolate the update path; consider SpecOps/third-party TLS enforcement."}],
    ["https://learn.microsoft.com/security-updates/windowsupdateservices/18125939"])

cls("ccm-logs-passwordhash-naa-credential-1843150a", "ad",
    "SCCM Network Access Account credential in CCM logs",
    "The SCCM client logs/policy expose a Network Access Account credential (PasswordHash/NAA), a reusable "
    "domain credential recoverable by any local user on the client.",
    [{"label": "Confirm the artifact (read-only)",
      "cmd": "cat '<evidence_path>'"}],
    [{"label": "Rotate and remove NAA",
      "text": "Rotate the NAA credential, migrate to Enhanced HTTP / PKI so no NAA is needed, and clear the exposed logs/policy."}],
    ["https://github.com/subat0mik/Misconfiguration-Manager"])

def main():
    # Fold in the peer-drafted, verified long-tail classes (REVIEW-009). The
    # hand-authored AD classes above take precedence on any id collision.
    merged = Path("docs/review/s2-kb-authoring/batches/merged.classes.json")
    if merged.is_file():
        peer = json.loads(merged.read_text())
        for rid, cls in peer.items():
            CLASSES.setdefault(rid, cls)
    kb = {"schema": 1, "categories": CATEGORIES,
          "service_categories": SERVICE_CATEGORIES, "classes": CLASSES}
    out = Path("aranumtoolkit/network/finding-kb.json")
    out.write_text(json.dumps(kb, indent=2) + "\n")
    print(f"wrote {out} — {len(CLASSES)} classes, {len(CATEGORIES)} categories")

if __name__ == "__main__":
    main()
