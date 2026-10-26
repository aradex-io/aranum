#!/usr/bin/env python3
"""S3 posture check catalog (PLAN-001 D3.2) — source of truth for the check ids
the two collectors emit, their severities on FAIL/WARN, KB category and matrix
group, and the exact status semantics. build_kb.py merges this with the authored
why/test/fix into finding-kb.json `checks`. Writes catalog.json beside itself.

Row: (id, title, group, category, sev_fail, sev_warn, semantics)
"""
import json
from pathlib import Path

L = "linux"; W = "windows"
LIN = [
 ("LIN-OS-RELEASE", "OS release and kernel", "patching", "linlocal", "", "", "INFO: distro, version, kernel release."),
 ("LIN-PKG-SECUPDATES", "Pending security updates", "patching", "linlocal", "high", "medium", "FAIL: >=1 pending security update in the package cache; WARN: non-security updates pending only; PASS: none. Reads cache only (apt-get -s / dnf -C), never refreshes."),
 ("LIN-PKG-AUTOUPDATE", "Automatic security updates", "patching", "linlocal", "", "low", "PASS: unattended-upgrades / dnf-automatic enabled; WARN: not configured."),
 ("LIN-REBOOT-REQUIRED", "Reboot pending for updates", "patching", "linlocal", "", "medium", "WARN: /var/run/reboot-required present (patched kernel/libs not loaded); PASS: absent."),
 ("LIN-SYSCTL-PTRACE", "Yama ptrace scope", "kernel", "linlocal", "", "medium", "WARN: kernel.yama.ptrace_scope=0; PASS: >=1; NA: Yama absent."),
 ("LIN-SYSCTL-KPTR", "Kernel pointer restriction", "kernel", "linlocal", "", "low", "WARN: kernel.kptr_restrict=0; PASS: >=1."),
 ("LIN-SYSCTL-DMESG", "dmesg restriction", "kernel", "linlocal", "", "low", "WARN: kernel.dmesg_restrict=0; PASS: 1."),
 ("LIN-SYSCTL-BPF", "Unprivileged eBPF", "kernel", "linlocal", "", "medium", "WARN: kernel.unprivileged_bpf_disabled=0; PASS: 1 or 2."),
 ("LIN-SYSCTL-USERNS", "Unprivileged user namespaces", "kernel", "linlocal", "", "low", "WARN: unprivileged userns creation allowed (unprivileged_userns_clone=1 / max_user_namespaces>0) and not AppArmor-restricted; PASS: disabled or apparmor_restrict_unprivileged_userns=1."),
 ("LIN-SYSCTL-ASLR", "ASLR", "kernel", "linlocal", "high", "", "FAIL: kernel.randomize_va_space<2; PASS: 2."),
 ("LIN-SYSCTL-SUIDDUMP", "setuid core dumps", "kernel", "linlocal", "", "medium", "WARN: fs.suid_dumpable!=0; PASS: 0."),
 ("LIN-SYSCTL-PROTLINKS", "Protected symlinks/hardlinks", "kernel", "linlocal", "", "medium", "WARN: fs.protected_symlinks or fs.protected_hardlinks =0; PASS: both 1."),
 ("LIN-SYSCTL-PERF", "perf_event paranoia", "kernel", "linlocal", "", "low", "WARN: kernel.perf_event_paranoid<2; PASS: >=2."),
 ("LIN-SYSCTL-IPFWD", "IPv4 forwarding", "network", "linlocal", "", "low", "WARN: net.ipv4.ip_forward=1 (host routes traffic; pivot aid); PASS: 0."),
 ("LIN-LSM-MAC", "Mandatory access control", "access-control", "linlocal", "", "medium", "PASS: SELinux enforcing or AppArmor enabled; WARN: SELinux permissive/disabled and no AppArmor."),
 ("LIN-FIREWALL", "Host firewall", "network", "linlocal", "", "medium", "PASS: ufw/firewalld/nftables/iptables service active or ufw ENABLED=yes; WARN: none active; ERR: cannot determine."),
 ("LIN-SSH-ROOTLOGIN", "SSH root login", "remote-access", "linlocal", "high", "", "FAIL: PermitRootLogin yes; PASS: no / prohibit-password / forced-commands-only / default; NA: no sshd_config."),
 ("LIN-SSH-PASSAUTH", "SSH password authentication", "remote-access", "linlocal", "", "medium", "WARN: PasswordAuthentication yes (explicit or default); PASS: no; NA: no sshd_config."),
 ("LIN-SSH-EMPTYPW", "SSH empty passwords", "remote-access", "linlocal", "critical", "", "FAIL: PermitEmptyPasswords yes; PASS: no/default; NA: no sshd_config."),
 ("LIN-SSH-X11", "SSH X11 forwarding", "remote-access", "linlocal", "", "low", "WARN: X11Forwarding yes; PASS: no/default; NA: no sshd_config."),
 ("LIN-SSH-MAXAUTH", "SSH MaxAuthTries", "remote-access", "linlocal", "", "low", "WARN: MaxAuthTries >4 (default 6); PASS: <=4; NA: no sshd_config."),
 ("LIN-SSH-CIPHERS", "SSH weak ciphers/MACs/KEX", "remote-access", "linlocal", "", "medium", "WARN: configured Ciphers/MACs/KexAlgorithms include cbc, arcfour, 3des, md5, sha1 KEX or group1; PASS: none configured weak (default set); NA: no sshd_config."),
 ("LIN-SSH-HOSTKEY-PERMS", "SSH host private key permissions", "remote-access", "linlocal", "high", "", "FAIL: an /etc/ssh/ssh_host_*_key is group/world readable or readable by the current non-root user; PASS: otherwise; NA: no host keys."),
 ("LIN-ACCT-UID0", "Extra UID 0 accounts", "accounts", "linlocal", "critical", "", "FAIL: any account other than root has UID 0; PASS: only root."),
 ("LIN-ACCT-EMPTYPW", "Accounts with empty password", "accounts", "linlocal", "critical", "", "FAIL: /etc/shadow has an empty password field; PASS: none; ERR: shadow not readable (needs root)."),
 ("LIN-ACCT-NOPASSWD", "sudo NOPASSWD rules", "accounts", "linlocal", "", "medium", "WARN: >=1 NOPASSWD rule in sudoers/sudoers.d; PASS: none; ERR: sudoers unreadable (needs root); NA: sudo absent."),
 ("LIN-ACCT-ADMINS", "Administrative group members", "accounts", "linlocal", "", "", "INFO: members of sudo/wheel/admin groups."),
 ("LIN-ACCT-UMASK", "Default umask", "accounts", "linlocal", "", "low", "WARN: login.defs UMASK grants group/other write (e.g. 002, 000); PASS: 022/027/077."),
 ("LIN-ACCT-AGING", "Password maximum age", "accounts", "linlocal", "", "low", "WARN: login.defs PASS_MAX_DAYS unset or >365; PASS: <=365."),
 ("LIN-FILE-SHADOW", "/etc/shadow permissions", "filesystem", "linlocal", "critical", "", "FAIL: /etc/shadow (or gshadow) world-readable or world-writable; PASS: otherwise."),
 ("LIN-FILE-PASSWD", "/etc/passwd permissions", "filesystem", "linlocal", "critical", "", "FAIL: /etc/passwd or /etc/group writable by group/other; PASS: otherwise."),
 ("LIN-MNT-TMP", "/tmp mount options", "filesystem", "linlocal", "", "low", "WARN: /tmp not a separate mount, or mounted without nosuid/nodev; PASS: separate mount with nosuid,nodev."),
 ("LIN-MNT-SHM", "/dev/shm mount options", "filesystem", "linlocal", "", "low", "WARN: /dev/shm mounted without noexec or nosuid; PASS: noexec,nosuid."),
 ("LIN-PATH-WW", "World-writable directories in PATH", "filesystem", "linlocal", "high", "", "FAIL: a directory on PATH (or /etc/environment PATH) is world-writable without sticky bit; PASS: none."),
 ("LIN-CRON-PERMS", "Cron configuration permissions", "filesystem", "linlocal", "high", "", "FAIL: /etc/crontab or an /etc/cron.* entry is world-writable; PASS: none."),
 ("LIN-LOG-AUDITD", "Audit daemon", "logging", "linlocal", "", "medium", "PASS: auditd active; WARN: not active."),
 ("LIN-LOG-SYSLOG", "System logging", "logging", "linlocal", "", "low", "PASS: rsyslog/syslog-ng active or journald persistent storage; WARN: only volatile journal."),
 ("LIN-TIME-SYNC", "Time synchronization", "logging", "linlocal", "", "low", "PASS: chronyd/systemd-timesyncd/ntpd active; WARN: none (breaks Kerberos and log correlation)."),
 ("LIN-BOOT-SECUREBOOT", "UEFI Secure Boot", "boot", "linlocal", "", "low", "PASS: Secure Boot enabled; WARN: UEFI with Secure Boot disabled; INFO: legacy BIOS boot."),
 ("LIN-SVC-FAILED", "Failed systemd units", "services", "linlocal", "", "", "INFO: count of failed units."),
 ("LIN-CTR-DOCKERSOCK", "Docker socket exposure", "services", "linlocal", "high", "", "FAIL: /var/run/docker.sock world-writable or writable by the current non-root user; PASS: present and restricted; NA: absent."),
 ("LIN-AD-JOINED", "Directory membership", "domain", "ad", "", "", "INFO: realm/sssd/winbind membership and realm name, or not joined."),
 ("LIN-AD-KEYTAB", "Host keytab readability", "domain", "ad", "critical", "", "FAIL: /etc/krb5.keytab readable by the current non-root user or world-readable; PASS: present and restricted; NA: absent."),
]
WIN = [
 ("WIN-OS-BUILD", "OS edition and build", "patching", "winlocal", "", "", "INFO: caption, build.UBR, product type (workstation/server/DC)."),
 ("WIN-PATCH-AGE", "Last update age", "patching", "winlocal", "high", "medium", "FAIL: newest installed hotfix >90 days old; WARN: 45-90 days; PASS: <45; ERR: no hotfix dates readable."),
 ("WIN-FW-DOMAIN", "Firewall - Domain profile", "network", "winlocal", "", "medium", "PASS: profile enabled (policy or local); WARN: disabled."),
 ("WIN-FW-PRIVATE", "Firewall - Private profile", "network", "winlocal", "", "medium", "PASS: profile enabled; WARN: disabled."),
 ("WIN-FW-PUBLIC", "Firewall - Public profile", "network", "winlocal", "high", "", "PASS: profile enabled; FAIL: disabled."),
 ("WIN-DEF-RTP", "Defender real-time protection", "endpoint-protection", "winlocal", "high", "", "PASS: real-time protection on; FAIL: off; NA: Defender not present (third-party AV)."),
 ("WIN-DEF-TAMPER", "Defender tamper protection", "endpoint-protection", "winlocal", "", "medium", "PASS: tamper protection on; WARN: off; NA: Defender not present."),
 ("WIN-DEF-SIGAGE", "Defender signature age", "endpoint-protection", "winlocal", "", "medium", "WARN: AV signatures >7 days old; PASS: <=7; NA: Defender not present."),
 ("WIN-BITLOCKER", "BitLocker on system drive", "boot", "winlocal", "", "medium", "PASS: system drive protection on; WARN: off; ERR: not readable without elevation."),
 ("WIN-SECUREBOOT", "UEFI Secure Boot", "boot", "winlocal", "", "low", "PASS: UEFISecureBootEnabled=1; WARN: 0; INFO: legacy BIOS / state key absent."),
 ("WIN-SMB-V1", "SMBv1 server", "network", "winlocal", "high", "", "FAIL: SMB1 server enabled (LanmanServer SMB1=1 or mrxsmb10 driver enabled); PASS: disabled/absent."),
 ("WIN-SMB-SRVSIGN", "SMB server signing required", "relay", "ad", "high", "", "FAIL: LanmanServer RequireSecuritySignature!=1 (relay target); PASS: 1."),
 ("WIN-SMB-CLISIGN", "SMB client signing required", "relay", "ad", "", "medium", "WARN: LanmanWorkstation RequireSecuritySignature!=1; PASS: 1."),
 ("WIN-NR-LLMNR", "LLMNR", "relay", "ad", "high", "", "FAIL: LLMNR not disabled by policy (DNSClient EnableMulticast!=0); PASS: 0."),
 ("WIN-NR-NBTNS", "NetBIOS over TCP/IP", "relay", "ad", "", "medium", "WARN: >=1 IP-enabled adapter with NetBIOS not disabled (NetbiosOptions!=2); PASS: all disabled."),
 ("WIN-NR-WPAD", "WPAD auto-proxy discovery", "relay", "ad", "", "medium", "WARN: WinHttpAutoProxySvc enabled and WPAD not disabled; PASS: service disabled or DisableWpad=1."),
 ("WIN-LDAP-CLISIGN", "LDAP client signing", "relay", "ad", "", "medium", "PASS: LDAPClientIntegrity=2 (require); WARN: 0 (none) or 1 (negotiate, default)."),
 ("WIN-ANON-RESTRICT", "Anonymous enumeration restrictions", "accounts", "winlocal", "", "medium", "WARN: RestrictAnonymousSAM=0 or RestrictAnonymous=0 with EveryoneIncludesAnonymous=1; PASS: restricted."),
 ("WIN-PS-V2", "PowerShell v2 engine", "logging", "winlocal", "", "medium", "WARN: PowerShell 2.0 engine installed (downgrade bypasses logging); PASS: absent."),
 ("WIN-PS-SBLOG", "PowerShell script-block logging", "logging", "winlocal", "", "medium", "PASS: EnableScriptBlockLogging=1 by policy; WARN: not enabled."),
 ("WIN-PS-TRANSCRIPT", "PowerShell transcription", "logging", "winlocal", "", "low", "PASS: EnableTranscripting=1 by policy; WARN: not enabled."),
 ("WIN-PS-LANGMODE", "PowerShell language mode", "access-control", "winlocal", "", "", "INFO: current session language mode (FullLanguage / ConstrainedLanguage)."),
 ("WIN-RDP-ENABLED", "Remote Desktop", "remote-access", "winlocal", "", "", "INFO: RDP enabled (fDenyTSConnections=0) or disabled."),
 ("WIN-RDP-NLA", "RDP Network Level Authentication", "remote-access", "winlocal", "high", "", "FAIL: RDP enabled and UserAuthentication!=1; PASS: NLA required; NA: RDP disabled."),
 ("WIN-CRED-RUNASPPL", "LSA protection (RunAsPPL)", "credential-protection", "winlocal", "", "medium", "PASS: Lsa RunAsPPL 1 or 2; WARN: not set."),
 ("WIN-CRED-CREDGUARD", "Credential Guard", "credential-protection", "winlocal", "", "low", "PASS: Credential Guard running; WARN: not running; ERR: DeviceGuard WMI unavailable."),
 ("WIN-CRED-WDIGEST", "WDigest cleartext credentials", "credential-protection", "winlocal", "critical", "", "FAIL: WDigest UseLogonCredential=1 (cleartext passwords in LSASS); PASS: 0/absent on 8.1+."),
 ("WIN-CRED-LMCOMPAT", "LAN Manager authentication level", "credential-protection", "winlocal", "high", "medium", "FAIL: LmCompatibilityLevel<3 (LM/NTLMv1 sent); WARN: 3-4 or unset; PASS: 5."),
 ("WIN-CRED-NOLMHASH", "LM hash storage", "credential-protection", "winlocal", "high", "", "FAIL: NoLMHash=0; PASS: 1/default."),
 ("WIN-CRED-CACHEDLOGONS", "Cached domain logons", "credential-protection", "winlocal", "", "low", "WARN: CachedLogonsCount >4 (default 10); PASS: <=4; NA: not domain-joined."),
 ("WIN-UAC-LUA", "UAC enabled", "access-control", "winlocal", "high", "", "FAIL: EnableLUA=0; PASS: 1."),
 ("WIN-UAC-CONSENT", "UAC admin consent prompt", "access-control", "winlocal", "", "medium", "WARN: ConsentPromptBehaviorAdmin=0 (elevate without prompting); PASS: otherwise."),
 ("WIN-UAC-LATFP", "LocalAccountTokenFilterPolicy", "access-control", "winlocal", "", "medium", "WARN: LocalAccountTokenFilterPolicy=1 (full admin token for remote local-account logons; pass-the-hash); PASS: 0/absent."),
 ("WIN-AIE", "AlwaysInstallElevated", "access-control", "winlocal", "critical", "", "FAIL: AlwaysInstallElevated=1 in both HKLM and HKCU; PASS: otherwise."),
 ("WIN-ACCT-ADMINS", "Local Administrators members", "accounts", "winlocal", "", "", "INFO: member count and names of the local Administrators group."),
 ("WIN-ACCT-GUEST", "Guest account", "accounts", "winlocal", "high", "", "FAIL: built-in Guest enabled; PASS: disabled."),
 ("WIN-AUTOLOGON", "AutoLogon stored password", "credential-protection", "creds", "critical", "medium", "FAIL: Winlogon DefaultPassword present; WARN: AutoAdminLogon=1 without stored password; PASS: neither. Never prints the value."),
 ("WIN-LAPS", "LAPS client policy", "accounts", "winlocal", "", "medium", "PASS: Windows LAPS or legacy AdmPwd policy enabled; WARN: no LAPS policy; NA: not domain-joined."),
 ("WIN-SVC-SPOOLER", "Print Spooler", "services", "winlocal", "", "medium", "WARN: Spooler running on a domain controller (coercion/PrintNightmare surface); INFO: running on a non-DC; PASS: stopped/disabled."),
 ("WIN-WINRM-HTTP", "WinRM transport", "remote-access", "winlocal", "high", "low", "FAIL: WinRM AllowUnencrypted=1; WARN: HTTP listener with no HTTPS listener; PASS: HTTPS or HTTP with encryption enforced; NA: WinRM not running."),
 ("WIN-DOMAIN-JOINED", "Domain membership", "domain", "ad", "", "", "INFO: domain name and role (workgroup / member / DC)."),
]
AD = [
 ("AD-PWPOL-MINLEN", "Domain minimum password length", "domain-policy", "ad", "high", "medium", "FAIL: minPwdLength<8; WARN: 8-13; PASS: >=14."),
 ("AD-PWPOL-LOCKOUT", "Domain account lockout threshold", "domain-policy", "ad", "high", "low", "FAIL: lockoutThreshold=0 (unlimited guessing); WARN: >10; PASS: 1-10."),
 ("AD-PWPOL-MAXAGE", "Domain maximum password age", "domain-policy", "ad", "", "", "INFO: maxPwdAge in days (0 = never expires)."),
 ("AD-KRBTGT-AGE", "krbtgt password age", "domain-privilege", "ad", "high", "medium", "FAIL: krbtgt pwdLastSet >365 days; WARN: 180-365; PASS: <180."),
 ("AD-KERBEROASTABLE", "Kerberoastable user accounts", "domain-privilege", "ad", "high", "", "FAIL: >=1 enabled user (not computer) with an SPN; PASS: 0."),
 ("AD-ASREP", "AS-REP roastable accounts", "domain-privilege", "ad", "high", "", "FAIL: >=1 enabled account with DONT_REQ_PREAUTH; PASS: 0."),
 ("AD-UNCONSTRAINED", "Unconstrained delegation (non-DC)", "domain-privilege", "ad", "high", "", "FAIL: >=1 enabled non-DC computer or user with TRUSTED_FOR_DELEGATION; PASS: 0."),
 ("AD-ADMINCOUNT", "adminCount=1 users", "domain-privilege", "ad", "", "", "INFO: count of users with adminCount=1."),
 ("AD-DA-MEMBERS", "Domain Admins membership", "domain-privilege", "ad", "", "medium", "WARN: >5 distinct (recursive) members; INFO: count otherwise."),
 ("AD-PROTECTED-USERS", "Protected Users group", "domain-privilege", "ad", "", "low", "WARN: Protected Users has no members; PASS: >=1."),
 ("AD-MAQ", "Machine account quota", "domain-policy", "ad", "", "medium", "WARN: ms-DS-MachineAccountQuota>0 (any user can join computers; RBCD/Certifried aid); PASS: 0."),
 ("AD-FUNC-LEVEL", "Domain/forest functional level", "domain-policy", "ad", "", "low", "WARN: domain functional level below 2016 (msDS-Behavior-Version<7); PASS: >=7."),
 ("AD-LDAP-SIGNING", "DC LDAP signing / channel binding", "relay", "ad", "high", "medium", "Run on a DC. FAIL: LDAPServerIntegrity<2, or signing required but LdapEnforceChannelBinding unset/0 (LDAPS relay open); WARN: channel binding 1 (when supported); PASS: LDAPServerIntegrity=2 AND LdapEnforceChannelBinding=2; NA: not a DC observer; ERR: registry unreadable (never a false PASS)."),
 ("AD-TRUSTS", "Domain trusts", "domain-policy", "ad", "", "", "INFO: count and direction of trustedDomain objects."),
 ("AD-LAPS-SCHEMA", "LAPS schema present", "domain-policy", "ad", "", "medium", "PASS: ms-Mcs-AdmPwd or msLAPS-Password attribute in schema; WARN: neither."),
]
out = []
for os_, rows, scope in ((L, LIN, "host"), (W, WIN, "host"), (W, AD, "domain")):
    for cid, title, group, cat, sf, sw, sem in rows:
        out.append({"id": cid, "os": os_, "scope": scope, "title": title, "group": group,
                    "category": cat, "sev_fail": sf, "sev_warn": sw, "semantics": sem})
ids = [r["id"] for r in out]
assert len(ids) == len(set(ids)), "duplicate id"
Path(__file__).with_name("catalog.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"linux={len(LIN)} windows-host={len(WIN)} ad={len(AD)} total={len(out)}")
