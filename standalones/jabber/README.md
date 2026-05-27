# standalones/jabber/ — XMPP / Jabber pentesting helpers

Authorized-testing-only. Scope, safety invariants, and gating decisions are recorded in [`aranumtoolkit/docs/ADR-001-19MAY2026-jabber-scope.md`](../../aranumtoolkit/docs/ADR-001-19MAY2026-jabber-scope.md). **Read it before using anything in this directory.**

## Safety summary (read first)

1. **Default behavior of every tool here is read-only.** No tool modifies target state unless an explicit subcommand / `--exploit` flag is passed.
2. **The OpenFire CVE helper is the only state-modifying tool.** Its `--exploit` subcommand requires the operator to type the target FQDN literally. The chain creates an admin user and uploads a JSP webshell plugin. **`--cleanup` must be rehearsed and ready before `--exploit` is fired.**
3. **No password spraying.** Per ADR-001 D2, this iteration ships single-credential validation only. If you need spray, it does not exist yet — do not improvise it from these primitives without a fresh ADR.
4. **The OpenFire exploit chain is lab-verify-before-trust.** The DWR call, multipart upload, and cleanup paths are written per the public CVE-2023-32315 advisory PoC pattern but have not been validated against a real vulnerable container in this repo's CI. Run against a known-vulnerable 4.7.4 lab container first.

## Tools

| Tool | Default behavior | Optional | Notes |
|---|---|---|---|
| [`../../aranumtoolkit/network/enum-jabber.sh`](../../aranumtoolkit/network/enum-jabber.sh) | 7-phase read-only XMPP server enum (banner / cert+SANs / SASL mechs / IBR-advertised / disco / MUC items / BOSH-WS / admin-API) | — | Auto-routed by `auto-enum.sh` from the `xmpp` category |
| [`jabber-user-enum.py`](jabber-user-enum.py) | SASL PLAIN response-differential username enum (read-only) | `--out` JSONL, `--delay` rate-shape | Deliberately does NOT use XEP-0077 IBR conflict-probe (that technique writes) |
| [`jabber-validate.py`](jabber-validate.py) | Single-credential SASL validation (SCRAM-SHA-256 → SCRAM-SHA-1 → PLAIN) | `--mechs` override, `JABBER_PASSWORD` env | NO spray. One user, one password, one attempt. |
| [`jabber-admin-api-probe.sh`](jabber-admin-api-probe.sh) | Detect Ejabberd `/api/`, Prosody `mod_admin_telnet` (5582), `mod_admin_web` (/admin) | — | Read-only HEAD/banner only |
| [`openfire-cve-2023-32315.py`](openfire-cve-2023-32315.py) `detect` | Path-traversal vulnerability probe (read-only) | — | Always safe to run during recon |
| [`openfire-cve-2023-32315.py`](openfire-cve-2023-32315.py) `exploit` | **MODIFIES TARGET** — admin create + JSP webshell upload | Requires typed-FQDN confirmation, `--plugin-jar PATH`, writes `--log` | See "Cleanup procedure" below |
| [`openfire-cve-2023-32315.py`](openfire-cve-2023-32315.py) `cleanup` | Reverse a prior `--exploit` run via the legitimate admin login | Scaffolded — see "Manual cleanup" below | |

## Typical workflow

```bash
# 1. Discover XMPP/Openfire targets via the auto-enum pipeline
./aranumtoolkit/network/auto-enum.sh -i scan.xml -o ./enum/

# 2. Inspect findings — enum-jabber.sh has populated per-host evidence files
ls ./enum/xmpp/                       # one dir per ip_port
cat ./enum/xmpp/10.0.0.5_5222/sasl_mechs.txt
cat ./enum/xmpp/10.0.0.5_5222/ibr_probe.txt
cat ./enum/xmpp/10.0.0.5_5222/cert_sans.txt   # domain inventory for next steps

# 3. If a server advertises a registration form OR you have a candidate user list
./standalones/jabber/jabber-user-enum.py \
    --host 10.0.0.5 --port 5222 --domain example.org \
    --user-list ./users.txt \
    --out ./enum/xmpp/10.0.0.5_5222/user_probe.jsonl

# 4. Found a credential (from prior phase, OSINT, or breach data)? Validate it.
JABBER_PASSWORD='Hunter2!' ./standalones/jabber/jabber-validate.py \
    --host 10.0.0.5 --port 5222 --domain example.org \
    --jid alice@example.org
# exit 0 = AUTH_OK ; exit 1 = AUTH_FAIL ; exit 2 = pre-auth error

# 5. If openfire-admin was also enumerated (9090/9091), probe the CVE
./standalones/jabber/openfire-cve-2023-32315.py --url http://10.0.0.5:9090 detect

# 6. *** Only proceed past detect with explicit engagement authorization. ***
#    Build your own audited webshell plugin first (see "Building a JSP plugin" below).
./standalones/jabber/openfire-cve-2023-32315.py --url http://10.0.0.5:9090 exploit \
    --plugin-jar ./my-audited-plugin.jar \
    --log /tmp/openfire-exploit-10.0.0.5.json
# Confirmation prompt will require you to type '10.0.0.5:9090' literally.
```

## Lab verification (required before engagement use of `exploit`)

Build a known-vulnerable container:

```bash
# Vulnerable Openfire 4.7.4 (do NOT pull a patched 4.7.5+)
docker run -d --name openfire-474 \
    -p 9090:9090 -p 9091:9091 -p 5222:5222 \
    sameersbn/openfire:4.7.4-1   # or build from source-pinned 4.7.4
```

Run the detect+exploit cycle against it. Verify:
1. `detect` reports `VULNERABLE`.
2. `exploit` (with typed-FQDN confirm) actually creates the admin you can see in `/admin/user-summary.jsp` once logged in with the captured credential.
3. The webshell plugin is reachable at the URL printed.
4. `cleanup` (or the manual procedure below) removes both.

If any step fails, the corresponding code path is incorrect for your Openfire build and needs adjustment before engagement use. **Do not run `exploit` against a real target until lab verification passes.**

## Building a JSP plugin (operator-supplied, per ADR-001 D3)

We deliberately do not bundle a webshell plugin — the operator brings their own so they know exactly what's being uploaded. Minimum plugin JAR layout:

```
my-plugin.jar
├── plugin.xml          # name, version, description, minServerVersion, class
├── lib/                # optional: dependencies
└── web/
    └── webshell.jsp    # the actual webshell (review the source!)
```

Minimal `plugin.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<plugin>
    <name>audit-shell</name>
    <description>Engagement-scoped diagnostic plugin</description>
    <author>engagement-team</author>
    <version>1.0.0</version>
    <minServerVersion>4.0.0</minServerVersion>
</plugin>
```

Build with `zip -r my-plugin.jar plugin.xml web/`. Audit `web/webshell.jsp` before every engagement — the contents of that file are 100% your responsibility.

## Manual cleanup (until the `cleanup` subcommand is lab-verified)

After `exploit`, the log file contains the admin credential and plugin name. To reverse manually:

1. **Log in as the captured admin:**
   ```
   open http://<target>:9090/login.jsp
   user: <admin_user from log>
   pass: <admin_pass from log>
   ```
2. **Delete the plugin:**
   - Navigate to: `Server → Server Settings → Plugins → Manage Plugins`
   - Find `<plugin_name from log>` and click the red X (Uninstall)
3. **Delete the admin:**
   - Navigate to: `Users/Groups → User Summary`
   - Click `<admin_user from log>` → `Delete User` → confirm

Both steps are reversible engagement-bounded changes; do them before disconnecting.

## What this directory does NOT do (and why)

- **No password spray.** Per ADR-001 D2 — lockout risk, engagement-time cost. Any future spray will require its own ADR with mandatory rate-cap + first-lockout-stop + typed-confirm gates.
- **No XEP-0077 conflict-probe username enum.** That technique creates accounts when the conflict path doesn't fire — a write side-effect. The SASL-differential approach in `jabber-user-enum.py` is read-only.
- **No Cisco UC / SIP / Matrix / Mattermost / Rocket.Chat tooling.** Scoped out of iteration H per ADR-001 D1. Each would need its own ADR.
- **No webshell plugin bundled.** Operator brings their own (per ADR-001 D3) — what we ship, you upload.
- **No persistence variant of the Openfire chain.** The plugin is intended for in-engagement use and cleanup. CLAUDE.md §9 invariant 4 enforced.

End of standalones/jabber/README.
