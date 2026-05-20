# Default Credential Sweep

Authorized testing only. Stdlib-only Python sweeper that fingerprints 28+ admin portals and tries known default credentials against each.

## Layout

```
creds/
├── default-creds.json        # the product catalog — fingerprints, cred lists, success conditions
├── default-creds-sweep.py    # the sweeper
└── README.md
```

## Why this exists

Default-credential findings are statistically the #1 way commodity attackers go from "external recon" to "RCE on something interesting". They're often skipped during dedicated pentest because they feel low-effort, but on a typical 1000-host engagement you'll find 5–15 of them, and each one is a P1 critical:

- Tomcat Manager `tomcat:tomcat` → WAR deploy RCE
- Jenkins `admin:admin` → Groovy script-console RCE
- ActiveMQ `admin:admin` → Jolokia MBean RCE (see `activemq/` toolkit)
- WebLogic `weblogic:weblogic` → deserialization RCE
- Splunk `admin:changeme` → search-app RCE
- pgAdmin `admin@pgadmin.org:admin` → all your databases
- MinIO `minioadmin:minioadmin` → every object in every bucket
- vCenter `administrator@vsphere.local:VMware1!` → datacenter takeover

## Products covered

| Tier | Products |
|---|---|
| **Critical RCE on success** | Tomcat, JBoss/WildFly, WebLogic, GlassFish, Jenkins, ActiveMQ, RabbitMQ (admin), Splunk, GitLab, MinIO, Airflow, F5 Big-IP, vCenter/ESXi, Cisco IOS, Mikrotik |
| **Critical data exposure** | Grafana, Kibana, Elasticsearch, Sonarqube, Nexus, Artifactory, pgAdmin, phpMyAdmin, Adminer, Jupyter, GitLab |
| **High-value config / pivots** | Keycloak, Hadoop YARN, Docker Registry, Spring Boot Actuator (unauth) |
| **Bonus** | MLflow/ZenML |

Catalog format is one JSON entry per product — `fingerprint_path` + `fingerprint_regex` confirms identity, then `creds` list + `success_re`/`success_code` confirms valid auth. Add new products by appending to the JSON.

## Quickstart

```bash
# Against a list of services discovered from your nmap scan
python3 ../network/nmap-parse.py scan.xml --all-ports | awk '{print $1}' > targets.txt
./default-creds-sweep.py --targets targets.txt --output findings.json

# Against one specific host
./default-creds-sweep.py --target http://10.0.0.5:8161

# Just fingerprint — what products are running, no auth attempts
./default-creds-sweep.py --targets targets.txt --fingerprint-only

# Narrow to one product
./default-creds-sweep.py --targets targets.txt --product 'Tomcat Manager'
```

## Output

For each successful auth:

```
[!!] http://10.0.0.5:8080  Tomcat Manager  tomcat:tomcat  (code-match)
     -> Deploy a malicious WAR via /manager/text/deploy?path=/x — RCE as the Tomcat user
```

Plus a JSON file with structured findings for downstream processing.

## Tuning

```
--threads N      parallel target threads (default 8)
--delay SECS     between credential attempts per target (default 0.2)
--fingerprint-only
                 just identify products; useful for first-pass recon without auth attempts
```

## What's NOT here (and why)

- **Service-protocol auth** (SSH/FTP/SMB/RDP/MSSQL/MySQL) — those are covered by `nxc` in the network dispatchers; this tool is HTTP-only by design.
- **SNMP communities** — see `network/enum-snmp.sh` with `onesixtyone`.
- **VNC blank-auth** — nmap `vnc-info` script.
- **IPMI cipher 0 / null-user** — specialised; use `ipmi-cipher-zero.nse`.

Keep the HTTP catalog focused. For non-HTTP defaults, use the right tool for the protocol.

## Extending the catalog

Append a new entry to `default-creds.json`:

```json
{
  "name": "MyProduct Console",
  "ports": [12345],
  "fingerprint_path": "/api/version",
  "fingerprint_regex": "MyProduct",
  "test_path": "/api/login",
  "creds": ["admin:admin","admin:myproduct"],
  "post": "user={USER}&pass={PASS}",
  "success_re": "Set-Cookie:.*session",
  "next_step": "What to do once authenticated"
}
```

The sweeper picks it up automatically — no code changes required.
