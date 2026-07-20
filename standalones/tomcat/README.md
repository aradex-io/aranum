# tomcat/ — Tomcat Manager post-discovery helper

Authorized-testing-only. Pairs with the `default-creds-sweep.py` "Tomcat Manager"
finding: once you have valid manager creds, this deploys an **operator-supplied**
WAR for code execution — the same "bring your own payload" model as
`standalones/jabber/openfire-cve-2023-32315.py` and the ActiveMQ Jolokia helper.

## `tomcat-war-deploy.sh`

```bash
# 1) detect (read-only default) — is the manager reachable and do the creds work?
./tomcat-war-deploy.sh --url http://TARGET:8080 --user tomcat --pass tomcat

# 2) deploy YOUR war (writes to target — requires --exploit + --war)
#    Build a JSP webshell WAR yourself, scoped to your engagement.
./tomcat-war-deploy.sh --url http://TARGET:8080 --user tomcat --pass s3cret \
    --war ./shell.war --path /reports --exploit
#    -> App base: http://TARGET:8080/reports/

# 3) clean up
./tomcat-war-deploy.sh --url http://TARGET:8080 --user tomcat --pass s3cret \
    --path /reports --undeploy
```

## Safety (CLAUDE.md §9)

- **Default is read-only detect.** `--exploit` (deploy) and `--undeploy` are the
  only state-mutating paths and are explicitly gated.
- **No payload is bundled.** You supply `--war`; nothing in this repo ships a
  webshell.
- `--insecure` skips TLS verification for self-signed engagement certs (opt-in).
- Always `--undeploy` the context you created before leaving the engagement.

## Notes

- Targets the **text** manager (`/manager/text/*`), which is script-friendly and
  present whenever the `manager-script` role is assigned. If only the HTML manager
  (`/manager/html`) exists, the CSRF-nonce flow differs — deploy by hand.
- `deploy?...&update=true` overwrites an existing context of the same path.
