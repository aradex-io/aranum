---
service: unknown
title: Unknown / Unidentified Service
ports: any
aliases: unknown, tcpwrapped
---

# Unknown service — quick wins

**When you see it:** nmap left a port as `unknown` / `tcpwrapped` — it matched no service
signature. This page is methodology: identify the protocol first (banner, probe responses,
byte patterns), then pivot to the right specialist page. aranum's `enum-unknown.sh` runs a
version-detection baseline, then a targeted NSE second pass based on what the first response
suggests.

> Authorized testing only. Triage is read-only. Sending crafted protocol probes (marked ✏️)
> can interact with the service in unexpected ways on fragile/embedded/OT targets — go gently
> and confirm scope before hammering an unidentified port.

## Triage (read-only)
```sh
nmap -sV --version-all -sC -p PORT H                 # aggressive version detection + default NSE
nc -nv -w 5 H PORT                                    # grab any banner (wait, then send \r\n)
{ printf '\r\n'; sleep 2; } | nc -w5 H PORT | xxd | head   # first bytes as hex (binary proto ID)
curl -sk https://H:PORT/  ; curl -s http://H:PORT/    # is it HTTP/HTTPS on an odd port?
```

## Quick wins

### Aggressive protocol identification
```sh
nmap -sV --version-all --version-intensity 9 -sC -p PORT H
amap H PORT                                           # legacy but good at odd protocols
```
*Why:* `--version-all` runs every probe regardless of port heuristics — the single best way to
name a service nmap's default intensity missed. `amap` fingerprints protocols nmap doesn't.

### HTTP/TLS retry on odd ports
```sh
curl -skI https://H:PORT/ ; curl -sI http://H:PORT/
openssl s_client -connect H:PORT -quiet 2>/dev/null | head   # TLS? cert reveals the app
```
*Why:* a large share of "unknown" ports are just web/APIs on non-standard ports; the TLS cert
CN/SAN or an HTTP `Server:` header names the product instantly → pivot to `wiki/http.md`.

### Byte-pattern / banner triage ✏️
```sh
{ printf '\x00'; sleep 1; } | nc -w3 H PORT | xxd | head        # some binary protos need a nudge
{ printf 'HELP\r\n'; sleep 1; } | nc -w3 H PORT                 # text protocols often answer HELP/?
```
*Why:* the first response bytes fingerprint the protocol (e.g. `REDIS`→ Redis, `SSH-2.0`,
`RFB 003` → VNC, `220` → FTP/SMTP). Match against known port/protocol databases, then jump to
the matching specialist page.

## aranum helpers
- `aranumtoolkit/network/enum-unknown.sh` — catch-all dispatcher: banner + HTTP/HTTPS probe, `nmap -sV --version-all -sC` baseline, then targeted NSE follow-ups (`http-*`, `ssl-*`, SSH/FTP/SMTP/Redis/VNC/RDP scripts) when the first pass suggests a protocol. Tune with `ENUM_UNKNOWN_HTTP_NSE`, `ENUM_UNKNOWN_TLS_NSE`, `ENUM_NMAP_*_TIMEOUT`.
- Once identified, pivot to the relevant page — `wiki/http.md`, `wiki/redis.md`, `wiki/ssh.md`, etc.

## Gotchas
- `tcpwrapped` means the TCP handshake completed but the service closed before responding — often a firewall/tarpit or an auth-gated service; not necessarily interesting.
- Fragile/OT/embedded devices can misbehave on unexpected input — the OT rule (never auto-probe) exists for a reason; keep probes minimal on anything that looks industrial.
- Non-response to one probe ≠ closed — try a few protocol nudges (`\r\n`, `\x00`, `HELP`) before giving up.
- Slow NSE scripts can stall the run — aranum bounds them with `ENUM_NMAP_SCRIPT_TIMEOUT` / `ENUM_NMAP_HOST_TIMEOUT` / `ENUM_NMAP_WALL_TIMEOUT`.

## Sources
- nmap service/version-detection docs (`--version-all`); `amap`; HackTricks Pentesting Methodology (service identification); aranum `enum-unknown.sh` header + README "Nmap defaults vs aranum depth".
