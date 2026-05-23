# `ot/` — OT / ICS read-side identification

> **Read this section before invoking anything in this directory.**
>
> OT probes (Modbus / S7 / EtherNet-IP / BACnet / OPC-UA / DNP3 / IEC 60870-5-104)
> can cause physical events on legacy or fragile devices even when restricted
> to read-side function codes. The safety controls in this directory are
> load-bearing — do not weaken them.

**Scope anchor:** [`docs/ADR-005-22MAY2026-ot-ics-safety-scope.md`](../docs/ADR-005-22MAY2026-ot-ics-safety-scope.md)
**Roadmap:** [`docs/ROADMAP-003-22MAY2026-tier4-ics-enumeration.md`](../docs/ROADMAP-003-22MAY2026-tier4-ics-enumeration.md)

---

## Hard rules (ADR-005)

1. **No write-side function code, ever.** No `--write`, `--exploit`, or
   `--rce` flag. There is no operator override. The list of prohibited
   function codes per protocol is in ADR-005 D2.
2. **`--ics-confirm` + typed `ICS-CONFIRMED` prompt before any probe.**
   The orchestrator (`ot-enum.sh`) sets `OT_CONFIRMED=1` only after the
   prompt; every dispatcher refuses without it.
3. **Throttle floor 500 ms per host (non-overridable).** Operator-supplied
   `--throttle aggressive` is ignored. Concurrency ceiling 4, default 2.
4. **No auto-routing.** `network/auto-enum.sh` does not invoke anything in
   `ot/`. It surfaces detected OT ports via a sentinel category
   (`ot-untouched`) with a hint, but does not probe.
5. **No traffic capture, no MITM, no ARP/DHCP spoof.** See ADR-005 D7.

---

## Quick start

```bash
# 1. Build a targets file (one per line, format: ip:port/proto)
cat > targets.txt <<EOF
10.0.0.5:502/modbus
10.0.0.6:102/s7
10.0.0.7:44818/enip
10.0.0.8:47808/bacnet
10.0.0.9:4840/opcua
10.0.0.10:20000/dnp3
10.0.0.11:2404/iec104
EOF

# 2. Run the orchestrator (will prompt for ICS-CONFIRMED)
bash ot/ot-enum.sh --ics-confirm --targets targets.txt --output ./ot-out
```

The prompt looks like:

```
WARNING — OT/ICS ENUMERATION GATE
...
Type the literal string  ICS-CONFIRMED  (case-sensitive, no quotes) to
proceed. Anything else aborts.
```

Typing anything other than the literal `ICS-CONFIRMED` exits rc=2.

---

## Dispatchers

Every dispatcher is **read-side identification only**. None of them will
modify device state.

| Script | Protocol / Port | Probe |
|---|---|---|
| [`enum-modbus.sh`](enum-modbus.sh) | Modbus TCP 502 | `nmap modbus-discover` (FC 17, aggressive=false) |
| [`enum-s7.sh`](enum-s7.sh) | Siemens S7comm 102 | `nmap s7-info` (Read SZL via COTP CR + Job 0x29) |
| [`enum-enip.sh`](enum-enip.sh) | EtherNet/IP 44818 (TCP+UDP) | `nmap enip-info` (List Identity 0x0063) |
| [`enum-bacnet.sh`](enum-bacnet.sh) | BACnet/IP 47808/udp | `nmap bacnet-info` (Who-Is broadcast) |
| [`enum-opcua.sh`](enum-opcua.sh) | OPC-UA 4840 | `nmap opcua-info` (GetEndpoints, no session) |
| [`enum-dnp3.sh`](enum-dnp3.sh) | DNP3 20000 | `nmap dnp3-info` (link-status, function 9) |
| [`enum-iec104.sh`](enum-iec104.sh) | IEC 60870-5-104 2404 | stdlib socket — TESTFR (act) APDU |

Each dispatcher writes findings to `$OUT/<ip>/<proto>_<port>.txt` and emits
a one-line `OT-ID <proto> <ip>:<port> — <fields>` hit. `network/report.py`
classifies these as LOW (situational awareness, not actionable on its own).

---

## What does *not* happen

- No FC 5/6/15/16/22/23 (Modbus write coil/register/multiple/mask).
- No PLC stop/start/firmware-download (S7).
- No Set Attribute / Reset / Forward Open with config-data (EtherNet/IP).
- No WriteProperty / ReinitializeDevice / DeviceCommunicationControl (BACnet).
- No Write / Call / AddNodes / AddReferences / DeleteNodes (OPC-UA).
- No Operate / Direct Operate / Cold Restart / Warm Restart (DNP3).
- No C_** ASDU (IEC 60870-5-104 control direction).

---

## If any of the above is unclear, do not run these tools.

If you are unsure whether your engagement covers OT scope, **stop and ask**.
The cost of a stalled PLC during a production run is much higher than the
cost of pausing this work for a written authorization confirmation.

---

## Out of scope (per ADR-005 D7 — separate repo + separate review)

- Modbus/DNP3/IEC traffic capture, replay, or MITM helpers.
- ARP-spoof or DHCP-spoof helpers for SCADA segment positioning.
- PLC firmware extraction utilities.
- HMI screen-scrape helpers.
- Engineering-workstation credential harvesters.
