# ROADMAP-003 — Tier 4 ICS / OT enumeration

**Date:** 2026-05-22
**Author:** plan-on-Opus / execute-on-Sonnet (CLAUDE.md §2)
**Iteration:** T4 (deferred slot from [ROADMAP-002](ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md) §Tier 4)
**Scope anchor:** [ADR-005](ADR-005-22MAY2026-ot-ics-safety-scope.md)
**Target tag:** `v0.24.0`

---

## Status legend

⬜ not started · 🟦 in progress · ✅ done · ⏸ blocked · ❌ declined

---

## Overall status

| Iteration | Theme | Effort | Status | Tag |
|---|---|---|---|---|
| **T4** | OT/ICS read-side identification probes (7 protocols, no write-side, double-gated, throttle floor) | ~2 days | ⬜ ADR-005 accepted; implementation pending | `v0.24.0` |

---

## Motivation

ROADMAP-002 §Tier 4 deferred OT/ICS enumeration pending a safety ADR.
ROADMAP-001 iteration I-A raised the same protocols (Modbus, S7,
EtherNet/IP, BACnet, OPC-UA, DNP3, IEC 60870-5-104) and likewise deferred.
[ADR-005](ADR-005-22MAY2026-ot-ics-safety-scope.md) (2026-05-22) accepts the
scope: read-side identification only, double-gated, throttle floor, separate
`ot/` directory, no auto-routing.

This roadmap turns ADR-005's decisions into a concrete v0.23.0 work plan.

---

## T4.0 — Directory and orchestrator skeleton

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/` (new top-level dir), `ot/ot-enum.sh`, `ot/_lib.sh`, `ot/README.md` |
| **Plan** | (1) Create `ot/` with a README that opens with the ADR-005 safety section verbatim. (2) `ot/_lib.sh` defines `OT_THROTTLE_MIN_MS=500` (floor, non-overridable), `OT_MAX_PARALLEL=2` (default), `OT_MAX_PARALLEL_HARD=4` (ceiling), `ot_confirm()` helper that prompts for the literal string `ICS-CONFIRMED`, `ot_throttle_sleep()` that respects the floor. (3) `ot/ot-enum.sh --ics-confirm` is the only auto-routing entrypoint; takes a `--targets` file of `ip:port/proto` triples (no nmap-XML auto-route — operator must hand-pick). |
| **Acceptance** | `ot/ot-enum.sh` without `--ics-confirm` exits with the safety message and rc=2. With `--ics-confirm`, prompts for the typed confirmation. Anything other than the literal `ICS-CONFIRMED` typed exactly exits rc=2. Confirmation sets `OT_CONFIRMED=1` in the dispatcher subprocess env. |
| **Commit** | `feat(ot): add ot/ orchestrator skeleton with double-gated safety prompt` |

---

## T4.1 — Modbus 502 read-side identification

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-modbus.sh` |
| **Plan** | (1) Verify `nmap` available; refuse on miss. (2) Run `nmap -Pn -sT --script modbus-discover -p 502 $ip` with `--script-args modbus-discover.aggressive=false` (passive — no slave-ID enumeration sweep, single FC 17 per discovered unit). (3) Parse the script output for vendor / product / firmware. (4) Emit findings to `$OUT/<ip>/modbus_502.txt` and a one-line summary to `$OUT/<ip>/_findings.txt`. |
| **Acceptance** | Dispatcher refuses to run without `OT_CONFIRMED=1`. Against a known-vulnerable lab fixture (e.g. ModbusPal or pymodbus simulator on localhost), emits exactly one read-side probe (verified via `tcpdump`). Against an open port serving HTTP instead of Modbus, emits 0 findings (the FP harness's cross-service test cell — see Phase 3 of the parent autonomous run). |
| **Commit** | `feat(ot): enum-modbus.sh — FC 17 / FC 43 read-side identification` |

---

## T4.2 — Siemens S7comm 102

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-s7.sh` |
| **Plan** | nmap `s7-info` NSE — sends COTP CR + Job 0x29 read SZL. Emits CPU model, firmware, plant identification, module type. Single probe per port. |
| **Acceptance** | As T4.1. Dispatcher emits exactly one `s7-info` probe per target; refuses without `OT_CONFIRMED=1`. |
| **Commit** | `feat(ot): enum-s7.sh — SZL read-side identification` |

---

## T4.3 — EtherNet/IP 44818

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-enip.sh` |
| **Plan** | nmap `enip-info` NSE — List Identity (0x0063) on UDP and TCP. Vendor / device type / product code / serial / product name. Single packet. |
| **Acceptance** | As T4.1. |
| **Commit** | `feat(ot): enum-enip.sh — List Identity read-side identification` |

---

## T4.4 — BACnet/IP 47808/udp

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-bacnet.sh` |
| **Plan** | nmap `bacnet-info` NSE on UDP 47808 — Who-Is broadcast with LOW=0 HIGH=4194303, then I-Am parse for device instances. Emit one finding per discovered device with vendor ID + firmware (when present). Throttle: 500ms minimum between targets. |
| **Acceptance** | As T4.1. Verify the Who-Is is a **single broadcast** per target subnet, not per host. |
| **Commit** | `feat(ot): enum-bacnet.sh — Who-Is read-side identification` |

---

## T4.5 — OPC-UA 4840

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-opcua.sh` |
| **Plan** | nmap `opcua-info` NSE — GetEndpoints (no session) on the discovery channel. Emit server URI, security policies advertised, server certificate SHA256, MessageSecurityMode list. Flag `None` security policy as MEDIUM severity (per ADR-005 D6). |
| **Acceptance** | As T4.1. Findings list every advertised policy; the `None`-policy detection is reported but never alone — the full policy list accompanies it. |
| **Commit** | `feat(ot): enum-opcua.sh — GetEndpoints read-side identification` |

---

## T4.6 — DNP3 20000

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-dnp3.sh` |
| **Plan** | nmap `dnp3-info` NSE — link-status request (link function 9). Emit master / outstation flag and the link-layer source/destination address. |
| **Acceptance** | As T4.1. |
| **Commit** | `feat(ot): enum-dnp3.sh — link-status read-side identification` |

---

## T4.7 — IEC 60870-5-104 (2404)

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/enum-iec104.sh` |
| **Plan** | Send TESTFR (act) APDU (`0x68 0x04 0x43 0x00 0x00 0x00`) via `nc` or `python3 -c "..."` (stdlib socket). Read the response — STARTDT confirm or no-response. Emit reachability + ASDU address if disclosed. **No** C_** ASDU emitted, ever (ADR-005 D2). |
| **Acceptance** | As T4.1. Probe is exactly 6 bytes outbound; response read with 3-second timeout. |
| **Commit** | `feat(ot): enum-iec104.sh — TESTFR read-side reachability probe` |

---

## T4.8 — Report integration

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `network/report.py` (extend with OT severity rules) |
| **Plan** | Severity table per ADR-005 D6:<br>- INFO: any `OT-ID:` line (vendor/model/firmware emit) for routine identification<br>- LOW: OPC-UA `None`-policy endpoint advertised (situational — context matters)<br>- MEDIUM: BACnet device with no security advertised AND firmware-rev disclosed (combined evidence)<br>- HIGH: reserved for future use (e.g. an OPC-UA endpoint advertising both `None` security AND `Anonymous` user-token policy on the same endpoint)<br>- CRITICAL: not used at T4. CVE-lookup deliberately out of scope (ADR-005 D6). |
| **Acceptance** | `report.py` against an `$OUT` directory containing OT findings produces the right severities per the table. The default (INFO) emits a count, not a CRITICAL alert. |
| **Commit** | `feat(network): report.py severity rules for OT identification findings` |

---

## T4.9 — Surface OT in nmap-parse without auto-routing

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `network/nmap-parse.py` |
| **Plan** | Add an `ot-untouched` category that matches OT ports (502, 102, 44818, 47808, 4840, 20000, 2404) and emits a one-line hint pointing to `docs/ROADMAP-003` and `ot/ot-enum.sh --ics-confirm`. **Crucially:** the category is **not** wired into `SERVICE_MAP`'s normal dispatch path — `auto-enum.sh` sees the hint and prints it; it does NOT invoke any `ot/enum-*.sh`. |
| **Acceptance** | A fixture XML with `<port portid="502">` triggers the hint, does not invoke any dispatcher, and exits 0. `nmap-parse.py --list-categories` shows `ot-untouched` distinct from the IT categories. |
| **Commit** | `feat(network): surface OT services via ot-untouched hint without auto-routing` |

---

## T4.10 — Deps + harness

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `deps-check.sh`, `tests/fp-harness.sh`, `tests/tp-server.py` |
| **Plan** | (1) `deps-check.sh` — add OT section asserting `nmap` (NSE scripts present), `python3 stdlib socket` (for T4.7), and the `OT_CONFIRMED` env var documentation. (2) `tests/tp-server.py` — add an `--ot-enip` stub that replies to a single List Identity (0x0063) packet, used by T4.3 acceptance. (3) `tests/fp-harness.sh` — extend the ENV-GATE TEST block to also assert each OT dispatcher refuses without `OT_CONFIRMED=1`. Cross-service FP test (from Phase 3 below) covers OT-vs-HTTP. |
| **Acceptance** | `bash deps-check.sh` reports OT section. `fp-harness.sh` env-gate block exits 0 with 0/7 expected failures for OT dispatchers without `OT_CONFIRMED`. |
| **Commit** | `test(ot): deps-check + FP harness env-gate coverage for T4 dispatchers` |

---

## T4.11 — Docs + release

| | |
|---|---|
| **Status** | ⬜ |
| **Files** | `ot/README.md`, top-level `README.md`, `CHANGELOG.md` |
| **Plan** | (1) `ot/README.md` — opens with ADR-005 safety section verbatim, then the dispatcher index, then a "how-to" that ends with "if any of the above is unclear, do not run these tools." (2) Top-level `README.md` — add an `ot/` row to the layout tree, with a warning callout that auto-routing is disabled. (3) `CHANGELOG.md` — roll `[Unreleased]` → `[v0.23.0]` with the T4 deliverables. |
| **Commit** | `docs(ot): README + top-level layout + CHANGELOG roll for v0.23.0` |
| **Tag** | `v0.24.0` annotated. |

---

## Out of scope (per ADR-005)

- Any write-side OT function code (FC 5/6/15/16/22/23, S7 stop/start, EIP
  Set Attribute, DNP3 Operate, BACnet WriteProperty, OPC-UA Write/Call,
  IEC C_** ASDU).
- OT firmware CVE-lookup feeds.
- Live PLC RCE PoCs.
- Traffic capture, replay, ARP/DHCP spoof, HMI scrape, EWS credential
  harvest.

Any of these → separate repo + separate review.

---

## Open items deferred to future iterations

- Modbus RTU-over-TCP (8502) — uncommon variant; could fold into T4.1 in a
  later patch.
- IEC 61850 MMS (102, shared port with S7) — substation-specific; needs its
  own scope conversation because MMS is more invasive than S7 ID probes.
- Lab VI Server / LabVIEW (3363) — surface overlaps with engineering
  workstations, not field devices; consider for ROADMAP-001 iteration I
  cleanup rather than T4.

End of roadmap.
