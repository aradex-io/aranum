# ADR-005 — OT / ICS enumeration: safety scope

| | |
|---|---|
| **Status** | Accepted (2026-05-22) |
| **Iteration** | T4 (Tier 4 ICS — deferred slot from [ROADMAP-002](ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md) §Tier 4) |
| **Tag** | `v0.24.0` (planned — v0.23.0 was consumed by enum-print.sh / I-K) |
| **Supersedes** | none |
| **Related** | [ROADMAP-002](ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md), [ROADMAP-003](ROADMAP-003-22MAY2026-tier4-ics-enumeration.md), CLAUDE.md §9 |

## Context

ROADMAP-002 §Tier 4 deferred ICS / OT enumeration (Modbus 502, S7 102,
EtherNet/IP 44818, BACnet/IP 47808/udp, OPC-UA 4840, DNP3 20000, IEC 60870-5-104
2404) pending an ADR that pins down the safety boundaries. ROADMAP-001 §I-A
("Industrial / OT") raised the same scope question and explicitly deferred
implementation.

OT systems differ from IT services in a way that the rest of aratool's threat
model does not currently model: **a read-side probe can cause a physical
event**. A poorly framed Modbus function-17 query against a PLC that owns the
lighting / motor / valve / instrument can stall the device or trip a safety
interlock. The "enumeration only" stance that protects us on IT services is
not load-bearing on OT.

This ADR records the scope and the safety controls before any T4 dispatcher
is written.

## Decisions

### D1 — OT dispatchers live under `standalones/ot/`, not `aranumtoolkit/network/`

**Decision:** Tier 4 enumeration scripts go in a new top-level `standalones/ot/`
directory. `aranumtoolkit/network/auto-enum.sh` does **not** auto-route to them and
`aranumtoolkit/network/nmap-parse.py` does **not** add OT categories to the auto-routing
`SERVICE_MAP`. Operators must run them by hand or via the new
`standalones/ot/ot-enum.sh` orchestrator with explicit `--ics-confirm`.

**Reason:** auto-routing is the wrong default for any service whose probes can
cause physical events. The existing `auto-enum.sh` workflow is "feed me an
nmap; I'll enumerate everything I see" — if a Modbus 502 hit lands in that
list and the operator is doing their first pass on a customer network, the
probe fires before the operator has read the engagement statement. Moving
OT scripts to their own directory makes that workflow impossible.

**Consequence:** `nmap-parse.py` *may* surface OT categories in its
`--list-services` output for situational awareness, but they are routed to a
sentinel category (e.g. `ot-untouched`) that emits a hint instead of
dispatching. The hint reads: *"Tier 4 OT services detected — see
`aranumtoolkit/docs/ROADMAP-003` and run `standalones/ot/ot-enum.sh` with `--ics-confirm` only after
written engagement authorization for OT scope."*

### D2 — Hard write-side prohibition (no operator override)

**Decision:** No T4 dispatcher will ever emit a write-side function code.
Specifically prohibited (non-exhaustive):

- Modbus: function codes 5 (Write Single Coil), 6 (Write Single Register),
  15 (Write Multiple Coils), 16 (Write Multiple Registers), 22 (Mask Write),
  23 (Read/Write Multiple). Also 8 (Diagnostic) subfunction 1 (Restart),
  4 (Force Listen Only).
- S7: PLC stop / start / firmware download / DB write commands.
- EtherNet/IP: Set Attribute, Reset, Forward Open with config-data.
- DNP3: Operate, Direct Operate, Cold Restart, Warm Restart.
- BACnet: WriteProperty, WritePropertyMultiple, ReinitializeDevice,
  DeviceCommunicationControl.
- OPC-UA: Write, Call, AddNodes, AddReferences, DeleteNodes.
- IEC 60870-5-104: any C_** ASDU (control direction).

**Reason:** CLAUDE.md §9 invariant 1 ("no script writes to a target without
an explicit `--write` / `--exploit` / `--rce` flag") is necessary for IT
services but **not sufficient** for OT. The write-side function codes on a
PLC do not just modify a database row — they can move valves, energize
motors, change setpoints, and trip interlocks. The reversibility property
that justifies an opt-in `--write` flag on Redis or ActiveMQ does not hold
here.

**Consequence:** there is no `--write`, `--exploit`, or `--rce` flag on T4
dispatchers. There is no operator override. A request to add one is refused.
A future engagement that genuinely needs OT write-side testing (e.g. an
isolated factory-acceptance test where the operator is the OEM) requires a
separate repo, separate review, and is not a future iteration here.

### D3 — Read-side function codes that are still risky require `--ics-confirm`

**Decision:** Even read-side OT function codes can stall fragile or
end-of-life PLCs. Therefore every T4 dispatcher requires `--ics-confirm` and
emits a one-time typed confirmation prompt:

```
WARNING: <protocol> probes can cause physical events on legacy/fragile
devices even with read-only function codes. Confirm written engagement
authorization includes OT scope.
Type the literal string ICS-CONFIRMED to proceed (no other input accepted):
```

The orchestrator `standalones/ot/ot-enum.sh --ics-confirm` confirms once at the start
and propagates the confirmation into a per-run env var (`OT_CONFIRMED=1`)
that individual dispatchers check. Direct dispatcher invocation requires
the same `--ics-confirm` flag and a typed prompt unless `OT_CONFIRMED=1` is
present in the env (which only `standalones/ot/ot-enum.sh` sets after its prompt).

**Reason:** OT engagement scope is often tighter than the rest of the
engagement — "yes for IT, schedule a separate maintenance window for OT" is
a common phrasing. The confirmation step forces the operator to acknowledge
the scope difference before the first probe leaves the test box.

**Consequence:** scripted/CI use of T4 dispatchers is **explicitly
unsupported**. Anyone wiring a T4 dispatcher into a CI pipeline is bypassing
the safety control and the script is not designed to remain safe under that
usage.

### D4 — Per-host throttle floor + concurrency ceiling

**Decision:** T4 dispatchers apply a minimum 500ms delay between probes to
the same target and a maximum concurrency of 1 (no parallel probes against a
single PLC, ever). The orchestrator `standalones/ot/ot-enum.sh` parallelizes at the host
level only, with a default `--max-parallel 2` and a hard ceiling of 4
configurable hosts in flight. Operator-supplied `--throttle aggressive` is
**ignored** in `standalones/ot/`; the throttle floor is non-negotiable.

**Reason:** legacy PLCs maintain very small per-connection state machines
and can drop or hang under back-to-back probes that an HTTP service would
not notice. The throttle floor protects the device; the concurrency ceiling
protects the operator from doing a "scan the whole subnet in parallel"
mistake.

**Consequence:** an `standalones/ot/ot-enum.sh` run against a /24 will take meaningfully
longer than the equivalent `aranumtoolkit/network/auto-enum.sh`. This is intentional.

### D5 — Probe set: read-side identification only

**Decision:** the v0.23.0 (T4) probe set is the minimum that identifies the
device and surfaces its risk profile. For each protocol:

| Protocol | Probe | Output |
|---|---|---|
| Modbus 502 | FC 17 (Report Slave ID); FC 43 (Read Device Identification, MEI types 0x01/0x02/0x04) | Vendor / product / firmware / device family |
| S7 102 | COTP CR + Job request 0x29 (Read SZL) on SZL-ID 0x11 / 0x1c | CPU model, firmware, name |
| EtherNet/IP 44818 | List Identity (0x0063) UDP/TCP — single packet | Vendor / device type / serial / product name |
| BACnet/IP 47808/udp | Who-Is broadcast (LOW limit 0, HIGH limit 4194303) | Device instances reachable |
| OPC-UA 4840 | GetEndpoints (no session) | Server URI / security policies / cert |
| DNP3 20000 | Link-status request (start byte 0x05 0x64, link func 9) | Master / outstation flag, address |
| IEC 60870-5-104 | TESTFR act (0x68 0x04 0x43 ...) | Connection accept / version probe |

No write-side function code, no session establishment that creates state on
the device beyond what the protocol requires for a single read.

**Reason:** an identification probe gives the operator enough to (a) confirm
device class, (b) cross-reference the vendor advisory feed, and (c) decide
whether deeper testing is warranted under the engagement scope. A heavier
probe set is not needed at T4 and increases the risk of stalling a fragile
device.

### D6 — Severity rules favor situational awareness over CVE multiplication

**Decision:** `aranumtoolkit/network/report.py` (or a new `standalones/ot/report.py` — see ROADMAP-003)
emits OT findings at INFO/LOW by default. A CRITICAL or HIGH severity is
assigned only when the probe surfaces a known unauthenticated control plane
(e.g. an OPC-UA endpoint advertising `None` security policy on the auth
channel, or a Modbus device returning a Schneider/Allen-Bradley CPU model
known to lack authentication entirely). Version-based CVE lookups for OT
firmware are **out of scope for T4** — they require maintained vendor feeds
that aratool does not ship.

**Reason:** CVE counts for OT firmware are noisy and almost always require
operator interpretation against the customer's patch posture. Surfacing them
in T4 invites false-positive findings that erode trust in the rest of the
report. Situational-awareness output ("Allen-Bradley ControlLogix 1756-L7x,
firmware 30.011, model B") is more useful and more honest.

### D7 — No SCADA traffic capture, no MITM helpers, no ARP spoofing

**Decision:** T4 ships read-side probes only. The repo does **not** add:

- Modbus/DNP3/IEC traffic capture or replay tools
- ARP-spoof or DHCP-spoof helpers for SCADA segment positioning
- PLC firmware extraction utilities
- HMI screen-scrape helpers
- Engineering-workstation credential harvesters

These are valid OT-pentest activities, but they belong in a separate repo
with stricter access. aratool's scope is enumeration; T4 stays inside that
scope.

**Reason:** CLAUDE.md §9 invariant 5 (no detection evasion / EDR unhook) is
the closest cousin of this prohibition. The reasoning extends: tools that
position the operator inside the control-plane traffic flow change the OPSEC
threat model from "operator runs a tool from a test box" to "operator
occupies the network segment." We do not want a single repo to span both.

## Status table for downstream documents

| Document | Status |
|---|---|
| `aranumtoolkit/docs/ROADMAP-003-22MAY2026-tier4-ics-enumeration.md` | Drafted alongside this ADR |
| `standalones/ot/` directory creation | Tracked in ROADMAP-003 §implementation |
| Update to `aranumtoolkit/docs/ROADMAP-001-19MAY2026-thoroughness-execution.md` iteration I-A | Mark "deferred to T4 / ADR-005" with link |
| Update to `aranumtoolkit/docs/ROADMAP-002-22MAY2026-tier1-tier2-enumeration.md` Tier 4 section | Cross-link to ADR-005 + ROADMAP-003 |

## Out-of-scope (decline up front)

- Any write-side OT function code. Not now, not under any operator-override.
- OT firmware CVE-lookup feeds.
- Live PLC RCE PoCs.
- Anything that positions aratool inside SCADA segment traffic (ARP/DHCP
  spoof, capture, MITM).

If a future engagement needs any of these, the answer is "not aratool" — open
a separate repo with the appropriate scope and access controls.
