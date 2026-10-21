# CONNECT Reply Simulator

**Authorized testing / lab use only.**

`connect-reply-sim.py` crafts the TCP segment a proxy / remote host sends back in response
to an HTTP `CONNECT host:port HTTP/1.1` request:

```
HTTP/1.1 200 Connection Established\r\n\r\n
```

It lets you present a "remote host" CONNECT reply to a client, a proxy-handling code path,
or network monitoring **without standing up a real proxy** — e.g. validating aranum's
`--proxy` routing, a tunneling client, or a detection rule, on a segment you own.

## Safety model (CLAUDE.md §1 / §9)

- **Dry-run by default.** The tool only *builds and prints* the packet (and can save a
  pcap). Nothing is transmitted until you add the explicit **`--send`** flag — the same
  "no target-write without an explicit flag" gate the rest of aranum uses.
- Point `--send` only at hosts/segments you are authorized to test. Aiming a
  crafted-source reply at third-party traffic is out of scope for this repo.
- No persistence, no exfiltration, no detection-evasion. A pcap is written only to the
  `--write-pcap` path you choose.
- Raw send / sniff require root; the tool says so and exits rather than failing silently.

## Dependency

`scapy` (`pip install scapy`). Listed as optional in `deps-check.sh`.

## Modes

### craft (default) — one simulated reply

```bash
# Dry-run: show the exact packet that WOULD be sent
sudo ./connect-reply-sim.py --src 10.0.0.9 --sport 8080 --dst 10.0.0.5 --dport 51000

# Transmit one reply on a lab segment
sudo ./connect-reply-sim.py --src 10.0.0.9 --dst 10.0.0.5 --dport 51000 --send

# Save the crafted packet to a pcap instead of sending (no root needed)
./connect-reply-sim.py --src 10.0.0.9 --dst 10.0.0.5 --dport 51000 --write-pcap reply.pcap
```

`--seq` / `--ack` set the TCP sequence/ack numbers; `--status` changes the HTTP status
line (e.g. `--status '407 Proxy Authentication Required'`); `--header` adds response
headers (repeatable); `--count` / `--interval` repeat the send.

### `--sniff-respond` — lab responder

Sniffs `--iface` for an inbound CONNECT to `--sport`, then crafts the matching reply with
the correct seq/ack derived from the observed request (reply "from" the host the client
dialed, back to the client). Still dry-run unless `--send` is given.

```bash
sudo ./connect-reply-sim.py --sniff-respond --iface eth0 --sport 8080 --send
# stop after one reply:
sudo ./connect-reply-sim.py --sniff-respond --iface eth0 --sport 8080 --send --max-replies 1
```

## Output / exit

Dry-run prints `packet.summary()` + `packet.show()`. Craft mode without the required
`--src/--dst/--dport` exits `2`. A missing scapy import exits `3`; needing root for
`--send`/sniff exits `4`.
