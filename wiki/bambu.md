# Bambu Lab device correlation

## What aranum reports

Aranum labels a Bambu Lab device as **likely** and **Low severity** only when
Nmap evidence contains explicit BBL/Bambu identity plus compatible protocol or
identity evidence on another distinct endpoint. Multiple matches from one scan
record count once, and common or unidentified ports never identify the vendor.

The `enum-bambu.sh` dispatcher is evidence-only. It records the prior parser
correlation and sends no device packet. In particular, it does not treat port
3000 as HTTP, does not treat port 6000 as X11, does not attempt proprietary
framing, and does not authenticate to MQTT or FTPS.

## Operator follow-up

Validate the recorded scan evidence manually. Any authenticated device
enumeration requires separately supplied authorization and credentials and is
outside this automatic correlation path.

Review the parser's stored evidence offline:

```bash
jq '.device_correlations[] | select(.vendor == "Bambu Lab")' parsed-scan.json
```
