# Offline data sources — provenance & freshness

aranum embeds curated offline datasets so it works air-gapped. Judgment quality
depends on their freshness. Each dataset carries an `updated` (ISO date) + `source`
in its own file; this is the index. `make data-audit` warns when any is stale.

| dataset | file | source | updated |
|---|---|---|---|
| default credentials catalog | `standalones/creds/default-creds.json` (`_meta.updated`) | vendor docs + public default-cred lists | 2026-07-20 |
| GTFOBins SUID subset | `standalones/linux/suid-gtfobins.sh` (header comment) | https://gtfobins.github.io/ (function=suid) | 2026-05 |
| service metadata / priorities | `aranumtoolkit/network/service-metadata.json` | curated in-repo | tracked via git |

## CVE reference lists (embedded in scripts)

CVE version-range checks live in the dispatchers/standalones themselves (e.g.
`sudo-enum.sh`, `looney-check.sh`, `enum-ssh.sh`, `redis-rce-lua.sh`). They are
**signals**, not confirmations — a distro may have backported a fix without a
version bump (the scripts say so). Refresh cadence: review against new CVEs each
release; the `Enhanced`/`Fixed` CHANGELOG sections record currency bumps.

## Refresh policy

- No live fetching at runtime (offline/minimal-dep constraint). Refresh is a
  deliberate maintainer action recorded in the CHANGELOG.
- Bump the dataset's `updated` field when you refresh it.
- `make data-audit` greps the `updated` dates and warns when any is older than
  ~9 months, so staleness is visible.
