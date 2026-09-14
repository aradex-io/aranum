# Offline data sources — provenance and freshness

`aranumtoolkit/data-sources.json` is the machine-readable source of truth for
every embedded dataset and rule family. Each entry records its source, explicit
owner, reviewed/refreshed date, maximum age, freshness policy, and either an
exact SHA-256 checksum or a reproducible derivation.

Derivations are typed machine-readable objects, not free-form assertions. The
audit validates declared JSON structure, hashes every input named by a source
manifest, and checks discovered-content rules against their actual roots,
markers, suffixes, and minimum inventory. Unsupported or malformed derivation
types fail the gate.

`make data-audit` validates the manifest schema, file existence, checksums,
derivations, and freshness. The CVE/version entry discovers every runtime and
wiki file carrying a CVE marker so a new embedded rule cannot silently fall
outside the inventory. A file being tracked by Git is not treated as evidence
that its content was recently reviewed.

Refreshes are deliberate maintainer actions: update the entry date, checksum or
derivation, and changelog in the same change. No live fetching occurs at
runtime, preserving air-gapped operation.
