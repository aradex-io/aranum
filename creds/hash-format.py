#!/usr/bin/env python3
"""hash-format.py — convert captured authentication hashes from Responder /
impacket / nxc output formats into hashcat- and john-ready files.

Recognised inputs (auto-detected from file content):
  - NTLMv2  : `USER::DOMAIN:CHALL:RESP:RESP` lines (Responder + nxc smb)
  - NTLMv1  : `USER::DOMAIN:LMRESP:NTRESP:CHALL`
  - AS-REP  : `$krb5asrep$23$user@DOMAIN:CHALL$RESP`
  - TGS-REP : `$krb5tgs$23$*spn$DOMAIN$user*$CHALL$RESP`

Output (under $OUT/hashes/):
  hashcat-ntlmv2.txt   ready for `hashcat -m 5600`
  hashcat-ntlmv1.txt   ready for `hashcat -m 5500`
  hashcat-asrep.txt    ready for `hashcat -m 18200`
  hashcat-tgs.txt      ready for `hashcat -m 13100`
  john-*.txt           same content (Hashcat and JtR formats overlap here)
  _index.tsv           one row per hash: type / user / domain / src_file

Per CLAUDE.md §9 invariant 2 (no exfil): files are written to the
operator-specified --output dir only. No phone-home, no network.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

# Anchor patterns on the canonical first chunk of each format. Greedy match
# from there so trailing whitespace / line endings are absorbed.
_PATTERNS = {
    "ntlmv2":  re.compile(r"^([^:]+?)::([^:]+):([0-9a-f]{16}):([0-9a-f]{32}):[0-9a-f]+$", re.I | re.M),
    "ntlmv1":  re.compile(r"^([^:]+?)::([^:]+):([0-9a-f]{48}):([0-9a-f]{48}):[0-9a-f]{16}$", re.I | re.M),
    "asrep":   re.compile(r"^\$krb5asrep\$23\$([^@]+)@([^:]+):[a-f0-9]+\$[a-f0-9]+$", re.I | re.M),
    # impacket GetUserSPNs hashcat-13100 format is:
    #   $krb5tgs$23$*user$realm$spn*$checksum$edata2
    # The user / realm / spn are inside the *...* wrapper, $-delimited.
    "tgs":     re.compile(r"^\$krb5tgs\$23\$\*([^$]+)\$([^$]+)\$([^*]+)\*\$[a-f0-9]+\$[a-f0-9]+$", re.I | re.M),
}

# hashcat mode mapping (for the doc comment at the top of each output file)
_HASHCAT_MODE = {
    "ntlmv2": "5600 (NetNTLMv2)",
    "ntlmv1": "5500 (NetNTLMv1)",
    "asrep":  "18200 (Kerberos AS-REP)",
    "tgs":    "13100 (Kerberos TGS-REP)",
}


def _detect_and_extract(text: str) -> dict[str, list[tuple[str, str, str]]]:
    """Returns {hash_type: [(line, user, domain), ...]}."""
    out: dict[str, list[tuple[str, str, str]]] = defaultdict(list)
    seen: set[str] = set()  # de-dup by full line
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line in seen:
            continue
        for kind, pat in _PATTERNS.items():
            m = pat.match(line)
            if m:
                seen.add(line)
                if kind == "tgs":
                    # *user$realm$spn* — three captures
                    user, domain = m.group(1), m.group(2)
                else:
                    user, domain = m.group(1), m.group(2)
                out[kind].append((line, user, domain))
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", type=Path,
                    help="one or more files containing captured hashes (Responder logs, "
                         "nxc smb output, impacket *.txt, ...)")
    ap.add_argument("-o", "--output", type=Path, required=True,
                    help="output dir (e.g. /tmp/engagement/hashes)")
    ap.add_argument("--no-john", action="store_true",
                    help="skip writing john-<type>.txt mirrors (same content as hashcat)")
    args = ap.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    extracted: dict[str, list[tuple[str, str, str, str]]] = defaultdict(list)
    for inp in args.inputs:
        if not inp.is_file():
            print(f"[!] not a file: {inp}", file=sys.stderr); continue
        text = inp.read_text(errors="replace")
        per = _detect_and_extract(text)
        for k, items in per.items():
            for (line, user, domain) in items:
                extracted[k].append((line, user, domain, str(inp)))

    if not any(extracted.values()):
        print("[?] no recognised hashes in any input"); return 0

    # Write per-type files
    for kind, items in extracted.items():
        header = f"# hashcat -m {_HASHCAT_MODE[kind]}\n# generated from {len(args.inputs)} input file(s); {len(items)} hash(es)\n"
        (args.output / f"hashcat-{kind}.txt").write_text(
            header + "\n".join(line for (line, _, _, _) in items) + "\n")
        if not args.no_john:
            # JtR uses the same line format for these — symlink would be cleaner
            # but a copy works portably
            (args.output / f"john-{kind}.txt").write_text(
                header + "\n".join(line for (line, _, _, _) in items) + "\n")
        print(f"[+] {kind}: {len(items)} hash(es) -> {args.output}/hashcat-{kind}.txt")

    # Index file — tsv with one row per hash for downstream review
    with (args.output / "_index.tsv").open("w") as f:
        f.write("type\tuser\tdomain\tsource_file\n")
        for kind, items in extracted.items():
            for (_, user, domain, src) in items:
                f.write(f"{kind}\t{user}\t{domain}\t{src}\n")
    print(f"[+] index: {args.output}/_index.tsv ({sum(len(v) for v in extracted.values())} rows)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr); sys.exit(130)
