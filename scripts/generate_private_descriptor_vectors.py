#!/usr/bin/env python3
"""Retain unchanged published private descriptor vectors (public test secrets).

No Rust derivation or generated expected scripts participate in this fixture.
The BIPs and these vectors are BSD-2-Clause; source checksums pin regeneration.
"""
import hashlib
import json
from pathlib import Path
import re
import urllib.request


def generate():
    root = Path(__file__).resolve().parents[1]
    sources = json.loads((root / "crates/primitives/tests/data/descriptors.json").read_text())["sources"]
    sources.append(dict(bip=387, url="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0387.mediawiki",
                        sha256="92a1a95be774be27f3f373e15dcd8bf291f542cd62535dd1ccbd95bd1022464e", license="BSD-2-Clause"))
    vectors = []
    for source in sources:
        raw = urllib.request.urlopen(source["url"], timeout=30).read()
        assert hashlib.sha256(raw).hexdigest() == source["sha256"]
        entries = []
        for line in raw.decode().split("==Test Vectors==", 1)[1].split("Invalid descriptors", 1)[0].splitlines():
            if match := re.fullmatch(r"\* <tt>(.+)</tt>", line):
                entries.append(dict(bip=source["bip"], descriptor=match[1], scripts=[]))
            if match := re.fullmatch(r"\*\* <tt>([0-9a-f]+)</tt>", line):
                entries[-1]["scripts"].append(match[1])
        vectors.extend(entry for entry in entries if re.search(r"xprv|(?<=[(,\]])[KL5][1-9A-HJ-NP-Za-km-z]{50,51}(?=[),/])", entry["descriptor"]))
    path = root / "crates/primitives/tests/data/private-descriptors.json"
    path.write_text(json.dumps(dict(sources=sources, vectors=vectors), indent=2) + "\n")
    print(f"Retained {len(vectors)} published private descriptors and {sum(len(v['scripts']) for v in vectors)} exact scripts")


if __name__ == "__main__":
    generate()
