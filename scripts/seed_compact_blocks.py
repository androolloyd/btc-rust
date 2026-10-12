#!/usr/bin/env python3
"""Seed compact primitives and the real framed P2P parser without overwriting."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def seed(corpus, p2p=False):
    fixture = json.loads((ROOT / "crates/network/tests/data/bip152.json").read_text())
    corpus.mkdir(parents=True, exist_ok=True)
    n = 0
    for i, case in enumerate(fixture["cases"]):
        for tag, command, field in [(0, "cmpctblock", "compact"), (2, "getblocktxn", "request"), (4, "blocktxn", "response")]:
            data = bytes.fromhex(case[field])
            if p2p:
                if case["version"] != 2:
                    continue
                data = bytes([{ "cmpctblock": 18, "getblocktxn": 19, "blocktxn": 20 }[command]]) + data
            else:
                data = bytes([tag + int(case["version"] == 2)]) + data
            path = corpus / f"bip152-{i}-{field}"
            if path.exists():
                assert path.read_bytes() == data, f"refusing to overwrite {path}"
            else:
                path.write_bytes(data)
            n += 1
    print(f"Seeded {n} Core compact-message encodings", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--p2p", action="store_true")
    args = parser.parse_args()
    seed(args.corpus, args.p2p)
