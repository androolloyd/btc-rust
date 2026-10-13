#!/usr/bin/env python3
"""Seed BIP330 sketch fuzzing without overwriting existing corpus artifacts."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def seed(corpus):
    fixture = json.loads((ROOT / "crates/network/tests/data/bip330-sketches.json").read_text())
    corpus.mkdir(parents=True, exist_ok=True)
    count = 0
    for group in ["sketches", "raw_decodes"]:
        for index, case in enumerate(fixture[group]):
            data = bytes.fromhex(case["hex"])
            if not data:
                continue
            path = corpus / f"bip330-{group}-{index}"
            if path.exists():
                assert path.read_bytes() == data, f"refusing to overwrite {path}"
            else:
                path.write_bytes(data)
            count += 1
    print(f"Seeded {count} nonempty independent sketch encodings", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    seed(parser.parse_args().corpus)
