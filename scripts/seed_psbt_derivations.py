#!/usr/bin/env python3
"""Serialize public derivation envelopes using unchanged published BIP32 keys."""
import argparse
import json
from pathlib import Path


def compact(n):
    if n < 253:
        return bytes([n])
    size = 2 if n <= 0xffff else 4 if n <= 0xffffffff else 8
    return bytes([{2: 253, 4: 254, 8: 255}[size]]) + n.to_bytes(size, "little")


def envelope(anchor, child):
    def origin(row):
        return bytes.fromhex(row["master_fingerprint"]) + b"".join(index.to_bytes(4, "little") for index in row["child_indices"])
    public = bytes.fromhex(child["serialized_xpub"])[45:]
    script = b"\x51\x20" + public[1:]
    # Public metadata envelope: no signatures, UTXOs or actual-chain claim.
    tx = bytes.fromhex("0200000001") + bytes([1]) * 32 + bytes.fromhex("0000000000ffffffff01")
    tx += (1000).to_bytes(8, "little") + compact(len(script)) + script + bytes(4)
    maps = [
        [(b"\x00", tx), (b"\x01" + bytes.fromhex(anchor["serialized_xpub"]), origin(anchor))],
        [(b"\x06" + public, origin(child)), (b"\x16" + public[1:], b"\x00" + origin(child))],
        [(b"\x02" + public, origin(child)), (b"\x07" + public[1:], b"\x00" + origin(child))],
    ]
    return b"psbt\xff" + b"".join(b"".join(compact(len(key)) + key + compact(len(value)) + value for key, value in records) + b"\x00" for records in maps)


def seed(corpus):
    source = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip32-keys.json"
    rows = json.loads(source.read_text())["valid_keys"]
    corpus.mkdir(parents=True, exist_ok=True)
    for index, child in enumerate(rows):
        path = child["child_indices"]
        anchor = next(row for row in rows if row["vector"] == child["vector"] and
                      path[:len(row["child_indices"])] == row["child_indices"] and
                      all(component < 0x80000000 for component in path[len(row["child_indices"]):]))
        raw = envelope(anchor, child)
        target = corpus / f"derivations-{index}"
        if target.exists():
            assert target.read_bytes() == raw, f"preserve existing seed: {target}"
        else:
            target.write_bytes(raw)
    print(f"Seeded {len(rows)} published BIP32 public derivation envelopes", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    seed(parser.parse_args().corpus)
