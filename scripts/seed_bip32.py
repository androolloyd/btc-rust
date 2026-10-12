#!/usr/bin/env python3
"""Seed BIP32 parsing/derivation with unchanged published extended keys."""
import argparse
import hashlib
import json
from pathlib import Path


def seed(corpus):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip32-keys.json"
    data = json.loads(fixture.read_text())
    keys = [row[kind] for row in data["valid_keys"] for kind in ["xpub", "xprv"]]
    keys += [row["key"] for row in data["invalid_keys"]]
    corpus.mkdir(parents=True, exist_ok=True)
    for index, key in enumerate(keys):
        value = 0
        for char in key:
            value = value * 58 + alphabet.index(char)
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        raw = bytes(len(key) - len(key.lstrip("1"))) + raw
        encoded = {f"published-base58-{index}": key.encode()}
        # The published invalid-checksum case must exercise Base58 decoding;
        # stripping that checksum would erase its intended negative condition.
        if len(raw) == 82 and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]:
            encoded[f"published-raw-{index}"] = raw[:-4]
        for name, data in encoded.items():
            target = corpus / name
            if target.exists(): assert target.read_bytes() == data, f"preserve existing seed: {target}"
            else: target.write_bytes(data)
    for index, text in enumerate(["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"]):
        target = corpus / f"legacy-address-{index}"
        if target.exists(): assert target.read_bytes() == text.encode(), f"preserve existing seed: {target}"
        else: target.write_text(text)
    crash = fixture.with_name("bip32-unicode-alias.txt").read_bytes()
    target = corpus / "unicode-original-crash"
    if target.exists(): assert target.read_bytes() == crash, f"preserve existing seed: {target}"
    else: target.write_bytes(crash)
    print(f"Seeded {len(keys)} published BIP32 keys as Base58 and checksum-valid raw records (only public test secrets)", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    seed(parser.parse_args().corpus)
