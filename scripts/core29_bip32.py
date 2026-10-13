#!/usr/bin/env python3
"""Post-HMAC BIP32 child-tweak boundaries using unchanged Core curve code.

These fixed scalars are public test data. Injected IL/IR bytes exercise the
rare arithmetic boundary; they are not claimed HMAC outputs from a real seed.
"""
import argparse
import json
from pathlib import Path
from core29_tapscript import reference, SOURCE, SOURCES


def vectors():
    key, script, _ = reference()
    curve = key.secp256k1
    order = curve.GE.ORDER
    cases = []
    for position, secret in enumerate([1, 2, 3, order - 1, 0x0101010101010101]):
        parent = secret * curve.G
        public = parent.to_bytes_compressed()
        fingerprint = script.hash160(public)[:4]
        depth = [0, 1, 254, 0, 3][position]
        header = bytes([depth]) + (bytes(4) if depth == 0 else bytes.fromhex("01020304"))
        header += (0 if depth == 0 else 17).to_bytes(4, "big") + bytes(range(32))
        pub_version = bytes.fromhex("0488b21e" if position % 2 == 0 else "043587cf")
        prv_version = bytes.fromhex("0488ade4" if position % 2 == 0 else "04358394")
        for name, tweak in [("zero", 0), ("one", 1), ("two", 2), ("high-valid", 1 << 255),
                            ("cancellation", order - secret), ("order-minus-one", order - 1),
                            ("order", order), ("order-plus-one", order + 1), ("maximum", (1 << 256) - 1)]:
            child = [0, 1, 0x7fffffff][len(cases) % 3]
            ir = bytes(reversed(range(32)))
            point = tweak * curve.G + parent
            allowed = tweak < order and not point.infinity
            child_header = bytes([depth + 1]) + fingerprint + child.to_bytes(4, "big") + ir
            cases.append({
                "case": f"parent-{position}-{name}",
                "parent_public": (pub_version + header + public).hex(),
                "parent_private": (prv_version + header + b"\x00" + secret.to_bytes(32, "big")).hex(),
                "child_index": child,
                "injected_hmac_result": (tweak.to_bytes(32, "big") + ir).hex(),
                "allowed": allowed,
                "expected_public": (pub_version + child_header + point.to_bytes_compressed()).hex() if allowed else None,
                "expected_private": (prv_version + child_header + b"\x00" + ((secret + tweak) % order).to_bytes(32, "big")).hex() if allowed else None,
            })
    return {
        "scope": "Post-HMAC CKDpub/CKDpriv arithmetic and extended-child serialization; injected results are not real-seed HMAC vectors.",
        "public_test_secrets": True,
        "reference_sources": {SOURCE + name: sha for name, sha in SOURCES.items()},
        "primary": ["https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki",
                    "https://github.com/bitcoin/bitcoin/blob/v29.0/src/pubkey.cpp",
                    "https://github.com/bitcoin/bitcoin/blob/v29.0/src/key.cpp"],
        "cases": cases,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = vectors()
    args.output.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Wrote {len(fixture['cases'])} Core post-HMAC arithmetic cases", flush=True)
