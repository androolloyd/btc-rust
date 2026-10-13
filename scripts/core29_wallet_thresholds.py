#!/usr/bin/env python3
"""Generate offline public Taproot wallet fixtures with pinned Core v29 code.

Synthetic outpoints exercise equations and supplied-prevout spending only. Live
wallet funding, Core mempool acceptance and mining are in check_core_psbt.py.
No Rust implementation participates in script, hash, key or signature creation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request

from core29_tapscript import reference, SOURCE, SOURCES

NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
BIP387 = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0387.mediawiki"
BIP387_SHA256 = "92a1a95be774be27f3f373e15dcd8bf291f542cd62535dd1ccbd95bd1022464e"


def compact(n):
    if n < 253:
        return bytes([n])
    size, prefix = (2, 0xfd) if n <= 0xffff else (4, 0xfe)
    return bytes([prefix]) + n.to_bytes(size, "little")


def psbt(tx, records):
    maps = [{b"\x00": tx.serialize_without_witness()}, records, {}]
    return (b"psbt\xff" + b"".join(
        b"".join(compact(len(k)) + k + compact(len(v)) + v for k, v in sorted(m.items())) + b"\x00"
        for m in maps)).hex()


def generate(path):
    raw = urllib.request.urlopen(BIP387, timeout=30).read()
    assert hashlib.sha256(raw).hexdigest() == BIP387_SHA256
    published = []
    for line in raw.decode().split("==Test Vectors==", 1)[1].split("Invalid descriptors", 1)[0].splitlines():
        match = re.fullmatch(r"\* <tt>(.+)</tt>", line)
        if match:
            published.append(dict(descriptor=match[1], scripts=[]))
        match = re.fullmatch(r"\*\* <tt>([0-9a-f]+)</tt>", line)
        if match:
            published[-1]["scripts"].append(match[1])
    published = [v for v in published if not re.search(r"xprv|tr\([LK5][^,)]{50,51}[,)]", v["descriptor"])]
    assert len(published) == 2 and sum(len(v["scripts"]) for v in published) == 4
    key, s, m = reference()
    secrets = [i.to_bytes(32, "big") for i in range(1, 1000)]
    public = [key.compute_xonly_pubkey(secret)[0] for secret in secrets]

    def code(keys, threshold):
        items = []
        for i, pub in enumerate(keys):
            items.extend([pub, s.OP_CHECKSIG if i == 0 else s.OP_CHECKSIGADD])
        return bytes(s.CScript(items + [threshold, s.OP_NUMEQUAL]))

    descriptors = []
    for n in list(range(1, 21)) + [21, 127, 128, 255, 256, 999]:
        for sorted_keys in [False, True]:
            keys = list(reversed(public[:n]))
            name = "sortedmulti_a" if sorted_keys else "multi_a"
            text = f"tr({NUMS.hex()},{name}({n}," + ",".join(pub.hex() for pub in keys) + "))"
            script = code(sorted(keys) if sorted_keys else keys, n)
            output = s.taproot_construct(NUMS, [("leaf", script)])
            leaf = output.leaves["leaf"]
            control = bytes([0xc0 | output.negflag]) + NUMS + leaf.merklebranch
            descriptors.append(dict(descriptor=text, script=script.hex(), script_pubkey=output.scriptPubKey.hex(),
                                    control=control.hex(), leaf_hash=leaf.leaf_hash.hex()))

    vectors = []
    cases = [("one-of-one", 1, 1, False, False), ("two-of-three", 3, 2, False, False),
             ("sixteen-of-twenty", 20, 16, True, False), ("seventeen-of-twenty", 20, 17, True, False),
             ("twenty-of-twenty", 20, 20, False, False), ("repeated-key", 3, 2, False, False),
             ("annex-two-of-three", 3, 2, False, True),
             ("128-of-128", 128, 128, False, False), ("256-of-256", 256, 256, False, False),
             ("two-of-999", 999, 2, False, False), ("999-of-999-repeated-key", 999, 999, False, False)]
    for name, n, threshold, mixed, annex_present in cases:
        repeated = "repeated-key" in name
        keys = [public[0]] * n if repeated else public[:n]
        priv = [secrets[0]] * n if repeated else secrets[:n]
        script = code(keys, threshold)
        info = s.taproot_construct(NUMS, [("leaf", script)])
        leaf = info.leaves["leaf"]
        control = bytes([0xc0 | info.negflag]) + NUMS + leaf.merklebranch
        tx = m.CTransaction()
        tx.version = 2
        tx.vin = [m.CTxIn(m.COutPoint(int("11" * 32, 16), 0), b"", 0xfffffffd)]
        tx.vout = [m.CTxOut(98_000, b"\x51")]
        tx.nLockTime = 23
        prevout = m.CTxOut(100_000, info.scriptPubKey)
        annex = b"\x50" + bytes(252) if annex_present else None
        records = {b"\x01": prevout.serialize(), b"\x15" + control: script + b"\xc0"}
        signatures = []
        cache = {}
        for i, (pub, secret) in enumerate(zip(keys, priv, strict=True)):
            if name == "two-of-999" and i < n - 3:
                signatures.append(b"")
                continue
            hash_type = 1 if mixed and i < 4 else 0
            if (pub, hash_type) not in cache:
                digest = s.TaprootSignatureHash(tx, [prevout], hash_type, scriptpath=True, leaf_script=script, annex=annex)
                cache[(pub, hash_type)] = key.sign_schnorr(secret, digest, aux=bytes(32)) + (bytes([hash_type]) if hash_type else b"")
            sig = cache[(pub, hash_type)]
            signatures.append(sig)
            records[b"\x14" + pub + leaf.leaf_hash] = sig
        partial = psbt(tx, records)
        # Minimal weight, retaining later script keys on equal sizes, per
        # Core v29 miniscript's reverse-order dynamic programming satisfaction.
        selected = set(sorted((i for i in range(n) if signatures[i]), key=lambda i: (len(signatures[i]), -i))[:threshold])
        slots = [signatures[i] if i in selected else b"" for i in reversed(range(n))]
        stack = slots + [script, control] + ([annex] if annex is not None else [])
        tx.wit.vtxinwit = [m.CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        final_records = {b"\x01": prevout.serialize(), b"\x08": m.ser_string_vector(stack)}
        vectors.append(dict(name=name, threshold=threshold, partial_records=len(records)-2,
                            partial_valid=annex is None, partial_psbt=partial, final_psbt=psbt(tx, final_records),
                            transaction=tx.serialize().hex(), script=script.hex(), witness=[item.hex() for item in stack]))
    path.write_text(json.dumps(dict(source=SOURCE, source_sha256=SOURCES, license="MIT",
        scope="Core reference-generated offline equations and descriptor commitments, with synthetic outpoints; live acceptance is separate.",
        bip387_source=BIP387, bip387_source_sha256=BIP387_SHA256, bip387_license="BSD-2-Clause",
        published=published, descriptors=descriptors, vectors=vectors), indent=2) + "\n")
    print(f"Generated {len(descriptors)} descriptor commitments and {len(vectors)} signed wallet fixtures", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-vectors", required=True, type=Path)
    generate(parser.parse_args().write_vectors)
