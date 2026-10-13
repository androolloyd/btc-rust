#!/usr/bin/env python3
"""Generate independent BIP330 fixtures with unchanged upstream minisketch/Core.

These are generated reference cases, not published official test vectors.
"""
import argparse
import json
from pathlib import Path
import random

from minisketch_reference import reference, SOURCE, SHA256, core_siphash, short_id_key
from core29_tapscript import SOURCE as CORE_SOURCE, SOURCES as CORE_SOURCES


def vectors():
    ref = reference()
    rng = random.Random(330)
    sketches = []
    for capacity in [0, 1, 2, 3, 4, 8, 16, 32, 64]:
        counts = sorted(set([0, min(1, capacity), capacity // 2, capacity, capacity + 1, capacity + 3]))
        for count in counts:
            elements = rng.sample(range(1, 1 << 32), count)
            sketch = ref.Minisketch(32, capacity)
            for element in elements:
                sketch.add(element)
            decoded = sketch.decode(capacity)
            if count <= capacity:
                assert decoded == sorted(elements)
            sketches.append(dict(name=f"capacity-{capacity}-count-{count}", capacity=capacity,
                                 elements=elements, hex=sketch.serialize().hex(), decoded=decoded))
    for name, elements, capacity in [("duplicate-cancels", [1, 2, 1], 4),
                                     ("xor-alias", [1, 2], 1), ("zero-alias", [1, 2, 3], 1),
                                     ("high-bits", [1, 0x80000000, 0xffffffff, 0x8d], 8)]:
        sketch = ref.Minisketch(32, capacity)
        for element in elements:
            sketch.add(element)
        sketches.append(dict(name=name, capacity=capacity, elements=elements,
                             hex=sketch.serialize().hex(), decoded=sketch.decode(capacity)))
    raw_decodes = []
    for capacity in [2, 3, 4, 8, 16, 32, 64]:
        for i in range(4):
            encoded = rng.getrandbits(32 * capacity).to_bytes(4 * capacity, "little")
            sketch = ref.Minisketch(32, capacity)
            sketch.deserialize(encoded)
            raw_decodes.append(dict(name=f"raw-{capacity}-{i}", hex=encoded.hex(), decoded=sketch.decode(capacity)))
    arithmetic = []
    gf = ref.GF2Ops(32)
    for a, b in [(1, 0xffffffff), (0x80000000, 2), (0x8d, 0x80000000)] + [(rng.randrange(1, 1 << 32), rng.randrange(1 << 32)) for _ in range(64)]:
        arithmetic.append(dict(a=a, b=b, product=gf.mul(a, b), inverse=gf.inv(a)))
    siphash = core_siphash()
    siphash_cases = [dict(k0=0x0706050403020100, k1=0x0f0e0d0c0b0a0908,
                         data=bytes(range(i)).hex(), hash=siphash(0x0706050403020100, 0x0f0e0d0c0b0a0908, bytes(range(i)))) for i in range(64)]
    short_ids = []
    for a, b in [(0, 0), (0, 1), (1, 0), (1, 1), (0xffffffffffffffff, 0), (0x0102030405060708, 0xaabbccddeeff0011)]:
        k0, k1 = short_id_key(a, b)
        for hash_bytes in [bytes(32), bytes([255]) * 32, bytes(range(32)), bytes(reversed(range(32)))] + [rng.getrandbits(256).to_bytes(32, "little") for _ in range(4)]:
            short_ids.append(dict(salt_a=a, salt_b=b, wtxid_internal=hash_bytes.hex(),
                                  short_id=1 + siphash(k0, k1, hash_bytes) % 0xffffffff))
    a, b = 12345, 67890
    k0, k1 = short_id_key(a, b)
    known = {}
    collision = None
    for i in range(500_000):
        wtxid = i.to_bytes(32, "little")
        sid = 1 + siphash(k0, k1, wtxid) % 0xffffffff
        if sid in known:
            collision = dict(salt_a=a, salt_b=b, short_id=sid,
                             wtxids_internal=[known[sid].hex(), wtxid.hex()])
            break
        known[sid] = wtxid
    assert collision is not None, "deterministic collision search failed"
    print(f"Found independently derived short-ID collision after {i + 1} hashes", flush=True)
    hashes = [rng.getrandbits(256).to_bytes(32, "little") for _ in range(8)]
    local, peer = hashes[:5], hashes[2:]
    peer_sketch = ref.Minisketch(32, 8)
    for wtxid in peer:
        peer_sketch.add(1 + siphash(k0, k1, wtxid) % 0xffffffff)
    reconciliation = dict(salt_a=a, salt_b=b, local_wtxids_internal=[v.hex() for v in local],
                          peer_sketch=peer_sketch.serialize().hex(), they_need_internal=[v.hex() for v in hashes[:2]],
                          we_need_ids=sorted(1 + siphash(k0, k1, v) % 0xffffffff for v in hashes[5:]))
    return dict(scope="BIP330 GF(2^32) sketches and salted wtxid short IDs; generated unchanged-reference cases, not published vectors or live peer negotiation",
                reference_sources={SOURCE: SHA256, **{CORE_SOURCE + name: sha for name, sha in CORE_SOURCES.items()}},
                sketches=sketches, raw_decodes=raw_decodes, arithmetic=arithmetic,
                siphash=siphash_cases, short_ids=short_ids, collision=collision, reconciliation=reconciliation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = vectors()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture, indent=2) + "\n")
    print(f"Wrote {len(fixture['sketches'])} constructed and {len(fixture['raw_decodes'])} arbitrary sketches", flush=True)
