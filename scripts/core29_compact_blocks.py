#!/usr/bin/env python3
"""Exact BIP152 fixtures from unchanged checksum-pinned Core v29 helpers.

These synthetic transactions demonstrate wire/hash/reconstruction semantics,
not script validity. Live acceptance separately uses real funded Core spends.
"""
import argparse
import json
from pathlib import Path

from core29_tapscript import reference, SOURCE, SOURCES


def vectors():
    _, _, m = reference()
    block = m.CBlock()
    block.nVersion = 0x20000000
    block.hashPrevBlock = int.from_bytes(bytes(range(32)), "little")
    block.nTime = 1_723_456_789
    block.nBits = 0x207fffff
    for i in range(6):
        tx = m.CTransaction()
        tx.version = 2
        tx.vin = [m.CTxIn(m.COutPoint(0 if i == 0 else i * 12345, 0xffffffff if i == 0 else i), b"\x01\x11" if i == 0 else b"", 0xfffffffd)]
        tx.vout = [m.CTxOut(5_000_000_000 if i == 0 else 100000 - i, b"\x51")]
        if i in [0, 1, 3]:
            tx.wit.vtxinwit = [m.CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = [bytes([i + 1]) * 32, bytes(range(33))]
        tx.nLockTime = i
        tx.rehash()
        block.vtx.append(tx)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.solve()
    cases = []
    for nonce in [0, 1, 0xffffffffffffffff, 0x0102030405060708]:
        for version in [1, 2]:
            for prefilled in [[0], [0, 2, 5], [1, 3], []]:
                compact = m.HeaderAndShortIDs()
                compact.initialize_from_block(block, nonce=nonce, prefill_list=prefilled, use_witness=version == 2)
                request_indices = [i for i in range(6) if i not in prefilled and i % 2]
                request = m.BlockTransactionsRequest(block.sha256)
                request.from_absolute(request_indices)
                response = m.BlockTransactions(block.sha256, [block.vtx[i] for i in request_indices])
                cases.append(dict(name=f"nonce-{nonce}-v{version}-prefilled-{prefilled}", version=version,
                    header=m.CBlockHeader(block).serialize().hex(), nonce=nonce,
                    k0=compact.get_siphash_keys()[0], k1=compact.get_siphash_keys()[1],
                    block=block.serialize(with_witness=version == 2).hex(),
                    transactions=[tx.serialize_with_witness().hex() if version == 2 else tx.serialize_without_witness().hex() for tx in block.vtx],
                    short_ids=compact.shortids, prefilled=prefilled, compact=compact.to_p2p().serialize().hex(),
                    request_indices=request_indices, request=request.serialize().hex(), response=response.serialize(with_witness=version == 2).hex()))
    requests = []
    for indices in [[], [0], [252, 253, 254], [253, 510, 65535], list(range(256))]:
        request = m.BlockTransactionsRequest(block.sha256)
        request.from_absolute(indices)
        requests.append(dict(indices=indices, hex=request.serialize().hex()))
    return dict(scope="Generated independent BIP152 v1/v2 wire/key/reconstruction cases; synthetic transactions are not signed-spend proofs",
                reference_sources={SOURCE + name: sha for name, sha in SOURCES.items()}, cases=cases, requests=requests)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = vectors()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(f"Wrote {len(output['cases'])} Core compact-block cases and {len(output['requests'])} request boundaries", flush=True)
