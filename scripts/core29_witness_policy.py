#!/usr/bin/env python3
"""Core-signed witness/key policy boundaries, with consensus checked separately.

Uses the checksum-pinned unchanged Core reference modules. Funding is mined in a
real block because future witness outputs need not be standard mempool outputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import core29_tapscript as tap
from core29_tapscript import reference, SOURCE, SOURCES

fund_in_block = True


def private(compressed=True):
    k, _, _ = reference()
    secret = k.ECKey()
    secret.set(bytes([31]) * 32, compressed=compressed)
    return secret


def cases():
    _, s, _ = reference()
    compressed = private().get_pubkey().get_bytes()
    uncompressed = private(False).get_pubkey().get_bytes()
    result = []

    def add(name, mode, script, allowed, interpreter, **extra):
        result.append(dict(name=name, mode=mode, script=bytes(script), allowed=allowed,
            interpreter_allowed=interpreter, policy_allowed=interpreter, **extra))

    for mode in ["p2sh", "witness", "wrapped"]:
        for label, public, policy in [("compressed", compressed, True), ("uncompressed", uncompressed, mode == "p2sh")]:
            add(f"{mode}-signed-{label}", mode, s.CScript([public, s.OP_CHECKSIG]), True, policy, sign=True, public=public)
        for label, public, shape in [("compressed", compressed, True), ("uncompressed", uncompressed, mode == "p2sh"),
                                      ("empty", b"", False), ("invalid-prefix", b"\x05" + compressed[1:], False),
                                      ("off-curve-compressed", b"\x02" + bytes(32), True)]:
            for multi in [False, True]:
                script = s.CScript([1, public, 1, s.OP_CHECKMULTISIG, s.OP_NOT]) if multi else s.CScript([public, s.OP_CHECKSIG, s.OP_NOT])
                add(f"{mode}-empty-signature-{label}-{multi}", mode, script, True, shape,
                    args=[b"", b""] if multi else [b""], public=public)
    for mode in ["wpkh", "wrapped-wpkh"]:
        for label, public, policy in [("compressed", compressed, True), ("uncompressed", uncompressed, False)]:
            add(f"{mode}-signed-{label}", mode, b"", True, policy, public=public, sign=True)
    bad = b"\x05" + compressed[1:]
    for required, args, policy in [(0, [b""], True), (1, [b"", b""], False), (2, [b"", b"", b""], True)]:
        # Top key is valid. With two empty signatures, the first failed check
        # already proves failure, so the earlier bad key is never examined.
        script = s.CScript([required, bad, compressed, 2, s.OP_CHECKMULTISIG] + ([s.OP_NOT] if required else []))
        add(f"witness-multisig-encoding-order-{required}", "witness", script, True, policy, args=args)
    for public in [b"\x02", b"\x02" + compressed[1:], uncompressed]:
        for sig in [b"", b"\x01"]:
            add(f"taproot-future-key-{len(public)}-{bool(sig)}", "taproot", s.CScript([public, s.OP_CHECKSIG] + ([] if sig else [s.OP_NOT])),
                True, False, args=[sig])
    add("taproot-future-key-empty-checksigadd", "taproot", s.CScript([1, b"\x02", s.OP_CHECKSIGADD]), True, False, args=[b""])
    add("taproot-future-key-checksigverify", "taproot", s.CScript([b"\x02", s.OP_CHECKSIGVERIFY, 1]), True, False, args=[b"\x01"])
    add("taproot-skipped-future-key", "taproot", s.CScript([0, s.OP_IF, b"\x02", s.OP_CHECKSIG, s.OP_ENDIF, 1]), True, True, args=[])
    add("taproot-empty-signature-32-byte-noncurve-key", "taproot", s.CScript([bytes(32), s.OP_CHECKSIG, s.OP_NOT]), True, True, args=[b""])
    for label, script, args, allowed, policy in [
        ("success", b"\xbb", [], True, False),
        ("success-skipped", bytes(s.CScript([0, s.OP_IF])) + b"\xbb" + bytes(s.CScript([s.OP_ENDIF, 1])), [], True, False),
        ("success-after-malformed", b"\x4c\x02\xbb", [], False, False),
        ("success-before-malformed", b"\xbb\x4c", [], True, False),
        ("success-in-push", s.CScript([b"\xbb", s.OP_DROP, 1]), [], True, True),
        ("success-oversized-argument", b"\xbb", [bytes(521)], True, False),
    ]:
        add(f"taproot-{label}", "taproot", script, allowed, policy, args=args)
    for version in [0xc2, 0xfa]:
        add(f"taproot-future-leaf-{version}", "taproot", s.CScript([s.OP_RETURN]), True, False,
            args=[bytes(521)], leaf_version=version)
    for version, program in [(1, b"\x11" * 20), (2, b"\x11" * 32), (16, b"\x11" * 40), (1, compressed[1:]), (1, b"\x4e\x73")]:
        for wrapped in [False, True]:
            if version == 1 and len(program) == 32 and not wrapped:
                continue
            anchor = version == 1 and program == b"\x4e\x73" and not wrapped
            add(f"future-witness-{version}-{len(program)}-{wrapped}", "future", b"", True, anchor,
                version=version, program=program, wrapped=wrapped)
            if anchor:
                # This tests the interpreter's native anchor exception. Complete
                # TRUC/anchor mempool policy is a separate acceptance surface.
                result[-1]["policy_allowed"] = None
    return result


def output(case):
    _, s, _ = reference()
    mode = case["mode"]
    if mode == "taproot":
        return tap.output(case)
    if mode == "future":
        program = s.CScript([case["version"], case["program"]])
    elif "wpkh" in mode:
        program = s.CScript([0, s.hash160(case["public"])])
    elif mode in ["witness", "wrapped"]:
        program = s.CScript([0, hashlib.sha256(case["script"]).digest()])
    else:
        program = case["script"]
    wrapped = mode in ["p2sh", "wrapped", "wrapped-wpkh"] or case.get("wrapped", False)
    previous = s.CScript([s.OP_HASH160, s.hash160(program), s.OP_EQUAL]) if wrapped else program
    return SimpleNamespace(scriptPubKey=bytes(previous), redeem=bytes(program) if wrapped else None)


def address(case, rpc):
    return rpc("decodescript", [output(case).scriptPubKey.hex()])["address"]


def spend(case, txid, index, amount, destination=b"\x51"):
    if case["mode"] == "taproot":
        tx, previous, _ = tap.spend(case, txid, index, amount, destination)
        return tx, previous, []
    _, s, m = reference()
    tx = m.CTransaction()
    tx.version = 2
    tx.nLockTime = 23
    tx.vin = [m.CTxIn(m.COutPoint(int(txid, 16), index), nSequence=0xfffffffd)]
    tx.vout = [m.CTxOut(amount - 10_000, destination)]
    info = output(case)
    previous = m.CTxOut(amount, info.scriptPubKey)
    args = list(case.get("args", []))
    digests = []
    if case.get("sign"):
        code = s.CScript([s.OP_DUP, s.OP_HASH160, s.hash160(case["public"]), s.OP_EQUALVERIFY, s.OP_CHECKSIG]) if "wpkh" in case["mode"] else s.CScript(case["script"])
        witness = case["mode"] != "p2sh"
        digest = s.SegwitV0SignatureHash(code, tx, 0, 1, amount) if witness else s.LegacySignatureHash(code, tx, 0, 1)[0]
        args = [private(len(case["public"]) == 33).sign_ecdsa(digest, rfc6979=True) + b"\x01"]
        if "wpkh" in case["mode"]:
            args.append(case["public"])
        digests.append(dict(script_code=bytes(code).hex(), digest=digest.hex(), witness=witness))
    if case["mode"] == "p2sh":
        tx.vin[0].scriptSig = s.CScript(args + [case["script"]])
    else:
        if case["mode"] in ["witness", "wrapped"]:
            args.append(case["script"])
        if info.redeem is not None:
            tx.vin[0].scriptSig = s.CScript([info.redeem])
        if args:
            tx.wit.vtxinwit = [m.CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = args
    return tx, previous, digests


def write_vectors(path):
    vectors = []
    for index, case in enumerate(cases()):
        tx, previous, digests = spend(case, "11" * 32, index, 100_000)
        vectors.append(dict(name=case["name"], transaction=tx.serialize().hex(), prevout=previous.serialize().hex(),
            allowed=case["allowed"], interpreter_allowed=case["interpreter_allowed"], policy_allowed=case["policy_allowed"], digests=digests))
    path.write_text(json.dumps(dict(source=SOURCE, source_sha256=SOURCES, license="MIT",
        scope="Witness/key script policy boundaries; independent funded Core block/mempool checks. Native anchor interpreter is covered; complete TRUC policy is not claimed.", vectors=vectors), indent=2) + "\n")
    print(f"Generated {len(vectors)} Core witness/key policy cases", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-vectors", type=Path, required=True)
    write_vectors(parser.parse_args().write_vectors)
