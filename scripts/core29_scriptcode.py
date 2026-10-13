#!/usr/bin/env python3
"""Legacy/BIP143 scriptCode cases signed by checksum-pinned Core v29 code.

The keys are public test secrets. Expected execution/policy outcomes are also
checked against actual funded Core blocks/mempool admission by check_core_p2p.
"""
import argparse
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from core29_tapscript import reference, SOURCE, SOURCES


def keys():
    k, _, _ = reference()
    result = []
    for value in [31, 32, 33]:
        key = k.ECKey()
        key.set(bytes([value]) * 32, compressed=True)
        result.append(key)
    return result


def push(data, prefix):
    if prefix == 0:
        assert len(data) <= 75
        return bytes([len(data)]) + data
    size = {0x4c: 1, 0x4d: 2, 0x4e: 4}[prefix]
    return bytes([prefix]) + len(data).to_bytes(size, "little") + data


def cases():
    _, s, _ = reference()
    public = keys()[0].get_pubkey().get_bytes()
    tail = bytes(s.CScript([public, s.OP_CHECKSIG]))
    result = []
    for mode in ["witness", "p2sh"]:
        for prefix, size in [(0, 0), (0, 2), (0, 75), (0x4c, 0), (0x4c, 2),
                             (0x4c, 76), (0x4c, 255), (0x4d, 0), (0x4d, 2),
                             (0x4d, 256), (0x4d, 520), (0x4e, 0), (0x4e, 2), (0x4e, 520)]:
            data = b"a" * size
            before = push(data, prefix) + bytes([s.OP_DROP, s.OP_CODESEPARATOR])
            minimal = prefix == 0 or prefix == 0x4c and 76 <= size <= 255 or prefix == 0x4d and size > 255
            result.append(dict(name=f"{mode}-prefix-{prefix}-{size}", mode=mode,
                script=before + tail, offsets=[len(before)], allowed=mode == "witness" or len(before + tail) <= 520,
                policy_allowed=mode == "witness" and minimal))
        # A nonminimal push in a skipped branch still advances the real byte
        # cursor, but MINIMALDATA does not reject the skipped encoding.
        before = bytes(s.CScript([0, s.OP_IF])) + push(b"ab", 0x4e)
        before += bytes(s.CScript([s.OP_DROP, s.OP_CODESEPARATOR, s.OP_ENDIF, s.OP_CODESEPARATOR]))
        result.append(dict(name=f"{mode}-skipped-push", mode=mode, script=before + tail,
            offsets=[len(before)], allowed=True, policy_allowed=mode == "witness"))
        before = bytes(s.CScript([0, s.OP_IF, s.OP_CODESEPARATOR, s.OP_ENDIF]))
        result.append(dict(name=f"{mode}-skipped-separator", mode=mode, script=before + tail,
            offsets=[0], allowed=True, policy_allowed=mode == "witness"))
        after = bytes(s.CScript([0, s.OP_IF, s.OP_CODESEPARATOR, s.OP_ENDIF]))
        result.append(dict(name=f"{mode}-later-separator", mode=mode, script=tail + after,
            offsets=[0], allowed=True, policy_allowed=mode == "witness"))
        first = bytes(s.CScript([s.OP_CODESEPARATOR, public, s.OP_CHECKSIGVERIFY, s.OP_CODESEPARATOR]))
        result.append(dict(name=f"{mode}-two-separators", mode=mode, script=first + tail,
            offsets=[1, len(first)], allowed=True, policy_allowed=mode == "witness"))
        for prefix in [0x4c, 0x4d, 0x4e]:
            before = push(b"ab", prefix) + bytes([s.OP_DROP, s.OP_CODESEPARATOR])
            # The former PUSHDATA1 offset points exactly at the separator.
            # Legacy hashing removes it, so that offset has the same digest;
            # BIP143 retains it and must reject the signature.
            result.append(dict(name=f"{mode}-wrong-prefix-{prefix}", mode=mode, script=before + tail,
                offsets=[len(before)], wrong_offset=5, allowed=mode == "p2sh" and prefix == 0x4c, policy_allowed=False))
        for hash_type in [2, 3, 0x81, 0x82, 0x83]:
            before = bytes(s.CScript([b"ab", s.OP_DROP, s.OP_CODESEPARATOR]))
            result.append(dict(name=f"{mode}-sighash-{hash_type}", mode=mode, script=before + tail,
                offsets=[len(before)], hash_type=hash_type, allowed=True, policy_allowed=mode == "witness"))
    # Checks in scriptSig have a real signature-dependent executing script,
    # while the funded P2PKH output stays fixed (avoids a circular prevout).
    for operation in ["single", "repeated", "skipped", "multisig", "multisigverify", "empty"]:
        result.append(dict(name=f"legacy-finddelete-{operation}", mode="sigscript", operation=operation,
            script=b"", offsets=[], allowed=True, policy_allowed=False))
    result.append(dict(name="legacy-finddelete-bad-multisig", mode="sigscript", operation="multisig",
        script=b"", offsets=[], corrupt=True, allowed=False, policy_allowed=False))
    return result


def output(case):
    _, s, _ = reference()
    if case["mode"] == "sigscript":
        public = keys()[0].get_pubkey().get_bytes()
        program = s.CScript([s.OP_DUP, s.OP_HASH160, s.hash160(public), s.OP_EQUALVERIFY, s.OP_CHECKSIG])
    elif case["mode"] == "witness":
        program = s.CScript([0, hashlib.sha256(case["script"]).digest()])
    else:
        program = s.CScript([s.OP_HASH160, s.hash160(case["script"]), s.OP_EQUAL])
    return SimpleNamespace(scriptPubKey=bytes(program))


def address(case, rpc):
    if case["mode"] == "sigscript":
        descriptor = f"pkh({keys()[0].get_pubkey().get_bytes().hex()})"
        descriptor += "#" + rpc("getdescriptorinfo", [descriptor])["checksum"]
        return rpc("deriveaddresses", [descriptor])[0]
    decoded = rpc("decodescript", [case["script"].hex()])
    return decoded["segwit"]["address"] if case["mode"] == "witness" else decoded["p2sh"]


def spend(case, txid, index, amount, destination=b"\x51"):
    _, s, m = reference()
    private = keys()
    public = [key.get_pubkey().get_bytes() for key in private]
    tx = m.CTransaction()
    tx.version = 2
    tx.nLockTime = 23
    tx.vin = [m.CTxIn(m.COutPoint(int(txid, 16), index), nSequence=0xfffffffd)]
    tx.vout = [m.CTxOut(amount - 10_000, destination)]
    previous = m.CTxOut(amount, output(case).scriptPubKey)
    digests = []
    hash_type = case.get("hash_type", 1)

    def sign(code, key, witness=False):
        code = s.CScript(code)
        digest = s.SegwitV0SignatureHash(code, tx, 0, hash_type, amount) if witness else s.LegacySignatureHash(code, tx, 0, hash_type)[0]
        digests.append(dict(script_code=bytes(code).hex(), digest=digest.hex(), hash_type=hash_type, witness=witness))
        return key.sign_ecdsa(digest, rfc6979=True) + bytes([hash_type])

    if case["mode"] == "sigscript":
        fund_sig = sign(previous.scriptPubKey, private[0])
        tail = [fund_sig, public[0]]
        operation = case["operation"]
        if operation in ["multisig", "multisigverify"]:
            op = s.OP_CHECKMULTISIGVERIFY if operation == "multisigverify" else s.OP_CHECKMULTISIG
            check = [2, public[1], public[2], 2, op]
            if op == s.OP_CHECKMULTISIG:
                check.append(s.OP_VERIFY)
            code = s.CScript([0] + check + tail)
            signatures = [sign(code, private[1]), sign(code, private[2])]
            if case.get("corrupt"):
                sig = bytearray(signatures[0]); sig[-2] ^= 1; signatures[0] = bytes(sig)
            tx.vin[0].scriptSig = s.CScript([0] + signatures + check + tail)
        elif operation == "empty":
            tx.vin[0].scriptSig = s.CScript([b"", public[1], s.OP_CHECKSIG, s.OP_NOT, s.OP_DROP] + tail)
        else:
            check = [public[1], s.OP_CHECKSIGVERIFY] + tail
            before = [s.OP_DROP] if operation == "repeated" else [0, s.OP_IF, s.OP_DROP, s.OP_ENDIF] if operation == "skipped" else []
            signature = sign(s.CScript(before + check), private[1])
            pushes = [signature, s.OP_DROP] if operation == "repeated" else [0, s.OP_IF, signature, s.OP_DROP, s.OP_ENDIF] if operation == "skipped" else []
            tx.vin[0].scriptSig = s.CScript(pushes + [signature] + check)
    else:
        signatures = [sign(case["script"][case.get("wrong_offset", offset):], private[0], case["mode"] == "witness")
                      for offset in case["offsets"]]
        signatures.reverse()  # First CHECKSIG consumes the top argument.
        if case["mode"] == "witness":
            tx.wit.vtxinwit = [m.CTxInWitness()]
            tx.wit.vtxinwit[0].scriptWitness.stack = signatures + [case["script"]]
        else:
            tx.vin[0].scriptSig = s.CScript(signatures + [case["script"]])
    return tx, previous, digests


def write_vectors(path):
    vectors = []
    for index, case in enumerate(cases()):
        tx, previous, digests = spend(case, "11" * 32, index, 100_000)
        vectors.append(dict(name=case["name"], transaction=tx.serialize().hex(), prevout=previous.serialize().hex(),
            allowed=case["allowed"], policy_allowed=case["policy_allowed"], digests=digests))
    path.write_text(json.dumps(dict(source=SOURCE, source_sha256=SOURCES, license="MIT",
        scope="Core reference-signed legacy/BIP143 scriptCode cases; execution labels independently checked against funded Core v29 blocks and policy.", vectors=vectors), indent=2) + "\n")
    print(f"Generated {len(vectors)} Core scriptCode cases", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-vectors", type=Path, required=True)
    write_vectors(parser.parse_args().write_vectors)
