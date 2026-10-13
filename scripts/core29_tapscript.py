#!/usr/bin/env python3
"""Independent Taproot cases using checksum-pinned Core v29 reference code.

Only fixture generation/acceptance uses the public test keys here. The Core
protocol modules are unchanged. Three non-protocol utility functions are
loaded from util.py without importing its unrelated node/process machinery.
"""
import argparse
import ast
import hashlib
import importlib
import json
from pathlib import Path
import random
import sys
import tempfile
import types
import urllib.request

SOURCES = {
    "key.py": "c820332654015a3f3f3d16d61e50beca1aafb9723e52aae84c20431f8e243217",
    "script.py": "ae8d3e2770933f35c755c00651ca6cc0b4d57a1ca95c687941637ffcdf1dc772",
    "messages.py": "37cdc47790abb64ad909beae0a12ffba99e5123b429a2879ce448414d8139c00",
    "crypto/ripemd160.py": "99da6dafa9804d3ca5490a736354027b10ec3d517206caad6ea28c0e097f6b9a",
    "crypto/secp256k1.py": "1b2d1c40fcc7360218833ef37d4337f8617833bc71dfd7238aa4e838809841eb",
    "crypto/siphash.py": "9ebc188ce51969a9757305939f295bbb2ba9a2f79dec19176eb79990b3df34a2",
    "util.py": "0f166c3d800ad77a348e70f57a4bf36d0a4a6e8d8bceeb249f62977287ae2b5e",
}
SOURCE = "https://raw.githubusercontent.com/bitcoin/bitcoin/v29.0/test/functional/test_framework/"
_REFERENCE = None


def reference():
    global _REFERENCE
    if _REFERENCE is not None:
        return _REFERENCE
    directory = Path(tempfile.mkdtemp(prefix="btc-core29-reference-"))
    framework = directory / "test_framework"
    for name, expected in SOURCES.items():
        with urllib.request.urlopen(SOURCE + name, timeout=30) as response:
            data = response.read()
        assert hashlib.sha256(data).hexdigest() == expected, f"Core source checksum: {name}"
        path = framework / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    sys.path.insert(0, str(directory))
    utility = types.ModuleType("test_framework.util")
    utility.random = random
    tree = ast.parse((framework / "util.py").read_text())
    wanted = {"assert_equal", "random_bitflip", "summarise_dict_differences"}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    assert {node.name for node in functions} == wanted
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(framework / "util.py"), "exec"), utility.__dict__)
    sys.modules["test_framework.util"] = utility
    _REFERENCE = tuple(importlib.import_module("test_framework." + name) for name in ["key", "script", "messages"])
    return _REFERENCE


def cases():
    key, s, _ = reference()
    secret = bytes([23]) * 32
    public, _ = key.compute_xonly_pubkey(secret)
    result = []

    def add(name, code, args, allowed, **extra):
        result.append(dict(name=name, script=bytes(code), args=args, allowed=allowed, **extra))

    add("empty-key-checksig-not", s.CScript([s.OP_CHECKSIG, s.OP_NOT]), [b"", b""], False)
    add("empty-key-checksigadd", s.CScript([s.OP_CHECKSIGADD]), [b"", b"\x01", b""], False)
    add("empty-key-checksigverify", s.CScript([s.OP_CHECKSIGVERIFY, 1]), [b"", b""], False)
    add("empty-signatures-free", s.CScript([public, s.OP_CHECKSIG, s.OP_NOT, s.OP_DROP] * 20 + [1]), [b""] * 20, True)
    for n, annex, expected in [(2, None, False), (2, b"\x50", True), (3, b"\x50", False)]:
        add(f"unknown-key-budget-{n}-{annex is not None}", s.CScript([s.OP_DUP, b"\x01", s.OP_CHECKSIGVERIFY] * n + [s.OP_DROP, 1]), [b"\x01"], expected, annex=annex)
    add("unknown-key-empty-signature", s.CScript([b"\x01", s.OP_CHECKSIG, s.OP_NOT]), [b""], True)
    add("checksigadd-empty-signature", s.CScript([1, public, s.OP_CHECKSIGADD]), [b""], True)
    for op in [s.OP_IF, s.OP_NOTIF]:
        for argument in [b"", b"\x01", b"\x02", b"\x00", b"\x80", b"\x01\x00"]:
            add(f"minimalif-{int(op)}-{argument.hex()}", s.CScript([op, 1, s.OP_ELSE, 1, s.OP_ENDIF]), [argument], argument in [b"", b"\x01"])
    add("nested-skipped-if", s.CScript([0, s.OP_IF, s.OP_IF, s.OP_ENDIF, s.OP_ENDIF, 1]), [], True)
    for op in [s.OP_CHECKMULTISIG, s.OP_CHECKMULTISIGVERIFY]:
        add(f"skipped-multisig-{int(op)}", s.CScript([0, s.OP_IF, op, s.OP_ENDIF, 1]), [], True)
        add(f"executed-multisig-{int(op)}", s.CScript([op, 1]), [], False)
    for n, expected in [(10, True), (11, False)]:
        add(f"known-key-budget-{n}", s.CScript([s.OP_DUP, public, s.OP_CHECKSIGVERIFY] * n + [s.OP_DROP, 1]), [], expected, sign=True)
    separator_cases = [
        ("separator-after-push", s.CScript([b"abcd", s.OP_DROP, s.OP_CODESEPARATOR, public, s.OP_CHECKSIG]), 2),
        ("separator-in-skipped-branch", s.CScript([0, s.OP_IF, s.OP_CODESEPARATOR, s.OP_ENDIF, public, s.OP_CHECKSIG]), -1),
        ("separator-after-skipped-branch", s.CScript([0, s.OP_IF, s.OP_CODESEPARATOR, s.OP_ENDIF, b"abcd", s.OP_DROP, s.OP_CODESEPARATOR, public, s.OP_CHECKSIG]), 6),
        ("separator-last-executed", s.CScript([s.OP_CODESEPARATOR, b"ab", s.OP_DROP, s.OP_CODESEPARATOR, public, s.OP_CHECKSIG]), 3),
    ]
    for name, script, position in separator_cases:
        add(name, script, [], True, sign=True, codesep=position)
    add("wrong-separator-signature", separator_cases[0][1], [], False, sign=True, codesep=-1)
    for size in [1, 252, 253, 521]:
        add(f"annex-script-{size}", s.CScript([public, s.OP_CHECKSIG]), [], True, sign=True, annex=b"\x50" + bytes(size - 1))
        add(f"annex-key-{size}", b"", [], True, keypath=True, sign=True, annex=b"\x50" + bytes(size - 1))
    for hash_type in [0, 1, 2, 3, 0x81, 0x82, 0x83]:
        add(f"separator-sighash-{hash_type}", separator_cases[0][1], [], True, sign=True, codesep=2, hash_type=hash_type)
    for hash_type in [4, 0x80, 0x84]:
        add(f"undefined-sighash-{hash_type}", s.CScript([public, s.OP_CHECKSIG]), [], False, sign=True, hash_type=hash_type)
    for depth, expected in [(0, True), (128, True), (129, False)]:
        add(f"control-depth-{depth}", s.CScript([public, s.OP_CHECKSIG]), [], expected, sign=True, depth=depth)
    for code, version, label in [(b"\xbb", 0xc0, "success"), (bytes([s.OP_RETURN]), 0xc2, "future")]:
        for depth, expected in [(128, True), (129, False)]:
            add(f"control-{label}-depth-{depth}", code, [], expected, depth=depth, leaf_version=version)
    add("control-truncated-depth-128", s.CScript([public, s.OP_CHECKSIG]), [], False, sign=True, depth=128, control_drop=1)
    for label, prefix, expected in [
        ("hidden-false-else", s.CScript([0, s.OP_IF, 1, s.OP_IF, s.OP_ELSE, s.OP_ELSE, s.OP_ENDIF, s.OP_ELSE, s.OP_ENDIF]), True),
        ("inner-false-else", s.CScript([1, s.OP_IF, 0, s.OP_IF, s.OP_ELSE, 1, s.OP_IF, s.OP_ELSE, s.OP_ELSE, s.OP_ENDIF, s.OP_ENDIF, s.OP_ENDIF]), True),
        ("repeated-else", s.CScript([1, s.OP_IF, s.OP_ELSE, s.OP_ELSE, s.OP_ELSE, s.OP_ELSE, s.OP_ENDIF]), True),
        ("else-without-if", s.CScript([s.OP_ELSE]), False),
        ("endif-without-if", s.CScript([s.OP_ENDIF]), False),
    ]:
        add(label, bytes(prefix) + bytes(s.CScript([public, s.OP_CHECKSIG])), [], expected, sign=True)
    # Exercise deep real scripts at runtime without committing megabytes of
    # repeated bytes to the fixture file. No artificial depth limit is imposed.
    depth = 250_000
    tail = bytes(s.CScript([public, s.OP_CHECKSIG]))
    for label, prefix, expected in [
        ("large-true-conditions", b"\x51\x63" * depth + b"\x68" * depth, True),
        ("large-skipped-conditions", b"\x00\x63" + b"\x63" * depth + b"\x68" * depth + b"\x67\x68", True),
        ("large-inner-else", b"\x51\x63" * depth + b"\x00\x63\x67\x67\x68" + b"\x68" * depth, True),
        ("large-unbalanced-conditions", b"\x51\x63" * depth + b"\x68" * (depth - 1), False),
    ]:
        add(label, prefix + tail, [], expected, sign=True, runtime_only=True)
    return result


def output(case):
    key, s, _ = reference()
    internal = key.compute_xonly_pubkey(bytes([23]) * 32)[0] if case.get("keypath") else bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
    version = case.get("leaf_version", 0xc0)
    tree = [("case", case["script"], version)]
    for i in range(case.get("depth", 0)):
        # Actual sibling leaf hashes, with public scripts, form a skewed tree.
        tree = [tree, (None, bytes(s.CScript([i, s.OP_DROP, 1])), version)]
    return s.taproot_construct(internal, [] if case.get("keypath") else tree)


def spend(case, txid, vout, amount, destination=b"\x51"):
    key, s, m = reference()
    info = output(case)
    tx = m.CTransaction()
    tx.version = 2
    tx.vin = [m.CTxIn(m.COutPoint(int(txid, 16), vout), b"", 0xfffffffd)]
    tx.vout = [m.CTxOut(amount - 10_000, destination)]
    prevout = m.CTxOut(amount, info.scriptPubKey)
    args = list(case["args"])
    digest = None
    if case.get("sign"):
        hash_type = case.get("hash_type", 0)
        digest = s.TaprootSignatureHash(tx, [prevout], hash_type, scriptpath=not case.get("keypath"),
            leaf_script=case["script"], codeseparator_pos=case.get("codesep", -1), annex=case.get("annex"), leaf_ver=case.get("leaf_version", 0xc0))
        secret = bytes([23]) * 32
        if case.get("keypath"):
            secret = key.tweak_add_privkey(secret, info.tweak)
        signature = key.sign_schnorr(secret, digest, aux=bytes(32))
        if hash_type:
            signature += bytes([hash_type])
        args.insert(0, signature)
    if not case.get("keypath"):
        leaf = info.leaves["case"]
        control = bytes([leaf.version | info.negflag]) + info.internal_pubkey + leaf.merklebranch
        if case.get("control_drop"):
            control = control[:-case["control_drop"]]
        args += [case["script"], control]
    if case.get("annex") is not None:
        args.append(case["annex"])
    tx.wit.vtxinwit = [m.CTxInWitness()]
    tx.wit.vtxinwit[0].scriptWitness.stack = args
    return tx, prevout, digest


def write_vectors(path):
    vectors = []
    for i, case in enumerate(cases()):
        if case.get("runtime_only"):
            continue
        tx, prevout, digest = spend(case, "11" * 32, i, 100_000)
        vectors.append(dict(name=case["name"], transaction=tx.serialize().hex(), prevout=prevout.serialize().hex(),
            allowed=case["allowed"], digest=digest.hex() if digest else None,
            hash_type=case.get("hash_type", 0), codesep=case.get("codesep", -1),
            annex=case.get("annex", b"").hex() if case.get("annex") else None,
            leaf_hash=output(case).leaves["case"].leaf_hash.hex() if not case.get("keypath") else None))
    path.write_text(json.dumps(dict(source=SOURCE, source_sha256=SOURCES, license="MIT", scope="Core reference-generated single-input Taproot execution/digest cases; acceptance labels additionally checked with live Core v29 blocks.", vectors=vectors), indent=2) + "\n")
    print(f"Generated {len(vectors)} Core reference cases", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-vectors", type=Path, required=True)
    write_vectors(parser.parse_args().write_vectors)
