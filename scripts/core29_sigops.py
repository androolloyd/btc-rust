#!/usr/bin/env python3
"""Independent Core signature-operation counts and live block/policy limits."""
import argparse
import json
from pathlib import Path

import core29_tapscript as tap
import core29_witness_policy as witness
from core29_tapscript import reference, SOURCE, SOURCES

fund_in_block = True
output = witness.output
address = witness.address


def cases():
    _, s, _ = reference()
    result = []

    def add(name, mode, multi=198, checks=0, legacy_multi=0, legacy_checks=0, fee=1_000_000):
        script = s.CScript([0, s.OP_IF] + [s.OP_CHECKMULTISIG] * multi + [s.OP_CHECKSIG] * checks + [s.OP_ENDIF, 1])
        case = dict(name=name, mode=mode, script=bytes(script), args=[], legacy_multi=legacy_multi,
                    legacy_checks=legacy_checks, fee=fee)
        count = cost(case)
        p2sh_standard = mode != "p2sh" or script.GetSigOpCount(True) <= 15
        case.update(allowed=count <= 80_000, policy_allowed=p2sh_standard and count <= 16_000 and fee >= count * 5,
                    reject_contains="bad-blk-sigops")
        result.append(case)

    for mode in ["p2sh", "witness", "wrapped"]:
        add(f"{mode}-count", mode)
        # Exact transaction policy boundary and first excess.
        if mode == "p2sh":
            add(f"{mode}-16000", mode, legacy_multi=2)
            add(f"{mode}-16080", mode, legacy_multi=3)
            add(f"{mode}-80000", mode, legacy_multi=802)
            add(f"{mode}-80004", mode, checks=1, legacy_multi=802)
        else:
            add(f"{mode}-16000", mode, legacy_multi=150, legacy_checks=10)
            add(f"{mode}-16001", mode, checks=1, legacy_multi=150, legacy_checks=10)
            add(f"{mode}-80000", mode, legacy_multi=950, legacy_checks=10)
            add(f"{mode}-80001", mode, multi=196, checks=1, legacy_multi=951)
        if mode != "p2sh":
            add(f"{mode}-sigop-fee-below", mode, fee=19_799)
            add(f"{mode}-sigop-fee-exact", mode, fee=19_800)
    add("p2sh-15", "p2sh", multi=0, checks=15, fee=100_000)
    capped = result[-1].copy()
    capped.update(name="p2sh-15-adjusted-rounded-rpc-cap", fee_cap=0.00333333)
    result.append(capped)
    capped = capped.copy()
    capped.update(name="p2sh-15-rpc-cap-below", fee_cap=0.00333330, policy_allowed=False)
    result.append(capped)
    add("p2sh-16", "p2sh", multi=0, checks=16, fee=100_000)
    # Taproot's skipped multisig is valid but contributes zero static input
    # sigops. These isolate legacy outputs and the context-free block limit.
    add("taproot-exempt", "taproot")
    add("legacy-80000", "taproot", legacy_multi=1000)
    add("legacy-80080", "taproot", legacy_multi=1001)
    return result


def extra_outputs(case):
    _, s, _ = reference()
    public = witness.private().get_pubkey().get_bytes()
    # Standard, curve-valid bare multisig/P2PKH outputs isolate static legacy
    # counts without masking positive admission with scriptpubkey policy.
    multi = s.CScript([1, public, 1, s.OP_CHECKMULTISIG])
    single = s.CScript([s.OP_DUP, s.OP_HASH160, s.hash160(public), s.OP_EQUALVERIFY, s.OP_CHECKSIG])
    return [multi] * case["legacy_multi"] + [single] * case["legacy_checks"]


def cost(case):
    _, s, _ = reference()
    value = sum(script.GetSigOpCount(False) for script in extra_outputs(case)) * 4
    if case["mode"] == "p2sh":
        value += s.CScript(case["script"]).GetSigOpCount(True) * 4
    elif case["mode"] != "taproot":
        value += s.CScript(case["script"]).GetSigOpCount(True)
    return value


def spend(case, txid, index, amount, destination=b"\x51"):
    _, s, m = reference()
    tx, previous, _ = witness.spend(case, txid, index, amount, destination)
    extra = extra_outputs(case)
    tx.vout[0].nValue = amount - case["fee"] - 1000 * len(extra)
    tx.vout.extend(m.CTxOut(1000, script) for script in extra)
    return tx, previous, []


def write_vectors(path):
    vectors = []
    for index, case in enumerate(cases()):
        tx, previous, _ = spend(case, "11" * 32, index, 10_000_000)
        vectors.append(dict(name=case["name"], transaction=tx.serialize().hex(), prevout=previous.serialize().hex(), cost=cost(case)))
    # Every OP_N accurate multisig count comes directly from Core's routine.
    _, s, _ = reference()
    scripts = [s.CScript([n, s.OP_CHECKMULTISIG, s.OP_CHECKSIGVERIFY]) for n in range(17)]
    scripts += [s.CScript([s.OP_CHECKSIG, b"\xac\xae", s.OP_CHECKMULTISIG]),
                s.CScript([0, s.OP_IF, 3, s.OP_CHECKMULTISIGVERIFY, s.OP_ENDIF, 1])]
    path.write_text(json.dumps(dict(source=SOURCE, source_sha256=SOURCES, license="MIT", vectors=vectors,
        scripts=[dict(script=bytes(code).hex(), accurate=code.GetSigOpCount(True), legacy=code.GetSigOpCount(False)) for code in scripts]), indent=2) + "\n")
    print(f"Generated {len(vectors)} Core cost cases and {len(scripts)} opcode counts", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-vectors", type=Path, required=True)
    write_vectors(parser.parse_args().write_vectors)
