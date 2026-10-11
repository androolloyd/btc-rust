#!/usr/bin/env python3
"""Check compiled CLI v0/v2 PSBT conversion with independently signed Core v29.

Uses a checksum-verified bitcoind, disposable regtest wallet, no peer discovery,
and real mature SegWit/Taproot coins. Core finalizes and checks the converted
transactions; the Rust converter does not claim to verify or create signatures.
"""
import argparse
import base64
import io
import json
from pathlib import Path
import subprocess
import tempfile

from check_core_p2p import core_rpc, free_port, wait_until


def cli(node, command, psbt, *extra):
    result = subprocess.run([str(node), "--json", command, psbt, *extra],
                            capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


def encode64(raw_hex):
    return base64.b64encode(bytes.fromhex(raw_hex)).decode()


def origin_records(entries, core=False):
    records = {}
    for entry in entries:
        path = entry["path"]
        if core:
            path = [int(part.rstrip("h'")) | (0x80000000 if part.endswith(("h", "'")) else 0)
                    for part in path.split("/")[1:]]
        records[entry["pubkey"]] = (entry["master_fingerprint"], path, sorted(entry.get("leaf_hashes", [])))
    return records


def check_taproot_metadata(decoded, independent):
    for actual, expected in zip(decoded["inputs"], independent["inputs"], strict=True):
        assert actual["tap_internal_key"] == expected.get("taproot_internal_key")
        assert actual["tap_merkle_root"] == expected.get("taproot_merkle_root")
        assert actual["has_tap_key_signature"] == ("taproot_key_path_sig" in expected)
        assert actual["tap_script_signatures"] == len(expected.get("taproot_script_path_sigs", []))
        assert origin_records(actual["tap_bip32_derivation"]) == origin_records(
            expected.get("taproot_bip32_derivs", []), core=True)
        scripts = [(leaf["control_block"], leaf["leaf_version"], leaf["script"])
                   for leaf in actual["tap_leaf_scripts"]]
        core_scripts = [(control, leaf["leaf_ver"], leaf["script"])
                        for leaf in expected.get("taproot_scripts", []) for control in leaf["control_blocks"]]
        assert sorted(scripts) == sorted(core_scripts)
    for actual, expected in zip(decoded["outputs"], independent["outputs"], strict=True):
        assert actual["tap_internal_key"] == expected.get("taproot_internal_key")
        assert origin_records(actual["tap_bip32_derivation"]) == origin_records(
            expected.get("taproot_bip32_derivs", []), core=True)
        tree = [(leaf["depth"], leaf["leaf_version"], leaf["script"]) for leaf in actual["tap_tree"] or []]
        core_tree = [(leaf["depth"], leaf["leaf_ver"], leaf["script"]) for leaf in expected.get("taproot_tree", [])]
        assert tree == core_tree


def script_addresses(port, kind):
    # The BIP341 NUMS point has no known secret; the wallet must spend a leaf.
    nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    descriptors = core_rpc(port, "listdescriptors", [True])["descriptors"]
    prefix = "tr(" if kind == "taproot-script" else "wpkh("
    original = next(d["desc"] for d in descriptors
                    if d["active"] and not d["internal"] and d["desc"].startswith(prefix))
    key = original.split("#")[0][len(prefix):-1]
    assert key.endswith("/0/*")
    if kind == "taproot-script":
        second = key[:-4] + "/1/*"
        private = f"tr({nums},{{pk({key}),pk({second})}})"
    else:
        private = f"wsh(pk({key}))"
        if kind == "sh-wsh":
            private = f"sh({private})"
    info = core_rpc(port, "getdescriptorinfo", [private])
    checked_private = private + "#" + info["checksum"]
    imported = core_rpc(port, "importdescriptors", [[{
        "desc": checked_private, "timestamp": "now", "range": [0, 10],
    }]])
    assert all(item["success"] for item in imported), imported
    # These wallet root keys include hardened paths; their public serialization
    # cannot derive those paths. Core derives the test addresses with its private keys.
    return core_rpc(port, "deriveaddresses", [checked_private, [0, 1]])


def compact_size(n):
    if n < 253:
        return bytes([n])
    size = 2 if n <= 0xffff else 4 if n <= 0xffffffff else 8
    return bytes([{2: 253, 4: 254, 8: 255}[size]]) + n.to_bytes(size, "little")


def psbt_maps(raw):
    stream = io.BytesIO(bytes.fromhex(raw))
    assert stream.read(5) == b"psbt\xff"

    def count():
        first = stream.read(1)[0]
        return first if first < 253 else int.from_bytes(stream.read({253: 2, 254: 4, 255: 8}[first]), "little")

    maps = []
    while stream.tell() < len(stream.getvalue()):
        records = {}
        while (size := count()):
            key = stream.read(size)
            records[key] = stream.read(count())
        maps.append(records)
    assert len(maps) == 3  # these real spends have one input and one output
    return maps


def encode_maps(maps):
    wire = bytearray(b"psbt\xff")
    for records in maps:
        for key, value in records.items():
            wire.extend(compact_size(len(key)) + key + compact_size(len(value)) + value)
        wire.append(0)
    return wire.hex()


def reject_spending_data(args, raw, reason):
    for command, extra in [("decode-psbt", []), ("convert-psbt", ["--version", "2"]), ("extract-psbt", [])]:
        result = subprocess.run([str(args.node), "--json", command, raw, *extra],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode != 0 and reason in result.stderr, (command, result.stderr)


def check_spending_data(args, port, raw, finalized, coin, expected_tx):
    parent = bytes.fromhex(core_rpc(port, "gettransaction", [coin["txid"]])["hex"])
    actual = core_rpc(port, "gettxout", [coin["txid"], coin["vout"]])
    amount = round(actual["value"] * 100_000_000)
    script = bytes.fromhex(actual["scriptPubKey"]["hex"])
    witness = amount.to_bytes(8, "little") + compact_size(len(script)) + script
    for original in [raw, finalized]:
        maps = psbt_maps(original)
        maps[1][b"\x00"] = parent
        good = encode_maps(maps)
        info = cli(args.node, "decode-psbt", good)["inputs"][0]["utxo"]
        assert info == {"value_sat": amount, "script_pubkey": script.hex(),
                        "source": "non_witness_utxo", "txid_linked": True}
        restored = cli(args.node, "convert-psbt", cli(args.node, "convert-psbt", good, "--version", "2")["psbt_hex"], "--version", "0")
        result = core_rpc(port, "finalizepsbt", [encode64(restored["psbt_hex"])])
        assert result["complete"] is True and result["hex"] == expected_tx
        if original == finalized:
            assert cli(args.node, "extract-psbt", restored["psbt_hex"])["tx_hex"] == expected_tx
        # Mutating the parent's locktime changes its txid even when outputs agree.
        corrupted = psbt_maps(good)
        corrupted[1][b"\x00"] = parent[:-4] + (int.from_bytes(parent[-4:], "little") ^ 1).to_bytes(4, "little")
        reject_spending_data(args, encode_maps(corrupted), "non-witness UTXO txid differs")
        try:
            core_rpc(port, "decodepsbt", [encode64(encode_maps(corrupted))])
        except RuntimeError as error:
            assert error.args[0]["code"] == -22
        else:
            raise AssertionError("Core accepted substituted parent transaction")
        # Both records must describe precisely the same output, not just an amount.
        for replacement in [(amount + 1).to_bytes(8, "little") + witness[8:], witness[:-1] + bytes([witness[-1] ^ 1])]:
            corrupted = psbt_maps(good)
            corrupted[1][b"\x01"] = replacement
            reject_spending_data(args, encode_maps(corrupted), "witness UTXO differs")
        # Alter an actual supplied input/output script, including wrapped P2WSH.
        for scope, key in [(1, b"\x04"), (1, b"\x05"), (2, b"\x00"), (2, b"\x01")]:
            if key in maps[scope]:
                corrupted = psbt_maps(good)
                corrupted[scope][key] += b"\x00"
                reject_spending_data(args, encode_maps(corrupted), "does not match")


def check_published_taproot_vectors(args, port):
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip371.json"
    for vector in json.loads(fixture.read_text())["vectors"]:
        raw = vector["hex"]
        if vector["status"] == "invalid":
            rejected = subprocess.run([str(args.node), "--json", "decode-psbt", raw],
                                      capture_output=True, text=True, timeout=30)
            assert rejected.returncode != 0, vector["case"]
            try:
                core_rpc(port, "decodepsbt", [encode64(raw)])
            except RuntimeError:
                pass
            else:
                raise AssertionError(f"Core accepted invalid vector: {vector['case']}")
        else:
            before = core_rpc(port, "decodepsbt", [encode64(raw)])
            check_taproot_metadata(cli(args.node, "decode-psbt", raw), before)
            converted = cli(args.node, "convert-psbt", raw, "--version", "2")
            restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
            after = core_rpc(port, "decodepsbt", [encode64(restored["psbt_hex"])])
            assert before == after, vector["case"]
    print("PASSED: all 17 published BIP371 cases agree with Core v29", flush=True)


def check_published_spending_vectors(args, port):
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip174-utxo.json"
    for vector in json.loads(fixture.read_text())["vectors"]:
        raw = vector["hex"]
        if vector["status"] == "script_mismatch":
            reject_spending_data(args, raw, "does not match")
        else:
            before = core_rpc(port, "decodepsbt", [encode64(raw)])
            converted = cli(args.node, "convert-psbt", raw, "--version", "2")
            restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
            assert core_rpc(port, "decodepsbt", [encode64(restored["psbt_hex"])]) == before
    print("PASSED: 8 published BIP174 spends preserve Core data; 3 signer-script failures rejected", flush=True)


def core_rejects_key(port, raw):
    try:
        core_rpc(port, "decodepsbt", [encode64(raw)])
    except RuntimeError as error:
        assert error.args[0]["code"] == -22, error
    else:
        raise AssertionError("Core accepted an invalid curve/key record")


def check_key_substitutions(args, port, raw):
    maps = psbt_maps(raw)
    # The off-curve x=7 point is published in BIP32 vector 5; its encoding has
    # the correct prefix and length, so length-only wallet checks cannot catch it.
    bad_point = b"\x02" + b"\x00" * 31 + b"\x07"
    for scope, kind in [(1, 2), (1, 6), (2, 2)]:
        for key in maps[scope]:
            if key[0] != kind or len(key) not in (34, 66):
                continue
            bad = psbt_maps(raw)
            value = bad[scope].pop(key)
            bad[scope][bytes([kind]) + bad_point] = value
            corrupted = encode_maps(bad)
            reject_spending_data(args, corrupted, "public key")
            core_rejects_key(port, corrupted)
            break


def check_published_key_vectors(args, port):
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip32-keys.json"
    data = json.loads(fixture.read_text())
    for vector in data["psbt_vectors"]:
        raw = vector["hex"]
        if vector["status"] == "invalid":
            reject_spending_data(args, raw, "xpub" if "global xpub" in vector["case"] else "public key")
            if vector["core_parse_reject"]:
                core_rejects_key(port, raw)
            else:
                # Core's PSBT decoder preserves custom version bytes. This
                # implementation explicitly supports standard xpub/tpub only.
                core_rpc(port, "decodepsbt", [encode64(raw)])
            continue
        expected = data["valid_keys"][vector["valid_key_index"]]
        decoded = cli(args.node, "decode-psbt", raw)
        independent = core_rpc(port, "decodepsbt", [encode64(raw)])
        extended = decoded["global_xpub_records"][0]
        assert decoded["global_xpubs"] == 1 and decoded["signatures_verified"] is False
        assert extended["xpub"] == expected["xpub"] == independent["global_xpubs"][0]["xpub"]
        assert extended["serialized_xpub"] == expected["serialized_xpub"]
        assert extended["master_fingerprint"] == expected["master_fingerprint"]
        assert extended["path"] == expected["child_indices"]
        for name in ["inputs", "outputs"]:
            assert origin_records(decoded[name][0]["bip32_derivation"]) == origin_records(
                independent[name][0]["bip32_derivs"], core=True)
        converted = cli(args.node, "convert-psbt", raw, "--version", "2")
        restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
        assert core_rpc(port, "decodepsbt", [encode64(restored["psbt_hex"])]) == independent
        check_key_substitutions(args, port, raw)
        maps = psbt_maps(raw)
        global_key = next(key for key in maps[0] if key[0] == 1)
        bad = psbt_maps(raw)
        bad[0][global_key] += b"\x00\x00\x00\x00"
        corrupted = encode_maps(bad)
        # Core's decoder does not bind origin paths to extended-key headers.
        core_rpc(port, "decodepsbt", [encode64(corrupted)])
        reject_spending_data(args, corrupted, "depth")
        if extended["path"]:
            bad = psbt_maps(raw)
            value = bytearray(bad[0][global_key])
            value[-4] ^= 1
            bad[0][global_key] = bytes(value)
            corrupted = encode_maps(bad)
            core_rpc(port, "decodepsbt", [encode64(corrupted)])
            reject_spending_data(args, corrupted, "child number")
        if len(extended["path"]) <= 1:
            bad = psbt_maps(raw)
            value = bytearray(bad[0][global_key])
            value[0] ^= 1
            bad[0][global_key] = bytes(value)
            corrupted = encode_maps(bad)
            core_rpc(port, "decodepsbt", [encode64(corrupted)])
            reject_spending_data(args, corrupted, "fingerprint")
    print("PASSED: 27 BIP32/BIP174 PSBT key cases, Core curve-key rejection and explicit origin/version checks", flush=True)


def check_published_signature_vectors(args, port):
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/psbt-signatures.json"
    for vector in json.loads(fixture.read_text())["psbt_vectors"]:
        raw = vector["hex"]
        # Core's PSBT decoder accepts these partial-signature bytes as metadata;
        # parsing is not validation of their DER/scalars/equation.
        independent = core_rpc(port, "decodepsbt", [encode64(raw)])
        if vector["status"] == "invalid":
            reject_spending_data(args, raw, "signature")
        else:
            decoded = cli(args.node, "decode-psbt", raw)
            assert decoded["signatures_verified"] is False
            converted = cli(args.node, "convert-psbt", raw, "--version", "2")
            restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
            assert core_rpc(port, "decodepsbt", [encode64(restored["psbt_hex"])]) == independent
    print("PASSED: 58 independent signature-encoding PSBT cases; equation status remains unverified", flush=True)


def check_signed_sighash_variants(args, port, unsigned, kind):
    names = [("ALL",1),("NONE",2),("SINGLE",3),
             ("ALL|ANYONECANPAY",0x81),("NONE|ANYONECANPAY",0x82),("SINGLE|ANYONECANPAY",0x83)]
    if kind in ["bech32m", "taproot-script"]:
        names.insert(0, ("DEFAULT",0))
    for name, hash_type in names:
        result = core_rpc(port, "walletprocesspsbt", [unsigned, True, name, True, False])
        # finalize=False intentionally keeps partial records; Core's complete
        # status can be false until they have been finalized. Require the real
        # signature records and independently validated final transaction below.
        maps = psbt_maps(base64.b64decode(result["psbt"]).hex())
        maps[1][b"\x03"] = hash_type.to_bytes(4, "little")
        raw = encode_maps(maps)
        finalized = core_rpc(port, "finalizepsbt", [encode64(raw)])
        assert finalized["complete"] is True, (kind, name)
        assert core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]["allowed"] is True
        decoded = cli(args.node, "decode-psbt", raw)
        fields = decoded["inputs"][0]
        assert fields["sighash_type"] == hash_type and decoded["signatures_verified"] is False
        types = [record["sighash_type"] for record in fields["partial_signature_records"]]
        types += [record["sighash_type"] for record in fields["tap_script_signature_records"]]
        if fields["tap_key_signature_sighash_type"] is not None:
            types.append(fields["tap_key_signature_sighash_type"])
        assert types and all(value == hash_type for value in types), (kind, name, types)
        converted = cli(args.node, "convert-psbt", raw, "--version", "2")
        v2 = cli(args.node, "decode-psbt", converted["psbt_hex"])
        assert v2["tx_modifiable"] == (4 if hash_type & 0x7f == 3 else 0)
        restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
        assert core_rpc(port, "finalizepsbt", [encode64(restored["psbt_hex"])])["hex"] == finalized["hex"]
        # Declarations are outside the transaction; substitution leaves the
        # same unsigned bytes/signatures but must fail our tool boundary.
        bad = psbt_maps(raw)
        bad[1][b"\x03"] = (2 if hash_type != 2 else 1).to_bytes(4,"little")
        corrupted = encode_maps(bad)
        core_rpc(port, "decodepsbt", [encode64(corrupted)])
        reject_spending_data(args, corrupted, "sighash")
        for key, sig in maps[1].items():
            if key[0] == 2:
                bad = psbt_maps(raw); bad[1][key] = b"\x31" + sig[1:]
                reject_spending_data(args, encode_maps(bad), "signature")
            elif key[0] in (0x13, 0x14):
                bad = psbt_maps(raw); bad[1][key] = sig[:64] + b"\x00"
                reject_spending_data(args, encode_maps(bad), "signature")
                bad = psbt_maps(raw); bad[1][key] = b"\xff"*32 + sig[32:]
                reject_spending_data(args, encode_maps(bad), "signature")
    print(f"PASSED: Core {kind} {len(names)} real sighash variants, declared-type rejection and v2 permissions", flush=True)


def check_taproot_substitutions(args, raw):
    maps = psbt_maps(raw)
    generator = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    variants = []
    if b"\x18" in maps[1] and b"\x17" in maps[1]:
        bad = psbt_maps(raw)
        root = bad[1][b"\x18"]
        bad[1][b"\x18"] = bytes([root[0] ^ 1]) + root[1:]
        variants.append(bad)
        bad = psbt_maps(raw)
        bad[1][b"\x17"] = generator
        variants.append(bad)
    for key in [key for key in maps[1] if key[0] == 0x15]:
        bad = psbt_maps(raw)
        leaf = bad[1][key]
        bad[1][key] = leaf[:-1] + b"\x00" + leaf[-1:]
        variants.append(bad)
        bad = psbt_maps(raw)
        value = bad[1].pop(key)
        bad[1][key[:1] + bytes([key[1] ^ 1]) + key[2:]] = value
        variants.append(bad)
        if len(key) > 34:
            bad = psbt_maps(raw)
            value = bad[1].pop(key)
            bad[1][key[:34] + bytes([key[34] ^ 1]) + key[35:]] = value
            variants.append(bad)
    if b"\x06" in maps[2] and b"\x05" in maps[2]:
        bad = psbt_maps(raw)
        bad[2][b"\x05"] = generator
        variants.append(bad)
        bad = psbt_maps(raw)
        tree = bad[2][b"\x06"]
        bad[2][b"\x06"] = tree[:-1] + bytes([tree[-1] ^ 1])
        variants.append(bad)
    for bad in variants:
        reject_spending_data(args, encode_maps(bad), "Taproot")


def check_published_commitment_vectors(args, port):
    fixture = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/bip341-commitments.json"
    for vector in json.loads(fixture.read_text())["psbt_vectors"]:
        raw = vector["hex"]
        before = core_rpc(port, "decodepsbt", [encode64(raw)])
        check_taproot_metadata(cli(args.node, "decode-psbt", raw), before)
        converted = cli(args.node, "convert-psbt", raw, "--version", "2")
        restored = cli(args.node, "convert-psbt", converted["psbt_hex"], "--version", "0")
        assert core_rpc(port, "decodepsbt", [encode64(restored["psbt_hex"])]) == before
        check_taproot_substitutions(args, raw)
    print("PASSED: 7 published BIP341 commitment wrappers and altered-proof rejections", flush=True)


def check_wallet(args, port, kind, script_pair=None):
    if kind in ["taproot-script", "wsh", "sh-wsh"]:
        assert script_pair is not None
        address, destination = script_pair
    else:
        address = core_rpc(port, "getnewaddress", ["", kind])
        destination = core_rpc(port, "getnewaddress", ["", kind])
    core_rpc(port, "generatetoaddress", [101, address], timeout=30)
    coins = [coin for coin in core_rpc(port, "listunspent", [100]) if coin["address"] == address]
    assert coins, f"no mature {kind} coin"
    coin = coins[0]
    original = core_rpc(port, "createpsbt", [[{"txid": coin["txid"], "vout": coin["vout"],
                                               "sequence": 0xfffffffd}],
                                             {destination: round(coin["amount"] - 0.00002, 8)}, 23])
    if kind in ["legacy", "bech32", "bech32m", "taproot-script"]:
        check_signed_sighash_variants(args, port, original, kind)
    # Keep the real signatures/derivations in the PSBT for the conversion check.
    signed = core_rpc(port, "walletprocesspsbt", [original, True, "ALL", True, False])["psbt"]
    original_hex = base64.b64decode(signed, validate=True).hex()
    decoded = cli(args.node, "decode-psbt", original_hex)
    independent = core_rpc(port, "decodepsbt", [signed])
    assert decoded["unsigned_txid"] == independent["tx"]["txid"]
    assert decoded["locktime"] == independent["tx"]["locktime"] == 23
    assert decoded["signatures_verified"] is False
    check_taproot_metadata(decoded, independent)
    check_key_substitutions(args, port, original_hex)
    if kind == "taproot-script":
        fields = decoded["inputs"][0]
        assert len(fields["tap_leaf_scripts"]) == 2
        assert all(len(bytes.fromhex(leaf["control_block"])) == 65 for leaf in fields["tap_leaf_scripts"])
        leaf_origins = [source for source in fields["tap_bip32_derivation"] if source["leaf_hashes"]]
        assert len(leaf_origins) == 2
        assert all(len(source["leaf_hashes"]) == 1 for source in leaf_origins)
        assert fields["tap_script_signatures"] == 2
        assert fields["has_tap_key_signature"] is False
        assert [leaf["depth"] for leaf in decoded["outputs"][0]["tap_tree"]] == [1, 1]
        assert sum(bool(source["leaf_hashes"]) for source in decoded["outputs"][0]["tap_bip32_derivation"]) == 2
        check_taproot_substitutions(args, original_hex)
    expected = core_rpc(port, "finalizepsbt", [signed])
    assert expected["complete"] is True
    v2 = cli(args.node, "convert-psbt", original_hex, "--version", "2")
    info = cli(args.node, "decode-psbt", v2["psbt_hex"])
    assert info["psbt_version"] == 2
    assert info["inputs"][0]["sequence"] == 0xfffffffd
    assert info["unsigned_tx_hex"] == decoded["unsigned_tx_hex"]
    restored = cli(args.node, "convert-psbt", v2["psbt_hex"], "--version", "0")
    restored64 = encode64(restored["psbt_hex"])
    finalized = core_rpc(port, "finalizepsbt", [restored64])
    assert finalized["complete"] is True
    assert finalized["hex"] == expected["hex"], "conversion changed a signed transaction"
    if kind == "taproot-script":
        witness = core_rpc(port, "decoderawtransaction", [finalized["hex"]])["vin"][0]["txinwitness"]
        assert len(witness) == 3 and len(bytes.fromhex(witness[-1])) == 65
    accepted = core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]
    assert accepted["allowed"] is True, accepted
    # Already-finalized witnesses must survive the same conversion as well.
    final_psbt = core_rpc(port, "finalizepsbt", [signed, False])["psbt"]
    final_hex = base64.b64decode(final_psbt, validate=True).hex()
    check_spending_data(args, port, original_hex, final_hex, coin, expected["hex"])
    v2_final = cli(args.node, "convert-psbt", final_hex, "--version", "2")
    final_restored = cli(args.node, "convert-psbt", v2_final["psbt_hex"], "--version", "0")
    assert core_rpc(port, "finalizepsbt", [encode64(final_restored["psbt_hex"])])["hex"] == expected["hex"]
    for encoded in [final_hex, v2_final["psbt_hex"], final_restored["psbt_hex"]]:
        extracted = cli(args.node, "extract-psbt", encoded)
        assert extracted["tx_hex"] == expected["hex"]
        assert extracted["signatures_verified"] is False
        assert core_rpc(port, "testmempoolaccept", [[extracted["tx_hex"]]])[0]["allowed"] is True
    core_rpc(port, "sendrawtransaction", [finalized["hex"]])
    core_rpc(port, "generatetoaddress", [1, address])
    # Trailing bytes are rejected at the actual binary boundary.
    malformed = subprocess.run([str(args.node), "--json", "decode-psbt", original_hex + "00"],
                               capture_output=True, text=True, timeout=30)
    assert malformed.returncode != 0
    print(f"PASSED: Core v29 {kind} real signed/finalized PSBT v0 -> v2 -> v0", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path("target/release/btc-node"))
    args = parser.parse_args()
    args.bitcoind = args.bitcoind.resolve()
    args.node = args.node.resolve()
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="btc-core-psbt-") as directory:
        root = Path(directory)
        with (root / "core.log").open("w") as log:
            core = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={root}", "-server",
                                     "-listen=0", "-dnsseed=0", "-discover=0", "-connect=0",
                                     "-listenonion=0", "-par=1", f"-rpcport={port}",
                                     "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                                     "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002"],
                                    stdout=log, stderr=log)
            try:
                wait_until(lambda: core_rpc(port, "getblockchaininfo", []))
                core_rpc(port, "createwallet", ["psbt-interop"])
                # Import before mining: only genesis needs scanning, and all
                # subsequent test coins are observed as their blocks arrive.
                script_pairs = {kind: script_addresses(port, kind)
                                for kind in ["wsh", "sh-wsh", "taproot-script"]}
                check_published_taproot_vectors(args, port)
                check_published_spending_vectors(args, port)
                check_published_key_vectors(args, port)
                check_published_signature_vectors(args, port)
                check_published_commitment_vectors(args, port)
                for kind in ["legacy", "p2sh-segwit", "bech32", "wsh", "sh-wsh", "bech32m", "taproot-script"]:
                    check_wallet(args, port, kind, script_pairs.get(kind))
                core_rpc(port, "stop", [])
                core.wait(timeout=15)
                assert core.returncode == 0
            except BaseException:
                print((root / "core.log").read_text()[-8000:])
                raise
            finally:
                if core.poll() is None:
                    core.terminate()
                    try:
                        core.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        core.kill()
                        core.wait(timeout=10)


if __name__ == "__main__":
    main()
