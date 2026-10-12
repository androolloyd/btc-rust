#!/usr/bin/env python3
"""Check compiled CLI v0/v2 PSBT conversion with independently signed Core v29.

Uses a checksum-verified bitcoind, disposable regtest wallet, no peer discovery,
and real mature legacy/SegWit/Taproot coins. Core signs independently; the Rust
finalizer assembles and verifies supplied signatures, and Core validates/mines
the result. Conversion/extraction alone do not verify or create signatures.
"""
import argparse
import base64
import io
import json
import hashlib
import re
from pathlib import Path
import subprocess
import tempfile
import time

from check_core_p2p import core_rpc, free_port, wait_until


def run_cli(node, command, psbt, *extra):
    # Linux limits a single argv string to ~128 KiB, below real 999-key
    # updater maps. The compiled tool reads the same bounded binary PSBT.
    if command in ["decode-psbt", "convert-psbt", "extract-psbt", "verify-psbt", "finalize-psbt", "verify-psbt-derivations"] and len(psbt) > 60_000:
        with tempfile.NamedTemporaryFile(prefix="btc-psbt-input-", suffix=".psbt") as file:
            file.write(bytes.fromhex(psbt)); file.flush()
            return run_cli(node, command, "@" + file.name, *extra)
    return subprocess.run([str(node), "--json", command, psbt, *extra], capture_output=True, text=True, timeout=30)


def cli(node, command, psbt, *extra):
    result = run_cli(node, command, psbt, *extra)
    assert result.returncode == 0, (command, result.stderr)
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


def script_addresses(port, kind, descriptors):
    # The BIP341 NUMS point has no known secret; the wallet must spend a leaf.
    nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    prefix = "tr(" if kind.startswith("taproot-") else "wpkh("
    original = next(d["desc"] for d in descriptors
                    if d["active"] and not d["internal"] and d["desc"].startswith(prefix))
    key = original.split("#")[0][len(prefix):-1]
    assert key.endswith("/0/*")
    if kind.startswith("taproot-"):
        second = key[:-4] + "/1/*"
        if kind.startswith("taproot-large-"):
            threshold, count = map(int, kind.rsplit("-", 1)[1].split("of"))
            keys = [key[:-4] + f"/{i}/*" for i in range(count)]
            name = "sortedmulti_a" if threshold == 2 else "multi_a"
            private = f"tr({nums},{name}({threshold}," + ",".join(reversed(keys)) + "))"
        elif "multisig" in kind or kind == "taproot-threshold-unbalanced":
            count = 20 if kind.endswith("17of20") else 3
            threshold = 17 if count == 20 else 2
            keys = [key[:-4] + f"/{i}/*" for i in range(count)]
            # Reversed public children test sorting after CKDpub, rather than
            # sorting textual root expressions before deriving actual keys.
            name = "sortedmulti_a" if "sortedmultisig" in kind else "multi_a"
            leaf = f"{name}({threshold}," + ",".join(reversed(keys)) + ")"
            if kind == "taproot-threshold-unbalanced":
                third, fourth = [key[:-4] + f"/{i}/*" for i in (3, 4)]
                leaf = f"{{{leaf},{{pk({third}),pk({fourth})}}}}"
            private = f"tr({nums},{leaf})"
        elif kind == "taproot-unbalanced":
            third = key[:-4] + "/2/*"
            private = f"tr({nums},{{pk({key}),{{pk({second}),pk({third})}}}})"
        else:
            private = f"tr({nums},{{pk({key}),pk({second})}})"
    else:
        if kind.endswith(("multisig", "multisig-2of3")):
            second = key[:-4] + "/1/*"
            third = "," + key[:-4] + "/2/*" if kind.endswith("2of3") else ""
            multi = f"multi(2,{key},{second}{third})"
            private = f"sh({multi})" if kind.startswith("sh-multisig") else f"wsh({multi})"
        else:
            private = f"wsh(pk({key}))"
        if kind.startswith("sh-wsh"):
            private = f"sh({private})"
    info = core_rpc(port, "getdescriptorinfo", [private])
    checked_private = private + "#" + info["checksum"]
    imported = core_rpc(port, "importdescriptors", [[{
        "desc": checked_private, "timestamp": "now", "range": [0, 1 if kind.startswith("taproot-large-") else 10],
    }]], timeout=60 if kind.startswith("taproot-large-") else 10)
    assert all(item["success"] for item in imported), imported
    # These wallet root keys include hardened paths; their public serialization
    # cannot derive those paths. Core derives the test addresses with its private keys.
    return core_rpc(port, "deriveaddresses", [checked_private, [0, 1]])


def compact_size(n):
    if n < 253:
        return bytes([n])
    size = 2 if n <= 0xffff else 4 if n <= 0xffffffff else 8
    return bytes([{2: 253, 4: 254, 8: 255}[size]]) + n.to_bytes(size, "little")


def psbt_maps(raw, expected_maps=3):
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
    assert len(maps) == expected_maps
    return maps


def encode_maps(maps):
    wire = bytearray(b"psbt\xff")
    for records in maps:
        for key, value in records.items():
            wire.extend(compact_size(len(key)) + key + compact_size(len(value)) + value)
        wire.append(0)
    return wire.hex()


def derive_descriptor(args, text, index=None, network="regtest"):
    extra = ["--network", network]
    if index is not None:
        extra += ["--index", str(index)]
    result = cli(args.node, "derive-descriptor", text, *extra)
    assert result["expansion_scope"] == "public_descriptor_scripts"
    assert all(result[field] is False for field in ["key_origins_verified", "wallet_ownership_verified", "signatures_verified", "active_chain_verified"])
    return result


def regtest_descriptor(text):
    # Core's regtest descriptor parser requires tpub versions. Keep every
    # published cryptographic/header byte after the version unchanged; do not
    # derive replacement keys or regenerate expected scripts.
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    def replace(match):
        value = 0
        for char in match[0]:
            value = value * 58 + alphabet.index(char)
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        assert len(raw) == 82 and raw[:4] == bytes.fromhex("0488b21e")
        assert hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]
        payload = bytes.fromhex("043587cf") + raw[4:-4]
        converted = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        value = int.from_bytes(converted, "big")
        result = ""
        while value:
            value, digit = divmod(value, 58)
            result = alphabet[digit] + result
        assert result.startswith("tpub")
        return result
    return re.sub(r"xpub[1-9A-HJ-NP-Za-km-z]+", replace, text)


def check_public_descriptor_vectors(args, port):
    source = Path(__file__).resolve().parents[1] / "crates/primitives/tests/data/descriptors.json"
    count = 0
    threshold_source = source.with_name("taproot-thresholds.json")
    vectors = json.loads(source.read_text())["vectors"] + json.loads(threshold_source.read_text())["published"]
    for vector in vectors:
        original = vector["descriptor"]
        text = regtest_descriptor(original)
        info = core_rpc(port, "getdescriptorinfo", [text])
        assert not info["hasprivatekeys"]
        for index, script in enumerate(vector["scripts"]):
            index = index if info["isrange"] else None
            assert derive_descriptor(args, original, index, network="mainnet")["script_pubkey"] == script
            checked = derive_descriptor(args, text, index)
            assert checked["script_pubkey"] == script
            assert checked["is_ranged"] == info["isrange"]
            assert derive_descriptor(args, f"raw({script})")["script_pubkey"] == script
            output = checked["descriptor"]
            assert core_rpc(port, "getdescriptorinfo", [output])["checksum"] == output.split("#")[1]
            params = [info["descriptor"]] + ([[index, index]] if index is not None else [])
            if checked["address"] is not None:
                assert core_rpc(port, "deriveaddresses", params) == [checked["address"]]
                assert core_rpc(port, "getaddressinfo", [checked["address"]])["scriptPubKey"] == script
                assert derive_descriptor(args, f"addr({checked['address']})")["script_pubkey"] == script
            else:
                try:
                    core_rpc(port, "deriveaddresses", params)
                    raise AssertionError("Core unexpectedly produced a bare-script address")
                except RuntimeError as failure:
                    assert "address" in str(failure).lower()
            count += 1
        if original != text:
            for wrong, network in [(original, "regtest"), (text, "mainnet")]:
                result = subprocess.run([str(args.node), "--json", "--network", network, "derive-descriptor", wrong, "--index", "0"] if info["isrange"] else [str(args.node), "--json", "--network", network, "derive-descriptor", wrong], capture_output=True, text=True, timeout=30)
                assert result.returncode != 0 and "selected network" in result.stderr
    key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    # Independently checked context/count boundaries, including minimally
    # encoded 17..20 multisig integers and the actual P2SH element-size cap.
    for outer, n, k in [("wsh", 20, 17), ("sh", 15, 1), ("sh-wsh", 20, 17)]:
        text = f"multi({k},{','.join([key] * n)})"
        text = f"sh(wsh({text}))" if outer == "sh-wsh" else f"{outer}({text})"
        checked = derive_descriptor(args, text)
        info = core_rpc(port, "getdescriptorinfo", [text])
        assert core_rpc(port, "deriveaddresses", [info["descriptor"]]) == [checked["address"]]
        assert core_rpc(port, "getaddressinfo", [checked["address"]])["scriptPubKey"] == checked["script_pubkey"]
    invalid = ["pk(aa)", "pkh(aa)", "wpkh(aa)", f"sh(sh(pk({key})))", f"wsh(wpkh({key}))", f"wsh(wsh(pk({key})))", f"sh(tr({key}))", f"multi(0,{key})", f"multi(1,{','.join([key] * 4)})", f"sh(multi(1,{','.join([key] * 16)}))", f"wsh(multi(1,{','.join([key] * 21)}))", f"pk([12345]{key})", f"pk({key}/*)"]
    for text in invalid:
        result = subprocess.run([str(args.node), "--json", "derive-descriptor", text], capture_output=True, text=True, timeout=30)
        assert result.returncode != 0 and not result.stdout.strip(), text
        try:
            core_rpc(port, "getdescriptorinfo", [text])
            raise AssertionError(f"Core accepted invalid descriptor: {text}")
        except RuntimeError:
            pass
    print(f"PASSED: {count} published public descriptor scripts, Core addresses/checksums, 3 multisig boundaries and {len(invalid)} shared rejections", flush=True)


def check_funded_descriptor(args, port, address, raw, kind, expected_maps=3, input_index=0):
    # Core exports the actual public descriptor for this funded output.
    info = core_rpc(port, "getaddressinfo", [address])
    checked = derive_descriptor(args, info["desc"])
    assert checked["script_pubkey"] == info["scriptPubKey"] and checked["address"] == address
    maps = psbt_maps(raw, expected_maps)
    records = maps[1 + input_index]
    for key, field in [(b"\x04", "redeem_script"), (b"\x05", "witness_script")]:
        if key in records:
            assert checked[field] == records[key].hex(), (kind, field)
    leaves = {(leaf["control_block"], leaf["script"]) for leaf in checked["tap_leaves"]}
    expected = {(key[1:].hex(), value[:-1].hex()) for key, value in records.items() if key[0] == 0x15}
    assert expected <= leaves, (kind, expected, leaves)
    if b"\x17" in records:
        assert checked["internal_key"] == records[b"\x17"].hex()
    if b"\x18" in records:
        assert checked["merkle_root"] == records[b"\x18"].hex()
    print(f"PASSED: Core {kind} funded descriptor, wrapped scripts and {len(expected)} independent control proofs", flush=True)


def public_xpub_records(port):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    records = {}
    # Public descriptors export the xpub after the hardened account prefix.
    # No seed/private key is needed for the suffix proofs below.
    for entry in core_rpc(port, "listdescriptors", [False])["descriptors"]:
        for fingerprint, path, text in re.findall(r"\[([0-9a-fA-F]{8})([^\]]*)\]((?:xpub|tpub)[1-9A-HJ-NP-Za-km-z]+)", entry["desc"]):
            value = 0
            for character in text:
                value = value * 58 + alphabet.index(character)
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
            assert len(raw) == 82 and hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]
            indices = [int(part.rstrip("h'")) | (0x80000000 if part.endswith(("h", "'")) else 0)
                       for part in path.split("/") if part]
            records[b"\x01" + raw[:-4]] = bytes.fromhex(fingerprint) + b"".join(index.to_bytes(4, "little") for index in indices)
    assert records, "Core public descriptors contain no xpub anchors"
    return records


def reject_derivations(args, raw, reason):
    result = run_cli(args.node, "verify-psbt-derivations", raw)
    assert result.returncode != 0 and reason in result.stderr, result.stderr


def check_key_derivation_proofs(args, port, raw, kind, expected_maps=3):
    maps = psbt_maps(raw, expected_maps)
    maps[0].update(public_xpub_records(port))
    anchored = encode_maps(maps)
    literal = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
    opaque = []
    for position, records in enumerate(maps[1:], 1):
        for key in records:
            if key in [b"\x16" + literal, b"\x07" + literal]:
                opaque.append((position, key))
    if opaque:
        # Core annotates a literal NUMS key too. No xpub can prove its source
        # here; the complete original must fail. Explicitly test only the HD
        # subset after removing those optional opaque origin records.
        reject_derivations(args, anchored, "no supplied global xpub")
        for position, key in opaque:
            maps[position].pop(key)
        anchored = encode_maps(maps)
    decoded = core_rpc(port, "decodepsbt", [encode64(anchored)])
    count = sum(len(fields.get("bip32_derivs", [])) + len(fields.get("taproot_bip32_derivs", []))
                for fields in decoded["inputs"] + decoded["outputs"])
    assert count > 0
    checked = cli(args.node, "verify-psbt-derivations", anchored)
    assert checked["origin_records_checked"] == count
    assert checked["derivation_equations_verified"] is True
    assert checked["derivation_steps_checked"] > 0
    assert checked["verification_scope"] == "public_derivations_from_supplied_xpubs"
    assert all(checked[field] is False for field in ["key_origins_verified", "wallet_ownership_verified", "signatures_verified", "taproot_leaf_membership_verified", "active_chain_verified"])
    converted = cli(args.node, "convert-psbt", anchored, "--version", "2")["psbt_hex"]
    assert cli(args.node, "verify-psbt-derivations", converted) == checked
    # Parsing preserves claims; the separate command proves relative equations.
    # Core decodepsbt accepts changed paths as metadata, not proof of derivation.
    for position, records in enumerate(maps[1:], 1):
        wanted = [6, 0x16] if position <= len(decoded["inputs"]) else [2, 7]
        for key in records:
            if key[0] not in wanted:
                continue
            bad = psbt_maps(anchored, expected_maps)
            data = bad[position][key]
            assert len(data) >= 8
            bad[position][key] = data[:-4] + (int.from_bytes(data[-4:], "little") ^ 1).to_bytes(4, "little")
            corrupted = encode_maps(bad)
            core_rpc(port, "decodepsbt", [encode64(corrupted)])
            reject_derivations(args, corrupted, "no supplied global xpub")
            break
    missing = psbt_maps(anchored, expected_maps)
    missing[0] = {key: value for key, value in missing[0].items() if key[0] != 1}
    reject_derivations(args, encode_maps(missing), "missing global xpub")
    print(f"PASSED: Core {kind} {count} real public derivation proofs, v0/v2 and altered-path rejection; {len(opaque)} unanchored literal records rejected", flush=True)


def reject_spending_data(args, raw, reason):
    for command, extra in [("decode-psbt", []), ("convert-psbt", ["--version", "2"]), ("extract-psbt", []), ("finalize-psbt", [])]:
        result = run_cli(args.node, command, raw, *extra)
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
            verified = cli(args.node, "verify-psbt", restored["psbt_hex"])
            assert verified["tx_hex"] == expected_tx and verified["txid_linked_prevouts"] == [True]
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


def reject_verification(args, raw, reason, partial=False):
    result = run_cli(args.node, "verify-psbt", raw, *(["--partial"] if partial else []))
    assert result.returncode != 0 and reason in result.stderr, result.stderr


def check_partial_verification(args, port, raw):
    decoded = cli(args.node, "decode-psbt", raw)
    fields = decoded["inputs"][0]
    count = fields["partial_signatures"] + fields["tap_script_signatures"] + int(fields["has_tap_key_signature"])
    assert count > 0
    converted = cli(args.node, "convert-psbt", raw, "--version", "2")["psbt_hex"]
    for encoded in [raw, converted]:
        checked = cli(args.node, "verify-psbt", encoded, "--partial")
        assert checked["signatures_verified"] is True and checked["partial_signatures_verified"] is True
        assert checked["signatures_checked"] == count and checked["signatures_per_input"] == [count]
        assert checked["spending_conditions_verified"] is False and checked["final_fields_verified"] is False
        assert checked["active_chain_verified"] is False and checked["key_origins_verified"] is False
        assert checked["taproot_annex_present"] is False and checked["fee_sat"] == 2000
        assert checked["unsigned_tx_hex"] == decoded["unsigned_tx_hex"] and "tx_hex" not in checked
        assert checked["verification_scope"] == "partial_signatures_against_supplied_prevouts"
    maps = psbt_maps(raw)
    records = [key for key in maps[1] if key[0] in (2, 0x13, 0x14)]
    for key in records:
        bad = psbt_maps(raw)
        # Keep numeric/DER encoding and type; change only the signature equation.
        signature = bytearray(bad[1][key]); signature[-2] ^= 1; bad[1][key] = bytes(signature)
        mutated = encode_maps(bad)
        cli(args.node, "decode-psbt", mutated)
        core_rpc(port, "decodepsbt", [encode64(mutated)])
        reject_verification(args, mutated, "signature equation failed", partial=True)
        reject_finalization(args, mutated, "signature equation failed")
        # Core may choose another leaf or ignore an excess multisig signature.
        # Isolate the corrupted leaf, or keep exactly two records for the 2-of-3
        # case, so its bad signature is required by the satisfaction.
        ecdsa_records = [record for record in records if record[0] == 2]
        if key[0] == 2 and len(ecdsa_records) == 3:
            keep = next(record for record in ecdsa_records if record != key)
            for other in ecdsa_records:
                if other not in (key, keep):
                    bad[1].pop(other)
        for other in records:
            if key[0] == 0x14 and other[0] == 0x14 and other != key:
                bad[1].pop(other)
        finalized = core_rpc(port, "finalizepsbt", [encode64(encode_maps(bad))])
        if finalized["complete"]:
            assert core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]["allowed"] is False
        if key[0] in (2, 0x14):
            # A curve-valid key unrelated to the committed script is still
            # invalid, even if the signature record otherwise parses.
            generator = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            bad = psbt_maps(raw); signature = bad[1].pop(key)
            wrong = b"\x02\x02" + generator if key[0] == 2 else b"\x14" + generator + key[33:]
            assert wrong != key
            bad[1][wrong] = signature
            cli(args.node, "decode-psbt", encode_maps(bad))
            reject_verification(args, encode_maps(bad), "does not belong", partial=True)
        if key[0] == 0x14:
            bad = psbt_maps(raw); signature = bad[1].pop(key)
            bad[1][key[:-1] + bytes([key[-1] ^ 1])] = signature
            reject_verification(args, encode_maps(bad), "missing committed Taproot leaf", partial=True)
    # At least one record per unfinalized input is required; absent verification
    # never turns into an empty successful result.
    bad = psbt_maps(raw)
    for key in records:
        bad[1].pop(key)
    reject_verification(args, encode_maps(bad), "missing partial signatures", partial=True)
    for key, reason in [(b"\x04", "missing redeem script"), (b"\x05", "missing witness script")]:
        if key in maps[1]:
            bad = psbt_maps(raw); bad[1].pop(key)
            reject_verification(args, encode_maps(bad), reason, partial=True)
    if any(key[0] == 0x14 for key in records):
        bad = psbt_maps(raw)
        for key in [key for key in bad[1] if key[0] == 0x15]:
            bad[1].pop(key)
        reject_verification(args, encode_maps(bad), "missing committed Taproot leaf", partial=True)
    if len([key for key in records if key[0] == 2]) == 2:
        bad = psbt_maps(raw); bad[1].pop(next(key for key in records if key[0] == 2))
        incomplete = encode_maps(bad)
        checked = cli(args.node, "verify-psbt", incomplete, "--partial")
        assert checked["signatures_checked"] == 1 and checked["spending_conditions_verified"] is False
        assert core_rpc(port, "finalizepsbt", [encode64(incomplete)])["complete"] is False
        reject_finalization(args, incomplete, "insufficient multisig signatures")


def reject_finalization(args, raw, reason):
    result = run_cli(args.node, "finalize-psbt", raw)
    assert result.returncode != 0, (reason, result.stdout)
    assert reason in result.stderr, (reason, result.stderr)
    assert not result.stdout.strip(), result.stdout


def check_automatic_finalization(args, port, raw, expected_tx, expected_maps=3):
    maps = psbt_maps(raw, expected_maps)
    # Reverse wire order and add opaque updater data. Finalization must order
    # signatures by script keys and retain unknown fields without interpreting them.
    for index, records in enumerate(maps):
        maps[index] = dict(reversed(list(records.items())))
        maps[index][b"\x50"] = bytes([index, 42])
    raw = encode_maps(maps)
    for encoded in [raw, cli(args.node, "convert-psbt", raw, "--version", "2")["psbt_hex"]]:
        before = psbt_maps(encoded, expected_maps)
        result = cli(args.node, "finalize-psbt", encoded)
        assert result["complete"] and result["spending_conditions_verified"] and result["signatures_verified"]
        assert result["partial_signatures_verified"]
        assert result["active_chain_verified"] is False and result["key_origins_verified"] is False
        assert result["tx_hex"] == expected_tx, (result["tx_hex"], expected_tx)
        after = psbt_maps(result["psbt_hex"], expected_maps)
        assert before[0] == after[0] and before[-1] == after[-1]
        counts = []
        for original, cleaned in zip(before[1:-1], after[1:-1], strict=True):
            counts.append(sum(key[0] in (2, 0x13, 0x14) for key in original))
            retained = {0, 1, 7, 8, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x50}
            assert all(key[0] in retained for key in cleaned), cleaned
            assert cleaned[b"\x50"] == original[b"\x50"]
            for key in [b"\x00", b"\x01", b"\x11", b"\x12"]:
                assert original.get(key) == cleaned.get(key)
        assert result["partial_signatures_per_input"] == counts
        assert result["partial_signatures_checked"] == sum(counts)
        verified = cli(args.node, "verify-psbt", result["psbt_hex"])
        assert verified["tx_hex"] == expected_tx
        assert verified["signatures_checked"] == result["signatures_checked"]
        repeated = cli(args.node, "finalize-psbt", result["psbt_hex"])
        assert repeated["psbt_hex"] == result["psbt_hex"] and repeated["partial_signatures_checked"] == 0
        restored = cli(args.node, "convert-psbt", result["psbt_hex"], "--version", "0")["psbt_hex"]
        assert core_rpc(port, "finalizepsbt", [encode64(restored)])["hex"] == expected_tx
        assert core_rpc(port, "testmempoolaccept", [[result["tx_hex"]]])[0]["allowed"] is True
    # A scalar-encoding-valid bad equation must fail before final fields or
    # cleaned metadata are returned, even if another leaf/signature can satisfy it.
    for key, signature in maps[1].items():
        if key[0] in (2, 0x13, 0x14):
            bad = psbt_maps(raw, expected_maps)
            changed = bytearray(signature)
            changed[10 if key[0] == 2 else 63] ^= 1
            bad[1][key] = bytes(changed)
            reject_finalization(args, encode_maps(bad), "partial signature equation failed")
    return result["tx_hex"]


def witness_items(data):
    stream = io.BytesIO(data)
    def size():
        prefix = stream.read(1)[0]
        return prefix if prefix < 253 else int.from_bytes(stream.read({253:2,254:4,255:8}[prefix]), "little")
    result = [stream.read(size()) for _ in range(size())]
    assert stream.read() == b""
    return result


def encoded_witness(items):
    return compact_size(len(items)) + b"".join(compact_size(len(item)) + item for item in items)


def check_final_verification(args, port, raw, expected_tx, signatures=1):
    verified = cli(args.node, "verify-psbt", raw)
    assert verified["tx_hex"] == expected_tx
    assert verified["signatures_verified"] is True and verified["spending_conditions_verified"] is True
    assert verified["signatures_checked"] == signatures
    assert verified["active_chain_verified"] is False and verified["partial_signatures_verified"] is False
    assert verified["verification_scope"] == "finalized_spends_against_supplied_prevouts"
    assert verified["fee_sat"] == 2000
    assert core_rpc(port, "testmempoolaccept", [[verified["tx_hex"]]])[0]["allowed"] is True
    # A signature with unchanged encoding but a different scalar must fail the
    # real equation, even though decoding and unchecked extraction still work.
    bad = psbt_maps(raw)
    if b"\x08" in bad[1]:
        items = witness_items(bad[1][b"\x08"])
        slot = next(i for i, item in enumerate(items) if item)
        sig = bytearray(items[slot]); sig[-2] ^= 1; items[slot] = bytes(sig)
        bad[1][b"\x08"] = encoded_witness(items)
    else:
        script = bytearray(bad[1][b"\x07"])
        offset = 1 if script[0] == 0 else 0  # legacy multisig dummy
        assert 9 <= script[offset] <= 73
        script[offset + script[offset] - 1] ^= 1
        bad[1][b"\x07"] = bytes(script)
    mutated = encode_maps(bad)
    cli(args.node, "decode-psbt", mutated)
    extracted = cli(args.node, "extract-psbt", mutated)
    reject_verification(args, mutated, "spending verification failed")
    assert core_rpc(port, "testmempoolaccept", [[extracted["tx_hex"]]])[0]["allowed"] is False
    # Declared types in final PSBTs are opaque to decode/extract, but the new
    # verifier binds them to the actual signatures it evaluates.
    bad = psbt_maps(raw)
    if b"\x08" in bad[1]:
        original_sig = next(item for item in witness_items(bad[1][b"\x08"]) if item)
    else:
        script = bad[1][b"\x07"]
        offset = 1 if script[0] == 0 else 0
        original_sig = script[offset + 1:offset + 1 + script[offset]]
    taproot = cli(args.node, "decode-psbt", raw)["inputs"][0]["utxo"]["script_pubkey"].startswith("5120")
    original_type = 0 if taproot and len(original_sig) == 64 else original_sig[-1]
    bad[1][b"\x03"] = (2 if original_type != 2 else 1).to_bytes(4,"little")
    reject_verification(args, encode_maps(bad), "declared sighash")
    # Locktime is covered by every defined sighash mode.
    bad = psbt_maps(raw)
    unsigned = bytearray(bad[0][b"\x00"]); unsigned[-4] ^= 1; bad[0][b"\x00"] = bytes(unsigned)
    reject_verification(args, encode_maps(bad), "spending verification failed")
    bad = psbt_maps(raw)
    bad[1].pop(b"\x00", None); bad[1].pop(b"\x01", None)
    reject_verification(args, encode_maps(bad), "missing UTXO")


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
    if kind in ["bech32m", "taproot-script", "taproot-multisig-2of3"]:
        names.insert(0, ("DEFAULT",0))
    for name, hash_type in names:
        result = core_rpc(port, "walletprocesspsbt", [unsigned, True, name, True, False])
        # finalize=False intentionally keeps partial records; Core's complete
        # status can be false until they have been finalized. Require the real
        # signature records and independently validated final transaction below.
        maps = psbt_maps(base64.b64decode(result["psbt"]).hex())
        maps[1][b"\x03"] = hash_type.to_bytes(4, "little")
        raw = encode_maps(maps)
        check_partial_verification(args, port, raw)
        finalized = core_rpc(port, "finalizepsbt", [encode64(raw)])
        assert finalized["complete"] is True, (kind, name)
        assert core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]["allowed"] is True
        check_automatic_finalization(args, port, raw, finalized["hex"])
        final_psbt = core_rpc(port, "finalizepsbt", [encode64(raw), False])["psbt"]
        check_final_verification(args, port, base64.b64decode(final_psbt).hex(), finalized["hex"],
                                 2 if kind == "taproot-multisig-2of3" else 1)
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


def check_threshold_satisfactions(args, port, unsigned, raw, kind):
    maps = psbt_maps(raw)
    keys = [key for key in maps[1] if key[0] == 0x14]
    n, threshold = (20, 17) if kind.endswith("17of20") else (3, 2)
    assert len(keys) == n
    leaf = next(value[:-1] for key, value in maps[1].items() if key[0] == 0x15)
    assert len(leaf) == n * 34 + (3 if threshold > 16 else 2)
    subsets = range(1, 8) if n == 3 else [(1 << 16) - 1, (1 << 17) - 1, (1 << 20) - 1]
    for bits in subsets:
        subset = psbt_maps(raw)
        for i, key in enumerate(keys):
            if not (bits >> i) & 1:
                subset[1].pop(key)
        encoded = encode_maps(subset)
        partial = cli(args.node, "verify-psbt", encoded, "--partial")
        assert partial["signatures_checked"] == bits.bit_count()
        assert partial["spending_conditions_verified"] is False
        independent = core_rpc(port, "finalizepsbt", [encode64(encoded)])
        assert independent["complete"] == (bits.bit_count() >= threshold)
        if independent["complete"]:
            check_automatic_finalization(args, port, encoded, independent["hex"])
            final = cli(args.node, "finalize-psbt", encoded)
            assert final["signatures_checked"] == threshold
            witness = core_rpc(port, "decoderawtransaction", [final["tx_hex"]])["vin"][0]["txinwitness"]
            assert len(witness) == n + 2 and sum(bool(item) for item in witness[:n]) == threshold
            # Empty placeholders are mandatory, and swapping the populated
            # slots changes the key under which an equation executes.
            final_maps = psbt_maps(final["psbt_hex"])
            for change in ["missing-slot", "wrong-order", "excess-signature"]:
                bad = psbt_maps(encode_maps(final_maps))
                stack = witness_items(bad[1][b"\x08"])
                populated = [i for i in range(n) if stack[i]]
                empty = [i for i in range(n) if not stack[i]]
                if change == "missing-slot":
                    stack.pop(0)
                elif change == "wrong-order":
                    a, b = populated[:2]; stack[a], stack[b] = stack[b], stack[a]
                elif empty:
                    stack[empty[0]] = stack[populated[0]]
                else:
                    continue
                bad[1][b"\x08"] = encoded_witness(stack)
                reason = {"missing-slot": "invalid tapscript witness slots", "wrong-order": "spending verification failed",
                          "excess-signature": "invalid tapscript signature threshold"}[change]
                reject_verification(args, encode_maps(bad), reason)
                tx = cli(args.node, "extract-psbt", encode_maps(bad))["tx_hex"]
                assert core_rpc(port, "testmempoolaccept", [[tx]])[0]["allowed"] is False
        else:
            reject_finalization(args, encoded, "missing supported Taproot script satisfaction")
    # All equations remain valid with mixed DEFAULT/ALL signatures. Selection
    # must minimize actual witness bytes, including the >252-byte leaf prefix.
    default = core_rpc(port, "walletprocesspsbt", [unsigned, True, "DEFAULT", True, False])["psbt"]
    defaults = psbt_maps(base64.b64decode(default).hex())
    mixed = psbt_maps(raw); mixed[1].pop(b"\x03", None)
    script_keys = [leaf[i * 34 + 1:i * 34 + 33] for i in range(n)]
    for key in keys:
        if script_keys.index(key[1:33]) >= (4 if n == 20 else 1):
            mixed[1][key] = defaults[1][key]
    encoded = encode_maps(mixed)
    independent = core_rpc(port, "finalizepsbt", [encode64(encoded)])
    assert independent["complete"]
    check_automatic_finalization(args, port, encoded, independent["hex"])
    declared = psbt_maps(encoded); declared[1][b"\x03"] = bytes(4)
    reject_spending_data(args, encode_maps(declared), "sighash")
    print(f"PASSED: Core {kind} threshold subsets, invalid witness slots, mixed signature lengths and exact final bytes", flush=True)


def check_large_threshold_wallet(args, port, kind, pair):
    threshold, n = map(int, kind.rsplit("-", 1)[1].split("of"))
    address, destination = pair
    core_rpc(port, "generatetoaddress", [101, address], timeout=30)
    coin = next(c for c in core_rpc(port, "listunspent", [100]) if c["address"] == address)
    unsigned = core_rpc(port, "createpsbt", [[{"txid": coin["txid"], "vout": coin["vout"], "sequence": 0xfffffffd}],
                                             {destination: round(coin["amount"] - 0.0005, 8)}, 23])
    started = time.monotonic()
    print(f"RUNNING: Core {kind} large wallet signer", flush=True)
    signed = core_rpc(port, "walletprocesspsbt", [unsigned, True, "ALL", True, False], timeout=180)["psbt"]
    print(f"SIGNED: Core {kind} in {time.monotonic() - started:.1f}s", flush=True)
    raw = base64.b64decode(signed).hex()
    assert len(raw) > 60_000  # force actual compiled binary-file input
    check_funded_descriptor(args, port, address, raw, kind)
    check_key_derivation_proofs(args, port, raw, kind)
    maps = psbt_maps(raw)
    keys = [key for key in maps[1] if key[0] == 0x14]
    assert len(keys) == n
    independent = core_rpc(port, "finalizepsbt", [signed], timeout=180)
    assert independent["complete"]
    for version in [0, 2]:
        encoded = raw if version == 0 else cli(args.node, "convert-psbt", raw, "--version", "2")["psbt_hex"]
        partial = cli(args.node, "verify-psbt", encoded, "--partial")
        assert partial["signatures_checked"] == n and partial["spending_conditions_verified"] is False
        result = cli(args.node, "finalize-psbt", encoded)
        assert result["tx_hex"] == independent["hex"]
        assert result["partial_signatures_checked"] == n and result["signatures_checked"] == threshold
        final = cli(args.node, "verify-psbt", result["psbt_hex"])
        assert final["tx_hex"] == independent["hex"] and final["fee_sat"] == 50_000
        assert final["active_chain_verified"] is False
        witness = witness_items(psbt_maps(result["psbt_hex"])[1][b"\x08"])
        assert len(witness) == n + 2 and sum(bool(item) for item in witness[:n]) == threshold
        assert len(witness[-2]) == n * 34 + (2 if threshold <= 16 else 4)
        assert core_rpc(port, "testmempoolaccept", [[final["tx_hex"]]])[0]["allowed"] is True
    # Real signatures at the beginning/middle/end all need to verify, including
    # hundreds of unselected records in the sorted 2-of-999 spend.
    for i in [0, n // 2, n - 1]:
        bad = psbt_maps(raw); sig = bytearray(bad[1][keys[i]]); sig[63] ^= 1; bad[1][keys[i]] = bytes(sig)
        reject_verification(args, encode_maps(bad), "partial signature equation failed", partial=True)
        reject_finalization(args, encode_maps(bad), "partial signature equation failed")
    insufficient = psbt_maps(raw)
    for key in keys[threshold - 1:]:
        insufficient[1].pop(key)
    partial = cli(args.node, "verify-psbt", encode_maps(insufficient), "--partial")
    assert partial["signatures_checked"] == threshold - 1
    assert core_rpc(port, "finalizepsbt", [encode64(encode_maps(insufficient))], timeout=180)["complete"] is False
    reject_finalization(args, encode_maps(insufficient), "missing supported Taproot script satisfaction")
    # A populated witness is never allowed to omit one of its key slots.
    final_maps = psbt_maps(result["psbt_hex"])
    witness = witness_items(final_maps[1][b"\x08"]); witness.pop(0)
    final_maps[1][b"\x08"] = encoded_witness(witness)
    damaged = encode_maps(final_maps)
    reject_verification(args, damaged, "invalid tapscript witness slots")
    tx = cli(args.node, "extract-psbt", damaged)["tx_hex"]
    assert core_rpc(port, "testmempoolaccept", [[tx]])[0]["allowed"] is False
    core_rpc(port, "sendrawtransaction", [independent["hex"]])
    core_rpc(port, "generatetoaddress", [1, address])
    print(f"PASSED: Core {kind} {n} real keys/signatures, binary file tools, exact v0/v2 final bytes, insufficient/corrupt rejection and mined spend", flush=True)


def check_wallet(args, port, kind, script_pair=None):
    if kind.startswith("taproot-") or kind in ["wsh", "sh-wsh", "wsh-multisig", "sh-wsh-multisig", "wsh-multisig-2of3"]:
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
    if kind in ["legacy", "bech32", "bech32m", "taproot-script", "taproot-multisig-2of3"]:
        check_signed_sighash_variants(args, port, original, kind)
    # Keep the real signatures/derivations in the PSBT for the conversion check.
    signed = core_rpc(port, "walletprocesspsbt", [original, True, "ALL", True, False])["psbt"]
    original_hex = base64.b64decode(signed, validate=True).hex()
    reject_verification(args, original_hex, "not finalized")
    decoded = cli(args.node, "decode-psbt", original_hex)
    check_funded_descriptor(args, port, address, original_hex, kind)
    check_key_derivation_proofs(args, port, original_hex, kind)
    check_partial_verification(args, port, original_hex)
    independent = core_rpc(port, "decodepsbt", [signed])
    assert decoded["unsigned_txid"] == independent["tx"]["txid"]
    assert decoded["locktime"] == independent["tx"]["locktime"] == 23
    assert decoded["signatures_verified"] is False
    check_taproot_metadata(decoded, independent)
    check_key_substitutions(args, port, original_hex)
    if "taproot-" in kind and "multisig" in kind:
        check_threshold_satisfactions(args, port, original, original_hex, kind)
    if kind == "wsh-multisig-2of3":
        assert decoded["inputs"][0]["partial_signatures"] == 3
        incomplete = psbt_maps(original_hex)
        keys = [key for key in incomplete[1] if key[0] == 2]
        for key in keys[1:]:
            incomplete[1].pop(key)
        encoded = encode_maps(incomplete)
        assert core_rpc(port, "finalizepsbt", [encode64(encoded)])["complete"] is False
        reject_finalization(args, encoded, "insufficient multisig signatures")
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
    if kind == "taproot-unbalanced":
        assert decoded["inputs"][0]["tap_script_signatures"] == 3
        assert sorted(len(bytes.fromhex(leaf["control_block"])) for leaf in decoded["inputs"][0]["tap_leaf_scripts"]) == [65, 97, 97]
        witness = core_rpc(port, "decoderawtransaction", [expected["hex"]])["vin"][0]["txinwitness"]
        assert len(bytes.fromhex(witness[-1])) == 65
    if kind == "taproot-threshold-unbalanced":
        # More deeply nested pk leaves have cheaper complete witnesses than
        # the shallower 2-of-3 threshold. Compare the whole serialized witness.
        assert decoded["inputs"][0]["tap_script_signatures"] == 5
        witness = core_rpc(port, "decoderawtransaction", [expected["hex"]])["vin"][0]["txinwitness"]
        assert len(witness) == 3 and len(bytes.fromhex(witness[-1])) == 97
    accepted = core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]
    assert accepted["allowed"] is True, accepted
    # Already-finalized witnesses must survive the same conversion as well.
    final_psbt = core_rpc(port, "finalizepsbt", [signed, False])["psbt"]
    final_hex = base64.b64decode(final_psbt, validate=True).hex()
    check_spending_data(args, port, original_hex, final_hex, coin, expected["hex"])
    rust_final_tx = check_automatic_finalization(args, port, original_hex, expected["hex"])
    count = 17 if kind.endswith("17of20") else 2 if "multisig" in kind else 1
    check_final_verification(args, port, final_hex, expected["hex"], count)
    v2_final = cli(args.node, "convert-psbt", final_hex, "--version", "2")
    final_restored = cli(args.node, "convert-psbt", v2_final["psbt_hex"], "--version", "0")
    assert core_rpc(port, "finalizepsbt", [encode64(final_restored["psbt_hex"])])["hex"] == expected["hex"]
    for encoded in [final_hex, v2_final["psbt_hex"], final_restored["psbt_hex"]]:
        extracted = cli(args.node, "extract-psbt", encoded)
        assert extracted["tx_hex"] == expected["hex"]
        assert extracted["signatures_verified"] is False
        verified = cli(args.node, "verify-psbt", encoded)
        assert verified["tx_hex"] == expected["hex"] and verified["signatures_verified"] is True
        assert core_rpc(port, "testmempoolaccept", [[extracted["tx_hex"]]])[0]["allowed"] is True
    core_rpc(port, "sendrawtransaction", [rust_final_tx])
    core_rpc(port, "generatetoaddress", [1, address])
    # Trailing bytes are rejected at the actual binary boundary.
    malformed = subprocess.run([str(args.node), "--json", "decode-psbt", original_hex + "00"],
                               capture_output=True, text=True, timeout=30)
    assert malformed.returncode != 0
    print(f"PASSED: Core v29 {kind} real signed/finalized PSBT v0 -> v2 -> v0", flush=True)


def check_two_input_taproot_verification(args, port):
    address = core_rpc(port, "getnewaddress", ["", "bech32m"])
    destination = core_rpc(port, "getnewaddress", ["", "bech32m"])
    core_rpc(port, "generatetoaddress", [102, address], timeout=30)
    coins = [coin for coin in core_rpc(port, "listunspent", [100]) if coin["address"] == address][:2]
    assert len(coins) == 2
    original = core_rpc(port, "createpsbt", [[{"txid": coin["txid"], "vout": coin["vout"], "sequence": 0xfffffffd} for coin in coins],
                                            {destination: round(sum(coin["amount"] for coin in coins) - 0.00002, 8)}, 23])
    signed = core_rpc(port, "walletprocesspsbt", [original, True, "DEFAULT", True, False])["psbt"]
    partial_hex = base64.b64decode(signed).hex()
    check_funded_descriptor(args, port, address, partial_hex, "two-input Taproot", expected_maps=4)
    check_key_derivation_proofs(args, port, partial_hex, "two-input Taproot", expected_maps=4)
    for encoded in [partial_hex, cli(args.node, "convert-psbt", partial_hex, "--version", "2")["psbt_hex"]]:
        checked = cli(args.node, "verify-psbt", encoded, "--partial")
        assert checked["signatures_per_input"] == [1, 1] and checked["signatures_checked"] == 2
        assert checked["spending_conditions_verified"] is False
    bad = psbt_maps(partial_hex, expected_maps=4)
    amount = bad[2][b"\x01"]
    bad[2][b"\x01"] = (int.from_bytes(amount[:8],"little") + 1).to_bytes(8,"little") + amount[8:]
    reject_verification(args, encode_maps(bad), "input 0: partial verification failed", partial=True)
    bad = psbt_maps(partial_hex, expected_maps=4); bad[2].pop(b"\x01")
    reject_verification(args, encode_maps(bad), "input 1: missing UTXO", partial=True)
    expected = core_rpc(port, "finalizepsbt", [signed])
    assert expected["complete"] is True
    rust_final_tx = check_automatic_finalization(args, port, partial_hex, expected["hex"], expected_maps=4)
    raw = base64.b64decode(core_rpc(port, "finalizepsbt", [signed, False])["psbt"]).hex()
    final_maps = psbt_maps(cli(args.node, "finalize-psbt", partial_hex)["psbt_hex"], expected_maps=4)
    mixed = psbt_maps(partial_hex, expected_maps=4)
    mixed[1] = final_maps[1]
    mixed_result = cli(args.node, "finalize-psbt", encode_maps(mixed))
    assert mixed_result["tx_hex"] == expected["hex"] and mixed_result["partial_signatures_per_input"] == [0, 1]
    damaged = psbt_maps(encode_maps(mixed), expected_maps=4)
    witness = witness_items(damaged[1][b"\x08"])
    sig = bytearray(witness[0]); sig[63] ^= 1; witness[0] = bytes(sig)
    damaged[1][b"\x08"] = encoded_witness(witness)
    reject_finalization(args, encode_maps(damaged), "spending verification failed")
    v2 = cli(args.node, "convert-psbt", raw, "--version", "2")["psbt_hex"]
    for encoded in [raw, v2]:
        verified = cli(args.node, "verify-psbt", encoded)
        assert verified["tx_hex"] == expected["hex"] and verified["signatures_checked"] == 2
        assert verified["fee_sat"] == 2000 and verified["txid_linked_prevouts"] == [False, False]
        assert core_rpc(port, "testmempoolaccept", [[verified["tx_hex"]]])[0]["allowed"] is True
    # Mutating only the second supplied amount must invalidate the first
    # signature's BIP341 digest: verification has to supply every prevout.
    bad = psbt_maps(raw, expected_maps=4)
    amount = bad[2][b"\x01"]
    bad[2][b"\x01"] = (int.from_bytes(amount[:8],"little") + 1).to_bytes(8,"little") + amount[8:]
    reject_verification(args, encode_maps(bad), "input 0: spending verification failed")
    bad = psbt_maps(raw, expected_maps=4); bad[2].pop(b"\x01")
    reject_verification(args, encode_maps(bad), "input 1: missing UTXO")
    core_rpc(port, "sendrawtransaction", [rust_final_tx])
    core_rpc(port, "generatetoaddress", [1, address])
    print("PASSED: Core two-input Taproot final verification and cross-input prevout substitution rejection", flush=True)


def check_legacy_multisig_partials(args, port, addresses):
    address, destination = addresses
    core_rpc(port, "generatetoaddress", [101, address], timeout=30)
    coin = next(coin for coin in core_rpc(port, "listunspent", [100]) if coin["address"] == address)
    original = core_rpc(port, "createpsbt", [[{"txid": coin["txid"], "vout": coin["vout"], "sequence": 0xfffffffd}],
                                           {destination: round(coin["amount"] - 0.00002, 8)}, 23])
    signed = core_rpc(port, "walletprocesspsbt", [original, True, "ALL", True, False])["psbt"]
    raw = base64.b64decode(signed).hex()
    check_funded_descriptor(args, port, address, raw, "legacy P2SH multisig")
    check_key_derivation_proofs(args, port, raw, "legacy P2SH multisig")
    check_partial_verification(args, port, raw)
    finalized = core_rpc(port, "finalizepsbt", [signed])
    assert finalized["complete"] is True
    rust_final_tx = check_automatic_finalization(args, port, raw, finalized["hex"])
    assert core_rpc(port, "testmempoolaccept", [[finalized["hex"]]])[0]["allowed"] is True
    final_psbt = core_rpc(port, "finalizepsbt", [signed, False])["psbt"]
    final_raw = base64.b64decode(final_psbt).hex()
    check_final_verification(args, port, final_raw, finalized["hex"], signatures=2)
    v2 = cli(args.node, "convert-psbt", final_raw, "--version", "2")["psbt_hex"]
    assert cli(args.node, "verify-psbt", v2)["tx_hex"] == finalized["hex"]
    # Bare witness-UTXO claims cannot make a legacy signature authenticate an amount.
    fields = cli(args.node, "decode-psbt", raw)["inputs"][0]["utxo"]
    script = bytes.fromhex(fields["script_pubkey"])
    bad = psbt_maps(raw); bad[1].pop(b"\x00")
    bad[1][b"\x01"] = fields["value_sat"].to_bytes(8,"little") + compact_size(len(script)) + script
    reject_verification(args, encode_maps(bad), "legacy verification requires non-witness UTXO", partial=True)
    core_rpc(port, "sendrawtransaction", [rust_final_tx])
    core_rpc(port, "generatetoaddress", [1, address])
    print("PASSED: Core legacy P2SH multisig partial equations, incomplete threshold and unsafe amount rejection", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path("target/release/btc-node"))
    parser.add_argument("--large-only", action="store_true", help="Run only the large threshold acceptance surfaces")
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
                                     "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002", "-keypool=2"],
                                    stdout=log, stderr=log)
            try:
                wait_until(lambda: core_rpc(port, "getblockchaininfo", []))
                core_rpc(port, "createwallet", ["psbt-interop"])
                # Import before mining: only genesis needs scanning, and all
                # subsequent test coins are observed as their blocks arrive.
                # Read the original private roots before importing the NUMS
                # descriptor: its deliberately unknown internal secret cannot
                # be exported by listdescriptors(private=true).
                descriptors = core_rpc(port, "listdescriptors", [True])["descriptors"]
                script_kinds = ["wsh", "sh-wsh", "taproot-script", "taproot-unbalanced", "wsh-multisig", "sh-wsh-multisig", "sh-multisig", "wsh-multisig-2of3",
                                             "taproot-multisig-2of3", "taproot-sortedmultisig-2of3", "taproot-multisig-17of20", "taproot-threshold-unbalanced",
                                             "taproot-large-2of999", "taproot-large-128of128", "taproot-large-999of999"]
                if args.large_only:
                    script_kinds = [kind for kind in script_kinds if kind.startswith("taproot-large-")]
                script_pairs = {kind: script_addresses(port, kind, descriptors) for kind in script_kinds}
                if not args.large_only:
                    check_public_descriptor_vectors(args, port)
                    check_published_taproot_vectors(args, port)
                    check_published_spending_vectors(args, port)
                    check_published_key_vectors(args, port)
                    check_published_signature_vectors(args, port)
                    check_published_commitment_vectors(args, port)
                    for kind in ["legacy", "p2sh-segwit", "bech32", "wsh", "sh-wsh", "bech32m", "taproot-script", "taproot-unbalanced", "wsh-multisig", "sh-wsh-multisig", "wsh-multisig-2of3",
                                 "taproot-multisig-2of3", "taproot-sortedmultisig-2of3", "taproot-multisig-17of20", "taproot-threshold-unbalanced"]:
                        check_wallet(args, port, kind, script_pairs.get(kind))
                    check_two_input_taproot_verification(args, port)
                    check_legacy_multisig_partials(args, port, script_pairs["sh-multisig"])
                for kind in ["taproot-large-2of999", "taproot-large-128of128", "taproot-large-999of999"]:
                    check_large_threshold_wallet(args, port, kind, script_pairs[kind])
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
