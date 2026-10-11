#!/usr/bin/env python3
"""Check compiled CLI v0/v2 PSBT conversion with independently signed Core v29.

Uses a checksum-verified bitcoind, disposable regtest wallet, no peer discovery,
and real mature SegWit/Taproot coins. Core finalizes and checks the converted
transactions; the Rust converter does not claim to verify or create signatures.
"""
import argparse
import base64
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
        records[entry["pubkey"]] = (entry["master_fingerprint"], path, sorted(entry["leaf_hashes"]))
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


def taproot_script_addresses(port):
    # The BIP341 NUMS point has no known secret; the wallet must spend a leaf.
    nums = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    descriptors = core_rpc(port, "listdescriptors", [True])["descriptors"]
    original = next(d["desc"] for d in descriptors
                    if d["active"] and not d["internal"] and d["desc"].startswith("tr("))
    key = original.split("#")[0][3:-1]
    assert key.endswith("/0/*")
    second = key[:-4] + "/1/*"
    private = f"tr({nums},{{pk({key}),pk({second})}})"
    info = core_rpc(port, "getdescriptorinfo", [private])
    checked_private = private + "#" + info["checksum"]
    imported = core_rpc(port, "importdescriptors", [[{
        "desc": checked_private, "timestamp": "now", "range": [0, 10],
    }]])
    assert all(item["success"] for item in imported), imported
    # These wallet root keys include hardened paths; their public serialization
    # cannot derive those paths. Core derives the test addresses with its private keys.
    return core_rpc(port, "deriveaddresses", [checked_private, [0, 1]])


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


def check_wallet(args, port, kind):
    if kind == "taproot-script":
        address, destination = taproot_script_addresses(port)
    else:
        address = core_rpc(port, "getnewaddress", ["", kind])
        destination = core_rpc(port, "getnewaddress", ["", kind])
    core_rpc(port, "generatetoaddress", [101, address])
    coins = [coin for coin in core_rpc(port, "listunspent", [100]) if coin["address"] == address]
    assert coins, f"no mature {kind} coin"
    coin = coins[0]
    original = core_rpc(port, "createpsbt", [[{"txid": coin["txid"], "vout": coin["vout"],
                                               "sequence": 0xfffffffd}],
                                             {destination: round(coin["amount"] - 0.00002, 8)}, 23])
    # Keep the real signatures/derivations in the PSBT for the conversion check.
    signed = core_rpc(port, "walletprocesspsbt", [original, True, "ALL", True, False])["psbt"]
    original_hex = base64.b64decode(signed, validate=True).hex()
    decoded = cli(args.node, "decode-psbt", original_hex)
    independent = core_rpc(port, "decodepsbt", [signed])
    assert decoded["unsigned_txid"] == independent["tx"]["txid"]
    assert decoded["locktime"] == independent["tx"]["locktime"] == 23
    assert decoded["signatures_verified"] is False
    check_taproot_metadata(decoded, independent)
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
                check_published_taproot_vectors(args, port)
                for kind in ["bech32", "bech32m", "taproot-script"]:
                    check_wallet(args, port, kind)
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
