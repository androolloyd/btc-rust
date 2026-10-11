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


def check_wallet(args, port, kind):
    address = core_rpc(port, "getnewaddress", ["", kind])
    core_rpc(port, "generatetoaddress", [101, address])
    coins = [coin for coin in core_rpc(port, "listunspent", [100]) if coin["address"] == address]
    assert coins, f"no mature {kind} coin"
    coin = coins[0]
    destination = core_rpc(port, "getnewaddress", ["", kind])
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
                for kind in ["bech32", "bech32m"]:
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
