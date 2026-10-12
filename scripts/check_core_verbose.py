#!/usr/bin/env python3
"""Compare actual verbose runtime RPC with released Core v29 on private regtest.

Core signs a mixed legacy/nested/v0/Taproot spend and its same-block child.
Both nodes validate the same real blocks, fork, restore the pool and restart.
Output script/descriptor/disassembly cases are carried by a validated coinbase.
No synthetic provider, wallet secret export or self-roundtrip oracle is used.
"""
import argparse
from io import BytesIO
import json
import math
from pathlib import Path
import subprocess
import tempfile

from check_core_http import http_rpc
from check_core_p2p import core_rpc, reserve_ports, wait_until
from core29_tapscript import reference


def scripts(key, script):
    secret = key.ECKey(); secret.set(bytes.fromhex("11" * 32), True)
    public = secret.get_pubkey().get_bytes()
    uncompressed = key.ECKey(); uncompressed.set(bytes.fromhex("11" * 32), False)
    full = uncompressed.get_pubkey().get_bytes()
    result = [b"", bytes([script.OP_TRUE]), bytes([script.OP_RETURN]),
              bytes(script.CScript([public, script.OP_CHECKSIG])),
              bytes(script.CScript([full, script.OP_CHECKSIG])),
              bytes(script.CScript([1, public, full, 2, script.OP_CHECKMULTISIG])),
              bytes(script.CScript([17] + [public] * 20 + [20, script.OP_CHECKMULTISIG])),
              bytes(script.CScript([script.OP_DUP, script.OP_HASH160, bytes(20), script.OP_EQUALVERIFY, script.OP_CHECKSIG])),
              bytes(script.CScript([script.OP_HASH160, bytes(20), script.OP_EQUAL])),
              bytes(script.CScript([0, bytes(20)])), bytes(script.CScript([0, bytes(32)])),
              bytes(script.CScript([1, public[1:]])), bytes(script.CScript([1, bytes.fromhex("ff" * 32)])),
              bytes(script.CScript([1, b"\x4e\x73"])), bytes(script.CScript([2, b"\x4e\x73"])),
              bytes(script.CScript([16, bytes(40)])), bytes(script.CScript([0, b"\x4e\x73"])),
              bytes(script.CScript([script.OP_RETURN, b"\x80", b"\xff" * 4, b"abcde"])),
              b"\x6a\x76", b"\x6a\x4c", b"\x51\x4d\x00", b"\x51\x4e\xff\xff\xff\xff",
              b"\x4c\x00\x01\x80\x4f\xff\xbc", b"\x21\x02" + bytes.fromhex("ff" * 32) + b"\xac",
              bytes(script.CScript([1, b"\x02" + bytes.fromhex("ff" * 32), 1, script.OP_CHECKMULTISIG])),
              b"\x51\x4c\x21" + public + b"\x51\xae", bytes(10_001)]
    # Independently classify every opcode, including unknowns and push errors.
    result += [bytes([script.OP_RETURN, op]) for op in range(256)]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1] / "target/release/btc-node")
    args = parser.parse_args(); args.bitcoind = args.bitcoind.resolve(); args.node = args.node.resolve()
    key, script, messages = reference()
    reservations = [reserve_ports(), reserve_ports(), reserve_ports(3), reserve_ports()]
    core_port, core_p2p, rust_port, rust_p2p = [entry.port for entry in reservations]
    with tempfile.TemporaryDirectory(prefix="btc-verbose-core-") as directory:
        root = Path(directory); (root / "core").mkdir(); (root / "rust").mkdir()
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                reservations[0].close(); reservations[1].close()
                core = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={root / 'core'}", "-server", "-listen=0",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1", "-keypool=2", "-txindex=1",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcuser=interop", "-rpcpassword=regtest-only",
                    "-fallbackfee=0.00002", f"-port={core_p2p}"], stdout=core_log, stderr=core_log)
                processes.append(core); wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                core_rpc(core_port, "createwallet", ["verbose"])
                command = [str(args.node), "--network", "regtest", "--datadir", str(root / "rust"),
                           "--rpc-port", str(rust_port), "--port", str(rust_p2p), "run"]
                reservations[2].close(); reservations[3].close()
                rust = subprocess.Popen(command, stdout=rust_log, stderr=rust_log); processes.append(rust)
                cookie = wait_until(lambda: (root / "rust" / ".cookie").read_text().strip())

                def rpc(method, params=()):
                    status, result = http_rpc(rust_port, cookie, json.dumps({"jsonrpc": "2.0", "method": method, "params": list(params), "id": 3}).encode())
                    assert status == 200, (method, status)
                    assert result.get("error") is None, (method, result)
                    return result["result"]

                comparisons = 0
                def compare(method, params):
                    nonlocal comparisons
                    actual = rpc(method, params); expected = core_rpc(core_port, method, params)
                    # The preexisting header response does not yet include Core's
                    # target. All transaction fields and other block fields agree.
                    if method == "getblock" and isinstance(expected, dict):
                        expected.pop("target", None)
                        # Core writes floating difficulty with fewer significant
                        # digits. No amount, size, byte, flag or tx field is relaxed.
                        assert math.isclose(actual["difficulty"], expected["difficulty"], rel_tol=1e-14)
                        expected["difficulty"] = actual["difficulty"]
                    if actual != expected:
                        def differences(a, b, path=""):
                            if type(a) is dict and type(b) is dict:
                                for name in sorted(a.keys() | b.keys()):
                                    yield from differences(a.get(name), b.get(name), path + "/" + name)
                            elif type(a) is list and type(b) is list and len(a) == len(b):
                                for i, (left, right) in enumerate(zip(a, b)): yield from differences(left, right, path + f"/{i}")
                            elif a != b: yield path, str(a)[:300], str(b)[:300]
                        raise AssertionError((method, params, list(differences(actual, expected))[:12]))
                    comparisons += 1
                    return actual

                families = ["legacy", "p2sh-segwit", "bech32", "bech32m"]
                addresses = [core_rpc(core_port, "getnewaddress", ["", family]) for family in families]
                hashes = []; parents = []
                for address in addresses:
                    block_hash = core_rpc(core_port, "generatetoaddress", [1, address])[0]; hashes.append(block_hash)
                    raw = core_rpc(core_port, "getblock", [block_hash, 0]); assert rpc("submitblock", [raw]) is None
                    block = compare("getblock", [block_hash, 3]); parents.append(block["tx"][0])
                    compare("gettxout", [parents[-1]["txid"], 0, False])
                for block_hash in core_rpc(core_port, "generatetoaddress", [100, addresses[2]]):
                    hashes.append(block_hash); assert rpc("submitblock", [core_rpc(core_port, "getblock", [block_hash, 0])]) is None
                inputs = [{"txid": parent["txid"], "vout": 0} for parent in parents]
                outputs = {address: 49.9999 for address in addresses}; outputs["data"] = "00ff1122"
                raw = core_rpc(core_port, "createrawtransaction", [inputs, outputs])
                signed = core_rpc(core_port, "signrawtransactionwithwallet", [raw]); assert signed["complete"]
                txid = core_rpc(core_port, "sendrawtransaction", [signed["hex"]]); assert rpc("sendrawtransaction", [signed["hex"]]) == txid
                decoded = compare("getrawtransaction", [txid, 2]); assert decoded["txid"] != decoded["hash"]
                assert "fee" not in decoded and "blockhash" not in decoded
                child_output = next(out for out in decoded["vout"] if out["scriptPubKey"].get("address") == addresses[2])
                child_raw = core_rpc(core_port, "createrawtransaction", [[{"txid": txid, "vout": child_output["n"]}], {addresses[2]: 49.9998}])
                child = core_rpc(core_port, "signrawtransactionwithwallet", [child_raw]); assert child["complete"]
                child_id = core_rpc(core_port, "sendrawtransaction", [child["hex"]]); assert rpc("sendrawtransaction", [child["hex"]]) == child_id
                for level in [False, True, None, -1, 0, 1, 2, 3, 4]: compare("getrawtransaction", [txid, level])
                mined = rpc("generatetoaddress", [1, addresses[2]])[0]
                assert core_rpc(core_port, "submitblock", [rpc("getblock", [mined, 0])]) is None
                for level in [False, True, None, -1, 0, 1, 2, 3, 4]: compare("getblock", [mined, level])
                for tx in [txid, child_id]:
                    for level in [0, 1, 2, 3]:
                        compare("getrawtransaction", [tx, level]); compare("getrawtransaction", [tx, level, mined])
                details = compare("getblock", [mined, 3])
                assert details["tx"][2]["vin"][0]["prevout"]["height"] == 105
                assert details["tx"][2]["vin"][0]["prevout"]["generated"] is False

                # Carry the complete display matrix through real block validation.
                original = core_rpc(core_port, "generatetoaddress", [1, addresses[2]])[0]
                block = messages.CBlock(); block.deserialize(BytesIO(bytes.fromhex(core_rpc(core_port, "getblock", [original, 0]))))
                core_rpc(core_port, "invalidateblock", [original])
                display_scripts = scripts(key, script)
                block.vtx[0].vout += [messages.CTxOut(0, item) for item in display_scripts]
                block.vtx[0].rehash(); block.hashMerkleRoot = block.calc_merkle_root(); block.solve()
                display_hash = block.hash
                assert core_rpc(core_port, "submitblock", [block.serialize().hex()]) is None
                assert rpc("submitblock", [block.serialize().hex()]) is None
                display = compare("getblock", [display_hash, 3])
                assert len(display["tx"][0]["vout"]) >= len(display_scripts)
                compare("getrawtransaction", [display["tx"][0]["txid"], 2, display_hash])
                for out in display["tx"][0]["vout"]:
                    compare("gettxout", [display["tx"][0]["txid"], out["n"], False])

                # Core's argument classifications are checked over authenticated HTTP.
                genesis = core_rpc(core_port, "getblockhash", [0]); genesis_id = core_rpc(core_port, "getblock", [genesis])["tx"][0]
                negatives = [("getrawtransaction", [txid, True, hashes[0]]),
                    ("getrawtransaction", [txid, True, "ff" * 32]), ("getrawtransaction", [genesis_id, True]),
                    ("getrawtransaction", [txid, "1"]), ("getrawtransaction", [txid, 1.5]),
                    ("getrawtransaction", [txid, 2147483648]), ("getrawtransaction", [txid, True, False]),
                    ("getblock", [mined, "2"]), ("getblock", [mined, {}]), ("getblock", [mined, 1.5])]
                errors = []
                for method, params in negatives:
                    body = json.dumps({"jsonrpc": "2.0", "id": 5, "method": method, "params": params}).encode()
                    actual = http_rpc(rust_port, cookie, body); expected = http_rpc(core_port, "interop:regtest-only", body)
                    assert actual[0] == expected[0] == 200
                    if actual[1]["error"]["code"] != expected[1]["error"]["code"]: errors.append((method, params, actual, expected))

                core_rpc(core_port, "invalidateblock", [mined])
                fork_address = core_rpc(core_port, "getnewaddress", [])
                for _ in range(3):
                    fork = core_rpc(core_port, "generateblock", [fork_address, []])["hash"]
                    assert rpc("submitblock", [core_rpc(core_port, "getblock", [fork, 0])]) is None
                assert rpc("getbestblockhash") == core_rpc(core_port, "getbestblockhash", [])
                assert set(rpc("getrawmempool")) == {txid, child_id}
                for tx in [txid, child_id]:
                    compare("getrawtransaction", [tx, 2]); stale = compare("getrawtransaction", [tx, 2, mined])
                    assert stale["confirmations"] == 0 and not stale["in_active_chain"] and "time" not in stale
                for level in [1, 2, 3]: compare("getblock", [mined, level]); compare("getblock", [display_hash, level])
                final = rpc("generatetoaddress", [1, addresses[2]])[0]
                assert core_rpc(core_port, "submitblock", [rpc("getblock", [final, 0])]) is None
                final_view = compare("getblock", [final, 3]); assert rpc("getrawmempool") == []
                for tx in [txid, child_id]: compare("getrawtransaction", [tx, 2])
                rpc("stop"); assert rust.wait(timeout=10) == 0
                rust = subprocess.Popen(command, stdout=rust_log, stderr=rust_log); processes.append(rust)
                cookie = wait_until(lambda: (root / "rust" / ".cookie").read_text().strip())
                wait_until(lambda: rpc("getbestblockhash") == final)
                assert compare("getblock", [final, 3]) == final_view
                for tx in [txid, child_id]: compare("getrawtransaction", [tx, 2]); compare("getrawtransaction", [tx, 2, mined])
                compare("getblock", [display_hash, 3])
                rpc("stop"); assert rust.wait(timeout=10) == 0
                core_rpc(core_port, "stop", []); assert core.wait(timeout=10) == 0
                assert not errors, errors
                print(f"PASSED: {comparisons} exact Core transaction/block/coin views, {len(display_scripts)} real coinbase output scripts, {len(negatives)} error classifications, four-family signed mixed input, same-block child, reorg/mempool restoration and durable restart", flush=True)
            except Exception:
                print((root / "rust.log").read_text()[-6000:]); raise
            finally:
                for entry in reservations: entry.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


if __name__ == "__main__": main()
