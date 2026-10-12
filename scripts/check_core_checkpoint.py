#!/usr/bin/env python3
"""Accept legacy checkpoint archival/resync with real Core v29 history.

Only disposable loopback regtest databases and Core's actual wallet/spends are
used. The old checkpoint deliberately retains a spent coin and stale indices;
archival must preserve every raw row without authorizing it during fresh sync.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from check_core_p2p import core_rpc, reserve_ports, rust_rpc, wait_until


def fixture(args, action, source, database):
    result = subprocess.run([str(args.fixture), action, str(source), str(database)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def rejected(port, method, params):
    try:
        rust_rpc(port, method, params)
    except RuntimeError:
        return
    raise AssertionError(f"{method} unexpectedly accepted an archived/spent coin")


def scenario(args, encrypted):
    reservations = [reserve_ports(), reserve_ports(), reserve_ports(2), reserve_ports()]
    core_port, core_p2p, rust_port, rust_p2p = [r.port for r in reservations]
    with tempfile.TemporaryDirectory(prefix="btc-checkpoint-core-") as directory:
        root = Path(directory)
        core_data = root / "core"; core_data.mkdir()
        rust_data = root / "rust"; rust_data.mkdir()
        database = rust_data / "utxo.redb"
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                reservations[0].close(); reservations[1].close()
                core = subprocess.Popen([
                    str(args.bitcoind), "-regtest", f"-datadir={core_data}", "-server", "-listen=1",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1", "-keypool=2",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                    "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002",
                    f"-bind=127.0.0.1:{core_p2p}", f"-port={core_p2p}", f"-v2transport={int(encrypted)}",
                ], stdout=core_log, stderr=core_log)
                processes.append(core)
                wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                core_rpc(core_port, "createwallet", ["checkpoint"])
                address = core_rpc(core_port, "getnewaddress", [])
                hashes = core_rpc(core_port, "generatetoaddress", [101, address])
                coins = []
                for height in (1, 2):
                    block = core_rpc(core_port, "getblock", [hashes[height-1]])
                    txid = block["tx"][0]
                    tx = core_rpc(core_port, "getrawtransaction", [txid, True, block["hash"]])
                    vout = next(output["n"] for output in tx["vout"] if output["value"] == 50)
                    assert core_rpc(core_port, "gettxout", [txid, vout]) is not None
                    coins.append({"transaction": tx["hex"], "txid": txid, "vout": vout,
                                  "height": height, "coinbase": True})
                destination = core_rpc(core_port, "getnewaddress", [])
                raw = core_rpc(core_port, "createrawtransaction", [[{"txid": coins[0]["txid"], "vout": coins[0]["vout"]}], {destination: 49.9999}])
                signed = core_rpc(core_port, "signrawtransactionwithwallet", [raw])
                assert signed["complete"]
                spent_id = core_rpc(core_port, "sendrawtransaction", [signed["hex"]])
                hashes += core_rpc(core_port, "generatetoaddress", [1, address])
                assert core_rpc(core_port, "gettxout", [coins[0]["txid"], coins[0]["vout"]]) is None
                manifest = root / "legacy.json"
                manifest.write_text(json.dumps({"height": 102, "hash": hashes[-1], "coins": coins}))
                fixture(args, "create", manifest, database)
                before = fixture(args, "digest", "active", database)
                base = [str(args.node), "--network", "regtest", "--datadir", str(rust_data),
                        "--rpc-port", str(rust_port), "--port", str(rust_p2p), "--log-level", "debug"]
                # The ordinary startup must preserve the unsupported database.
                result = subprocess.run(base + ["--connect", "127.0.0.1:1", "run"], capture_output=True, text=True, timeout=30)
                assert result.returncode != 0 and "legacy checkpoint migration" in result.stderr
                assert fixture(args, "digest", "active", database) == before
                reservations[2].close(); reservations[3].close()
                recovery = base + ["--connect", "127.0.0.1:1", "run", "--resync-legacy-checkpoint"]
                rust = subprocess.Popen(recovery, stdout=rust_log, stderr=rust_log); processes.append(rust)
                info = wait_until(lambda: rust_rpc(rust_port, "getblockchaininfo", []))
                archive = info["legacy_checkpoint_archive"]
                assert archive == {"height": 102, "hash": hashes[-1], "genesis": core_rpc(core_port, "getblockhash", [0]), "used_for_validation": False}
                assert info["blocks"] == 0 and rust_rpc(rust_port, "getrawmempool", []) == []
                for coin in coins:
                    assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"]]) is None
                rejected(rust_port, "sendrawtransaction", [signed["hex"]])
                # Stop midway through an actual validated prefix via SIGKILL.
                for height, hash in enumerate(hashes[:37], start=1):
                    assert rust_rpc(rust_port, "submitblock", [core_rpc(core_port, "getblock", [hash, 0])]) is None
                    assert rust_rpc(rust_port, "getblockcount", []) == height
                assert rust_rpc(rust_port, "gettxout", [coins[0]["txid"], coins[0]["vout"]]) is not None
                rust.kill(); rust.wait(timeout=10)
                assert fixture(args, "digest", "archive", database) == before
                # Repeating the recovery flag cannot archive/reset fresh progress.
                command = base + ["--connect", f"127.0.0.1:{core_p2p}", "run", "--resync-legacy-checkpoint"]
                rust = subprocess.Popen(command, stdout=rust_log, stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == hashes[-1], timeout=60)
                peers = wait_until(lambda: rust_rpc(rust_port, "getpeerinfo", []))
                assert len(peers) == 1 and peers[0]["transport_protocol_type"] == ("v2" if encrypted else "v1")
                assert rust_rpc(rust_port, "getblockchaininfo", [])["legacy_checkpoint_archive"] == archive
                assert rust_rpc(rust_port, "getrawmempool", []) == []
                assert rust_rpc(rust_port, "gettxout", [coins[0]["txid"], coins[0]["vout"]]) is None
                rejected(rust_port, "sendrawtransaction", [signed["hex"]])
                for txid, vout in [(coins[1]["txid"], coins[1]["vout"]), (spent_id, 0)]:
                    actual = rust_rpc(rust_port, "gettxout", [txid, vout])
                    expected = core_rpc(core_port, "gettxout", [txid, vout])
                    assert actual and expected
                    for field in ("bestblock", "confirmations", "value", "coinbase"):
                        assert actual[field] == expected[field], (field,actual,expected)
                    assert actual["scriptPubKey"]["hex"] == expected["scriptPubKey"]["hex"]
                for height in (1, 37, 101, 102):
                    assert rust_rpc(rust_port, "getblockhash", [height]) == hashes[height-1]
                    assert rust_rpc(rust_port, "getblock", [hashes[height-1], 0]) == core_rpc(core_port, "getblock", [hashes[height-1], 0])
                new = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == new)
                new = core_rpc(core_port, "generatetoaddress", [1, address])[-1]
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == new)
                rust_rpc(rust_port, "stop", []); assert rust.wait(timeout=10) == 0
                assert fixture(args, "digest", "archive", database) == before
                rust = subprocess.Popen(base + ["--connect", "127.0.0.1:1", "run"], stdout=rust_log, stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == new)
                assert rust_rpc(rust_port, "getblockcount", []) == 104
                assert rust_rpc(rust_port, "getblockchaininfo", [])["legacy_checkpoint_archive"] == archive
                assert rust_rpc(rust_port, "gettxout", [coins[0]["txid"], coins[0]["vout"]]) is None
                rust_rpc(rust_port, "stop", []); assert rust.wait(timeout=10) == 0
                assert fixture(args, "digest", "archive", database) == before
                core_rpc(core_port, "stop", []); assert core.wait(timeout=10) == 0
                print(f"PASSED: legacy checkpoint v{2 if encrypted else 1}: all raw rows preserved, genesis reset, 37-block crash/restart, 102-block P2P resync, spent-coin rejection, bilateral mining and 104-block restart", flush=True)
            except Exception:
                print((root / "rust.log").read_text()[-10000:])
                print((root / "core.log").read_text()[-3000:])
                raise
            finally:
                for reservation in reservations: reservation.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--node", type=Path, default=root / "target/release/btc-node")
    parser.add_argument("--fixture", type=Path, default=root / "target/release/examples/legacy_checkpoint_fixture")
    args = parser.parse_args()
    args.node = args.node.resolve(); args.bitcoind = args.bitcoind.resolve(); args.fixture = args.fixture.resolve()
    for encrypted in (False, True): scenario(args, encrypted)


if __name__ == "__main__": main()
