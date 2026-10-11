#!/usr/bin/env python3
"""Check inbound/outbound v1/v2 relay, reconnect and restart against Core v29.

Requires a checksum-verified bitcoind binary; uses disposable data directories
and loopback connections, with discovery disabled on both regtest nodes. Core's
regtest clock is advanced during transaction relay waits so privacy trickling
does not make acceptance depend on unbounded random wall-clock delays.
"""
import argparse
import base64
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


class WaitTimeout(RuntimeError):
    pass


def wait_until(check, timeout=30, description="condition", on_retry=None):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
            last = value
        except (OSError, ValueError, RuntimeError) as error:
            last = error
        if on_retry is not None:
            on_retry()
        time.sleep(0.05)
    raise WaitTimeout(f"{description} timed out: last observation: {last}")


def free_port(span=1, excluded=()):
    for _ in range(100):
        held = []
        try:
            first = socket.socket()
            first.bind(("127.0.0.1", 0))
            held.append(first)
            port = first.getsockname()[1]
            if port + span > 65536 or any(value in excluded for value in range(port, port + span)):
                continue
            for offset in range(1, span):
                other = socket.socket()
                held.append(other)
                other.bind(("127.0.0.1", port + offset))
            return port
        except OSError:
            pass
        finally:
            for item in held:
                item.close()
    raise RuntimeError("no available port range")


def core_rpc(port, method, params, timeout=10):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/", data=payload)
    request.add_header("Authorization", "Basic " + base64.b64encode(b"interop:regtest-only").decode())
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        result = json.load(response)
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


def rust_rpc(port, method, params):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall((json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}) + "\n").encode())
        with connection.makefile("rb") as reader:
            result = json.loads(reader.readline(8 * 1024 * 1024 + 4096))
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


class CoreClock:
    """Drive Core's actual regtest relay scheduler without relaxing validation.

    Core v29 net_processing.cpp uses exponentially distributed 5s/2s inventory
    intervals and mockable GetTime. Freeze time from process startup, then move
    it one second per retry. Retain the wall-clock timeout and cap advancement
    below the two-hour future-block bound of the real-time Rust validator.
    """
    def __init__(self, port):
        self.port = port
        self.initial = self.now = int(time.time())

    def advance(self):
        if self.now - self.initial >= 3600:
            raise RuntimeError("Core relay test clock exceeded its one-hour bound")
        self.now += 1
        core_rpc(self.port, "setmocktime", [self.now])


def relay_snapshot(core_port, rust_port):
    snapshot = {}
    for node, port, rpc in [("Core", core_port, core_rpc), ("Rust", rust_port, rust_rpc)]:
        snapshot[node] = {}
        for method in ["getbestblockhash", "getrawmempool", "getpeerinfo"]:
            try:
                snapshot[node][method] = rpc(port, method, [])
            except (OSError, ValueError, RuntimeError) as error:
                snapshot[node][method] = str(error)
    return json.dumps(snapshot, sort_keys=True)


def wait_for_tx_relay(core_port, rust_port, clock, txid, from_core):
    source = core_rpc if from_core else rust_rpc
    target = rust_rpc if from_core else core_rpc
    source_port, target_port = (core_port, rust_port) if from_core else (rust_port, core_port)
    direction = "Core -> Rust" if from_core else "Rust -> Core"
    assert txid in source(source_port, "getrawmempool", []), f"{direction}: missing source transaction {txid}"
    try:
        wait_until(lambda: txid in target(target_port, "getrawmempool", []),
                   description=f"{direction} mempool relay of {txid}", on_retry=clock.advance)
    except RuntimeError as error:
        raise RuntimeError(f"{error}; mocktime={clock.now}; {relay_snapshot(core_port, rust_port)}") from error


def signed_wallet_spend(core_port, coin=None, fee=0.00002):
    # Core supplies a real mature wallet coin and independently signs SegWit.
    if coin is None:
        coins = core_rpc(core_port, "listunspent", [100])
        assert coins, "expected a mature Core wallet coin"
        coin = coins[0]
    address = core_rpc(core_port, "getnewaddress", ["", "bech32"])
    amount = round(coin["amount"] - fee, 8)
    raw = core_rpc(core_port, "createrawtransaction", [[{"txid": coin["txid"], "vout": coin["vout"]}], {address: amount}])
    signed = core_rpc(core_port, "signrawtransactionwithwallet", [raw])
    assert signed["complete"] is True
    return signed["hex"], coin


def check_reorg_and_mempool(core_port, rust_port, p2p_port, outbound, encrypted, clock):
    core_rpc(core_port, "createwallet", ["interop-wallet"])
    address = core_rpc(core_port, "getnewaddress", ["", "bech32"])
    hashes = core_rpc(core_port, "generatetoaddress", [105, address], timeout=30)
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == hashes[-1], timeout=60)
    # Core -> Rust wtxid announcement and actual signature-checked admission.
    parent_id = core_rpc(core_port, "sendtoaddress", ["mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", 0.25])
    assert parent_id in core_rpc(core_port, "getrawmempool", [])
    # Negative control: a completed handshake and synchronized chain cannot
    # guarantee a transaction announcement while Core's privacy timer is frozen.
    # This reproduces the scheduler dependency without waiting 30 real seconds.
    try:
        wait_until(lambda: parent_id in rust_rpc(rust_port, "getrawmempool", []),
                   timeout=0.25, description="frozen-clock transaction relay")
    except WaitTimeout:
        assert parent_id not in rust_rpc(rust_port, "getrawmempool", [])
        assert len(core_rpc(core_port, "getpeerinfo", [])) == len(rust_rpc(rust_port, "getpeerinfo", [])) == 1
    else:
        raise AssertionError("Core announced a transaction without advancing its frozen trickle timer")
    wait_for_tx_relay(core_port, rust_port, clock, parent_id, from_core=True)
    raw, replacement_coin = signed_wallet_spend(core_port)
    core_accept = core_rpc(core_port, "testmempoolaccept", [[raw]])[0]
    rust_accept = rust_rpc(rust_port, "testmempoolaccept", [[raw]])[0]
    assert core_accept["allowed"] == rust_accept["allowed"] is True
    assert core_accept["vsize"] == rust_accept["vsize"]
    assert core_accept["fees"]["base"] == rust_accept["fees"]["base"]
    assert core_rpc(core_port, "testmempoolaccept", [[raw], 0.00001])[0]["allowed"] is False
    assert rust_rpc(rust_port, "testmempoolaccept", [[raw], 0.00001])[0]["allowed"] is False
    # Rust -> Core relay lets Core independently verify the same witness tx.
    child_id = rust_rpc(rust_port, "sendrawtransaction", [raw])
    wait_for_tx_relay(core_port, rust_port, clock, child_id, from_core=False)
    replacement, _ = signed_wallet_spend(core_port, replacement_coin, 0.00008)
    assert core_rpc(core_port, "testmempoolaccept", [[replacement]])[0]["allowed"] is True
    assert rust_rpc(rust_port, "testmempoolaccept", [[replacement]])[0]["allowed"] is True
    replaced_id = child_id
    child_id = rust_rpc(rust_port, "sendrawtransaction", [replacement])
    wait_for_tx_relay(core_port, rust_port, clock, child_id, from_core=False)
    assert replaced_id not in core_rpc(core_port, "getrawmempool", [])
    assert replaced_id not in rust_rpc(rust_port, "getrawmempool", [])
    assert rust_rpc(rust_port, "getmempoolinfo", [])["size"] == 2
    hashes = rust_rpc(rust_port, "generatetoaddress", [1, address])
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == hashes[-1])
    assert core_rpc(core_port, "getrawmempool", []) == rust_rpc(rust_port, "getrawmempool", []) == []
    mined = core_rpc(core_port, "getblock", [hashes[-1]])
    assert parent_id in mined["tx"] and child_id in mined["tx"]
    assert core_rpc(core_port, "getblock", [hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [hashes[-1], 0])
    # A real signed immature coinbase spend is rejected by both validators.
    coinbase = core_rpc(core_port, "getblock", [hashes[-1], 2])["tx"][0]
    immature = {"txid": coinbase["txid"], "vout": 0, "amount": coinbase["vout"][0]["value"]}
    raw_immature = core_rpc(core_port, "createrawtransaction", [[{"txid": immature["txid"], "vout": immature["vout"]}], {address: round(immature["amount"] - 0.00002, 8)}])
    raw_immature = core_rpc(core_port, "signrawtransactionwithwallet", [raw_immature])["hex"]
    assert core_rpc(core_port, "testmempoolaccept", [[raw_immature]])[0]["allowed"] is False
    assert rust_rpc(rust_port, "testmempoolaccept", [[raw_immature]])[0]["allowed"] is False
    # Separate branches, including a real spend in the branch to be disconnected.
    core_rpc(core_port, "setnetworkactive", [False])
    wait_until(lambda: not rust_rpc(rust_port, "getpeerinfo", []))
    raw_fork, coin = signed_wallet_spend(core_port)
    fork_txid = rust_rpc(rust_port, "sendrawtransaction", [raw_fork])
    old_hashes = rust_rpc(rust_port, "generatetoaddress", [2, address])
    assert rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False]) is None
    new_hashes = core_rpc(core_port, "generatetoaddress", [3, address])
    core_rpc(core_port, "setnetworkactive", [True])
    if not outbound:
        core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == new_hashes[-1], timeout=60)
    assert rust_rpc(rust_port, "getblockheader", [old_hashes[-1]])["confirmations"] == -1
    restored = rust_rpc(rust_port, "gettxout", [coin["txid"], coin["vout"], False])
    assert restored["value"] == coin["amount"]
    assert restored["confirmations"] == core_rpc(core_port, "gettxout", [coin["txid"], coin["vout"], False])["confirmations"]
    assert fork_txid in rust_rpc(rust_port, "getrawmempool", [])
    wait_for_tx_relay(core_port, rust_port, clock, fork_txid, from_core=False)
    final = rust_rpc(rust_port, "generatetoaddress", [1, address])[-1]
    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == final)
    assert fork_txid in core_rpc(core_port, "getblock", [final])["tx"]
    assert core_rpc(core_port, "getblock", [final, 0]) == rust_rpc(rust_port, "getblock", [final, 0])
    assert rust_rpc(rust_port, "getrawmempool", []) == []
    return final, old_hashes[-1]


def scenario(args, encrypted, outbound):
    mode = "v2" if encrypted else "v1"
    direction = "outbound" if outbound else "inbound"
    with tempfile.TemporaryDirectory(prefix=f"btc-core-{direction}-{mode}-") as directory:
        root = Path(directory)
        core_data, rust_data = root / "core", root / "rust"
        core_data.mkdir()
        rust_data.mkdir()
        core_port = free_port()
        clock = CoreClock(core_port)
        rust_port = free_port(3, {core_port})
        p2p_port = free_port(excluded={core_port, *range(rust_port, rust_port + 3)})
        core_p2p = free_port(excluded={core_port, p2p_port, *range(rust_port, rust_port + 3)})
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                core_command = [
                    str(args.bitcoind), "-regtest", f"-datadir={core_data}", "-server", f"-listen={int(outbound)}",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                    "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002", f"-v2transport={int(encrypted)}",
                    f"-mocktime={clock.now}", "-debug=net", "-debug=mempool",
                ]
                if outbound:
                    core_command += [f"-bind=127.0.0.1:{core_p2p}", f"-port={core_p2p}"]
                core = subprocess.Popen(core_command, stdout=core_log, stderr=core_log)
                processes.append(core)
                wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
                initial_height = 19 if outbound else 0
                if initial_height:
                    core_rpc(core_port, "generatetoaddress", [initial_height, address])
                rust_command = [
                    str(args.node), "--network", "regtest", "--datadir", str(rust_data),
                    "--rpc-port", str(rust_port), "--port", str(p2p_port), "--log-level", "debug",
                ]
                if outbound:
                    rust_command += ["--connect", f"127.0.0.1:{core_p2p}"]
                rust_command += ["run"]
                rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getblockchaininfo", []))
                if not outbound:
                    core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
                core_peers = wait_until(lambda: [peer for peer in core_rpc(core_port, "getpeerinfo", [])
                                                if peer.get("version", 0) >= 70016 and peer.get("transport_protocol_type") == mode])
                rust_peers = wait_until(lambda: rust_rpc(rust_port, "getpeerinfo", []))
                assert len(core_peers) == len(rust_peers) == 1
                assert core_peers[0]["transport_protocol_type"] == mode, core_peers
                assert rust_peers[0]["transport_protocol_type"] == mode, rust_peers
                assert rust_peers[0]["inbound"] is (not outbound)
                assert core_peers[0]["inbound"] is outbound
                wait_until(lambda: rust_rpc(rust_port, "getblockcount", []) == initial_height)
                assert core_peers[0]["relaytxes"] is True
                assert core_peers[0]["permissions"] == [], "acceptance must use ordinary peer validation"
                if encrypted:
                    assert core_peers[0]["session_id"] == rust_peers[0]["session_id"]
                    assert int(core_peers[0]["services"], 16) & (1 << 11)
                rust_hashes = rust_rpc(rust_port, "generatetoaddress", [3, address])
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_hashes[-1])
                # Core independently checks our coinbase construction and proof of work.
                assert core_rpc(core_port, "getblockcount", []) == initial_height + 3
                core_hashes = core_rpc(core_port, "generatetoaddress", [2, address])
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1])
                assert rust_rpc(rust_port, "getblockcount", []) == initial_height + 5
                assert core_rpc(core_port, "getblock", [core_hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [core_hashes[-1], 0])
                if outbound:
                    # Core drops our outbound connection; recover missing history
                    # across more than one live-download window, then keep relaying.
                    previous_peer = core_peers[0]["id"]
                    core_rpc(core_port, "disconnectnode", ["", previous_peer])
                    core_hashes = core_rpc(core_port, "generatetoaddress", [20, address])
                    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1], timeout=60)
                    core_peers = core_rpc(core_port, "getpeerinfo", [])
                    rust_peers = rust_rpc(rust_port, "getpeerinfo", [])
                    assert len(core_peers) == len(rust_peers) == 1
                    assert core_peers[0]["id"] != previous_peer
                    assert rust_peers[0]["inbound"] is False
                    assert core_peers[0]["transport_protocol_type"] == rust_peers[0]["transport_protocol_type"] == mode
                    if encrypted:
                        assert core_peers[0]["session_id"] == rust_peers[0]["session_id"]
                    rust_rpc(rust_port, "stop", [])
                    assert rust.wait(10) == 0
                    wait_until(lambda: not core_rpc(core_port, "getpeerinfo", []))
                    core_hashes = core_rpc(core_port, "generatetoaddress", [2, address])
                    rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                    processes.append(rust)
                    wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1])
                    assert rust_rpc(rust_port, "getblockcount", []) == initial_height + 27
                    rust_hashes = rust_rpc(rust_port, "generatetoaddress", [1, address])
                    wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_hashes[-1])
                    assert core_rpc(core_port, "getblock", [rust_hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [rust_hashes[-1], 0])
                final, stale = check_reorg_and_mempool(core_port, rust_port, p2p_port, outbound, encrypted, clock)
                rust_rpc(rust_port, "stop", [])
                assert rust.wait(10) == 0
                wait_until(lambda: not core_rpc(core_port, "getpeerinfo", []))
                rust = subprocess.Popen(rust_command, stdout=rust_log, stderr=rust_log)
                processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == final)
                assert rust_rpc(rust_port, "getblockheader", [stale])["confirmations"] == -1
                assert rust_rpc(rust_port, "getrawmempool", []) == []
                rust_rpc(rust_port, "stop", [])
                core_rpc(core_port, "stop", [])
                assert rust.wait(10) == core.wait(10) == 0
                print(f"{direction} {mode}: Core/Rust sessions, real blocks both ways, "
                      + ("IBD, reconnect/restart, " if outbound else "") + "signed mempool relay/mining, spend reorg/undo, restart, and shutdown passed")
                print(f"{direction} {mode}: frozen-clock negative control and actual P2P relay passed "
                      f"with {clock.now - clock.initial}s of bounded Core clock advancement")
            except Exception:
                print((root / "rust.log").read_text()[-20000:])
                debug = core_data / "regtest" / "debug.log"
                print(debug.read_text()[-20000:] if debug.exists() else (root / "core.log").read_text())
                raise
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1] / "target/release/btc-node")
    args = parser.parse_args()
    args.bitcoind = args.bitcoind.resolve()
    args.node = args.node.resolve()
    for outbound in [False, True]:
        for encrypted in [False, True]:
            scenario(args, encrypted, outbound)


if __name__ == "__main__":
    main()
