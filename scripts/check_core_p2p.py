#!/usr/bin/env python3
"""Check real v1/v2 transport and bidirectional regtest relay against Core v29.

Requires a checksum-verified bitcoind binary; uses disposable data directories
and loopback connections, with discovery disabled on both regtest nodes.
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


def wait_until(check, timeout=30):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, RuntimeError) as error:
            last = error
        time.sleep(0.05)
    raise RuntimeError(f"condition timed out: {last}")


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


def core_rpc(port, method, params):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/", data=payload)
    request.add_header("Authorization", "Basic " + base64.b64encode(b"interop:regtest-only").decode())
    try:
        response = urllib.request.urlopen(request, timeout=10)
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


def scenario(args, encrypted):
    mode = "v2" if encrypted else "v1"
    with tempfile.TemporaryDirectory(prefix=f"btc-core-{mode}-") as directory:
        root = Path(directory)
        core_data, rust_data = root / "core", root / "rust"
        core_data.mkdir()
        rust_data.mkdir()
        core_port = free_port()
        rust_port = free_port(3, {core_port})
        p2p_port = free_port(excluded={core_port, *range(rust_port, rust_port + 3)})
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                core = subprocess.Popen([
                    str(args.bitcoind), "-regtest", f"-datadir={core_data}", "-server", "-listen=0",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                    "-rpcuser=interop", "-rpcpassword=regtest-only", f"-v2transport={int(encrypted)}",
                ], stdout=core_log, stderr=core_log)
                processes.append(core)
                rust = subprocess.Popen([
                    str(args.node), "--network", "regtest", "--datadir", str(rust_data),
                    "--rpc-port", str(rust_port), "--port", str(p2p_port), "--log-level", "warn", "run",
                ], stdout=rust_log, stderr=rust_log)
                processes.append(rust)
                wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                wait_until(lambda: rust_rpc(rust_port, "getblockchaininfo", []))
                core_rpc(core_port, "addnode", [f"127.0.0.1:{p2p_port}", "onetry", encrypted])
                core_peers = wait_until(lambda: [peer for peer in core_rpc(core_port, "getpeerinfo", [])
                                                if peer.get("version", 0) >= 70016 and peer.get("transport_protocol_type") == mode])
                rust_peers = wait_until(lambda: rust_rpc(rust_port, "getpeerinfo", []))
                assert len(core_peers) == len(rust_peers) == 1
                assert core_peers[0]["transport_protocol_type"] == mode, core_peers
                assert rust_peers[0]["transport_protocol_type"] == mode, rust_peers
                assert rust_peers[0]["inbound"] is True
                assert core_peers[0]["relaytxes"] is False
                if encrypted:
                    assert core_peers[0]["session_id"] == rust_peers[0]["session_id"]
                    assert int(core_peers[0]["services"], 16) & (1 << 11)
                address = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
                rust_hashes = rust_rpc(rust_port, "generatetoaddress", [3, address])
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == rust_hashes[-1])
                # Core independently checks our coinbase construction and proof of work.
                assert core_rpc(core_port, "getblockcount", []) == 3
                core_hashes = core_rpc(core_port, "generatetoaddress", [2, address])
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == core_hashes[-1])
                assert rust_rpc(rust_port, "getblockcount", []) == 5
                assert core_rpc(core_port, "getblock", [core_hashes[-1], 0]) == rust_rpc(rust_port, "getblock", [core_hashes[-1], 0])
                rust_rpc(rust_port, "stop", [])
                core_rpc(core_port, "stop", [])
                assert rust.wait(10) == core.wait(10) == 0
                print(f"{mode}: Core/Rust handshake, session comparison, real blocks both ways, and shutdown passed")
            except Exception:
                print((root / "rust.log").read_text())
                debug = core_data / "regtest" / "debug.log"
                print(debug.read_text()[-10000:] if debug.exists() else (root / "core.log").read_text())
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
    scenario(args, False)
    scenario(args, True)


if __name__ == "__main__":
    main()
