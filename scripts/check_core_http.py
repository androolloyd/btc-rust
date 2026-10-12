#!/usr/bin/env python3
"""Accept compiled HTTP RPC using released Core v29 bitcoin-cli and bitcoind.

Uses disposable loopback regtest nodes, actual P2P block validation, wallet
signatures and per-start cookie files. Credentials are never logged or in argv.
"""
import argparse
import base64
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile

from check_core_p2p import core_rpc, reserve_ports, rust_rpc, wait_until


def http_rpc(port, cookie, body, path="/", method="POST"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request(method, path, body=body, headers={
            "Authorization": "Basic " + base64.b64encode(cookie.encode()).decode(),
            "Content-Type": "application/json",
        })
        response = connection.getresponse()
        raw = response.read(16 * 1024 * 1024 + 1)
        assert len(raw) <= 16 * 1024 * 1024
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def normalized(value):
    if isinstance(value, list): return [normalized(item) for item in value]
    if not isinstance(value, dict): return value
    out = dict(value)
    if isinstance(out.get("error"), dict):
        # Method-specific diagnostic prose is not the transport contract.
        out["error"] = {"code": out["error"]["code"]}
    return out


def bitcoin_cli(args, root, port, method, params=(), reject=False):
    command = [str(args.cli), "-regtest", f"-datadir={root / 'cli'}",
               "-rpcconnect=127.0.0.1", f"-rpcport={port}",
               f"-rpccookiefile={root / 'rust' / '.cookie'}", "-rpcclienttimeout=30", method]
    command += [json.dumps(value, separators=(",", ":")) if not isinstance(value, str) else value for value in params]
    result = subprocess.run(command, capture_output=True, text=True, timeout=40)
    credential = (root / "rust" / ".cookie").read_text().strip() if (root / "rust" / ".cookie").exists() else ""
    if credential: assert credential not in result.stdout + result.stderr, "CLI leaked credential"
    if reject:
        assert result.returncode != 0 and not result.stdout.strip()
        return result.stderr
    assert result.returncode == 0, result.stderr
    if not result.stdout.strip(): return None
    try: return json.loads(result.stdout)
    except json.JSONDecodeError: return result.stdout.strip()


def check_envelopes(core_port, rust_port, cookie):
    cases = [
        {"method": "getblockcount", "id": 1},
        {"jsonrpc": "1.0", "method": "getbestblockhash", "id": "legacy"},
        {"jsonrpc": "2.0", "method": "getblockhash", "params": [0], "id": "v2"},
        {"jsonrpc": "2.0", "method": "getblockcount", "id": None},
        {"jsonrpc": None, "method": "getblockcount", "params": None, "id": 7},
        {"method": "estimatefee", "params": [6], "id": "fee"},
        {"jsonrpc": "2.0", "method": "estimatefee", "params": [6], "id": "fee"},
        {"method": "no_such_method", "id": "missing"},
        {"jsonrpc": "2.0", "method": "no_such_method", "id": "missing"},
        {"method": "getblockhash", "params": [-1], "id": 8},
        {"jsonrpc": "2.0", "method": "getblockhash", "params": [-1], "id": 8},
        {"jsonrpc": "2.0", "method": "getblockcount"},
        {"jsonrpc": "2.0", "method": "no_such_method"},
        [],
        [{"jsonrpc": "2.0", "method": "getblockcount"}, {"jsonrpc": "2.0", "method": "no_such_method"}],
        [{"jsonrpc": "2.0", "method": "getblockcount"}, {"method": "getblockcount", "id": "a"},
         {"jsonrpc": "2.0", "method": "no_such_method", "id": "b"}],
    ]
    raw_cases = [json.dumps(case).encode() for case in cases] + [b"{", b"null"]
    for raw in raw_cases:
        expected = http_rpc(core_port, "interop:regtest-only", raw)
        actual = http_rpc(rust_port, cookie, raw)
        assert actual[0] == expected[0], (raw, actual, expected)
        assert normalized(actual[1]) == normalized(expected[1]), (raw, actual, expected)
    assert http_rpc(rust_port, cookie, b'{"method":"getblockcount","params":{},"id":1}')[1]["error"]["code"] == -32602
    for method, path, status in [("GET", "/", 405), ("POST", "/wallet/unknown", 404)]:
        assert http_rpc(rust_port, cookie, b"{}", path, method)[0] == status
    print(f"PASSED: {len(raw_cases)} actual Core v29 HTTP/version/batch/notification classifications and explicit named/wallet unsupported errors", flush=True)


def check_hostile(port, cookie):
    authorization = base64.b64encode(cookie.encode()).decode()
    stop = b'{"jsonrpc":"2.0","method":"stop","id":99}'
    for fields, status in [
        ("Authorization: Basic wrong\r\nContent-Length: 1\r\n", 401),
        (f"Authorization: Basic {authorization}\r\nContent-Length: 1\r\nContent-Length: 1\r\n", 400),
        (f"Authorization: Basic {authorization}\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n", 400),
        (f"Authorization: Basic {authorization}\r\nContent-Length: 9000000\r\n", 413),
        (f"Authorization: Basic {authorization}\r\n", 411),
        (f"Authorization: Basic {authorization}\r\nContent-Length: 1\r\nExpect: unknown\r\n", 417),
    ]:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
            connection.sendall((f"POST / HTTP/1.1\r\nHost: localhost\r\n{fields}\r\nx\n").encode() + stop + b"\n")
            response = http.client.HTTPResponse(connection); response.begin()
            assert response.status == status
            response.read()
        assert rust_rpc(port, "getblockcount", []) >= 0, "hostile body executed stop"
    # Authenticate Expect before waiting for body; then fragment the real body.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        body = b'{"jsonrpc":"2.0","method":"getblockcount","id":1}'
        connection.sendall((f"POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic {authorization}\r\nContent-Length: {len(body)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").encode())
        with connection.makefile("rb") as reader:
            assert reader.readline() == b"HTTP/1.1 100 Continue\r\n"
            assert reader.readline() == b"\r\n"
            for byte in body: connection.sendall(bytes([byte]))
            assert reader.readline().startswith(b"HTTP/1.1 200 ")
            size = 0
            while (line := reader.readline()) != b"\r\n":
                if line.lower().startswith(b"content-length:"): size = int(line.split(b":", 1)[1])
            assert json.loads(reader.read(size))["id"] == 1
    print("PASSED: compiled-node auth-before-body, Expect, fragmented body and hostile framing cannot dispatch stop", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1] / "target/release/btc-node")
    args = parser.parse_args(); args.bitcoind = args.bitcoind.resolve(); args.node = args.node.resolve()
    args.cli = (args.cli or args.bitcoind.parent / "bitcoin-cli").resolve()
    reservations = [reserve_ports(), reserve_ports(), reserve_ports(3), reserve_ports()]
    core_port, core_p2p, rust_port, rust_p2p = [reservation.port for reservation in reservations]
    with tempfile.TemporaryDirectory(prefix="btc-http-core-") as directory:
        root = Path(directory)
        for name in ("core", "rust", "cli"): (root / name).mkdir()
        processes = []
        with (root / "core.log").open("w") as core_log, (root / "rust.log").open("w") as rust_log:
            try:
                reservations[0].close(); reservations[1].close()
                core = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={root / 'core'}", "-server", "-listen=1",
                    "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1", "-keypool=2",
                    f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                    "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002",
                    f"-bind=127.0.0.1:{core_p2p}", f"-port={core_p2p}"], stdout=core_log, stderr=core_log)
                processes.append(core); wait_until(lambda: core_rpc(core_port, "getblockchaininfo", []))
                core_rpc(core_port, "createwallet", ["http"]); address = core_rpc(core_port, "getnewaddress", [])
                command = [str(args.node), "--network", "regtest", "--datadir", str(root / "rust"),
                           "--rpc-port", str(rust_port), "--port", str(rust_p2p), "--connect", f"127.0.0.1:{core_p2p}", "run"]
                reservations[2].close(); reservations[3].close()
                rust = subprocess.Popen(command, stdout=rust_log, stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getblockcount", []) == 0)
                cookie_path = root / "rust" / ".cookie"; cookie = cookie_path.read_text().strip()
                assert cookie.startswith("__cookie__:") and len(cookie) == 75
                assert cookie_path.stat().st_mode & 0o777 == 0o600
                assert bitcoin_cli(args, root, rust_port, "getblockcount") == 0
                check_envelopes(core_port, rust_port, cookie); check_hostile(rust_port, cookie)
                hashes = bitcoin_cli(args, root, rust_port, "generatetoaddress", [101, address])
                assert len(hashes) == 101
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == hashes[-1], timeout=60)
                assert bitcoin_cli(args, root, rust_port, "getblock", [hashes[0], 0]) == core_rpc(core_port, "getblock", [hashes[0], 0])
                block = core_rpc(core_port, "getblock", [hashes[0]])
                parent = core_rpc(core_port, "getrawtransaction", [block["tx"][0], True, hashes[0]])
                vout = next(output["n"] for output in parent["vout"] if output["value"] == 50)
                destination = core_rpc(core_port, "getnewaddress", [])
                raw = core_rpc(core_port, "createrawtransaction", [[{"txid": parent["txid"], "vout": vout}], {destination: 49.9999}])
                signed = core_rpc(core_port, "signrawtransactionwithwallet", [raw]); assert signed["complete"]
                assert core_rpc(core_port, "testmempoolaccept", [[signed["hex"]]])[0]["allowed"]
                txid = bitcoin_cli(args, root, rust_port, "sendrawtransaction", [signed["hex"]])
                assert bitcoin_cli(args, root, rust_port, "getrawmempool") == [txid]
                assert bitcoin_cli(args, root, rust_port, "getrawtransaction", [txid]) == signed["hex"]
                assert bitcoin_cli(args, root, rust_port, "gettxout", [parent["txid"], vout]) is None
                assert bitcoin_cli(args, root, rust_port, "gettxout", [parent["txid"], vout, False])["value"] == 50
                mined = bitcoin_cli(args, root, rust_port, "generatetoaddress", [1, address])[-1]
                wait_until(lambda: core_rpc(core_port, "getbestblockhash", []) == mined)
                assert txid in core_rpc(core_port, "getblock", [mined])["tx"]
                assert "-32601" in bitcoin_cli(args, root, rust_port, "estimatefee", [6], reject=True)
                assert "-32601" in bitcoin_cli(args, root, rust_port, "prioritisetransaction", [txid, 0, 5000], reject=True)
                before = bitcoin_cli(args, root, rust_port, "getbestblockhash")
                assert "-22" in bitcoin_cli(args, root, rust_port, "sendrawtransaction", ["ff"], reject=True)
                bitcoin_cli(args, root, rust_port, "sendrawtransaction", [signed["hex"]], reject=True)
                assert bitcoin_cli(args, root, rust_port, "getbestblockhash") == before
                assert bitcoin_cli(args, root, rust_port, "getrawmempool") == []
                check_envelopes(core_port, rust_port, cookie)
                # Real notifications mutate the same chain without response bytes.
                status, result = http_rpc(rust_port, cookie, json.dumps({"jsonrpc": "2.0", "method": "generatetoaddress", "params": [1,address]}).encode())
                assert (status,result) == (204,None)
                wait_until(lambda: core_rpc(core_port, "getblockcount", []) == 103)
                final = bitcoin_cli(args, root, rust_port, "getbestblockhash")
                assert bitcoin_cli(args, root, rust_port, "stop") == "Bitcoin server stopping"
                assert rust.wait(timeout=10) == 0 and not cookie_path.exists()
                rust = subprocess.Popen(command, stdout=rust_log, stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port, "getbestblockhash", []) == final)
                new_cookie = cookie_path.read_text().strip(); assert cookie != new_cookie
                assert http_rpc(rust_port, cookie, b'{"method":"stop","id":1}')[0] == 401
                assert bitcoin_cli(args, root, rust_port, "getblockcount") == 103
                assert bitcoin_cli(args, root, rust_port, "gettxout", [parent["txid"], vout]) is None
                bitcoin_cli(args, root, rust_port, "stop"); assert rust.wait(timeout=10) == 0 and not cookie_path.exists()
                assert cookie not in (root / "rust.log").read_text() and new_cookie not in (root / "rust.log").read_text()
                core_rpc(core_port, "stop", []); assert core.wait(timeout=10) == 0
                print("PASSED: released bitcoin-cli cookie auth, 101 real mined blocks, Core-signed HTTP admission/mining, invalid/spent rejection, mutating 204 notification, HTTP stop, cookie rotation and durable 103-block restart", flush=True)
            except Exception:
                # The node never logs credentials. Avoid dumping arbitrary CLI
                # bodies/headers or a cookie on a failed protocol assertion.
                print((root / "rust.log").read_text()[-8000:]); raise
            finally:
                for reservation in reservations: reservation.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


if __name__ == "__main__": main()
