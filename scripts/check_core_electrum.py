#!/usr/bin/env python3
"""Accept the actual experimental Electrum chain/transaction listener with Core.

No wallet/protocol-completeness claim: negotiation and missing index methods
must fail explicitly. Real Core-funded signatures, actual header bytes and
independently calculated merkle paths cover admission, mining, fork and restart.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
from check_core_p2p import core_rpc, reserve_ports, rust_rpc, wait_until


class Client:
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.stream = self.socket.makefile("rb"); self.id = 0; self.notifications = []
    def send(self, body): self.socket.sendall(json.dumps(body).encode() + b"\n")
    def read(self):
        line = self.stream.readline(16 * 1024 * 1024 + 1)
        assert line.endswith(b"\n") and len(line) <= 16 * 1024 * 1024
        return json.loads(line)
    def call(self, method, params=(), reject=False):
        self.id += 1; self.send({"id": self.id, "jsonrpc": "2.0", "method": method, "params": params})
        while True:
            reply = self.read()
            if "method" in reply: self.notifications.append(reply); continue
            assert reply["id"] == self.id
            if reject:
                assert "error" in reply and "result" not in reply, reply
                return reply["error"]
            assert "error" not in reply, reply
            return reply["result"]
    def header(self, height):
        def matches(value): return value["method"] == "blockchain.headers.subscribe" and value["params"][0]["height"] == height
        for value in self.notifications:
            if matches(value): self.notifications.remove(value); return value["params"][0]
        while True:
            value = self.read(); assert "id" not in value and "method" in value
            if matches(value): return value["params"][0]
    def close(self): self.stream.close(); self.socket.close()


def proof(txids, position):
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]; index = position; branch = []
    while len(hashes) > 1:
        branch.append(hashes[min(index ^ 1, len(hashes)-1)][::-1].hex())
        hashes = [hashlib.sha256(hashlib.sha256(hashes[i] + hashes[min(i+1,len(hashes)-1)]).digest()).digest() for i in range(0,len(hashes),2)]
        index >>= 1
    return branch, hashes[0][::-1].hex()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(__file__).resolve().parents[1]/"target/release/btc-node")
    args = parser.parse_args(); args.bitcoind = args.bitcoind.resolve(); args.node = args.node.resolve()
    reserved = [reserve_ports(), reserve_ports(), reserve_ports(3), reserve_ports(), reserve_ports()]
    core_port, core_p2p, rust_port, rust_p2p, electrum_port = [entry.port for entry in reserved]
    with tempfile.TemporaryDirectory(prefix="btc-electrum-core-") as directory:
        root = Path(directory); (root/"core").mkdir(); (root/"rust").mkdir()
        processes = []; clients = []
        with (root/"core.log").open("w") as core_log, (root/"rust.log").open("w") as rust_log:
            try:
                reserved[0].close(); reserved[1].close()
                core = subprocess.Popen([str(args.bitcoind), "-regtest", f"-datadir={root/'core'}", "-server", "-listen=0", "-dnsseed=0", "-discover=0", "-connect=0", "-listenonion=0", "-par=1", "-keypool=2", "-txindex=1", f"-rpcport={core_port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-rpcuser=interop", "-rpcpassword=regtest-only", "-fallbackfee=0.00002", f"-port={core_p2p}"], stdout=core_log, stderr=core_log)
                processes.append(core); wait_until(lambda: core_rpc(core_port,"getblockcount",[]) == 0)
                core_rpc(core_port,"createwallet",["electrum"]); address = core_rpc(core_port,"getnewaddress",[])
                command = [str(args.node), "--network", "regtest", "--datadir", str(root/"rust"), "--rpc-port",str(rust_port),"--port",str(rust_p2p),"--electrum-port",str(electrum_port),"run"]
                for entry in reserved[2:]: entry.close()
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getblockcount",[]) == 0)
                client = Client(electrum_port); clients.append(client)
                genesis = core_rpc(core_port,"getblockhash",[0]); genesis_header = core_rpc(core_port,"getblockheader",[genesis,False])
                assert client.call("blockchain.block.header",[0]) == genesis_header
                assert client.call("blockchain.headers.subscribe") == {"height":0,"hex":genesis_header}
                assert client.call("blockchain.block.headers",{"start_height":0,"count":5000}) == {"count":1,"hex":genesis_header,"max":2016}
                for method, params in [("server.features",[]),("blockchain.scripthash.get_balance",["00"*32]),("blockchain.scripthash.get_history",["00"*32]),("blockchain.scripthash.listunspent",["00"*32]),("blockchain.scripthash.subscribe",["00"*32]),("blockchain.estimatefee",[6]),("blockchain.block.header",[0,1])]:
                    assert client.call(method,params,True)["code"] == -32601
                unsupported = Client(electrum_port); clients.append(unsupported)
                assert unsupported.call("server.version",["acceptance",["1.4","1.4.5"]],True)["code"] == -32601
                assert unsupported.stream.readline() == b""; unsupported.close(); clients.remove(unsupported)
                for method, params in [("blockchain.block.header",[-1]),("blockchain.block.headers",[0,-1]),("blockchain.block.headers",[0,"2"]),("blockchain.transaction.get",["00"*32,1])]:
                    assert client.call(method,params,True)["code"] == -32602
                assert client.call("blockchain.block.headers",[2**64-1,5000]) == {"count":0,"hex":"","max":2016}
                assert client.call("blockchain.transaction.get",["00"*32],True)["code"] == 1
                assert client.call("blockchain.transaction.broadcast",["ff"],True)["code"] == 1
                hashes = core_rpc(core_port,"generatetoaddress",[101,address]); raw_headers = []
                for block_hash in hashes:
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[block_hash,0])]) is None
                    raw_headers.append(core_rpc(core_port,"getblockheader",[block_hash,False]))
                assert client.header(101) == {"height":101,"hex":raw_headers[-1]}
                assert client.call("blockchain.block.headers",[100,100]) == {"count":2,"hex":"".join(raw_headers[99:]),"max":2016}
                parent = core_rpc(core_port,"getblock",[hashes[0],2])["tx"][0]; parent_id = parent["txid"]
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":parent_id,"vout":0}],{address:49.9999}])
                signed = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert signed["complete"]
                txid = client.call("blockchain.transaction.broadcast",{"raw_tx":signed["hex"]})
                assert txid == core_rpc(core_port,"sendrawtransaction",[signed["hex"]])
                assert rust_rpc(rust_port,"getrawmempool",[]) == [txid]
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                assert client.call("blockchain.transaction.get",{"tx_hash":txid,"verbose":True}) == core_rpc(core_port,"getrawtransaction",[txid,True])
                assert client.call("blockchain.transaction.get_merkle",[txid,101],True)["code"] == 1
                # Preserve a partial inbound request across real outgoing notifications.
                client.id += 1; ping_id = client.id
                client.socket.sendall(f'{{"jsonrpc":"2.0","id":{ping_id},"method":'.encode())
                mined = rust_rpc(rust_port,"generatetoaddress",[1,address])[0]
                assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[mined,0])]) is None
                assert client.header(102) == {"height":102,"hex":core_rpc(core_port,"getblockheader",[mined,False])}
                client.socket.sendall(b'"server.ping","params":[]}\n')
                reply = client.read(); assert reply == {"jsonrpc":"2.0","id":ping_id,"result":None}
                block = core_rpc(core_port,"getblock",[mined]); branch, merkle = proof(block["tx"],1)
                assert merkle == block["merkleroot"]
                assert client.call("blockchain.transaction.get_merkle",[txid,102]) == {"block_height":102,"pos":1,"merkle":branch}
                assert client.call("blockchain.transaction.get",[txid,True]) == core_rpc(core_port,"getrawtransaction",[txid,True])
                # A three-transaction block tests odd-width sibling duplication.
                children = []
                for parent_hash in hashes[1:3]:
                    funding = core_rpc(core_port,"getblock",[parent_hash,2])["tx"][0]
                    raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0}],{address:49.9999}])
                    spend = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert spend["complete"]
                    child = client.call("blockchain.transaction.broadcast",[spend["hex"]]); core_rpc(core_port,"sendrawtransaction",[spend["hex"]]); children.append(child)
                odd = rust_rpc(rust_port,"generatetoaddress",[1,address])[0]; assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[odd,0])]) is None
                odd_block = core_rpc(core_port,"getblock",[odd]); assert len(odd_block["tx"]) == 3
                for position, tx in enumerate(odd_block["tx"]):
                    branch, root_hash = proof(odd_block["tx"],position); assert root_hash == odd_block["merkleroot"]
                    assert client.call("blockchain.transaction.get_merkle",[tx,103]) == {"block_height":103,"pos":position,"merkle":branch}
                core_rpc(core_port,"invalidateblock",[mined]); fork_address = core_rpc(core_port,"getnewaddress",[])
                for _ in range(3):
                    fork = core_rpc(core_port,"generateblock",[fork_address,[]])["hash"]
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[fork,0])]) is None
                assert client.header(104) == {"height":104,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                assert client.call("blockchain.transaction.get_merkle",[txid,102],True)["code"] == 1
                assert client.call("blockchain.transaction.get",[txid,True]) == core_rpc(core_port,"getrawtransaction",[txid,True])
                assert set(rust_rpc(rust_port,"getrawmempool",[])) == {txid,*children}
                before = rust_rpc(rust_port,"getbestblockhash",[])
                assert client.call("blockchain.transaction.broadcast",[signed["hex"]],True)["code"] == 1
                assert rust_rpc(rust_port,"getbestblockhash",[]) == before
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                assert client.stream.readline() == b""; client.close(); clients.remove(client)
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getbestblockhash",[]) == before)
                client = Client(electrum_port); clients.append(client)
                assert client.call("blockchain.headers.subscribe") == {"height":104,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                # Batch IDs, notifications and malformed members use actual provider data.
                client.send([{"id":"a","method":"blockchain.block.header","params":[104],"jsonrpc":"2.0"},{"method":"server.ping","jsonrpc":"2.0"},7])
                reply = client.read(); assert len(reply) == 2 and reply[0]["id"] == "a" and reply[0]["result"] == core_rpc(core_port,"getblockheader",[fork,False]) and reply[1]["error"]["code"] == -32600
                # Hold the configured port: node startup must fail, not disable silently.
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                client.close(); clients.remove(client)
                occupied = socket.socket(); occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                occupied.bind(("127.0.0.1",electrum_port)); occupied.listen()
                try:
                    failure = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(failure)
                    assert failure.wait(timeout=10) != 0
                    assert not (root/"rust"/".cookie").exists()
                finally: occupied.close()
                core_rpc(core_port,"stop",[]); assert core.wait(timeout=10) == 0
                print("PASSED: actual Core genesis/headers and ranges, real signed Electrum admission/mining, witness txid/verbose parity, independent even/odd merkle paths, fragmented-request notification, reorg/pool restore, 104-block restart, explicit unsupported/malformed errors, shutdown and startup bind failure",flush=True)
            except Exception:
                print((root/"rust.log").read_text()[-6000:]); raise
            finally:
                for entry in reserved: entry.close()
                for client in clients: client.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=10)
                        except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)


if __name__ == "__main__": main()
