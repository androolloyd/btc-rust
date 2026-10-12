#!/usr/bin/env python3
"""Accept the actual experimental Electrum chain/transaction listener with Core.

No protocol-completeness claim: negotiation and missing subscription methods
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


def wallet_snapshot(client, core_port, watch_scripts):
    """Independent oracle: Core's actual blocks/coins and actual mempool fees.

    Do not derive expected rows, byte order, balances or spentness from Rust.
    Includes immature coinbase outputs, spent-script-only touches and pool deltas.
    """
    from decimal import Decimal
    sat = lambda value: int(Decimal(str(value)) * 100_000_000)
    script_hash = lambda script: hashlib.sha256(bytes.fromhex(script)).digest()[::-1].hex()
    histories = {script: [] for script in watch_scripts}; coins = {}; known = {}
    pool_rows = {script: [] for script in watch_scripts}; deltas = dict.fromkeys(watch_scripts, 0)
    spendable = lambda output: not output["scriptPubKey"]["hex"].startswith("6a") and len(output["scriptPubKey"]["hex"]) <= 20_000
    for height in range(1,core_rpc(core_port,"getblockcount",[])+1):
        block = core_rpc(core_port,"getblock",[core_rpc(core_port,"getblockhash",[height]),2])
        for tx in block["tx"]:
            touched = set()
            for vin in tx["vin"]:
                if "coinbase" in vin: continue
                op = (vin["txid"],vin["vout"]); output = known[op]
                touched.add(output["scriptPubKey"]["hex"]); coins.pop(op,None)
            for output in tx["vout"]:
                op = (tx["txid"],output["n"]); known[op] = output
                if spendable(output):
                    script = output["scriptPubKey"]["hex"]; touched.add(script)
                    coins[op] = (script,height,sat(output["value"]))
            for script in touched & histories.keys(): histories[script].append({"tx_hash":tx["txid"],"height":height})
    balances = {script:sum(value for owner,_,value in coins.values() if owner == script) for script in watch_scripts}
    # Cross-check every watched confirmed coin against actual Core coin queries.
    for (txid,vout),(script,height,value) in coins.items():
        if script in watch_scripts:
            coin = core_rpc(core_port,"gettxout",[txid,vout,False]); assert coin is not None and sat(coin["value"]) == value
    pool_ids = set(core_rpc(core_port,"getrawmempool",[])); pool = {txid:core_rpc(core_port,"getrawtransaction",[txid,True]) for txid in pool_ids}
    for txid,tx in pool.items():
        for output in tx["vout"]: known[(txid,output["n"])] = output
    for txid in sorted(pool):
        tx = pool[txid]; touched = set(); height = -1 if any(vin["txid"] in pool_ids for vin in tx["vin"]) else 0
        for vin in tx["vin"]:
            op = (vin["txid"],vin["vout"]); output = known[op]; script = output["scriptPubKey"]["hex"]; touched.add(script); coins.pop(op,None)
            if script in deltas: deltas[script] -= sat(output["value"])
        for output in tx["vout"]:
            if spendable(output):
                script = output["scriptPubKey"]["hex"]; touched.add(script)
                if script in deltas: deltas[script] += sat(output["value"])
        fee = sat(core_rpc(core_port,"getmempoolentry",[txid])["fees"]["base"])
        for script in touched & pool_rows.keys(): pool_rows[script].append({"tx_hash":txid,"height":height,"fee":fee})
    # Build final pool outputs after all spends (parent iteration order arbitrary).
    pool_spent = {(vin["txid"],vin["vout"]) for tx in pool.values() for vin in tx["vin"]}
    for txid,tx in pool.items():
        for output in tx["vout"]:
            op = (txid,output["n"])
            if spendable(output) and op not in pool_spent: coins[op] = (output["scriptPubKey"]["hex"],0,sat(output["value"]))
    for script in watch_scripts:
        sh = script_hash(script)
        balance = client.call("blockchain.scripthash.get_balance",{"scripthash":sh.upper()})
        assert balance == {"confirmed":balances[script],"unconfirmed":deltas[script]}, (script,balance,{"confirmed":balances[script],"unconfirmed":deltas[script]},pool_rows[script])
        history = client.call("blockchain.scripthash.get_history",[sh]); confirmed_count = len(histories[script])
        assert history[:confirmed_count] == histories[script], (sh,history,histories[script])
        normalize = lambda values: sorted(values,key=lambda value:value["tx_hash"])
        assert normalize(history[confirmed_count:]) == pool_rows[script]
        assert normalize(client.call("blockchain.scripthash.get_mempool",[sh])) == pool_rows[script]
        unspent = client.call("blockchain.scripthash.listunspent",[sh])
        expected = [{"tx_hash":txid,"tx_pos":vout,"height":height,"value":value} for (txid,vout),(owner,height,value) in coins.items() if owner == script]
        key = lambda value:(value["tx_hash"],value["tx_pos"])
        assert sorted(unspent,key=key) == sorted(expected,key=key), (sh,unspent,expected)
        assert [value for value in unspent if value["height"]] == [value for value in expected if value["height"]]
    print(f"wallet oracle passed: Core height {core_rpc(core_port,'getblockcount',[])}, {len(pool)} real pool transactions, {len(watch_scripts)} scripts",flush=True)


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
                for method, params in [("server.features",[]),("blockchain.scripthash.subscribe",["00"*32]),("blockchain.estimatefee",[6]),("blockchain.block.header",[0,1])]:
                    assert client.call(method,params,True)["code"] == -32601
                unsupported = Client(electrum_port); clients.append(unsupported)
                assert unsupported.call("server.version",["acceptance",["1.4","1.4.5"]],True)["code"] == -32601
                assert unsupported.stream.readline() == b""; unsupported.close(); clients.remove(unsupported)
                for method, params in [("blockchain.block.header",[-1]),("blockchain.block.headers",[0,-1]),("blockchain.block.headers",[0,"2"]),("blockchain.transaction.get",["00"*32,1])]:
                    assert client.call(method,params,True)["code"] == -32602
                assert client.call("blockchain.block.headers",[2**64-1,5000]) == {"count":0,"hex":"","max":2016}
                assert client.call("blockchain.transaction.get",["00"*32],True)["code"] == 1
                assert client.call("blockchain.transaction.broadcast",["ff"],True)["code"] == 1
                destination = core_rpc(core_port,"getnewaddress",[])
                scripts = [core_rpc(core_port,"getaddressinfo",[value])["scriptPubKey"] for value in [address,destination]]
                scripts += ["51", "6a04deadbeef", "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"]
                wallet_snapshot(client,core_port,scripts)
                for value in ["", "00"*31, "gg"*32, 42, None]:
                    assert client.call("blockchain.scripthash.get_history",[value],True)["code"] == -32602
                assert client.call("blockchain.scripthash.get_history",["ff"*32]) == []
                hashes = core_rpc(core_port,"generatetoaddress",[101,address]); raw_headers = []
                for block_hash in hashes:
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[block_hash,0])]) is None
                    raw_headers.append(core_rpc(core_port,"getblockheader",[block_hash,False]))
                assert client.header(101) == {"height":101,"hex":raw_headers[-1]}
                assert client.call("blockchain.block.headers",[100,100]) == {"count":2,"hex":"".join(raw_headers[99:]),"max":2016}
                wallet_snapshot(client,core_port,scripts)
                parent = core_rpc(core_port,"getblock",[hashes[0],2])["tx"][0]; parent_id = parent["txid"]
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":parent_id,"vout":0}],{address:49.9999}])
                signed = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert signed["complete"]
                txid = client.call("blockchain.transaction.broadcast",{"raw_tx":signed["hex"]})
                assert txid == core_rpc(core_port,"sendrawtransaction",[signed["hex"]])
                assert rust_rpc(rust_port,"getrawmempool",[]) == [txid]
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                assert client.call("blockchain.transaction.get",{"tx_hash":txid,"verbose":True}) == core_rpc(core_port,"getrawtransaction",[txid,True])
                assert client.call("blockchain.transaction.get_merkle",[txid,101],True)["code"] == 1
                wallet_snapshot(client,core_port,scripts)
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
                wallet_snapshot(client,core_port,scripts)
                # A three-transaction block tests odd-width sibling duplication.
                children = []; signed_spends = {txid:signed["hex"]}
                for parent_hash in hashes[1:3]:
                    funding = core_rpc(core_port,"getblock",[parent_hash,2])["tx"][0]
                    raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0}],{address:49.9999}])
                    spend = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert spend["complete"]
                    child = client.call("blockchain.transaction.broadcast",[spend["hex"]]); core_rpc(core_port,"sendrawtransaction",[spend["hex"]]); children.append(child); signed_spends[child] = spend["hex"]
                wallet_snapshot(client,core_port,scripts)
                odd = rust_rpc(rust_port,"generatetoaddress",[1,address])[0]; assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[odd,0])]) is None
                odd_block = core_rpc(core_port,"getblock",[odd]); assert len(odd_block["tx"]) == 3
                for position, tx in enumerate(odd_block["tx"]):
                    branch, root_hash = proof(odd_block["tx"],position); assert root_hash == odd_block["merkleroot"]
                    assert client.call("blockchain.transaction.get_merkle",[tx,103]) == {"block_height":103,"pos":position,"merkle":branch}
                wallet_snapshot(client,core_port,scripts)
                core_rpc(core_port,"invalidateblock",[mined]); fork_address = core_rpc(core_port,"getnewaddress",[])
                for _ in range(3):
                    fork = core_rpc(core_port,"generateblock",[fork_address,[]])["hash"]
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[fork,0])]) is None
                assert client.header(104) == {"height":104,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                assert client.call("blockchain.transaction.get_merkle",[txid,102],True)["code"] == 1
                assert client.call("blockchain.transaction.get",[txid,True]) == core_rpc(core_port,"getrawtransaction",[txid,True])
                assert set(rust_rpc(rust_port,"getrawmempool",[])) == {txid,*children}
                # Core first invalidates to height 101, where the height-3
                # funding is immature for the next block and its spend is
                # dropped. Rust switches atomically only at winning height104.
                # Re-admit any now-mature signed spend to Core, then compare
                # independently derived wallet results on identical pools.
                core_pool = set(core_rpc(core_port,"getrawmempool",[])); assert core_pool <= signed_spends.keys()
                for restored in signed_spends.keys() - core_pool:
                    assert core_rpc(core_port,"sendrawtransaction",[signed_spends[restored]]) == restored
                assert set(core_rpc(core_port,"getrawmempool",[])) == {txid,*children}
                wallet_snapshot(client,core_port,scripts)
                # Replace a restored real spend, then admit its dependent child.
                funding = core_rpc(core_port,"getblock",[hashes[1],2])["tx"][0]
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0,"sequence":0xfffffffd}],{destination:49.9998}])
                replacement = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert replacement["complete"]
                replacement_id = client.call("blockchain.transaction.broadcast",[replacement["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[replacement["hex"]]) == replacement_id
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":replacement_id,"vout":0}],{destination:49.9997}])
                child = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert child["complete"]
                child_id = client.call("blockchain.transaction.broadcast",[child["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[child["hex"]]) == child_id
                assert children[0] not in rust_rpc(rust_port,"getrawmempool",[])
                wallet_snapshot(client,core_port,scripts)
                fork = rust_rpc(rust_port,"generatetoaddress",[1,destination])[0]; assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[fork,0])]) is None
                assert client.header(105) == {"height":105,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                block = core_rpc(core_port,"getblock",[fork]); assert block["tx"].index(replacement_id) < block["tx"].index(child_id)
                wallet_snapshot(client,core_port,scripts)
                before = rust_rpc(rust_port,"getbestblockhash",[])
                assert client.call("blockchain.transaction.broadcast",[signed["hex"]],True)["code"] == 1
                assert rust_rpc(rust_port,"getbestblockhash",[]) == before
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                assert client.stream.readline() == b""; client.close(); clients.remove(client)
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getbestblockhash",[]) == before)
                client = Client(electrum_port); clients.append(client)
                assert client.call("blockchain.headers.subscribe") == {"height":105,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                wallet_snapshot(client,core_port,scripts)
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                # Batch IDs, notifications and malformed members use actual provider data.
                client.send([{"id":"a","method":"blockchain.block.header","params":[105],"jsonrpc":"2.0"},{"method":"server.ping","jsonrpc":"2.0"},7])
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
                print("PASSED: actual Core genesis/headers and ranges, real signed Electrum admission/mining, witness txid/verbose parity, independent even/odd merkle paths, fragmented-request notification, reorg/pool restore, 105-block restart, four real script-query oracles including RBF/dependent/same-block spends, explicit unsupported/malformed errors, shutdown and startup bind failure",flush=True)
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
