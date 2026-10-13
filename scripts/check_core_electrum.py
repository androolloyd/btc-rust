#!/usr/bin/env python3
"""Accept the actual experimental Electrum chain/transaction listener with Core.

Local protocol 1.4 negotiation is checked against released ElectrumX; public/TLS
qualification is separate. Real Core-funded signatures, actual header bytes and
independently calculated merkle paths cover admission, mining, fork and restart.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
from check_core_p2p import core_rpc, reserve_ports, rust_rpc, wait_until, stage_snapshot
from electrumx_reference import merkle_reference, protocol_reference, methods_1_4_reference


def reject_unverified_stage_inputs(core_port,rust_port,raw):
    from core29_tapscript import reference
    from io import BytesIO
    import copy
    _,_,messages=reference()
    actual=messages.CBlock();actual.deserialize(BytesIO(bytes.fromhex(raw)))
    frozen=stage_snapshot(rust_port,height=0,block_hash=core_rpc(core_port,"getblockhash",[0]))
    header=bytearray(bytes.fromhex(raw)[:80]);bits=int.from_bytes(header[72:76],"little")
    target=(bits&0x7fffff) << (8*((bits>>24)-3))
    sha256d=lambda b:hashlib.sha256(hashlib.sha256(b).digest()).digest()
    while int.from_bytes(sha256d(header),"little") <= target:
        header[76:80]=(int.from_bytes(header[76:80],"little")+1).to_bytes(4,"little")
    pow_bad=(header+bytes.fromhex(raw)[80:]).hex()
    unknown=copy.deepcopy(actual);unknown.nTime+=1;unknown.solve()
    body_bad=bytearray(unknown.serialize());body_bad[-1]^=1
    reward=copy.deepcopy(actual);reward.vtx[0].vout[0].nValue+=1
    reward.vtx[0].rehash();reward.hashMerkleRoot=reward.calc_merkle_root();reward.solve()
    # Core only runs contextual rewards when activating a candidate. Rewind its
    # real mined history so these height-one candidates must connect at genesis.
    # Restore the genuine chain afterward; a low-work side acceptance is no oracle.
    old_tip=core_rpc(core_port,"getbestblockhash",[])
    first_hash=sha256d(bytes.fromhex(raw)[:80])[::-1].hex()
    core_rpc(core_port,"invalidateblock",[first_hash],timeout=60)
    assert core_rpc(core_port,"getblockcount",[])==0
    try:
        for label,body,rejection in [("header PoW",pow_bad,"high-hash"),("body commitment",body_bad.hex(),"bad-txnmrklroot"),("executed reward",reward.serialize().hex(),"bad-cb-amount")]:
            result=core_rpc(core_port,"submitblock",[body])
            assert result==rejection,(label,result)
            assert isinstance(rust_rpc(rust_port,"submitblock",[body]),str),label
            assert core_rpc(core_port,"getblockcount",[])==0,label
            assert rust_rpc(rust_port,"getstageinfo",[])==frozen,label
    finally:
        core_rpc(core_port,"reconsiderblock",[first_hash],timeout=60)
    assert core_rpc(core_port,"getbestblockhash",[])==old_tip
    print("Stages: independently rejected header/body/execution cannot advance durable phases",flush=True)


class Client:
    methods=set()
    notification_methods=set()
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.stream = self.socket.makefile("rb"); self.id = 0; self.notifications = []; self.subscriptions = {}; self.status_counts = {}
    def send(self, body):
        for member in body if isinstance(body,list) else [body]:
            if isinstance(member,dict) and isinstance(member.get("method"),str):self.methods.add(member["method"])
        self.socket.sendall(json.dumps(body).encode() + b"\n")
    def read(self):
        line = self.stream.readline(16 * 1024 * 1024 + 1)
        assert line.endswith(b"\n") and len(line) <= 16 * 1024 * 1024
        value = json.loads(line)
        if isinstance(value,dict) and isinstance(value.get("method"),str):self.notification_methods.add(value["method"])
        if isinstance(value,dict) and value.get("method") == "blockchain.scripthash.subscribe":
            assert "id" not in value and value["jsonrpc"] == "2.0" and len(value["params"]) == 2
            script,status = value["params"]; assert script in self.subscriptions
            assert status is None or isinstance(status,str) and len(status) == 64
            assert self.subscriptions[script] != status, ("duplicate status",value)
            self.subscriptions[script] = status; self.status_counts[script] = self.status_counts.get(script,0)+1
        return value
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
    def subscribe(self, script, expected):
        status = self.call("blockchain.scripthash.subscribe",{"scripthash":script.upper()}); assert status == expected
        self.subscriptions[script] = status; self.status_counts.setdefault(script,0)
    def expect_status(self, script, expected):
        while self.subscriptions[script] != expected:
            value = self.read(); assert "id" not in value and "method" in value
            self.notifications.append(value)
    def unsubscribe(self, script):
        assert self.call("blockchain.scripthash.unsubscribe",{"scripthash":script.upper()}) is True
        self.subscriptions.pop(script)
        assert self.call("blockchain.scripthash.unsubscribe",[script]) is False
    def close(self): self.stream.close(); self.socket.close()


def server_identity(client, port, genesis):
    features=client.call("server.features")
    assert features=={"hosts":{"127.0.0.1":{"tcp_port":port}},"genesis_hash":genesis,"hash_function":"sha256","server_version":"btc-rust 0.1.0","protocol_min":"1.4","protocol_max":"1.4","pruning":None,"peer_discovery":"off","donations":False}
    assert client.call("server.version",{"protocol_version":["1.4","1.4.5"]})==[features["server_version"],"1.4"]
    assert client.call("server.version",["repeat","9.9"],True)["code"]==1
    assert client.call("server.ping") is None
    assert isinstance(client.call("server.banner"),str)
    assert client.call("server.donation_address")==""
    assert client.call("server.peers.subscribe")==[]
    assert client.call("server.add_peer",{"features":{"hosts":{"must-not-resolve.invalid":{"tcp_port":1}},"genesis_hash":"00"*32}}) is False
    assert client.call("server.peers.subscribe")==[]
    for value in [None,[],"host",42]:assert client.call("server.add_peer",[value],True)["code"]==-32602
    return features


def version_oracle(port):
    reference=protocol_reference()
    cases=["1.4",["1.0","1.4"],["1.4","1.4.5"],["1.0","2.0"],["1.4","1.4"],"1.3","1.5","2.0","1.4.0",["1.4.1","2.0"],["1.5","1.3"],"01.004","", "bad",["1.3","1.3.9"],["0.0","1.3.99"]]
    for version in cases:
        negotiated,_=reference(version,(1,4),(1,4));client=Client(port)
        try:
            if negotiated is None:
                assert client.call("server.version",["oracle",version],True)["code"]==1
                assert client.stream.readline()==b""
            else:
                assert client.call("server.version",["oracle",version])==["btc-rust 0.1.0",".".join(map(str,negotiated))]
                assert client.call("server.ping") is None
                assert client.call("server.version",[],True)["code"]==1
                assert client.call("server.ping") is None
        finally:client.close()
    # Each connection owns negotiation; omissions and legacy/v2 frames work.
    for params in [[],["name"],{}, {"client_name":"named"},{"protocol_version":"1.4"}]:
        client=Client(port)
        try:assert client.call("server.version",params)==["btc-rust 0.1.0","1.4"]
        finally:client.close()
    invalid=[[None,"1.4"],[False,"1.4"],["n",None],["n",[]],["n",["1.4",2]], ["n","1.4","extra"],["n"*129,"1.4"],["line\nname","1.4"],{"client_name":None},{"protocol_version":None},{"client":"unknown"}]
    for params in invalid:
        client=Client(port)
        try:
            assert client.call("server.version",params,True)["code"]==-32602
            assert client.stream.readline()==b""
        finally:client.close()
    client=Client(port)
    try:
        client.send({"id":"legacy","method":"server.version","params":["legacy","1.4"]})
        assert client.read()=={"id":"legacy","result":["btc-rust 0.1.0","1.4"],"error":None}
        assert client.call("server.ping") is None
    finally:client.close()
    client=Client(port)
    try:
        client.send([{"id":"first","jsonrpc":"2.0","method":"server.version","params":["batch","1.4"]},{"id":"duplicate","jsonrpc":"2.0","method":"server.version","params":["batch","9.9"]},{"id":"ping","jsonrpc":"2.0","method":"server.ping"}])
        response=client.read()
        assert len(response)==3 and response[0]=={"id":"first","jsonrpc":"2.0","result":["btc-rust 0.1.0","1.4"]}
        assert response[1]["id"]=="duplicate" and response[1]["error"]["code"]==1
        assert response[2]=={"id":"ping","jsonrpc":"2.0","result":None}
        assert client.call("server.ping") is None
    finally:client.close()
    client=Client(port)
    try:
        client.send({"method":"server.version","params":["notification","1.4"],"jsonrpc":"2.0"})
        assert client.call("server.ping") is None
        assert client.call("server.version",[],True)["code"]==1
        assert client.call("server.ping") is None
    finally:client.close()
    print(f"version oracle passed: {len(cases)} released ElectrumX selections, five default/named cases, eleven typed/bounded failures, legacy/notification ownership and persistent duplicate errors",flush=True)


def rejected_version_cannot_admit(port, rpc_port, signed):
    before=rust_rpc(rpc_port,"getrawmempool",[]);tip=rust_rpc(rpc_port,"getbestblockhash",[])
    for notification in [False,True]:
        client=Client(port)
        try:
            version={"jsonrpc":"2.0","method":"server.version","params":["rejected","9.9"]}
            if not notification:version["id"]="version"
            client.send([version,{"jsonrpc":"2.0","id":"must-not-admit","method":"blockchain.transaction.broadcast","params":[signed]}])
            if not notification:
                response=client.read();assert len(response)==1 and response[0]["id"]=="version" and response[0]["error"]["code"]==1
            assert client.stream.readline()==b""
            assert rust_rpc(rpc_port,"getrawmempool",[])==before
            assert rust_rpc(rpc_port,"getbestblockhash",[])==tip
        finally:client.close()
    print("rejected-version batch passed: a real valid Core-signed spend cannot execute after request/notification negotiation failure",flush=True)


def proof(txids, position):
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]; index = position; branch = []
    while len(hashes) > 1:
        branch.append(hashes[min(index ^ 1, len(hashes)-1)][::-1].hex())
        hashes = [hashlib.sha256(hashlib.sha256(hashes[i] + hashes[min(i+1,len(hashes)-1)]).digest()).digest() for i in range(0,len(hashes),2)]
        index >>= 1
    return branch, hashes[0][::-1].hex()


def position_proofs(client, core_port, heights):
    cases=0
    reference=merkle_reference()
    for height in heights:
        block=core_rpc(core_port,"getblock",[core_rpc(core_port,"getblockhash",[height])])
        leaves=[bytes.fromhex(identifier)[::-1] for identifier in block["tx"]]
        for position,identifier in enumerate(block["tx"]):
            branch,root=reference.branch_and_root(leaves,position)
            assert root[::-1].hex()==block["merkleroot"]
            branch=[value[::-1].hex() for value in branch]
            assert client.call("blockchain.transaction.id_from_pos",[height,position])==identifier
            assert client.call("blockchain.transaction.id_from_pos",{"height":height,"tx_pos":position,"merkle":False})==identifier
            assert client.call("blockchain.transaction.id_from_pos",[height,position,True])=={"tx_hash":identifier,"merkle":branch}
            assert client.call("blockchain.transaction.get_merkle",[identifier,height])=={"block_height":height,"pos":position,"merkle":branch}
            cases+=4
        assert client.call("blockchain.transaction.id_from_pos",[height,len(leaves),True],True)["code"]==1
        assert client.call("blockchain.transaction.id_from_pos",[height,2**64-1],True)["code"]==1
    print(f"position oracle passed: {cases} actual Core/ElectrumX transaction-position comparisons at heights {heights}",flush=True)


def checkpoint_proofs(client, core_port, full=False):
    """Actual Core headers + unchanged upstream ElectrumX, never Rust expected data."""
    tip = core_rpc(core_port,"getblockcount",[])
    hashes = [core_rpc(core_port,"getblockhash",[height]) for height in range(tip+1)]
    headers = [core_rpc(core_port,"getblockheader",[value,False]) for value in hashes]
    leaves = [hashlib.sha256(hashlib.sha256(bytes.fromhex(header)).digest()).digest() for header in headers]
    assert [leaf[::-1].hex() for leaf in leaves] == hashes
    reference = merkle_reference(); cases = 0
    checkpoints = sorted({n for n in [1,2,3,4,7,8,15,16,31,32,63,64,100,101,102,103,104,105,tip] if 0 < n <= tip})
    if not full: checkpoints = sorted({min(100,tip), min(103,tip),tip} - {0})
    snapshots = {}
    for cp in checkpoints:
        positions = range(cp+1) if full else sorted({0,cp//2,cp})
        for height in positions:
            branch,root = reference.branch_and_root(leaves[:cp+1],height)
            expected = {"header":headers[height],"branch":[value[::-1].hex() for value in branch],"root":root[::-1].hex()}
            manual_branch,manual_root = proof(hashes[:cp+1],height)
            assert (expected["branch"],expected["root"]) == (manual_branch,manual_root)
            assert reference.root_from_proof(leaves[height],branch,height) == root
            result = client.call("blockchain.block.header",{"height":height,"cp_height":cp})
            assert result == expected, (cp,height,result,expected)
            snapshots[(height,cp)] = result; cases += 1
        for start,count in [(0,1),(cp//2,2),(cp,1)]:
            end = min(start+count-1,tip)
            if end > cp: continue
            branch,root = reference.branch_and_root(leaves[:cp+1],end)
            expected = {"count":end-start+1,"hex":"".join(headers[start:end+1]),"max":2016,"branch":[value[::-1].hex() for value in branch],"root":root[::-1].hex()}
            assert client.call("blockchain.block.headers",[start,count,cp]) == expected
            cases += 1
    # Actual returned count determines the proof endpoint after tip truncation.
    if tip:
        branch,root = reference.branch_and_root(leaves,tip)
        expected = {"count":2,"hex":"".join(headers[tip-1:]),"max":2016,"branch":[value[::-1].hex() for value in branch],"root":root[::-1].hex()}
        assert client.call("blockchain.block.headers",{"start_height":tip-1,"count":5000,"cp_height":tip}) == expected; cases += 1
        for method,params in [("blockchain.block.header",[0,tip+1]),("blockchain.block.header",[tip+1,tip]),("blockchain.block.headers",[tip-1,2,tip-1]),("blockchain.block.header",[0,2**64-1])]:
            assert client.call(method,params,True)["code"] == 1
    assert client.call("blockchain.block.headers",[2**64-1,5000,2**64-1]) == {"count":0,"hex":"","max":2016}
    assert client.call("blockchain.block.headers",[0,0,2**64-1]) == {"count":0,"hex":"","max":2016}
    for value in [-1,1.5,True,"1"]:
        assert client.call("blockchain.block.header",[0,value],True)["code"] == -32602
        assert client.call("blockchain.block.headers",[0,0,value],True)["code"] == -32602
    print(f"checkpoint oracle passed: Core height {tip}, {cases} actual upstream-reference proof comparisons",flush=True)
    return snapshots


def chunk_boundary(client, core_port, expected_tip=2018):
    tip = core_rpc(core_port,"getblockcount",[]); assert tip == expected_tip
    hashes = [core_rpc(core_port,"getblockhash",[height]) for height in range(tip+1)]
    headers = [core_rpc(core_port,"getblockheader",[value,False]) for value in hashes]
    leaves = [bytes.fromhex(value)[::-1] for value in hashes]; reference = merkle_reference()
    for position in [0,1,2015,2016,tip]:
        branch,root = reference.branch_and_root(leaves,position)
        assert client.call("blockchain.block.header",[position,tip]) == {"header":headers[position],"branch":[value[::-1].hex() for value in branch],"root":root[::-1].hex()}
    results = []
    for start,requested in [(0,2**64-1),(1,2016),(tip-1,5000)]:
        count = min(requested,2016,tip-start+1); last = start+count-1
        branch,root = reference.branch_and_root(leaves,last)
        expected = {"count":count,"hex":"".join(headers[start:start+count]),"max":2016,"branch":[value[::-1].hex() for value in branch],"root":root[::-1].hex()}
        result = client.call("blockchain.block.headers",{"start_height":start,"count":requested,"cp_height":tip})
        assert result == expected; results.append(result)
    print("checkpoint chunk cap passed: 2019 actual Core headers, exact 2016-header cap endpoint, short ranges and cached paths",flush=True)
    return results


def wallet_snapshot(client, core_port, watch_scripts, observers=()):
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
    statuses = {}
    for script in watch_scripts:
        sh = script_hash(script)
        text = "".join(f'{row["tx_hash"]}:{row["height"]}:' for row in histories[script]+pool_rows[script])
        statuses[sh] = hashlib.sha256(text.encode()).hexdigest() if text else None
        if client is None: continue
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
    for observer in ((client,) if client else ()) + tuple(observers):
        for script,expected in statuses.items():
            if script in observer.subscriptions: observer.expect_status(script,expected)
    if client is None: return statuses
    print(f"wallet oracle passed: Core height {core_rpc(core_port,'getblockcount',[])}, {len(pool)} real pool transactions, {len(watch_scripts)} scripts",flush=True)
    return statuses


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
                stage_snapshot(rust_port,core_port)
                identity=server_identity(client,electrum_port,genesis)
                version_oracle(electrum_port)
                assert client.call("blockchain.block.header",[0]) == genesis_header
                position_proofs(client,core_port,[0])
                assert client.call("blockchain.headers.subscribe") == {"height":0,"hex":genesis_header}
                assert client.call("blockchain.block.headers",{"start_height":0,"count":5000}) == {"count":1,"hex":genesis_header,"max":2016}
                assert client.call("blockchain.estimatefee",[6]) == -1
                assert client.call("blockchain.relayfee") == 0.00001
                assert client.call("mempool.get_fee_histogram") == []
                assert client.call("blockchain.block.header",[0,1],True)["code"] == 1
                assert client.call("blockchain.block.headers",[0,0,1]) == {"count":0,"hex":"","max":2016}
                for method, params in [("blockchain.block.header",[-1]),("blockchain.block.headers",[0,-1]),("blockchain.block.headers",[0,"2"]),("blockchain.transaction.get",["00"*32,1])]:
                    assert client.call(method,params,True)["code"] == -32602
                assert client.call("blockchain.block.headers",[2**64-1,5000]) == {"count":0,"hex":"","max":2016}
                assert client.call("blockchain.transaction.get",["00"*32],True)["code"] == 1
                assert client.call("blockchain.transaction.broadcast",["ff"],True)["code"] == 1
                destination = core_rpc(core_port,"getnewaddress",[])
                scripts = [core_rpc(core_port,"getaddressinfo",[value])["scriptPubKey"] for value in [address,destination]]
                scripts += ["51", "6a04deadbeef", "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac"]
                initial = wallet_snapshot(client,core_port,scripts)
                for script,status in initial.items(): client.subscribe(script,status)
                main_script = hashlib.sha256(bytes.fromhex(scripts[0])).digest()[::-1].hex()
                second = Client(electrum_port); clients.append(second); second.subscribe(main_script,initial[main_script])
                for value in ["", "00"*31, "gg"*32, 42, None]:
                    assert client.call("blockchain.scripthash.get_history",[value],True)["code"] == -32602
                assert client.call("blockchain.scripthash.get_history",["ff"*32]) == []
                for method in ["blockchain.scripthash.subscribe","blockchain.scripthash.unsubscribe"]:
                    assert client.call(method,{"scripthash":42},True)["code"] == -32602
                hashes = core_rpc(core_port,"generatetoaddress",[101,address]); raw_headers = []
                reject_unverified_stage_inputs(core_port,rust_port,core_rpc(core_port,"getblock",[hashes[0],0]))
                for height,block_hash in enumerate(hashes,1):
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[block_hash,0])]) is None
                    raw_headers.append(core_rpc(core_port,"getblockheader",[block_hash,False]))
                    stage_snapshot(rust_port,height=height,block_hash=block_hash)
                assert client.header(101) == {"height":101,"hex":raw_headers[-1]}
                assert client.call("blockchain.block.headers",[100,100]) == {"count":2,"hex":"".join(raw_headers[99:]),"max":2016}
                checkpoint_proofs(client,core_port,full=True)
                position_proofs(client,core_port,[0,1,50,100,101])
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                parent = core_rpc(core_port,"getblock",[hashes[0],2])["tx"][0]; parent_id = parent["txid"]
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":parent_id,"vout":0}],{address:49.9999}])
                signed = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert signed["complete"]
                rejected_version_cannot_admit(electrum_port,rust_port,signed["hex"])
                # A real subscribe+broadcast batch changes state after the
                # initial query but before its response leaves the connection.
                # The captured revision must still produce the new status.
                before_admission = wallet_snapshot(None,core_port,scripts)[main_script]
                race = Client(electrum_port); clients.append(race)
                expected_txid = core_rpc(core_port,"decoderawtransaction",[signed["hex"]])["txid"]
                race.send([{"jsonrpc":"2.0","id":"initial","method":"blockchain.scripthash.subscribe","params":[main_script]},{"jsonrpc":"2.0","id":"admission","method":"blockchain.transaction.broadcast","params":{"raw_tx":signed["hex"]}}])
                assert race.read() == [{"jsonrpc":"2.0","id":"initial","result":before_admission},{"jsonrpc":"2.0","id":"admission","result":expected_txid}]
                race.subscriptions[main_script] = before_admission
                txid = core_rpc(core_port,"sendrawtransaction",[signed["hex"]]); assert txid == expected_txid
                race.expect_status(main_script,wallet_snapshot(None,core_port,scripts)[main_script])
                assert race.status_counts[main_script] >= 1
                race.close(); clients.remove(race)
                assert rust_rpc(rust_port,"getrawmempool",[]) == [txid]
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                assert client.call("blockchain.transaction.get",{"tx_hash":txid,"verbose":True}) == core_rpc(core_port,"getrawtransaction",[txid,True])
                assert client.call("blockchain.transaction.get_merkle",[txid,101],True)["code"] == 1
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                # Preserve a partial inbound request across real outgoing notifications.
                client.id += 1; ping_id = client.id
                client.socket.sendall(f'{{"jsonrpc":"2.0","id":{ping_id},"method":'.encode())
                mined = rust_rpc(rust_port,"generatetoaddress",[1,address])[0]
                assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[mined,0])]) is None
                assert client.header(102) == {"height":102,"hex":core_rpc(core_port,"getblockheader",[mined,False])}
                partial_status = wallet_snapshot(None,core_port,scripts)
                client.expect_status(main_script,partial_status[main_script])
                client.socket.sendall(b'"server.ping","params":[]}\n')
                reply = client.read(); assert reply == {"jsonrpc":"2.0","id":ping_id,"result":None}
                block = core_rpc(core_port,"getblock",[mined]); branch, merkle = proof(block["tx"],1)
                assert merkle == block["merkleroot"]
                assert client.call("blockchain.transaction.get_merkle",[txid,102]) == {"block_height":102,"pos":1,"merkle":branch}
                assert client.call("blockchain.transaction.get",[txid,True]) == core_rpc(core_port,"getrawtransaction",[txid,True])
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                # A three-transaction block tests odd-width sibling duplication.
                children = []; signed_spends = {txid:signed["hex"]}
                for parent_hash in hashes[1:3]:
                    funding = core_rpc(core_port,"getblock",[parent_hash,2])["tx"][0]
                    raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0}],{address:49.9999}])
                    spend = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert spend["complete"]
                    child = client.call("blockchain.transaction.broadcast",[spend["hex"]]); core_rpc(core_port,"sendrawtransaction",[spend["hex"]]); children.append(child); signed_spends[child] = spend["hex"]
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                odd = rust_rpc(rust_port,"generatetoaddress",[1,address])[0]; assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[odd,0])]) is None
                odd_block = core_rpc(core_port,"getblock",[odd]); assert len(odd_block["tx"]) == 3
                for position, tx in enumerate(odd_block["tx"]):
                    branch, root_hash = proof(odd_block["tx"],position); assert root_hash == odd_block["merkleroot"]
                    assert client.call("blockchain.transaction.get_merkle",[tx,103]) == {"block_height":103,"pos":position,"merkle":branch}
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                position_proofs(client,core_port,[102,103])
                old_position = client.call("blockchain.transaction.id_from_pos",[102,1,True])
                old_coinbase = client.call("blockchain.transaction.id_from_pos",[102,0])
                old_checkpoints = checkpoint_proofs(client,core_port)
                # Leave the exact later checkpoint cached before side branches
                # arrive; it must change only once the new branch is active.
                old_cached = client.call("blockchain.block.header",[100,103])
                client.unsubscribe(main_script); unsubscribed_count = client.status_counts[main_script]
                old_stages=stage_snapshot(rust_port,core_port)
                core_rpc(core_port,"invalidateblock",[mined]); fork_address = core_rpc(core_port,"getnewaddress",[])
                for _ in range(3):
                    fork = core_rpc(core_port,"generateblock",[fork_address,[]])["hash"]
                    assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[fork,0])]) is None
                    if core_rpc(core_port,"getblockcount",[]) <= 103:
                        assert client.call("blockchain.block.header",[100,103]) == old_cached
                        assert rust_rpc(rust_port,"getstageinfo",[])==old_stages
                        assert client.call("blockchain.transaction.id_from_pos",[102,1,True]) == old_position
                stage_snapshot(rust_port,core_port)
                # Query the warmed prefix before another checkpoint can evict
                # it, so a cache keyed only by height would fail this regression.
                changed = client.call("blockchain.block.header",[100,103])
                assert changed["header"] == old_cached["header"] and changed["root"] != old_cached["root"] and changed["branch"] != old_cached["branch"]
                assert client.call("blockchain.transaction.id_from_pos",[102,0]) != old_coinbase
                assert client.call("blockchain.transaction.id_from_pos",[102,1],True)["code"] == 1
                position_proofs(client,core_port,[102,103,104])
                new_checkpoints = checkpoint_proofs(client,core_port)
                assert changed["root"] == new_checkpoints[(0,103)]["root"]
                assert new_checkpoints[(0,100)] == old_checkpoints[(0,100)]
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
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                assert client.status_counts[main_script] == unsubscribed_count
                restored_status = wallet_snapshot(None,core_port,scripts)[main_script]
                client.subscribe(main_script,restored_status); client.subscribe(main_script,restored_status)
                # Replace a restored real spend, then admit its dependent child.
                funding = core_rpc(core_port,"getblock",[hashes[1],2])["tx"][0]
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0,"sequence":0xfffffffd}],{destination:49.9998}])
                replacement = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert replacement["complete"]
                replacement_id = client.call("blockchain.transaction.broadcast",[replacement["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[replacement["hex"]]) == replacement_id
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":replacement_id,"vout":0}],{destination:49.9997}])
                child = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert child["complete"]
                child_id = client.call("blockchain.transaction.broadcast",[child["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[child["hex"]]) == child_id
                assert children[0] not in rust_rpc(rust_port,"getrawmempool",[])
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                removed_parent,removed_child = replacement_id,child_id
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":funding["txid"],"vout":0,"sequence":0xfffffffd}],{destination:49.9996}])
                replacement = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert replacement["complete"]
                replacement_id = client.call("blockchain.transaction.broadcast",[replacement["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[replacement["hex"]]) == replacement_id
                assert {removed_parent,removed_child}.isdisjoint(rust_rpc(rust_port,"getrawmempool",[]))
                assert {removed_parent,removed_child}.isdisjoint(core_rpc(core_port,"getrawmempool",[]))
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                raw = core_rpc(core_port,"createrawtransaction",[[{"txid":replacement_id,"vout":0}],{destination:49.9995}])
                child = core_rpc(core_port,"signrawtransactionwithwallet",[raw]); assert child["complete"]
                child_id = client.call("blockchain.transaction.broadcast",[child["hex"]]); assert core_rpc(core_port,"sendrawtransaction",[child["hex"]]) == child_id
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                # Reopen with a real multi-root/dependent mempool, then prove
                # status order remains stable and sessions require resubscribe.
                pool_checkpoint = checkpoint_proofs(client,core_port)
                stable_pool = wallet_snapshot(None,core_port,scripts)
                pool_tip = rust_rpc(rust_port,"getbestblockhash",[])
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                for old in [client,second]:
                    assert old.stream.readline() == b""; old.close(); clients.remove(old)
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getbestblockhash",[]) == pool_tip)
                client = Client(electrum_port); clients.append(client)
                assert client.call("blockchain.scripthash.unsubscribe",[main_script]) is False
                assert checkpoint_proofs(client,core_port) == pool_checkpoint
                assert wallet_snapshot(client,core_port,scripts) == stable_pool
                for script,status in stable_pool.items(): client.subscribe(script,status)
                second = Client(electrum_port); clients.append(second); second.subscribe(main_script,stable_pool[main_script])
                assert client.call("blockchain.headers.subscribe")["height"] == 104
                fork = rust_rpc(rust_port,"generatetoaddress",[1,destination])[0]; assert core_rpc(core_port,"submitblock",[rust_rpc(rust_port,"getblock",[fork,0])]) is None
                assert client.header(105) == {"height":105,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                block = core_rpc(core_port,"getblock",[fork]); assert block["tx"].index(replacement_id) < block["tx"].index(child_id)
                wallet_snapshot(client,core_port,scripts,observers=(second,))
                final_checkpoints = checkpoint_proofs(client,core_port)
                stable_status = wallet_snapshot(None,core_port,scripts)
                counts = dict(client.status_counts)
                before = rust_rpc(rust_port,"getbestblockhash",[])
                assert client.call("blockchain.transaction.broadcast",[signed["hex"]],True)["code"] == 1
                assert rust_rpc(rust_port,"getbestblockhash",[]) == before
                assert client.status_counts == counts
                unknown = hashlib.sha256(bytes.fromhex(scripts[2])).digest()[::-1].hex()
                assert client.status_counts[unknown] == 0
                # Per-connection cap, canonical case, sequential batch removal,
                # notification unsubscribe and reuse of freed capacity.
                bounded = Client(electrum_port); clients.append(bounded)
                hashes_for_limit = [hashlib.sha256(f"limit:{i}".encode()).hexdigest() for i in range(65)]
                for script in hashes_for_limit[:64]: bounded.subscribe(script,None)
                assert bounded.call("blockchain.scripthash.subscribe",[hashes_for_limit[64]],True)["code"] == 1
                bounded.subscribe(hashes_for_limit[0],None)
                bounded.unsubscribe(hashes_for_limit[0]); bounded.subscribe(hashes_for_limit[64],None)
                bounded.send([{"id":"first","jsonrpc":"2.0","method":"blockchain.scripthash.unsubscribe","params":[hashes_for_limit[64]]},{"id":"again","jsonrpc":"2.0","method":"blockchain.scripthash.unsubscribe","params":{"scripthash":hashes_for_limit[64].upper()}}])
                reply = bounded.read(); assert reply == [{"jsonrpc":"2.0","id":"first","result":True},{"jsonrpc":"2.0","id":"again","result":False}]
                bounded.subscriptions.pop(hashes_for_limit[64]); bounded.subscribe(hashes_for_limit[64],None)
                bounded.send({"jsonrpc":"2.0","method":"blockchain.scripthash.unsubscribe","params":[hashes_for_limit[64]]})
                assert bounded.call("blockchain.scripthash.unsubscribe",[hashes_for_limit[64]]) is False
                bounded.subscriptions.pop(hashes_for_limit[64]); bounded.close(); clients.remove(bounded)
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                assert client.stream.readline() == b""; client.close(); clients.remove(client)
                assert second.stream.readline() == b""; second.close(); clients.remove(second)
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getbestblockhash",[]) == before)
                stage_snapshot(rust_port,core_port)
                client = Client(electrum_port); clients.append(client)
                assert client.call("blockchain.headers.subscribe") == {"height":105,"hex":core_rpc(core_port,"getblockheader",[fork,False])}
                assert server_identity(client,electrum_port,genesis)==identity
                assert client.call("blockchain.scripthash.unsubscribe",[main_script]) is False
                assert checkpoint_proofs(client,core_port) == final_checkpoints
                position_proofs(client,core_port,[0,102,103,104,105])
                after_restart = wallet_snapshot(client,core_port,scripts)
                assert after_restart == stable_status
                for script,status in after_restart.items(): client.subscribe(script,status)
                assert client.call("blockchain.transaction.get",[txid]) == signed["hex"]
                # Batch IDs, notifications and malformed members use actual provider data.
                client.send([{"id":"a","method":"blockchain.block.header","params":[105],"jsonrpc":"2.0"},{"method":"server.ping","jsonrpc":"2.0"},7])
                reply = client.read(); assert len(reply) == 2 and reply[0]["id"] == "a" and reply[0]["result"] == core_rpc(core_port,"getblockheader",[fork,False]) and reply[1]["error"]["code"] == -32600
                # Extend real validated state beyond the chunk cap, without
                # running broad wallet subscriptions during the bulk fixture.
                client.close(); clients.remove(client)
                long_address = core_rpc(core_port,"getnewaddress",[])
                remaining = 2018-core_rpc(core_port,"getblockcount",[])
                while remaining:
                    count = min(100,remaining)
                    for block_hash in core_rpc(core_port,"generatetoaddress",[count,long_address]):
                        assert rust_rpc(rust_port,"submitblock",[core_rpc(core_port,"getblock",[block_hash,0])]) is None
                    remaining -= count
                    stage_snapshot(rust_port,core_port)
                client = Client(electrum_port); clients.append(client)
                position_proofs(client,core_port,[2015,2016,2017,2018])
                long_results = chunk_boundary(client,core_port)
                long_tip = rust_rpc(rust_port,"getbestblockhash",[])
                rust_rpc(rust_port,"stop",[]); assert rust.wait(timeout=10) == 0
                client.close(); clients.remove(client)
                rust = subprocess.Popen(command,stdout=rust_log,stderr=rust_log); processes.append(rust)
                wait_until(lambda: rust_rpc(rust_port,"getbestblockhash",[]) == long_tip)
                stage_snapshot(rust_port,core_port)
                client = Client(electrum_port); clients.append(client)
                assert chunk_boundary(client,core_port) == long_results
                assert server_identity(client,electrum_port,genesis)==identity
                position_proofs(client,core_port,[0,2016,2018])
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
                assert not (methods_1_4_reference()-Client.methods), ("unexercised released protocol methods",methods_1_4_reference()-Client.methods)
                assert "server.peers.subscribe" not in Client.notification_methods
                print("catalog passed: all 22 released Bitcoin Electrum 1.4 methods exercised by the real listener; peer queries produce no notifications",flush=True)
                print("PASSED: actual Core genesis/headers and ranges, exact transaction-position views and upstream branches, real signed Electrum admission/mining, witness txid/verbose parity, independent even/odd merkle paths, fragmented-request notification, reorg/pool restore, 105-block restart, four real script-query oracles including RBF/descendant eviction/dependent/same-block spends, actual status SHA256 and notifications, fragmented subscription updates, connection isolation/unsubscribe/limits, stable restart, actual header checkpoint proofs against ElectrumX/Core, cached reorg and 2018-block restart, exact 2016 chunk cap, explicit unsupported/malformed errors, shutdown and startup bind failure",flush=True)
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
