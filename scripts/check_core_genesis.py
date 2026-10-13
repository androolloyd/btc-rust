#!/usr/bin/env python3
"""Compare exact live genesis bodies/positions on all five networks with Core.

All processes use fresh disposable stores, loopback RPC and disabled discovery.
No public peers, mining, coins or real wallets are involved.
"""
import argparse
import hashlib
import math
from pathlib import Path
import subprocess
import tempfile
from check_core_p2p import core_rpc, reserve_ports, rust_rpc, wait_until
from check_core_electrum import Client


def same(actual, expected):
    assert actual.keys() == expected.keys(), (actual, expected)
    for key,value in expected.items():
        if key == "difficulty": assert math.isclose(actual[key],value,rel_tol=1e-14)
        else: assert actual[key] == value, (key,actual[key],value)


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--bitcoind",type=Path,required=True)
    parser.add_argument("--node",type=Path,default=Path(__file__).resolve().parents[1]/"target/release/btc-node")
    args=parser.parse_args();args.bitcoind=args.bitcoind.resolve();args.node=args.node.resolve()
    for network,chain in [("mainnet","main"),("testnet","test"),("testnet4","testnet4"),("signet","signet"),("regtest","regtest")]:
        ports=[reserve_ports(),reserve_ports(),reserve_ports(3),reserve_ports(),reserve_ports()]
        cp,cpp,rp,rpp,ep=[item.port for item in ports]
        with tempfile.TemporaryDirectory(prefix="btc-genesis-core-") as directory:
            root=Path(directory);(root/"core").mkdir();(root/"rust").mkdir();processes=[];client=None
            with (root/"core.log").open("w") as cl,(root/"rust.log").open("w") as rl:
                try:
                    ports[0].close()
                    # Keep the unlistening Core P2P socket reserved throughout;
                    # Rust's explicit connect disables all DNS/public discovery.
                    core=subprocess.Popen([str(args.bitcoind),f"-chain={chain}",f"-datadir={root/'core'}","-server","-listen=0","-dnsseed=0","-discover=0","-connect=0","-listenonion=0","-disablewallet=1","-par=1",f"-rpcport={cp}","-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=interop","-rpcpassword=regtest-only",f"-port={cpp}"],stdout=cl,stderr=cl);processes.append(core)
                    wait_until(lambda: core_rpc(cp,"getblockcount",[]) == 0)
                    for item in ports[2:]:item.close()
                    command=[str(args.node),"--network",network,"--datadir",str(root/"rust"),"--rpc-port",str(rp),"--port",str(rpp),"--electrum-port",str(ep),"--connect",f"127.0.0.1:{cpp}","run"]
                    rust=subprocess.Popen(command,stdout=rl,stderr=rl);processes.append(rust)
                    wait_until(lambda: rust_rpc(rp,"getblockcount",[]) == 0)
                    expected_hash=core_rpc(cp,"getblockhash",[0]);expected_header=core_rpc(cp,"getblockheader",[expected_hash,False])
                    expected_body=core_rpc(cp,"getblock",[expected_hash,0]);genesis=core_rpc(cp,"getblock",[expected_hash,2]);identifier=genesis["tx"][0]["txid"]
                    snapshots=[]
                    for reopened in [False,True]:
                        assert rust_rpc(rp,"getbestblockhash",[]) == expected_hash
                        assert rust_rpc(rp,"getblockhash",[0]) == expected_hash
                        assert rust_rpc(rp,"getblockheader",[expected_hash,False]) == expected_header
                        assert rust_rpc(rp,"getblock",[expected_hash,0]) == expected_body
                        same(rust_rpc(rp,"getblockheader",[expected_hash]),core_rpc(cp,"getblockheader",[expected_hash]))
                        for level in [1,2,3]:same(rust_rpc(rp,"getblock",[expected_hash,level]),core_rpc(cp,"getblock",[expected_hash,level]))
                        client=Client(ep)
                        assert client.call("blockchain.transaction.id_from_pos",[0,0]) == identifier
                        assert client.call("blockchain.transaction.id_from_pos",{"height":0,"tx_pos":0,"merkle":True}) == {"tx_hash":identifier,"merkle":[]}
                        assert client.call("blockchain.transaction.get_merkle",[identifier,0]) == {"block_height":0,"pos":0,"merkle":[]}
                        assert client.call("blockchain.block.header",[0]) == expected_header
                        assert client.call("blockchain.transaction.id_from_pos",[0,1],True)["code"] == 1
                        assert client.call("blockchain.transaction.id_from_pos",[1,0],True)["code"] == 1
                        for flag in [None,0,1,"true",{},[]]:
                            assert client.call("blockchain.transaction.id_from_pos",[0,0,flag],True)["code"] == -32602
                            assert client.call("blockchain.transaction.id_from_pos",{"height":0,"tx_pos":0,"merkle":flag},True)["code"] == -32602
                        for value in [-1,1.5,True,"0",None]:
                            assert client.call("blockchain.transaction.id_from_pos",[value,0],True)["code"] == -32602
                            assert client.call("blockchain.transaction.id_from_pos",[0,value],True)["code"] == -32602
                        assert client.call("blockchain.transaction.id_from_pos",[0,2**64-1,True],True)["code"] == 1
                        for pool in [False,True]:
                            assert rust_rpc(rp,"gettxout",[identifier,0,pool]) is None
                            assert core_rpc(cp,"gettxout",[identifier,0,pool]) is None
                        try:rust_rpc(rp,"getrawtransaction",[identifier,True]);raise AssertionError("genesis ordinary transaction lookup unexpectedly succeeded")
                        except RuntimeError as error:assert "-5" in str(error)
                        script=bytes.fromhex(genesis["tx"][0]["vout"][0]["scriptPubKey"]["hex"])
                        sh=hashlib.sha256(script).digest()[::-1].hex()
                        assert client.call("blockchain.scripthash.get_balance",[sh]) == {"confirmed":0,"unconfirmed":0}
                        assert client.call("blockchain.scripthash.get_history",[sh]) == []
                        assert client.call("blockchain.scripthash.listunspent",[sh]) == []
                        snapshots.append((expected_hash,expected_body,identifier));client.close();client=None
                        rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10) == 0
                        if not reopened:
                            rust=subprocess.Popen(command,stdout=rl,stderr=rl);processes.append(rust)
                            wait_until(lambda: rust_rpc(rp,"getblockcount",[]) == 0)
                    assert snapshots[0] == snapshots[1]
                    core_rpc(cp,"stop",[]);assert core.wait(timeout=10) == 0
                    print(f"PASSED {network}: exact Core genesis hash/header/body/verbose views, real position and empty-branch proofs, typed/range errors, no genesis coins/history and durable restart",flush=True)
                except Exception:
                    print((root/"core.log").read_text()[-2500:]);print((root/"rust.log").read_text()[-5000:]);raise
                finally:
                    if client:client.close()
                    for process in processes:
                        if process.poll() is None:
                            process.terminate()
                            try:process.wait(timeout=10)
                            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    for item in ports:item.close()


if __name__ == "__main__":main()
