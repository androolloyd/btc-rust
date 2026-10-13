#!/usr/bin/env python3
"""Accept actual durable delivery/metrics against private checksum-verified Core.

Optional --legacy-node exercises a real prior binary. CI instead removes only
new ExEx records from a stopped Core-validated store with the controlled fixture.
No chain bodies, coins or stage receipts are invented or changed by that fixture.
"""
import argparse
from pathlib import Path
import subprocess
import tempfile
from check_core_p2p import core_rpc, rust_rpc, reserve_ports, wait_until


def caught_up(cp,rp,expected_transactions):
    def snapshot():
        info=rust_rpc(rp,"getexexinfo",[])
        worker=info["consumers"][0]
        if not worker["caught_up"] or worker["status"]!="running":return False
        assert worker["name"]=="validated-metrics-v1" and worker["status"]=="running",info
        assert worker["sequence"]==info["sequence"] and worker["height"]==info["height"]
        assert worker["blockhash"]==info["blockhash"]==core_rpc(cp,"getbestblockhash",[])
        assert worker["metrics"]=={"transactions":expected_transactions,"spendable_coins":core_rpc(cp,"gettxoutsetinfo",["none"])["txouts"]}
        return info
    return wait_until(snapshot,timeout=30,description="real durable metrics catch-up")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind",type=Path,required=True)
    parser.add_argument("--node",type=Path,default=Path(__file__).resolve().parents[1]/"target/release/btc-node")
    parser.add_argument("--legacy-node",type=Path)
    parser.add_argument("--fixture",type=Path,default=Path(__file__).resolve().parents[1]/"target/release/examples/exex_fixture")
    args=parser.parse_args();args.node=args.node.resolve();args.bitcoind=args.bitcoind.resolve();args.fixture=args.fixture.resolve()
    if args.legacy_node:args.legacy_node=args.legacy_node.resolve()
    held=[reserve_ports(),reserve_ports(),reserve_ports(3),reserve_ports()]
    cp,core_p2p,rp,rust_p2p=[p.port for p in held]
    with tempfile.TemporaryDirectory(prefix="btc-core-exex-") as directory:
        root=Path(directory);(root/"core").mkdir();(root/"rust").mkdir();processes=[]
        with (root/"core.log").open("w") as clog,(root/"rust.log").open("w") as rlog:
            try:
                held[0].close();held[1].close()
                core=subprocess.Popen([str(args.bitcoind),"-regtest",f"-datadir={root/'core'}","-server","-listen=0","-connect=0","-dnsseed=0","-discover=0","-listenonion=0","-par=1","-txindex=1","-keypool=2",f"-rpcport={cp}","-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=interop","-rpcpassword=regtest-only","-fallbackfee=0.00002",f"-port={core_p2p}"],stdout=clog,stderr=clog);processes.append(core)
                wait_until(lambda:core_rpc(cp,"getblockcount",[])==0);core_rpc(cp,"createwallet",["exex"])
                address=core_rpc(cp,"getnewaddress",[]);destination=core_rpc(cp,"getnewaddress",[])
                command=["--network","regtest","--datadir",str(root/"rust"),"--rpc-port",str(rp),"--port",str(rust_p2p),"run"]
                for port in held[2:]:port.close()
                old=args.legacy_node or args.node
                rust=subprocess.Popen([str(old),*command],stdout=rlog,stderr=rlog);processes.append(rust)
                wait_until(lambda:rust_rpc(rp,"getblockcount",[])==0)
                hashes=core_rpc(cp,"generatetoaddress",[101,address])
                for block_hash in hashes:assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[block_hash,0])]) is None
                rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10)==0
                if not args.legacy_node:
                    subprocess.run([str(args.fixture),"strip",str(root/"rust"/"utxo.redb")],check=True)
                rust=subprocess.Popen([str(args.node),*command],stdout=rlog,stderr=rlog);processes.append(rust)
                wait_until(lambda:rust_rpc(rp,"getblockcount",[])==101)
                initial=caught_up(cp,rp,101);assert initial["sequence"]==initial["bootstrap_height"]==101
                events=[];after=0
                while after<101:
                    batch=rust_rpc(rp,"getexexjournal",[after,64]);events+=batch["events"];after=events[-1]["sequence"]
                assert [(e["sequence"],e["event"],e["height"],e["blockhash"]) for e in events]==[(i,"connect",i,h) for i,h in enumerate(hashes,1)]
                for event in events:
                    assert event["parent"]==core_rpc(cp,"getblockheader",[event["blockhash"]])["previousblockhash"]
                    assert event["transactions"]==event["created_coins"]==1 and event["spent_coins"]==0
                parent=core_rpc(cp,"getblock",[hashes[0],2])["tx"][0]
                raw=core_rpc(cp,"createrawtransaction",[[{"txid":parent["txid"],"vout":0}],{destination:49.999}])
                signed=core_rpc(cp,"signrawtransactionwithwallet",[raw]);assert signed["complete"]
                txid=core_rpc(cp,"sendrawtransaction",[signed["hex"]]);assert rust_rpc(rp,"sendrawtransaction",[signed["hex"]])==txid
                paid=core_rpc(cp,"generateblock",[address,[txid]])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[paid,0])]) is None
                paid_info=caught_up(cp,rp,103);assert paid_info["sequence"]==102
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[paid,0])])=="duplicate"
                assert rust_rpc(rp,"getexexinfo",[])["sequence"]==102
                core_rpc(cp,"invalidateblock",[paid],timeout=60);fork_address=core_rpc(cp,"getnewaddress",[])
                fork=[]
                for _ in range(3):
                    block_hash=core_rpc(cp,"generateblock",[fork_address,[]])["hash"];fork.append(block_hash)
                    assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[block_hash,0])]) is None
                    if len(fork)==1:assert rust_rpc(rp,"getexexinfo",[])["sequence"]==102
                final=caught_up(cp,rp,104);assert final["sequence"]==106
                changes=rust_rpc(rp,"getexexjournal",[102,64])["events"]
                assert [(e["event"],e["height"],e["blockhash"]) for e in changes]==[("disconnect",102,paid)]+[("connect",i,h) for i,h in enumerate(fork,102)]
                assert changes[0]["transactions"]==2 and changes[0]["created_coins"]==2 and changes[0]["spent_coins"]==1
                assert rust_rpc(rp,"getexexjournal",[106,0])["events"]==[]
                for params in [[107,1],[0,65],[-1,1],[0,"1"]]:
                    try:rust_rpc(rp,"getexexjournal",params)
                    except RuntimeError:pass
                    else:raise AssertionError(("invalid journal range accepted",params))
                rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10)==0
                rust=subprocess.Popen([str(args.node),*command],stdout=rlog,stderr=rlog);processes.append(rust)
                wait_until(lambda:rust_rpc(rp,"getblockcount",[])==104)
                reopened=caught_up(cp,rp,104);assert reopened==final
                assert rust_rpc(rp,"getexexjournal",[102,64])["events"]==changes
                rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10)==0
                database=root/"rust"/"utxo.redb"
                subprocess.run([str(args.fixture),"corrupt",str(database)],check=True)
                before=subprocess.check_output([str(args.fixture),"digest",str(database)],text=True)
                with (root/"refused.log").open("w") as log:
                    refused=subprocess.Popen([str(args.node),*command],stdout=log,stderr=log);processes.append(refused)
                    assert refused.wait(timeout=10)!=0
                assert "ExEx" in (root/"refused.log").read_text()
                assert subprocess.check_output([str(args.fixture),"digest",str(database)],text=True)==before
                core_rpc(cp,"stop",[]);assert core.wait(timeout=10)==0
                print("PASSED durable ExEx: actual 101-block adoption, Core coin/transaction-count oracle, real funded signed spend, duplicate/equal-work retention, exact reorg ordering and reversed metrics, durable state/cursor restart, bounds and corrupt-journal refusal",flush=True)
            except Exception:
                print((root/"rust.log").read_text()[-15000:]);print((root/"core.log").read_text()[-10000:]);raise
            finally:
                for port in held:port.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


if __name__=="__main__":main()
