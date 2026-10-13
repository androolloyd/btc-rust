#!/usr/bin/env python3
"""Actual validated fee-provider acceptance, never a quote oracle from Rust.

Core wallet signs the funding transaction; Core and Rust independently validate
180 funded witness spends, replacement, delayed mining and a winning reorg.
Histogram expectations execute the unchanged released ElectrumX compressor over
Core fees/vsizes. Empirical quotes are checked from the actual observed delays;
no Bitcoin Core estimator algorithm parity is claimed.
"""
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from check_core_p2p import core_rpc, rust_rpc, reserve_ports, wait_until
from check_core_electrum import Client
from electrumx_reference import fee_histogram_reference


def compact(n):
    if n < 253: return bytes([n])
    if n <= 65535: return b"\xfd" + struct.pack("<H",n)
    return b"\xfe" + struct.pack("<I",n)


def transaction(txid, index, outputs, witness=None):
    body = struct.pack("<i",2)
    if witness is not None: body += b"\x00\x01"
    body += b"\x01" + bytes.fromhex(txid)[::-1] + struct.pack("<I",index) + b"\x00" + struct.pack("<I",0xfffffffd)
    body += compact(len(outputs))
    for amount,script in outputs:
        body += struct.pack("<q",amount) + compact(len(script)) + script
    if witness is not None:
        body += compact(len(witness))
        for item in witness: body += compact(len(item)) + item
    return (body + struct.pack("<I",0)).hex()


def pool_oracle(client, cp, rp):
    entries=core_rpc(cp,"getrawmempool",[True]); histogram={}; total=0; size=0
    for entry in entries.values():
        fee=int(Decimal(str(entry["fees"]["base"])) * 100_000_000)
        vsize=entry["vsize"]; rate=(fee*10//vsize)/10
        histogram[rate]=histogram.get(rate,0)+vsize; total+=fee; size+=vsize
    expected=[list(row) for row in fee_histogram_reference()(histogram,bin_size=100_000)]
    assert client.call("mempool.get_fee_histogram") == expected
    assert rust_rpc(rp,"getmempoolfees",[]) == {"count":len(entries),"vsize":size,"total_fee":total,"fee_histogram":expected}
    info=rust_rpc(rp,"getmempoolinfo",[])
    assert info["bytes"] == size and info["size"] == len(entries)
    assert client.call("blockchain.relayfee") == info["minrelaytxfee"] == core_rpc(cp,"getmempoolinfo",[])["minrelaytxfee"]
    return expected


def quotes(client, rp, expected):
    for target,wanted in expected.items():
        for mode in ["CONSERVATIVE","ECONOMICAL"]:
            value=wanted[mode] if isinstance(wanted,dict) else wanted
            assert client.call("blockchain.estimatefee",{"number":target,"mode":mode}) == value
            assert rust_rpc(rp,"estimatefee",[target,mode]) == value
            smart=rust_rpc(rp,"estimatesmartfee",[target,mode])
            if value == -1: assert "feerate" not in smart and smart["errors"] == ["Insufficient observed confirmation data"]
            else: assert smart == {"feerate":value,"blocks":target}


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--bitcoind",type=Path,required=True)
    parser.add_argument("--node",type=Path,default=Path(__file__).resolve().parents[1]/"target/release/btc-node")
    args=parser.parse_args(); args.bitcoind=args.bitcoind.resolve(); args.node=args.node.resolve()
    ports=[reserve_ports(),reserve_ports(),reserve_ports(3),reserve_ports(),reserve_ports()]
    cp,cpp,rp,rpp,ep=[item.port for item in ports]
    with tempfile.TemporaryDirectory(prefix="btc-core-fees-") as directory:
        root=Path(directory);(root/"core").mkdir();(root/"rust").mkdir(); processes=[];client=None
        with (root/"core.log").open("w") as cl,(root/"rust.log").open("w") as rl:
            try:
                ports[0].close();ports[1].close()
                core=subprocess.Popen([str(args.bitcoind),"-regtest",f"-datadir={root/'core'}","-server","-listen=0","-dnsseed=0","-discover=0","-connect=0","-listenonion=0","-par=1","-keypool=2","-txindex=1",f"-rpcport={cp}","-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=interop","-rpcpassword=regtest-only","-fallbackfee=0.00002",f"-port={cpp}"],stdout=cl,stderr=cl);processes.append(core)
                wait_until(lambda: core_rpc(cp,"getblockcount",[]) == 0)
                core_rpc(cp,"setmocktime",[int(time.time())])
                core_rpc(cp,"createwallet",["fees"]); address=core_rpc(cp,"getnewaddress",[])
                destination=bytes.fromhex(core_rpc(cp,"getaddressinfo",[address])["scriptPubKey"])
                command=[str(args.node),"--network","regtest","--datadir",str(root/"rust"),"--rpc-port",str(rp),"--port",str(rpp),"--electrum-port",str(ep),"run"]
                for item in ports[2:]:item.close()
                rust=subprocess.Popen(command,stdout=rl,stderr=rl);processes.append(rust)
                wait_until(lambda: rust_rpc(rp,"getblockcount",[]) == 0);client=Client(ep)
                assert client.call("server.version",["fee-acceptance","1.4"]) == ["btc-rust 0.1.0","1.4"]
                quotes(client,rp,{1:-1,2:-1,144:-1,145:-1,1008:-1}); assert pool_oracle(client,cp,rp) == []
                for target in [0,-1,1.5,True,"2"]:
                    assert client.call("blockchain.estimatefee",[target],True)["code"] == -32602
                for mode in ["unknown",1,False,{}]:
                    assert "unknown fee" in client.call("blockchain.estimatefee",[2,mode],True)["message"]
                for h in core_rpc(cp,"generatetoaddress",[101,address]):
                    assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[h,0])]) is None
                # Core-signed funding pays a real standard witness program.  Its
                # 99 dropped arguments give independent large/small virtual sizes.
                script=b"\x75"*99+b"\x51"; program=b"\x00\x20"+hashlib.sha256(script).digest()
                coin=next(value for value in core_rpc(cp,"listunspent",[]) if value["confirmations"] >= 101)
                amount=int(Decimal(str(coin["amount"]))*100_000_000)
                unsigned=transaction(coin["txid"],coin["vout"],[(1_000_000,program)]*180+[(amount-180_000_000-100_000,destination)])
                signed=core_rpc(cp,"signrawtransactionwithwallet",[unsigned]);assert signed["complete"]
                funding=core_rpc(cp,"sendrawtransaction",[signed["hex"]]);assert client.call("blockchain.transaction.broadcast",[signed["hex"]]) == funding
                block=core_rpc(cp,"generateblock",[address,[signed["hex"]]])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[block,0])]) is None
                raws=[];ids=[]
                for index in range(180):
                    witness=[(b"\x42"*80 if index < 160 else b"")]*99+[script]
                    draft=transaction(funding,index,[(999_000,destination)],witness)
                    vsize=core_rpc(cp,"decoderawtransaction",[draft])["vsize"]
                    rate=20 if index < 5 else 5 if index < 115 else 2 if index < 160 else 8
                    raw=transaction(funding,index,[(1_000_000-rate*vsize,destination)],witness)
                    identifier=core_rpc(cp,"sendrawtransaction",[raw]); assert client.call("blockchain.transaction.broadcast",[raw]) == identifier
                    raws.append(raw);ids.append(identifier)
                histogram=pool_oracle(client,cp,rp);assert len(histogram) >= 2, histogram
                quotes(client,rp,{1:-1,2:-1})
                # A genuine replacement is a failed confirmation of the removed
                # lower-fee transaction, not an invented successful observation.
                index=159;vsize=core_rpc(cp,"getmempoolentry",[ids[index]])["vsize"]
                replacement=transaction(funding,index,[(1_000_000-4*vsize,destination)],[b"\x42"*80]*99+[script])
                ids[index]=core_rpc(cp,"sendrawtransaction",[replacement]);assert client.call("blockchain.transaction.broadcast",[replacement]) == ids[index];raws[index]=replacement
                pool_oracle(client,cp,rp)
                bad=bytearray.fromhex(raws[0]);bad[-5]^=1
                before=pool_oracle(client,cp,rp);client.call("blockchain.transaction.broadcast",[bad.hex()],True)
                assert pool_oracle(client,cp,rp) == before
                # Wait one real block without confirming the pool; pending entries
                # count as misses for target one, and remain censored for target two.
                empty=core_rpc(cp,"generateblock",[address,[]])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[empty,0])]) is None
                quotes(client,rp,{1:-1,2:-1})
                partial=core_rpc(cp,"generateblock",[address,ids[:160]])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[partial,0])]) is None
                quotes(client,rp,{1:-1,2:{"CONSERVATIVE":-1,"ECONOMICAL":0.00002},3:0.00002})
                pool_oracle(client,cp,rp)
                mined=core_rpc(cp,"generateblock",[address,ids[160:]])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[mined,0])]) is None
                assert len(core_rpc(cp,"getblock",[partial])["tx"]) == 161
                assert len(core_rpc(cp,"getblock",[mined])["tx"]) == 21
                assert pool_oracle(client,cp,rp) == []
                quotes(client,rp,{1:-1,2:{"CONSERVATIVE":-1,"ECONOMICAL":0.00002},3:0.00002,6:0.00002,144:0.00002,145:-1})
                print("PASSED learned quotes: 180 actual Core-validated funded witness spends, delayed confirmation, replacement failure and exact released ElectrumX large-bin histograms",flush=True)
                rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10) == 0;client.close();client=None
                rust=subprocess.Popen(command,stdout=rl,stderr=rl);processes.append(rust)
                wait_until(lambda: rust_rpc(rp,"getbestblockhash",[]) == mined);client=Client(ep)
                assert client.call("server.version",["fee-restart","1.4"]) == ["btc-rust 0.1.0","1.4"]
                quotes(client,rp,{1:-1,2:{"CONSERVATIVE":-1,"ECONOMICAL":0.00002},3:0.00002,6:0.00002});assert pool_oracle(client,cp,rp) == []
                # A fixed Core clock makes timing collisions deterministic. A
                # different real coinbase recipient must distinguish the fork
                # even when old/new templates share exactly the same timestamp.
                old_branch={h:core_rpc(cp,"getblockhash",[h]) for h in [103,104,105]}
                fork_address=core_rpc(cp,"getnewaddress",[])
                core_rpc(cp,"invalidateblock",[empty],timeout=60)
                for _ in range(4):
                    fork=core_rpc(cp,"generateblock",[fork_address,[]])["hash"]
                    height=core_rpc(cp,"getblockcount",[])
                    assert fork != old_branch.get(height)
                    assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[fork,0])]) is None
                    quotes(client,rp,{1:-1,3:0.00002 if core_rpc(cp,"getblockcount",[]) <= 105 else -1})
                assert rust_rpc(rp,"getbestblockhash",[]) == fork
                pool_oracle(client,cp,rp);quotes(client,rp,{1:-1,2:-1})
                again=core_rpc(cp,"generateblock",[address,ids])["hash"]
                assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[again,0])]) is None
                quotes(client,rp,{1:0.00002,2:0.00002});assert pool_oracle(client,cp,rp) == []
                # Expire the real observations through ordinary validation.
                for start in [25,25,25,25,25,20]:
                    for h in core_rpc(cp,"generatetoaddress",[start,address],timeout=30):
                        assert rust_rpc(rp,"submitblock",[core_rpc(cp,"getblock",[h,0])]) is None
                quotes(client,rp,{1:-1,2:-1})
                rust_rpc(rp,"stop",[]);assert rust.wait(timeout=10) == 0;client.close();client=None
                core_rpc(cp,"stop",[]);assert core.wait(timeout=10) == 0
                print("PASSED fee providers: native RPC/Electrum policy and units, censored/insufficient/aged data, actual RBF, invalid-spend state preservation, durable learning restart, equal-work retention, winning-reorg reset/relearning and 144-block expiration",flush=True)
            except Exception:
                print((root/"rust.log").read_text()[-5000:]);raise
            finally:
                if client:client.close()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=10)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                for item in ports:item.close()


if __name__ == "__main__": main()
