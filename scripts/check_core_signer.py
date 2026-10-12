#!/usr/bin/env python3
"""Accept compiled ECDSA signing against independently funded/mined Core v29.

Uses only public fixture keys and disposable loopback regtest coins. Core's HD
wallet funds actual outputs; only Rust signs their spends. Core checks every
new equation, mempool acceptance and mining. Private WIFs enter file input only.
"""
import argparse
import base64
from io import BytesIO
import json
from pathlib import Path
import subprocess
import tempfile

from check_core_p2p import core_rpc, free_port, wait_until
from check_core_psbt import cli, psbt_maps, encode_maps, encode64, check_private_descriptor_vectors
from core29_tapscript import reference
from core29_psbt_signing import wif


def sign(args, raw, keys, cap=2000, reject=False, require_parents=True):
    with tempfile.NamedTemporaryFile(mode="w",prefix="btc-signer-keys-") as secret_file, tempfile.NamedTemporaryFile(prefix="btc-signer-psbt-") as psbt_file:
        secret_file.write("\n".join(keys)); secret_file.flush()
        psbt_file.write(bytes.fromhex(raw)); psbt_file.flush()
        command=[str(args.node),"--json","--network","regtest","sign-psbt","@"+psbt_file.name,"--key-file",secret_file.name,"--max-fee-sat",str(cap)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    assert all(key not in result.stdout+result.stderr for key in keys)
    if reject:
        assert result.returncode != 0 and not result.stdout.strip()
        return None
    assert result.returncode == 0,result.stderr
    output=json.loads(result.stdout)
    assert output["signing_scope"] in ["ecdsa_sighash_all_partial_signing","known_ecdsa_and_taproot_keypath_partial_signing","known_ecdsa_and_taproot_partial_signing"]
    assert output["signatures_verified"] and output["partial_signatures_verified"]
    assert all(output[name] is False for name in ["spending_conditions_verified","final_fields_verified","key_origins_verified","change_outputs_verified","active_chain_verified"])
    if require_parents: assert all(output["txid_linked_prevouts"])
    assert output["fee_sat"] <= cap
    return output


def core_psbt(args, raw):
    # Core v29 receives v0. Rust independently exercises BIP370 construction,
    # modifier updates and v2 -> v0 conversion with unchanged transactions.
    return encode64(cli(args.node,"convert-psbt",raw,"--version","0")["psbt_hex"])

def run_cases(args,port):
    key,s,m=reference()
    fixture=json.loads((Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/ecdsa-signer.json").read_text())
    vectors=fixture["vectors"]
    # Retain exact independent RFC6979 records on synthetic parents; these
    # offline equations are not substituted for the actual funding below.
    for vector in vectors:
        test_keys=[]
        for text in vector["wifs"]:
            # Public fixture WIF bytes are converted only in the version byte.
            from check_core_psbt import regtest_descriptor
            test_keys.append(regtest_descriptor("pk("+text+")")[3:-1])
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",vector["psbt"],"--version",str(version))["psbt_hex"]
            if version==2:
                records=psbt_maps(raw,len(vector["signatures"])+2)
                records[0][b"\x06"]=b"\x07"; raw=encode_maps(records)
            output=sign(args,raw,test_keys,1000)
            records=psbt_maps(output["psbt_hex"],len(vector["signatures"])+2)
            for fields,expected in zip(records[1:],vector["signatures"]):
                for signature in expected:
                    public=bytes.fromhex(signature["public_key"])
                    actual=fields[b"\x02"+public]
                    assert actual.hex()==signature["signature"]
                    verifier=key.ECPubKey(); verifier.set(public)
                    assert verifier.verify_ecdsa(actual[:-1],bytes.fromhex(signature["digest"]))
            core=core_rpc(port,"decodepsbt",[core_psbt(args,output["psbt_hex"])])
            assert core["tx"]["txid"]==output["unsigned_txid"]
            again=sign(args,output["psbt_hex"],test_keys,1000)
            assert again["signatures_added"]==0 and again["psbt_hex"]==output["psbt_hex"]
        vector["test_keys"]=test_keys
    print(f"PASSED: {len(vectors)} independent RFC6979/low-S signer cases, exact signatures, both PSBT versions, modifier flags and idempotence",flush=True)
    address=core_rpc(port,"getnewaddress",[])
    core_rpc(port,"generatetoaddress",[101,address],timeout=30)
    funding=m.CTransaction(); funding.version=2
    positions=[]
    for vector in vectors:
        records=psbt_maps(vector["psbt"],len(vector["signatures"])+2)
        original=m.CTransaction(); original.deserialize(BytesIO(records[0][b"\x00"]))
        offsets=[]
        for i,txin in enumerate(original.vin):
            parent=m.CTransaction(); parent.deserialize(BytesIO(records[i+1][b"\x00"]))
            offsets.append(len(funding.vout))
            funding.vout.append(m.CTxOut(200000,parent.vout[txin.prevout.n].scriptPubKey))
        positions.append(offsets)
    funded=core_rpc(port,"fundrawtransaction",[funding.serialize_without_witness().hex(),{"changePosition":len(funding.vout)}])
    signed_funding=core_rpc(port,"signrawtransactionwithwallet",[funded["hex"]])
    assert signed_funding["complete"]
    funding_id=core_rpc(port,"sendrawtransaction",[signed_funding["hex"]])
    core_rpc(port,"generatetoaddress",[1,address])
    actual=m.CTransaction(); actual.deserialize(BytesIO(bytes.fromhex(signed_funding["hex"]))); actual.rehash()
    assert funding_id==actual.hash
    assert [(out.nValue,out.scriptPubKey) for out in actual.vout[:len(funding.vout)]]==[(out.nValue,out.scriptPubKey) for out in funding.vout]
    destination=core_rpc(port,"getnewaddress",[])
    destination_script=bytes.fromhex(core_rpc(port,"getaddressinfo",[destination])["scriptPubKey"])
    txids=[]
    for vector,offsets in zip(vectors,positions):
        original=psbt_maps(vector["psbt"],len(vector["signatures"])+2)
        tx=m.CTransaction(); tx.version=2; tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(actual.sha256,index),b"",0xfffffffd) for index in offsets]
        tx.vout=[m.CTxOut(200000*len(offsets)-2000,destination_script)]
        records=[{b"\x00":tx.serialize_without_witness()}]
        for fields,index in zip(original[1:-1],offsets):
            fields={k:v for k,v in fields.items() if k[0] != 2}
            fields[b"\x00"]=actual.serialize()
            if b"\x01" in fields: fields[b"\x01"]=actual.vout[index].serialize()
            records.append(fields)
        records.append({}); unsigned=encode_maps(records)
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",unsigned,"--version",str(version))["psbt_hex"]
            sign(args,raw,vector["test_keys"],1999,reject=True)
            missing=psbt_maps(raw,len(offsets)+2)
            for fields in missing[1:-1]: fields.pop(b"\x00")
            sign(args,encode_maps(missing),vector["test_keys"],reject=True)
            result=sign(args,raw,vector["test_keys"])
            assert result["fee_sat"]==2000
            assert result["outputs"]==[{"value_sat":tx.vout[0].nValue,"script_pubkey":destination_script.hex()}]
            if not vector["sufficient"]:
                assert core_rpc(port,"finalizepsbt",[core_psbt(args,result["psbt_hex"]),False])["complete"] is False
                more=[wif(i.to_bytes(32,"big"),testnet=True) for i in (1,2)]
                result=sign(args,result["psbt_hex"],more)
                assert result["signatures_added"]==2 and result["signatures_checked"]==3
            partial=core_rpc(port,"decodepsbt",[core_psbt(args,result["psbt_hex"])])
            assert partial["tx"]["txid"]==result["unsigned_txid"]
            independent=core_rpc(port,"finalizepsbt",[core_psbt(args,result["psbt_hex"])])
            assert independent["complete"]
            ours=cli(args.node,"finalize-psbt",result["psbt_hex"])
            assert ours["tx_hex"]==independent["hex"]
            accepted=core_rpc(port,"testmempoolaccept",[[ours["tx_hex"]]])[0]
            assert accepted["allowed"],accepted
            assert round(accepted["fees"]["base"]*100000000)==2000
            if version==0: first=ours["tx_hex"]
            else: assert ours["tx_hex"]==first
            bad=psbt_maps(result["psbt_hex"],len(offsets)+2)
            sig=next(k for k in bad[1] if k[0]==2); value=bytearray(bad[1][sig]); value[12]^=1; bad[1][sig]=bytes(value)
            sign(args,encode_maps(bad),vector["test_keys"],reject=True)
        txids.append(core_rpc(port,"sendrawtransaction",[first]))
        print(f"PASSED: funded {vector['name']} Rust signing, Core partial/final bytes, fee/full-parent/corrupt rejection and actual mempool admission",flush=True)
    mined=core_rpc(port,"generatetoaddress",[1,address])[0]
    block=core_rpc(port,"getblock",[mined,1])
    assert set(txids)<=set(block["tx"])
    print(f"PASSED: all {len(txids)} independently funded Rust-signed spends mined by Core",flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind",type=Path,required=True)
    parser.add_argument("--node",type=Path,default=Path("target/release/btc-node"))
    parser.add_argument("--taproot-only",action="store_true",help="Run the independently funded Taproot key-path signer cases")
    parser.add_argument("--taproot-script-only",action="store_true",help="Run independently funded known Taproot leaf signer cases")
    args=parser.parse_args(); args.node=args.node.resolve(); args.bitcoind=args.bitcoind.resolve()
    port=free_port()
    with tempfile.TemporaryDirectory(prefix="btc-core-signer-") as directory:
        root=Path(directory)
        with (root/"core.log").open("w") as log:
            core=subprocess.Popen([str(args.bitcoind),"-regtest",f"-datadir={root}","-server","-listen=0","-dnsseed=0","-discover=0","-connect=0","-listenonion=0","-par=1",f"-rpcport={port}","-rpcbind=127.0.0.1","-rpcallowip=127.0.0.1","-rpcuser=interop","-rpcpassword=regtest-only","-fallbackfee=0.00002","-keypool=2"],stdout=log,stderr=log)
            try:
                wait_until(lambda:core_rpc(port,"getblockchaininfo",[]))
                core_rpc(port,"createwallet",["signer-interop"])
                # The shared strict WIF decoder also drives private descriptors.
                check_private_descriptor_vectors(args,port)
                if args.taproot_script_only:
                    from check_core_taproot_script_signer import run_cases as run_scripts
                    run_scripts(args,port)
                elif args.taproot_only:
                    from check_core_taproot_signer import run_cases as run_taproot
                    run_taproot(args,port)
                else:
                    run_cases(args,port)
                core_rpc(port,"stop",[]); core.wait(timeout=15); assert core.returncode==0
            except BaseException:
                print((root/"core.log").read_text()[-6000:]); raise
            finally:
                if core.poll() is None:
                    core.terminate()
                    try: core.wait(timeout=10)
                    except subprocess.TimeoutExpired: core.kill(); core.wait(timeout=10)


if __name__=="__main__":main()
