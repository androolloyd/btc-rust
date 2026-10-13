#!/usr/bin/env python3
"""Actual Core-funded known-leaf signing and independent Schnorr equations.

Runs in check_core_signer.py's disposable regtest sandbox. Only Core signs the
funding transaction; Rust signs every tested spend and each sequential cosigner.
"""
from io import BytesIO
import json
from pathlib import Path
from check_core_p2p import core_rpc
from check_core_psbt import cli,run_cli,psbt_maps,encode_maps,regtest_descriptor
from check_core_signer import sign,core_psbt
from core29_tapscript import reference


def test_keys(text):return [regtest_descriptor("pk("+value+")")[3:-1] for value in text]


def equations(key,s,tx,outputs,records):
    for i,(output,fields) in enumerate(zip(outputs,records,strict=True)):
        if bytes(output.scriptPubKey)[:2]!=b"\x51\x20":
            public=next(raw[1:] for raw in fields if raw[0]==2)
            code=s.CScript([s.OP_DUP,s.OP_HASH160,s.hash160(public),s.OP_EQUALVERIFY,s.OP_CHECKSIG])
            digest=s.SegwitV0SignatureHash(code,tx,i,1,output.nValue)
            verifier=key.ECPubKey();verifier.set(public)
            assert verifier.verify_ecdsa(fields[b"\x02"+public][:-1],digest)
            continue
        leaves={}
        for raw,value in fields.items():
            if raw[0]==0x15:
                leaves[s.TaggedHash("TapLeaf",bytes([value[-1]])+s.ser_string(value[:-1]))]=(value[:-1],value[-1])
        cache={}
        for raw,sig in fields.items():
            if raw[0]!=0x14:continue
            public,leaf_hash=raw[1:33],raw[33:]
            script,version=leaves[leaf_hash];assert version==0xc0
            mode=sig[64] if len(sig)==65 else 0;assert mode in (0,1)
            if (leaf_hash,mode) not in cache:
                cache[(leaf_hash,mode)]=s.TaprootSignatureHash(tx,outputs,mode,input_index=i,scriptpath=True,leaf_script=script,leaf_ver=version)
            assert key.verify_schnorr(public,sig[:64],cache[(leaf_hash,mode)])
        assert b"\x13" not in fields


def run_cases(args,port):
    key,s,m=reference()
    fixture=json.loads((Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/taproot-script-signer.json").read_text())
    vectors=fixture["vectors"]
    for vector in fixture["unsupported"]:
        sign(args,vector["psbt"],test_keys(vector["wifs"]),1000,reject=True,require_parents=False)
    for vector in vectors:
        vector["keys"]=test_keys(vector["wifs"]);source=psbt_maps(vector["psbt"],len(vector["script_pubkeys"])+2)
        tx=m.CTransaction();tx.deserialize(BytesIO(source[0][b"\x00"]))
        outputs=[m.CTxOut() for _ in source[1:-1]]
        for out,fields in zip(outputs,source[1:-1],strict=True):out.deserialize(BytesIO(fields[b"\x01"]))
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",vector["psbt"],"--version",str(version))["psbt_hex"]
            signed=sign(args,raw,vector["keys"],1000,require_parents=vector["mixed"])
            assert signed["signing_scope"]=="known_ecdsa_and_taproot_partial_signing"
            assert signed["schnorr_aux_randomness"]=="os_random_for_new_signatures"
            assert signed["input_signature_schemes"][-1]==("taproot_scriptpath_all" if vector["hash_type"] else "taproot_scriptpath_default")
            records=psbt_maps(signed["psbt_hex"],len(outputs)+2)
            equations(key,s,tx,outputs,records[1:-1])
            expected={b"\x14"+bytes.fromhex(row["record"]) for row in vector["expected"]}
            assert {raw for raw in records[-2] if raw[0]==0x14}==expected
            again=sign(args,signed["psbt_hex"],vector["keys"],1000,require_parents=vector["mixed"])
            assert again["signatures_added"]==0 and again["psbt_hex"]==signed["psbt_hex"]
            if vector["remaining_wifs"]:
                assert run_cli(args.node,"finalize-psbt",signed["psbt_hex"]).returncode!=0
                assert not core_rpc(port,"finalizepsbt",[core_psbt(args,signed["psbt_hex"])])["complete"]
                signed=sign(args,signed["psbt_hex"],test_keys(vector["remaining_wifs"]),1000,require_parents=False)
            final=cli(args.node,"finalize-psbt",signed["psbt_hex"])
            independent=core_rpc(port,"finalizepsbt",[core_psbt(args,signed["psbt_hex"])],timeout=30)
            assert independent["complete"] and independent["hex"]==final["tx_hex"]
    first=vectors[0]
    a=sign(args,first["psbt"],first["keys"],1000,require_parents=False)
    b=sign(args,first["psbt"],first["keys"],1000,require_parents=False)
    assert next(value for raw,value in psbt_maps(a["psbt_hex"])[1].items() if raw[0]==0x14)!=next(value for raw,value in psbt_maps(b["psbt_hex"])[1].items() if raw[0]==0x14)
    print(f"PASSED: {len(vectors)} Core leaf equations/templates, DEFAULT/ALL, both PSBT versions, nonce freshness, idempotence and 3 unsupported-only leaves",flush=True)
    address=core_rpc(port,"getnewaddress",[]);core_rpc(port,"generatetoaddress",[101,address],timeout=30)
    funding=m.CTransaction();funding.version=2;positions=[]
    for vector in vectors:
        offsets=[]
        for script in vector["script_pubkeys"]:
            offsets.append(len(funding.vout));funding.vout.append(m.CTxOut(200000,bytes.fromhex(script)))
        positions.append(offsets)
    funded=core_rpc(port,"fundrawtransaction",[funding.serialize_without_witness().hex(),{"changePosition":len(funding.vout)}])
    funded=core_rpc(port,"signrawtransactionwithwallet",[funded["hex"]]);assert funded["complete"]
    funding_id=core_rpc(port,"sendrawtransaction",[funded["hex"]]);core_rpc(port,"generatetoaddress",[1,address])
    parent=m.CTransaction();parent.deserialize(BytesIO(bytes.fromhex(funded["hex"])));parent.rehash();assert parent.hash==funding_id
    assert [(out.nValue,out.scriptPubKey) for out in parent.vout[:len(funding.vout)]]==[(out.nValue,out.scriptPubKey) for out in funding.vout]
    destination=core_rpc(port,"getnewaddress",[]);script=bytes.fromhex(core_rpc(port,"getaddressinfo",[destination])["scriptPubKey"])
    txids=[]
    for vector,offsets in zip(vectors,positions,strict=True):
        fee=50000 if len(vector["expected"])>=128 else 2000
        tx=m.CTransaction();tx.version=2;tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,index),b"",0xfffffffd) for index in offsets]
        tx.vout=[m.CTxOut(200000*len(offsets)-fee,script)]
        outputs=[parent.vout[index] for index in offsets]
        source=psbt_maps(vector["psbt"],len(offsets)+2)
        records=[{b"\x00":tx.serialize_without_witness()}]
        for i,fields in enumerate(source[1:-1]):
            fields={raw:value for raw,value in fields.items() if raw[0] not in (0,0x14)}
            fields[b"\x01"]=outputs[i].serialize()
            if vector["mixed"]:fields[b"\x00"]=parent.serialize()
            if vector["existing"]:
                row=vector["expected"][0];leaf=vector["signature_leaves"][row["record"][64:]]
                digest=s.TaprootSignatureHash(tx,outputs,vector["hash_type"],input_index=i,scriptpath=True,leaf_script=bytes.fromhex(leaf["script"]),leaf_ver=leaf["version"])
                fields[b"\x14"+bytes.fromhex(row["record"])]=key.sign_schnorr(bytes.fromhex(row["public_test_secret"]),digest,aux=bytes(32))
            records.append(fields)
        records.append({});unsigned=encode_maps(records)
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",unsigned,"--version",str(version))["psbt_hex"]
            sign(args,raw,vector["keys"],fee-1,reject=True,require_parents=False)
            signed=sign(args,raw,vector["keys"],fee,require_parents=vector["mixed"])
            assert signed["fee_sat"]==fee and signed["txid_linked_prevouts"]==[vector["mixed"]]*len(offsets)
            actual=psbt_maps(signed["psbt_hex"],len(offsets)+2);equations(key,s,tx,outputs,actual[1:-1])
            if vector["remaining_wifs"]:
                assert run_cli(args.node,"finalize-psbt",signed["psbt_hex"]).returncode!=0
                signed=sign(args,signed["psbt_hex"],test_keys(vector["remaining_wifs"]),fee,require_parents=False)
                equations(key,s,tx,outputs,psbt_maps(signed["psbt_hex"],len(offsets)+2)[1:-1])
            final=cli(args.node,"finalize-psbt",signed["psbt_hex"])
            independent=core_rpc(port,"finalizepsbt",[core_psbt(args,signed["psbt_hex"])],timeout=30)
            assert independent["complete"] and independent["hex"]==final["tx_hex"]
            acceptance=core_rpc(port,"testmempoolaccept",[[final["tx_hex"]]],timeout=30)[0]
            assert acceptance["allowed"],acceptance
            assert round(acceptance["fees"]["base"]*100000000)==fee
            bad=psbt_maps(signed["psbt_hex"],len(offsets)+2);record=next(raw for raw in reversed(bad[-2]) if raw[0]==0x14)
            sig=bytearray(bad[-2][record]);sig[20]^=1;bad[-2][record]=bytes(sig)
            sign(args,encode_maps(bad),vector["keys"],fee,reject=True,require_parents=False)
            missing=psbt_maps(unsigned,len(offsets)+2);missing[-2]={raw:value for raw,value in missing[-2].items() if raw[0]!=0x15}
            sign(args,encode_maps(missing),vector["keys"],fee,reject=True,require_parents=False)
            if vector["mixed"]:
                missing=psbt_maps(unsigned,len(offsets)+2);missing[-2].pop(b"\x00")
                sign(args,encode_maps(missing),vector["keys"],fee,reject=True,require_parents=False)
        txids.append(core_rpc(port,"sendrawtransaction",[final["tx_hex"]]))
        print(f"PASSED: funded {vector['name']}, independent Rust leaf signatures/Core equations/final bytes, fee/context/corrupt rejection and admission",flush=True)
    mined=core_rpc(port,"generatetoaddress",[1,address])[0]
    assert set(txids)<=set(core_rpc(port,"getblock",[mined,1])["tx"])
    print(f"PASSED: all {len(txids)} independently funded Rust leaf-signed spends mined by Core",flush=True)
