#!/usr/bin/env python3
"""Taproot signer acceptance using actual Core-funded outputs and new Rust signatures.

Invoked by check_core_signer.py --taproot-only in its disposable Core sandbox.
Random signatures are checked with independent Core math/preimages and through
actual Core mempool/block validation. No Rust signatures fund the test outputs.
"""
from io import BytesIO
import json
from pathlib import Path

from check_core_p2p import core_rpc
from check_core_psbt import cli,psbt_maps,encode_maps,regtest_descriptor
from check_core_signer import sign,core_psbt
from core29_tapscript import reference


def check_equations(key,s,tx,outputs,fields,schemes):
    for i,(record,scheme) in enumerate(zip(fields,schemes)):
        if scheme.startswith("taproot"):
            sig=record[b"\x13"]; hash_type=1 if scheme.endswith("all") else 0
            assert len(sig)==(65 if hash_type else 64)
            if hash_type: assert sig[-1]==1
            digest=s.TaprootSignatureHash(tx,outputs,hash_type,input_index=i)
            assert key.verify_schnorr(bytes(outputs[i].scriptPubKey)[2:],sig[:64],digest)
        else:
            public=next(raw[1:] for raw in record if raw[0]==2)
            code=s.CScript([s.OP_DUP,s.OP_HASH160,s.hash160(public),s.OP_EQUALVERIFY,s.OP_CHECKSIG])
            digest=s.SegwitV0SignatureHash(code,tx,i,1,outputs[i].nValue)
            verifier=key.ECPubKey();verifier.set(public)
            assert verifier.verify_ecdsa(record[b"\x02"+public][:-1],digest)


def run_cases(args,port):
    key,s,m=reference()
    vectors=json.loads((Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/taproot-key-signer.json").read_text())["vectors"]
    for vector in vectors:
        keys=[regtest_descriptor("pk("+text+")")[3:-1] for text in vector["wifs"]]
        vector["test_keys"]=keys
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",vector["psbt"],"--version",str(version))["psbt_hex"]
            result=sign(args,raw,keys,1000,require_parents=False)
            assert result["schnorr_aux_randomness"]=="os_random_for_new_signatures"
            assert result["input_signature_schemes"]==[entry["scheme"] for entry in vector["signatures"]]
            records=psbt_maps(result["psbt_hex"],len(vector["signatures"])+2)
            for record,expected in zip(records[1:-1],vector["signatures"]):
                if expected["scheme"].startswith("taproot"):
                    sig=record[b"\x13"]
                    assert key.verify_schnorr(bytes.fromhex(expected["public_key"]),sig[:64],bytes.fromhex(expected["digest"]))
                    assert len(sig)==len(bytes.fromhex(expected["signature"]))
                else:
                    assert record[b"\x02"+bytes.fromhex(expected["public_key"])].hex()==expected["signature"]
            again=sign(args,result["psbt_hex"],keys,1000,require_parents=False)
            assert again["signatures_added"]==0 and again["psbt_hex"]==result["psbt_hex"]
            final=cli(args.node,"finalize-psbt",result["psbt_hex"])
            independent=core_rpc(port,"finalizepsbt",[core_psbt(args,result["psbt_hex"])])
            assert independent["complete"] and independent["hex"]==final["tx_hex"]
    # Fresh signing has fresh supplemental nonce data; re-signing existing
    # verified records above is intentionally idempotent instead.
    first=vectors[0]
    a=sign(args,first["psbt"],first["test_keys"],1000,require_parents=False)
    b=sign(args,first["psbt"],first["test_keys"],1000,require_parents=False)
    assert psbt_maps(a["psbt_hex"])[1][b"\x13"]!=psbt_maps(b["psbt_hex"])[1][b"\x13"]
    print(f"PASSED: {len(vectors)} independent key-path equations, 64/65-byte signatures, both PSBT versions, fresh entropy and idempotence",flush=True)
    address=core_rpc(port,"getnewaddress",[])
    core_rpc(port,"generatetoaddress",[101,address],timeout=30)
    funding=m.CTransaction();funding.version=2;positions=[]
    for vector in vectors:
        offsets=[]
        for script in vector["script_pubkeys"]:
            offsets.append(len(funding.vout));funding.vout.append(m.CTxOut(200000,bytes.fromhex(script)))
        positions.append(offsets)
    funded=core_rpc(port,"fundrawtransaction",[funding.serialize_without_witness().hex(),{"changePosition":len(funding.vout)}])
    funded=core_rpc(port,"signrawtransactionwithwallet",[funded["hex"]]);assert funded["complete"]
    funding_id=core_rpc(port,"sendrawtransaction",[funded["hex"]]);core_rpc(port,"generatetoaddress",[1,address])
    parent=m.CTransaction();parent.deserialize(BytesIO(bytes.fromhex(funded["hex"])));parent.rehash()
    assert parent.hash==funding_id
    assert [(out.nValue,out.scriptPubKey) for out in parent.vout[:len(funding.vout)]]==[(out.nValue,out.scriptPubKey) for out in funding.vout]
    destination=core_rpc(port,"getnewaddress",[])
    destination_script=bytes.fromhex(core_rpc(port,"getaddressinfo",[destination])["scriptPubKey"])
    txids=[]
    for vector,offsets in zip(vectors,positions):
        source=psbt_maps(vector["psbt"],len(offsets)+2)
        tx=m.CTransaction();tx.version=2;tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,index),b"",0xfffffffd) for index in offsets]
        tx.vout=[m.CTxOut(200000*len(offsets)-2000,destination_script)]
        records=[{b"\x00":tx.serialize_without_witness()}]
        outputs=[parent.vout[index] for index in offsets]
        schemes=[entry["scheme"] for entry in vector["signatures"]]
        mixed="ecdsa_all" in schemes
        for i,(fields,index) in enumerate(zip(source[1:-1],offsets)):
            # Existing synthetic-parent signatures cannot sign this actual
            # funding transaction. Recompute that one independent leaf record.
            fields={raw:value for raw,value in fields.items() if raw[0] not in (0,0x14)}
            fields[b"\x01"]=outputs[i].serialize()
            if mixed:fields[b"\x00"]=parent.serialize()
            if vector["name"]=="existing-known-leaf":
                control,leaf=next((raw[1:],value) for raw,value in fields.items() if raw[0]==0x15 and value[-1]==0xc0 and len(value[:-1])==34)
                digest=s.TaprootSignatureHash(tx,outputs,0,input_index=i,scriptpath=True,leaf_script=s.CScript(leaf[:-1]))
                leaf_secret=(17).to_bytes(32,"big");public=key.compute_xonly_pubkey(leaf_secret)[0]
                leaf_hash=s.TaggedHash("TapLeaf",bytes([leaf[-1]])+s.ser_string(leaf[:-1]))
                fields[b"\x14"+public+leaf_hash]=key.sign_schnorr(leaf_secret,digest,aux=bytes(32))
            records.append(fields)
        records.append({});unsigned=encode_maps(records)
        for version in (0,2):
            raw=cli(args.node,"convert-psbt",unsigned,"--version",str(version))["psbt_hex"]
            sign(args,raw,vector["test_keys"],1999,reject=True,require_parents=False)
            signed=sign(args,raw,vector["test_keys"],require_parents=mixed)
            assert signed["fee_sat"]==2000 and signed["txid_linked_prevouts"]==[mixed]*len(offsets)
            actual=psbt_maps(signed["psbt_hex"],len(offsets)+2)
            check_equations(key,s,tx,outputs,actual[1:-1],schemes)
            final=cli(args.node,"finalize-psbt",signed["psbt_hex"])
            independent=core_rpc(port,"finalizepsbt",[core_psbt(args,signed["psbt_hex"])])
            assert independent["complete"] and independent["hex"]==final["tx_hex"]
            acceptance=core_rpc(port,"testmempoolaccept",[[final["tx_hex"]]])[0]
            assert acceptance["allowed"],acceptance
            assert round(acceptance["fees"]["base"]*100000000)==2000
            bad=psbt_maps(signed["psbt_hex"],len(offsets)+2)
            index=next(i for i,fields in enumerate(bad) if b"\x13" in fields)
            sig=bytearray(bad[index][b"\x13"]);sig[20]^=1;bad[index][b"\x13"]=bytes(sig)
            sign(args,encode_maps(bad),vector["test_keys"],reject=True,require_parents=False)
            if len(offsets)==2 and not mixed:
                changed=psbt_maps(signed["psbt_hex"],len(offsets)+2)
                value=bytearray(changed[2][b"\x01"]);value[:8]=(200001).to_bytes(8,"little");changed[2][b"\x01"]=bytes(value)
                sign(args,encode_maps(changed),vector["test_keys"],cap=2001,reject=True,require_parents=False)
            if mixed:
                missing=psbt_maps(unsigned,len(offsets)+2);missing[2].pop(b"\x00")
                sign(args,encode_maps(missing),vector["test_keys"],reject=True,require_parents=False)
            elif b"\x18" in records[1] and not any(raw[0]==0x15 for raw in records[1]):
                missing=psbt_maps(unsigned,len(offsets)+2);missing[1].pop(b"\x18")
                sign(args,encode_maps(missing),vector["test_keys"],reject=True,require_parents=False)
            if vector["name"]=="existing-known-leaf":
                bad=psbt_maps(signed["psbt_hex"]);leaf=next(raw for raw in bad[1] if raw[0]==0x14)
                sig=bytearray(bad[1][leaf]);sig[20]^=1;bad[1][leaf]=bytes(sig)
                sign(args,encode_maps(bad),vector["test_keys"],reject=True,require_parents=False)
        txids.append(core_rpc(port,"sendrawtransaction",[final["tx_hex"]]))
        print(f"PASSED: funded {vector['name']} real Rust key-path signing, independent equations, Core finalization/admission and context/corrupt rejection",flush=True)
    mined=core_rpc(port,"generatetoaddress",[1,address])[0]
    assert set(txids)<=set(core_rpc(port,"getblock",[mined,1])["tx"])
    print(f"PASSED: all {len(txids)} independently funded Rust-signed Taproot/mixed spends mined by Core",flush=True)
