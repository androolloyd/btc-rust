#!/usr/bin/env python3
"""Generate known Taproot leaf signer cases with unchanged pinned Core modules.

Public test WIFs and synthetic parents establish independent equations only.
Actual funded/mined acceptance is in check_core_taproot_script_signer.py.
"""
import json
from pathlib import Path
from core29_tapscript import reference,SOURCE,SOURCES
from core29_psbt_signing import wif,maps
from core29_wallet_thresholds import NUMS


def generate():
    key,s,m=reference()
    material={}
    def owner(n):
        if n not in material:
            secret=n.to_bytes(32,"big");public,odd=key.compute_xonly_pubkey(secret)
            material[n]=(secret,public,odd)
        return material[n]
    def pk(n):return bytes(s.CScript([owner(n)[1],s.OP_CHECKSIG]))
    def multi(numbers,threshold,sort=False):
        public=[owner(n)[1] for n in numbers]
        if sort:public.sort()
        code=[]
        for i,pub in enumerate(public):code.extend([pub,s.OP_CHECKSIG if i==0 else s.OP_CHECKSIGADD])
        return bytes(s.CScript(code+[threshold,s.OP_NUMEQUAL]))
    even=next(n for n in range(1,20) if not owner(n)[2]);odd=next(n for n in range(1,20) if owner(n)[2])
    cases=[]
    def add(name,tree,numbers,hash_type=0,remaining=(),mixed=False,omit_internal=False,existing=False):
        tr=s.taproot_construct(NUMS,tree)
        parent=m.CTransaction();parent.version=2
        parent.vin=[m.CTxIn(m.COutPoint(83000+len(cases),0),b"",0xfffffffd)]
        parent.vout=[m.CTxOut(100000,tr.scriptPubKey)]
        if mixed:parent.vout.insert(0,m.CTxOut(100000,bytes(s.CScript([0,s.hash160(bytes([2|owner(3)[2]])+owner(3)[1])]))))
        parent.rehash()
        tx=m.CTransaction();tx.version=2;tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,i),b"",0xfffffffd) for i in range(len(parent.vout))]
        tx.vout=[m.CTxOut(len(parent.vout)*100000-1000,b"\x51")]
        fields={b"\x01":parent.vout[-1].serialize(),b"\x03":hash_type.to_bytes(4,"little")}
        if not omit_internal:fields[b"\x17"]=NUMS
        for leaf in tr.leaves.values():
            control=bytes([leaf.version|tr.negflag])+NUMS+leaf.merklebranch
            fields[b"\x15"+control]=bytes(leaf.script)+bytes([leaf.version])
        def signatures(selected):
            records={}
            for leaf in tr.leaves.values():
                if leaf.version!=0xc0:continue
                digest=s.TaprootSignatureHash(tx,parent.vout,hash_type,input_index=len(parent.vout)-1,scriptpath=True,leaf_script=leaf.script,leaf_ver=leaf.version)
                for n in selected:
                    secret,public,_=owner(n)
                    # These generated templates use canonical 32-byte pushes;
                    # only actual known template leaves belong to the signer.
                    if bytes([32])+public not in bytes(leaf.script) or bytes(leaf.script).startswith(bytes([s.OP_CODESEPARATOR])):continue
                    record=public+leaf.leaf_hash
                    signature=key.sign_schnorr(secret,digest,aux=bytes(32))+(bytes([hash_type]) if hash_type else b"")
                    records[record.hex()]=dict(record=record.hex(),signature=signature.hex(),digest=digest.hex(),public_key=public.hex(),public_test_secret=secret.hex())
            return [records[record] for record in sorted(records)]
        expected=signatures(numbers)
        signature_leaves={leaf.leaf_hash.hex():dict(script=bytes(leaf.script).hex(),version=leaf.version) for leaf in tr.leaves.values() if any(row["record"][64:]==leaf.leaf_hash.hex() for row in expected+signatures(remaining))}
        if existing:
            record=expected[0];fields[b"\x14"+bytes.fromhex(record["record"])]=bytes.fromhex(record["signature"])
        records=[];wifs=[]
        if mixed:
            fields[b"\x00"]=parent.serialize_without_witness()
            records.append({b"\x00":parent.serialize_without_witness(),b"\x01":parent.vout[0].serialize(),b"\x03":(1).to_bytes(4,"little")})
            wifs.append(wif(owner(3)[0]))
        records.append(fields);wifs.extend(wif(owner(n)[0]) for n in sorted(set(numbers)))
        cases.append(dict(name=name,psbt=maps([{b"\x00":tx.serialize_without_witness()},*records,{}]),wifs=list(dict.fromkeys(wifs)),remaining_wifs=[wif(owner(n)[0]) for n in remaining],
                          expected=expected,remaining_expected=signatures(remaining),signature_leaves=signature_leaves,existing=existing,mixed=mixed,hash_type=hash_type,script_pubkeys=[bytes(out.scriptPubKey).hex() for out in parent.vout],
                          opposite_wifs=[wif((key.ORDER-int.from_bytes(owner(n)[0],"big")).to_bytes(32,"big")) for n in sorted(set(numbers))],uncompressed_wifs=[wif(owner(n)[0],False) for n in sorted(set(numbers))]))
    for n in (even,odd):
        for mode in (0,1):add(f"pk-P{int(owner(n)[2])}-hash{mode}",[("pk",pk(n))],[n],mode)
    for sort in (False,True):
        for mode in (0,1):add(f"{'sorted' if sort else ''}multi-a-2of3-hash{mode}",[("multi",multi([3,1,2],2,sort))],[3,1,2],mode)
    add("partial-2of3",[("multi",multi([1,2,3],2))],[1],remaining=[2])
    add("repeated-key-2of3",[("multi",multi([odd]*3,2))],[odd])
    add("multiple-known-and-opaque",[("pk",pk(odd)),[("multi",multi([odd,7],1)),("opaque",bytes(s.CScript([s.OP_RETURN])),0xc2)]],[odd])
    add("duplicate-leaf-proofs",[("pk",pk(odd)),[("again",pk(odd)),("opaque",b"\x6a")]], [odd])
    add("no-optional-internal",[("pk",pk(odd))],[odd],omit_internal=True)
    add("existing-known-record",[("multi",multi([1,2,3],2))],[1,2,3],existing=True)
    add("mixed-ecdsa-scriptpath",[("pk",pk(odd))],[odd],mixed=True)
    add("128of128",[("multi",multi(list(range(1,129)),128))],list(range(1,129)))
    add("999of999",[("multi",multi(list(range(1,1000)),999))],list(range(1,1000)))
    # Unsupported-only leaves supply real commitments but no signing authority.
    denied=[]
    for name,script,version in [("separator",bytes(s.CScript([s.OP_CODESEPARATOR,owner(odd)[1],s.OP_CHECKSIG])),0xc0),
                                ("future-leaf",pk(odd),0xc2),("op-success",b"\x50",0xc0)]:
        tr=s.taproot_construct(NUMS,[("leaf",script,version)]);leaf=tr.leaves["leaf"]
        tx=m.CTransaction();tx.version=2;tx.vin=[m.CTxIn(m.COutPoint(99999+len(denied),0),b"",0xfffffffd)];tx.vout=[m.CTxOut(99000,b"\x51")]
        control=bytes([version|tr.negflag])+NUMS+leaf.merklebranch
        fields={b"\x01":m.CTxOut(100000,tr.scriptPubKey).serialize(),b"\x15"+control:script+bytes([version])}
        denied.append(dict(name=name,psbt=maps([{b"\x00":tx.serialize_without_witness()},fields,{}]),wifs=[wif(owner(odd)[0])]))
    path=Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/taproot-script-signer.json"
    path.write_text(json.dumps(dict(source=SOURCE,sha256=SOURCES,license="MIT",scope="Generated Core reference equations with synthetic outpoints; funded acceptance is separate.",vectors=cases,unsupported=denied),indent=2)+"\n")
    path.with_suffix(".keys").write_text("\n".join(sorted({text for vector in cases if len(vector['wifs'])<=24 for text in vector['wifs']}))+"\n")
    print(f"Generated {len(cases)} known script signer cases and {len(denied)} unsupported committed leaves",flush=True)


if __name__=="__main__":generate()
