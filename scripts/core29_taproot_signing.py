#!/usr/bin/env python3
"""Independent key-path signer fixtures, with published BIP341 objects retained.

Generated cases use unchanged checksum-pinned Core modules and public test WIFs.
Synthetic outpoints prove offline equations only; funded/mined acceptance is a
separate check. Fixed auxiliary bytes are vectors, never a production RNG mode.
"""
import hashlib
import json
from pathlib import Path
import urllib.request

from core29_tapscript import reference,SOURCE,SOURCES
from core29_psbt_signing import wif,maps

BIP341="https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json"
BIP341_HASH="403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f"


def generate():
    raw=urllib.request.urlopen(BIP341,timeout=30).read()
    assert hashlib.sha256(raw).hexdigest()==BIP341_HASH
    published=json.loads(raw)["keyPathSpending"]
    k,s,m=reference()
    leaf_secret=(17).to_bytes(32,"big"); leaf_key=k.compute_xonly_pubkey(leaf_secret)[0]
    tree=[("known",bytes(s.CScript([leaf_key,s.OP_CHECKSIG]))),[("opaque",bytes(s.CScript([s.OP_RETURN])),0xc2),("third",bytes(s.CScript([s.OP_TRUE])))]]
    chosen={}
    for has_tree in (False,True):
        for number in range(1,256):
            secret=number.to_bytes(32,"big"); internal,odd=k.compute_xonly_pubkey(secret)
            tr=s.taproot_construct(internal,tree if has_tree else None)
            chosen.setdefault((has_tree,odd,bool(tr.negflag)),(secret,tr))
        assert len([entry for entry in chosen if entry[0]==has_tree])==4
    cases=[]
    def add(name,participants,proof=False,existing_leaf=False):
        parent=m.CTransaction(); parent.version=2
        parent.vin=[m.CTxIn(m.COutPoint(54321+len(cases),0),b"",0xfffffffd)]
        outputs=[]; records=[]; owners=[]
        for secret,tr,hash_type in participants:
            if tr is None:
                key=k.ECKey(); key.set(secret,True); public=key.get_pubkey().get_bytes()
                output=m.CTxOut(100000,bytes(s.CScript([0,s.hash160(public)])))
                records.append({}); owners.append(wif(secret)); outputs.append(output)
            else:
                output=m.CTxOut(100000,bytes(tr.scriptPubKey)); outputs.append(output)
                fields={b"\x01":output.serialize(),b"\x17":tr.internal_pubkey,b"\x03":hash_type.to_bytes(4,"little")}
                if tr.merkle_root and not proof: fields[b"\x18"]=tr.merkle_root
                if proof or existing_leaf:
                    for leaf in tr.leaves.values():
                        control=bytes([leaf.version|tr.negflag])+tr.internal_pubkey+leaf.merklebranch
                        fields[b"\x15"+control]=bytes(leaf.script)+bytes([leaf.version])
                records.append(fields); owners.append(wif(secret))
        parent.vout=outputs; parent.rehash()
        tx=m.CTransaction(); tx.version=2; tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,i),b"",0xfffffffd) for i in range(len(outputs))]
        tx.vout=[m.CTxOut(len(outputs)*100000-1000,bytes(s.CScript([s.OP_TRUE])))]
        signatures=[]
        mixed=any(tr is None for _,tr,_ in participants)
        for i,(secret,tr,hash_type) in enumerate(participants):
            if mixed: records[i][b"\x00"]=parent.serialize_without_witness()
            if tr is None:
                key=k.ECKey(); key.set(secret,True); public=key.get_pubkey().get_bytes()
                records[i][b"\x01"]=outputs[i].serialize()
                code=s.CScript([s.OP_DUP,s.OP_HASH160,s.hash160(public),s.OP_EQUALVERIFY,s.OP_CHECKSIG])
                digest=s.SegwitV0SignatureHash(code,tx,i,1,100000)
                signature=key.sign_ecdsa(digest,rfc6979=True)+b"\x01"
                signatures.append(dict(scheme="ecdsa_all",public_key=public.hex(),signature=signature.hex(),digest=digest.hex()))
            else:
                tweaked=k.tweak_add_privkey(secret,tr.tweak); assert tweaked is not None
                digest=s.TaprootSignatureHash(tx,outputs,hash_type,input_index=i)
                signature=k.sign_schnorr(tweaked,digest,aux=bytes(32))+(bytes([hash_type]) if hash_type else b"")
                signatures.append(dict(scheme="taproot_keypath_all" if hash_type else "taproot_keypath_default",public_key=tr.output_pubkey.hex(),signature=signature.hex(),digest=digest.hex(),
                                       internal_key=tr.internal_pubkey.hex(),merkle_root=tr.merkle_root.hex() if tr.merkle_root else None,tweaked_secret=tweaked.hex()))
                if existing_leaf:
                    leaf=tr.leaves["known"]
                    leaf_digest=s.TaprootSignatureHash(tx,outputs,0,input_index=i,scriptpath=True,leaf_script=s.CScript(leaf.script),leaf_ver=leaf.version)
                    records[i][b"\x14"+leaf_key+leaf.leaf_hash]=k.sign_schnorr(leaf_secret,leaf_digest,aux=bytes(32))
        cases.append(dict(name=name,wifs=owners,uncompressed_wifs=[wif(secret,False) for secret,_,_ in participants],opposite_wifs=[wif((k.ORDER-int.from_bytes(secret,"big")).to_bytes(32,"big")) for secret,_,_ in participants],psbt=maps([{b"\x00":tx.serialize_without_witness()},*records,{}]),signatures=signatures,
                          script_pubkeys=[bytes(out.scriptPubKey).hex() for out in outputs],auxiliary="00"*32))
    for (has_tree,odd_p,odd_q),(secret,tr) in chosen.items():
        for hash_type in (0,1):
            add(f"tree{int(has_tree)}-P{int(odd_p)}-Q{int(odd_q)}-hash{hash_type}",[(secret,tr,hash_type)])
    secret,tr=chosen[(True,True,True)]
    add("proof-inferred-root",[(secret,tr,0)],proof=True)
    add("existing-known-leaf",[(secret,tr,0)],existing_leaf=True)
    first=chosen[(False,False,False)]
    add("two-witness-only-taproot-inputs",[(first[0],first[1],0),(secret,tr,1)])
    add("mixed-ecdsa-taproot-inputs",[((3).to_bytes(32,"big"),None,1),(secret,tr,0)])
    # All published private tweaks and zero-aux Schnorr witnesses are retained,
    # including hash modes outside the bounded public signer API.
    for entry in published:
        for row in entry["inputSpending"]:
            given,intermediary=row["given"],row["intermediary"]
            secret=bytes.fromhex(given["internalPrivkey"])
            tweaked=k.tweak_add_privkey(secret,bytes.fromhex(intermediary["tweak"]))
            assert tweaked.hex()==intermediary["tweakedPrivkey"]
            signature=k.sign_schnorr(tweaked,bytes.fromhex(intermediary["sigHash"]),aux=bytes(32))
            if given["hashType"]: signature+=bytes([given["hashType"]])
            assert signature.hex()==row["expected"]["witness"][0]
    path=Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/taproot-key-signer.json"
    path.write_text(json.dumps(dict(source=SOURCE,sha256=SOURCES,license="Core reference modules: MIT; published BIP341: BSD-3-Clause",published_source=BIP341,published_sha256=BIP341_HASH,
                                   published=published,vectors=cases),indent=2)+"\n")
    path.with_suffix(".keys").write_text("\n".join(sorted({key for row in cases for key in row["wifs"]}))+"\n")
    print(f"Generated {len(cases)} independent key-path signer cases and retained {sum(len(entry['inputSpending']) for entry in published)} published private-tweak/signature vectors")


if __name__=="__main__":generate()
