#!/usr/bin/env python3
"""Generate ECDSA PSBT signer cases using checksum-pinned Core v29 modules.

Public test WIFs and synthetic txid-linked parents establish offline equations
only. check_core_signer.py supplies real funded/mined Core acceptance separately.
Core RFC6979/low-S signatures, scripts and preimages are generated without Rust.
"""
import hashlib
import json
from pathlib import Path

from core29_tapscript import reference, SOURCE, SOURCES


def compact(n):
    if n < 253: return bytes([n])
    return b"\xfd" + n.to_bytes(2, "little")


def maps(records):
    return (b"psbt\xff" + b"".join(b"".join(compact(len(k)) + k + compact(len(v)) + v
                 for k,v in sorted(record.items())) + b"\x00" for record in records)).hex()


def wif(secret, compressed=True, testnet=False):
    payload = bytes([0xef if testnet else 0x80]) + secret + (b"\x01" if compressed else b"")
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value, output = int.from_bytes(raw, "big"), ""
    while value:
        value, digit = divmod(value, 58); output = alphabet[digit] + output
    return output


def generate():
    k,s,m = reference()
    def material(number, compressed=True):
        secret = number.to_bytes(32, "big")
        key = k.ECKey(); key.set(secret, compressed)
        return key, key.get_pubkey().get_bytes(), wif(secret, compressed)
    def pk(public): return bytes(s.CScript([public,s.OP_CHECKSIG]))
    def pkh(public): return bytes(s.CScript([s.OP_DUP,s.OP_HASH160,s.hash160(public),s.OP_EQUALVERIFY,s.OP_CHECKSIG]))
    def wpkh(public): return bytes(s.CScript([0,s.hash160(public)]))
    def sh(code): return bytes(s.CScript([s.OP_HASH160,s.hash160(code),s.OP_EQUAL]))
    def wsh(code): return bytes(s.CScript([0,hashlib.sha256(code).digest()]))
    def multi(keys, sorted_keys=False, threshold=2):
        public = [entry[1] for entry in keys]
        if sorted_keys: public.sort()
        return bytes(s.CScript([threshold,*public,len(public),s.OP_CHECKMULTISIG]))
    keys = [material(i) for i in (3,1,2)]
    cases = []
    def add(name, code, owners, witness=False, wrap=None, subset=None):
        redeem = witness_script = None
        program = code
        if witness:
            if wrap == "wpkh": program = wpkh(owners[0][1])
            else: witness_script, program = code, wsh(code)
        if name.startswith("sh-"): redeem, program = program, sh(program)
        parent = m.CTransaction(); parent.version=2
        parent.vin=[m.CTxIn(m.COutPoint(123456+len(cases),0),b"",0xfffffffd)]
        parent.vout=[m.CTxOut(100000,program)]; parent.rehash()
        tx=m.CTransaction(); tx.version=2; tx.nLockTime=23
        tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,0),b"",0xfffffffd)]
        tx.vout=[m.CTxOut(99000,wpkh(material(99)[1]))]
        record={b"\x00":parent.serialize_without_witness(), b"\x03":(1).to_bytes(4,"little")}
        if witness: record[b"\x01"]=parent.vout[0].serialize()
        if redeem is not None: record[b"\x04"]=redeem
        if witness_script is not None: record[b"\x05"]=witness_script
        digest = s.SegwitV0SignatureHash(s.CScript(code),tx,0,1,100000) if witness else s.LegacySignatureHash(s.CScript(code),tx,0,1)[0]
        selected=owners if subset is None else owners[:subset]
        signatures=[dict(public_key=public.hex(), signature=(key.sign_ecdsa(digest,rfc6979=True)+b"\x01").hex(), digest=digest.hex())
                    for key,public,_ in selected]
        cases.append(dict(name=name, wifs=[entry[2] for entry in selected], psbt=maps([{b"\x00":tx.serialize_without_witness()},record,{}]),
                          signatures=[signatures], sufficient=subset is None))
    for compressed in (True,False):
        owner=[material(7,compressed)]
        for kind,code in [("pk",pk(owner[0][1])),("pkh",pkh(owner[0][1]))]:
            suffix="compressed" if compressed else "uncompressed"
            for prefix in ("","sh-"): add(prefix+kind+"-"+suffix,code,owner)
    for prefix in ("","sh-"):
        add(prefix+"wpkh",pkh(keys[0][1]),keys[:1],True,"wpkh")
        for kind,code in [("wsh-pk",pk(keys[0][1])),("wsh-pkh",pkh(keys[0][1]))]:
            add(prefix+kind,code,keys[:1],True)
    for sorted_keys in (False,True):
        code=multi(keys,sorted_keys)
        for prefix in ("","sh-","wsh-","sh-wsh-"):
            add(prefix+("sortedmulti" if sorted_keys else "multi"),code,keys,"wsh" in prefix)
    add("wsh-partial-2of3",multi(keys),keys,True,subset=1)
    sixteen=[material(i) for i in range(1,17)]
    add("wsh-16of16",multi(sixteen,True,16),sixteen,True)
    # Two independent BIP143 equations: neither commits the other's amount.
    owners=[material(1),material(2)]
    parent=m.CTransaction(); parent.version=2
    parent.vin=[m.CTxIn(m.COutPoint(654321,0),b"",0xfffffffd)]
    parent.vout=[m.CTxOut(100000,wpkh(entry[1])) for entry in owners]; parent.rehash()
    tx=m.CTransaction(); tx.version=2; tx.nLockTime=23
    tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,i),b"",0xfffffffd) for i in range(2)]
    tx.vout=[m.CTxOut(199000,wpkh(material(99)[1]))]
    records=[]; signatures=[]
    for i,(key,public,_) in enumerate(owners):
        records.append({b"\x00":parent.serialize_without_witness(),b"\x01":parent.vout[i].serialize()})
        digest=s.SegwitV0SignatureHash(s.CScript(pkh(public)),tx,i,1,100000)
        signatures.append([dict(public_key=public.hex(),signature=(key.sign_ecdsa(digest,rfc6979=True)+b"\x01").hex(),digest=digest.hex())])
    cases.append(dict(name="two-segwit-inputs",wifs=[entry[2] for entry in owners],psbt=maps([{b"\x00":tx.serialize_without_witness()},*records,{}]),signatures=signatures,sufficient=True))
    path=Path(__file__).resolve().parents[1]/"crates/primitives/tests/data/ecdsa-signer.json"
    path.write_text(json.dumps(dict(source=SOURCE,sha256=SOURCES,license="Core reference modules: MIT",vectors=cases),indent=2)+"\n")
    print(f"Generated {len(cases)} independent signer cases")


if __name__ == "__main__": generate()
