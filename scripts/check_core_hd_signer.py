#!/usr/bin/env python3
"""Actual HD private signing, independent Core math and funded/mined acceptance.

check_core_signer.py --hd-only owns the disposable Core sandbox. Core provides
funding and unsigned HD updater metadata; it never signs a tested spend.
"""
from io import BytesIO
import json,re,subprocess,tempfile
from pathlib import Path
from check_core_p2p import core_rpc
from check_core_psbt import cli,run_cli,psbt_maps,encode_maps,regtest_descriptor,encode64
from check_core_signer import core_psbt
from core29_tapscript import reference
from core29_wallet_thresholds import NUMS


def test_anchors(entries):return [regtest_descriptor('pk('+text+')')[3:-1] for text in entries]


def regtest_psbt(raw,count):
    records=psbt_maps(raw,count)
    for key in list(records[0]):
        if key[0]==1:
            value=records[0].pop(key);records[0][b'\x01'+bytes.fromhex('043587cf')+key[5:]]=value
    return encode_maps(records)


def sign_hd(args,raw,anchors,cap=2000,reject=False):
    with tempfile.NamedTemporaryFile(mode='w',prefix='btc-hd-private-') as key_file,tempfile.NamedTemporaryFile(prefix='btc-hd-psbt-') as psbt_file:
        key_file.write('\n'.join(anchors));key_file.flush();psbt_file.write(bytes.fromhex(raw));psbt_file.flush()
        command=[str(args.node),'--json','--network','regtest','sign-hd-psbt','@'+psbt_file.name,'--key-file',key_file.name,'--max-fee-sat',str(cap)]
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
    assert all(text not in result.stdout+result.stderr and text.split(']')[-1] not in result.stdout+result.stderr for text in anchors)
    if reject:
        assert result.returncode!=0 and not result.stdout.strip();return None
    assert result.returncode==0,result.stderr
    out=json.loads(result.stdout)
    assert out['signing_scope']=='hd_known_templates_partial_signing' and out['owned_input_derivations_verified']
    assert out['signatures_verified'] and out['partial_signatures_verified']
    assert all(out[field] is False for field in ['spending_conditions_verified','final_fields_verified','key_origins_verified','change_outputs_verified','active_chain_verified','output_derivations_verified','master_identity_authenticated'])
    assert out['input_derivations_checked']>0 and out['fee_sat']<=cap
    return out


def equations(key,s,tx,outputs,records):
    for i,(out,fields) in enumerate(zip(outputs,records,strict=True)):
        program=bytes(out.scriptPubKey)
        if program[:2]==b'\x51\x20':
            leaves={s.TaggedHash('TapLeaf',bytes([value[-1]])+s.ser_string(value[:-1])):(value[:-1],value[-1]) for raw,value in fields.items() if raw[0]==0x15}
            cache={}
            for raw,sig in fields.items():
                if raw[0] not in (0x13,0x14):continue
                mode=sig[64] if len(sig)==65 else 0;assert mode in (0,1)
                if raw[0]==0x13:
                    pub=program[2:]
                    if ('key',mode) not in cache:cache[('key',mode)]=s.TaprootSignatureHash(tx,outputs,mode,input_index=i)
                    digest=cache[('key',mode)]
                else:
                    pub=raw[1:33];script,version=leaves[raw[33:]];assert version==0xc0
                    if (raw[33:],mode) not in cache:cache[(raw[33:],mode)]=s.TaprootSignatureHash(tx,outputs,mode,input_index=i,scriptpath=True,leaf_script=script,leaf_ver=version)
                    digest=cache[(raw[33:],mode)]
                assert key.verify_schnorr(pub,sig[:64],digest)
        else:
            if program[:2]==b'\xa9\x14':program=fields[b'\x04']
            witness=program[:2] in (b'\0\x14',b'\0\x20')
            if program[:2]==b'\0\x14':code=bytes(s.CScript([s.OP_DUP,s.OP_HASH160,program[2:],s.OP_EQUALVERIFY,s.OP_CHECKSIG]))
            elif program[:2]==b'\0\x20':code=fields[b'\x05']
            else:code=program
            digest=s.SegwitV0SignatureHash(code,tx,i,1,out.nValue) if witness else s.LegacySignatureHash(s.CScript(code),tx,i,1)[0]
            for raw,sig in fields.items():
                if raw[0]==2:
                    public=key.ECPubKey();public.set(raw[1:]);assert sig[-1]==1 and public.verify_ecdsa(sig[:-1],digest)


def inspect_signed(args,port,key,s,tx,outputs,signed,anchors,fee):
    records=psbt_maps(signed['psbt_hex'],len(outputs)+2);equations(key,s,tx,outputs,records[1:-1])
    again=sign_hd(args,signed['psbt_hex'],anchors,fee)
    assert again['signatures_added']==0 and again['psbt_hex']==signed['psbt_hex']
    return records


def complete(args,port,signed,remaining,fee):
    if remaining:
        assert run_cli(args.node,'finalize-psbt',signed['psbt_hex']).returncode!=0
        assert not core_rpc(port,'finalizepsbt',[core_psbt(args,signed['psbt_hex'])])['complete']
        signed=sign_hd(args,signed['psbt_hex'],remaining,fee)
    final=cli(args.node,'finalize-psbt',signed['psbt_hex'])
    independent=core_rpc(port,'finalizepsbt',[core_psbt(args,signed['psbt_hex'])],timeout=60)
    assert independent['complete'] and independent['hex']==final['tx_hex']
    return signed,final


def run_cases(args,port):
    key,s,m=reference();root=Path(__file__).resolve().parents[1]
    vectors=json.loads((root/'crates/primitives/tests/data/hd-signer.json').read_text())['vectors']
    for vector in vectors:
        vector['keys']=test_anchors(vector['anchors']);vector['remaining']=test_anchors(vector['remaining_anchors'])
        raw=regtest_psbt(vector['psbt'],len(vector['expected'])+2);vector['regtest_psbt']=raw
        source=psbt_maps(raw,len(vector['expected'])+2);tx=m.CTransaction();tx.deserialize(BytesIO(source[0][b'\x00']))
        outputs=[]
        for i,fields in enumerate(source[1:-1]):
            if b'\x01' in fields:out=m.CTxOut();out.deserialize(BytesIO(fields[b'\x01']))
            else:
                parent=m.CTransaction();parent.deserialize(BytesIO(fields[b'\x00']));out=parent.vout[tx.vin[i].prevout.n]
            outputs.append(out)
        for version in (0,2):
            encoded=cli(args.node,'convert-psbt',raw,'--version',str(version))['psbt_hex']
            signed=sign_hd(args,encoded,vector['keys'],1000)
            records=inspect_signed(args,port,key,s,tx,outputs,signed,vector['keys'],1000)
            assert signed['input_derivations_checked']==len(vector['children'])
            if vector['deep'] and not vector['master_and_deep']:assert signed['anchor_master_paths_verified']==[False]
            else:assert all(signed['anchor_master_paths_verified'])
            for fields,expected in zip(records[1:-1],vector['expected'],strict=True):
                for row in expected:
                    raw_key=bytes.fromhex(row['record']);sig=fields[raw_key]
                    assert len(sig)==len(bytes.fromhex(row['signature']))
                    if raw_key[0]==2:assert sig.hex()==row['signature']
            complete(args,port,signed,vector['remaining'],1000)
    print(f'PASSED: {len(vectors)} independent real-HMAC HD cases, Core equations, both PSBT versions, exact ECDSA, partial cosigning and idempotence',flush=True)
    address=core_rpc(port,'getnewaddress',[]);core_rpc(port,'generatetoaddress',[101,address],timeout=30)
    funding=m.CTransaction();funding.version=2;positions=[]
    for vector in vectors:
        offsets=[]
        for script in vector['script_pubkeys']:offsets.append(len(funding.vout));funding.vout.append(m.CTxOut(200000,bytes.fromhex(script)))
        positions.append(offsets)
    funded=core_rpc(port,'fundrawtransaction',[funding.serialize_without_witness().hex(),{'changePosition':len(funding.vout)}]);funded=core_rpc(port,'signrawtransactionwithwallet',[funded['hex']]);assert funded['complete']
    funding_id=core_rpc(port,'sendrawtransaction',[funded['hex']]);core_rpc(port,'generatetoaddress',[1,address])
    parent=m.CTransaction();parent.deserialize(BytesIO(bytes.fromhex(funded['hex'])));parent.rehash();assert parent.hash==funding_id
    assert [(o.nValue,o.scriptPubKey) for o in parent.vout[:len(funding.vout)]]==[(o.nValue,o.scriptPubKey) for o in funding.vout]
    destination=core_rpc(port,'getnewaddress',[]);destination_script=bytes.fromhex(core_rpc(port,'getaddressinfo',[destination])['scriptPubKey']);txids=[]
    for vector,offsets in zip(vectors,positions,strict=True):
        fee=50000 if len(vector['children'])>=128 else 2000
        tx=m.CTransaction();tx.version=2;tx.nLockTime=23;tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,index),b'',0xfffffffd) for index in offsets];tx.vout=[m.CTxOut(len(offsets)*200000-fee,destination_script)]
        outputs=[parent.vout[index] for index in offsets];source=psbt_maps(vector['regtest_psbt'],len(offsets)+2)
        mixed=any(not kind.startswith('tr-') for kind in vector['input_kinds']);records=[{**source[0],b'\x00':tx.serialize_without_witness()}]
        for i,fields in enumerate(source[1:-1]):
            fields={raw:value for raw,value in fields.items() if raw[0]!=0}
            if b'\x01' in fields:fields[b'\x01']=outputs[i].serialize()
            if mixed:fields[b'\x00']=parent.serialize()
            records.append(fields)
        records.append({});unsigned=encode_maps(records)
        for version in (0,2):
            raw=cli(args.node,'convert-psbt',unsigned,'--version',str(version))['psbt_hex']
            sign_hd(args,raw,vector['keys'],fee-1,reject=True)
            signed=sign_hd(args,raw,vector['keys'],fee);assert signed['fee_sat']==fee and signed['txid_linked_prevouts']==[mixed]*len(offsets)
            actual=inspect_signed(args,port,key,s,tx,outputs,signed,vector['keys'],fee)
            signed,final=complete(args,port,signed,vector['remaining'],fee);equations(key,s,tx,outputs,psbt_maps(signed['psbt_hex'],len(offsets)+2)[1:-1])
            acceptance=core_rpc(port,'testmempoolaccept',[[final['tx_hex']]],timeout=60)[0];assert acceptance['allowed'],acceptance
            assert round(acceptance['fees']['base']*100000000)==fee
            bad=psbt_maps(signed['psbt_hex'],len(offsets)+2);index=next(i for i,fields in enumerate(bad[1:-1],1) if any(raw[0] in (2,0x13,0x14) for raw in fields))
            record=next(raw for raw in reversed(bad[index]) if raw[0] in (2,0x13,0x14));sig=bytearray(bad[index][record]);sig[20]^=1;bad[index][record]=bytes(sig)
            sign_hd(args,encode_maps(bad),vector['keys'],fee,reject=True)
            missing=psbt_maps(unsigned,len(offsets)+2);missing[1]={raw:value for raw,value in missing[1].items() if raw[0] not in (6,0x16)}
            sign_hd(args,encode_maps(missing),vector['keys'],fee,reject=True)
        txids.append(core_rpc(port,'sendrawtransaction',[final['tx_hex']]))
        print(f"PASSED: funded HD {vector['name']}, private derivation/Rust signatures/Core final bytes/admission and missing-origin/corrupt/fee rejection",flush=True)
    mined=core_rpc(port,'generatetoaddress',[1,address])[0];assert set(txids)<=set(core_rpc(port,'getblock',[mined,1])['tx'])
    print(f'PASSED: all {len(txids)} independently funded HD-signed spends mined by Core',flush=True)
    native_wallet_cases(args,port,key,s,m,address)


def run_native_cases(args,port):
    key,s,m=reference();address=core_rpc(port,'getnewaddress',[])
    core_rpc(port,'generatetoaddress',[101,address],timeout=30)
    native_wallet_cases(args,port,key,s,m,address)


def native_wallet_cases(args,port,key,s,m,address):
    # Preserve the original provider roots before importing additional scripts.
    # Private exports stay in process memory/temporary key files, never logs.
    entries=core_rpc(port,'listdescriptors',[True])['descriptors'];anchors=[]
    for entry in entries:
        anchors.extend(re.findall(r'(?:\[[0-9a-fA-F]{8}(?:/[0-9]+[h\x27]?)*\])?tprv[1-9A-HJ-NP-Za-km-z]{107}',entry['desc']))
    anchors=list(dict.fromkeys(anchors));assert anchors
    try:
        return native_wallet_with_anchors(args,port,key,s,m,address,anchors)
    except Exception as failure:
        message=str(failure)
        for text in anchors:
            message=message.replace(text,'[private anchor redacted]').replace(text.split(']')[-1],'[private anchor redacted]')
        raise RuntimeError(message) from None


def native_wallet_with_anchors(args,port,key,s,m,address,anchors):
    destinations=[]
    for kind in ['legacy','p2sh-segwit','bech32','bech32m']:destinations.append((kind,core_rpc(port,'getnewaddress',['',kind])))
    provider=anchors[0]
    for kind,expression in [('hardened-wsh',f'wsh(pk({provider}/0/7h))'),('hardened-tapleaf',f'tr({NUMS.hex()},pk({provider}/0/8h))'),('hardened-tapmulti',f'tr({NUMS.hex()},sortedmulti_a(2,{provider}/0/9h,{provider}/0/10h,{provider}/0/11h))')]:
        info=core_rpc(port,'getdescriptorinfo',[expression]);descriptor=expression+'#'+info['checksum']
        outcome=core_rpc(port,'importdescriptors',[[{'desc':descriptor,'timestamp':'now'}]])[0];assert outcome['success']
        destinations.append((kind,core_rpc(port,'deriveaddresses',[descriptor])[0]))
    targets={dest:0.002 for _,dest in destinations}
    funding_id=core_rpc(port,'sendmany',['',targets]);core_rpc(port,'generatetoaddress',[1,address])
    parent=m.CTransaction();parent.deserialize(BytesIO(bytes.fromhex(core_rpc(port,'gettransaction',[funding_id])['hex'])));parent.rehash()
    scripts={dest:bytes.fromhex(core_rpc(port,'getaddressinfo',[dest])['scriptPubKey']) for _,dest in destinations}
    destination=core_rpc(port,'getnewaddress',[]);out_script=bytes.fromhex(core_rpc(port,'getaddressinfo',[destination])['scriptPubKey']);txids=[]
    for kind,dest in destinations:
        index=next(i for i,out in enumerate(parent.vout) if bytes(out.scriptPubKey)==scripts[dest]);output=parent.vout[index]
        tx=m.CTransaction();tx.version=2;tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,index),b'',0xfffffffd)];tx.vout=[m.CTxOut(output.nValue-2000,out_script)]
        raw=encode_maps([{b'\x00':tx.serialize_without_witness()},{},{}]);updated=core_rpc(port,'walletprocesspsbt',[encode64(raw),False,'ALL',True,False])
        import base64
        records=psbt_maps(base64.b64decode(updated['psbt']).hex())
        assert not any(raw[0] in (2,0x13,0x14) for raw in records[1])
        records[1][b'\x00']=parent.serialize();unsigned=encode_maps(records)
        for version in (0,2):
            raw=cli(args.node,'convert-psbt',unsigned,'--version',str(version))['psbt_hex']
            signed=sign_hd(args,raw,anchors);inspect_signed(args,port,key,s,tx,[output],signed,anchors,2000)
            _,final=complete(args,port,signed,[],2000)
            accepted=core_rpc(port,'testmempoolaccept',[[final['tx_hex']]])[0];assert accepted['allowed'],accepted
        txids.append(core_rpc(port,'sendrawtransaction',[final['tx_hex']]))
        print(f'PASSED: actual Core HD provider {kind}, unsigned updater origins, hardened private derivation, Rust-only signing and Core admission',flush=True)
    mined=core_rpc(port,'generatetoaddress',[1,address])[0];assert set(txids)<=set(core_rpc(port,'getblock',[mined,1])['tx'])
    print(f'PASSED: {len(txids)} actual Core HD provider spends mined; no spend signed by Core',flush=True)
