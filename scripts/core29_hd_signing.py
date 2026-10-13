#!/usr/bin/env python3
"""Independent real-HMAC HD signing fixtures; no Rust participates.

Standard-library HMAC/serialization and unchanged checksum-pinned Core curve,
script, preimage and signature code. Published BIP32 keys cross-check all 17
real-seed paths. Synthetic parents prove offline equations, not chain state.
"""
import hashlib,hmac,json
from pathlib import Path
from core29_tapscript import reference,SOURCE,SOURCES
from core29_psbt_signing import maps
from core29_wallet_thresholds import NUMS

ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58(payload):
    raw=payload+hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n=int.from_bytes(raw,'big');out=''
    while n:n,d=divmod(n,58);out=ALPHABET[d]+out
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+out


def master(seed):
    data=hmac.new(b'Bitcoin seed',seed,hashlib.sha512).digest()
    return dict(secret=data[:32],chain=data[32:],depth=0,parent=bytes(4),child=0)


def public(key,k):
    ec=k.ECKey();ec.set(key['secret'],True)
    return ec.get_pubkey().get_bytes()


def fingerprint(key,k,s):return s.hash160(public(key,k))[:4]


def derive(key,path,k,s):
    for index in path:
        data=(b'\0'+key['secret'] if index&0x80000000 else public(key,k))+index.to_bytes(4,'big')
        hashed=hmac.new(key['chain'],data,hashlib.sha512).digest()
        left=int.from_bytes(hashed[:32],'big');assert left<k.ORDER
        scalar=(int.from_bytes(key['secret'],'big')+left)%k.ORDER;assert scalar
        key=dict(secret=scalar.to_bytes(32,'big'),chain=hashed[32:],depth=key['depth']+1,parent=fingerprint(key,k,s),child=index)
    return key


def serialize(key,k,private=True,testnet=False):
    version=(0x04358394 if testnet else 0x0488ade4) if private else (0x043587cf if testnet else 0x0488b21e)
    return version.to_bytes(4,'big')+bytes([key['depth']])+key['parent']+key['child'].to_bytes(4,'big')+key['chain']+(b'\0'+key['secret'] if private else public(key,k))


def origin(fp,path):return fp+b''.join(i.to_bytes(4,'little') for i in path)
def path_text(path):return '/'.join(str(i&0x7fffffff)+('h' if i&0x80000000 else '') for i in path)


def generate():
    k,s,m=reference();root=Path(__file__).resolve().parents[1]
    published=json.loads((root/'crates/primitives/tests/data/bip32-keys.json').read_text())['valid_keys']
    for row in published:
        child=derive(master(bytes.fromhex(row['seed_hex'])),row['child_indices'],k,s)
        assert base58(serialize(child,k))==row['xprv'] and base58(serialize(child,k,False))==row['xpub']
    seeds=[bytes(range(16)),bytes(range(16,32)),bytes(range(32,48))]
    roots=[master(seed) for seed in seeds];fps=[fingerprint(key,k,s) for key in roots]
    anchors=[base58(serialize(key,k)) for key in roots]
    vectors=[]
    def owner(r=0,index=0,purpose=84,hard=False):
        path=[purpose|0x80000000,0x80000000,0x80000000,0,index|(0x80000000 if hard else 0)]
        key=derive(roots[r],path,k,s)
        return dict(root=r,path=path,key=key,public=public(key,k),xonly=public(key,k)[1:])
    def multi(owners,n,tap=False,sort=False):
        pubs=[owner['xonly'] if tap else owner['public'] for owner in owners]
        if sort:pubs.sort()
        if not tap:return bytes(s.CScript([n,*pubs,len(pubs),s.OP_CHECKMULTISIG]))
        code=[]
        for i,pub in enumerate(pubs):code.extend([pub,s.OP_CHECKSIG if i==0 else s.OP_CHECKSIGADD])
        return bytes(s.CScript(code+[n,s.OP_NUMEQUAL]))
    def build(kind,owners,mode=0,partial=False,hard=False):
        first=owners[0];fields={};code=None;leaf=None;tr=None
        if kind.startswith('tr-'):
            if kind=='tr-key':tr=s.taproot_construct(first['xonly'])
            elif kind=='tr-tree-key':tr=s.taproot_construct(first['xonly'],[('leaf',bytes(s.CScript([owners[-1]['xonly'],s.OP_CHECKSIG])))])
            else:
                code=bytes(s.CScript([first['xonly'],s.OP_CHECKSIG])) if kind=='tr-pk' else multi(owners,2,True,'sorted' in kind)
                tr=s.taproot_construct(NUMS,[('leaf',code)]);leaf=tr.leaves['leaf']
            program=bytes(tr.scriptPubKey);fields[b'\x17']=tr.internal_pubkey
            if tr.merkle_root:fields[b'\x18']=tr.merkle_root
            for value in tr.leaves.values():
                fields[b'\x15'+bytes([value.version|tr.negflag])+tr.internal_pubkey+value.merklebranch]=bytes(value.script)+bytes([value.version])
            if leaf:fields[b'\x16'+NUMS]=b'\0'+bytes(4) # literal NUMS origin is foreign metadata
            key_owners=owners if leaf else owners[:1]
            for entry in key_owners:
                fields[b'\x16'+entry['xonly']]=(b'\x01'+leaf.leaf_hash if leaf else b'\0')+origin(fps[entry['root']],entry['path'])
            fields[b'\x03']=mode.to_bytes(4,'little')
            witness=True
        else:
            witness='w' in kind;pub=first['public']
            if kind=='pk-uncompressed':
                ec=k.ECKey();ec.set(first['key']['secret'],False);pub=ec.get_pubkey().get_bytes()
            if 'multi' in kind:code=multi(owners,2,False,'sorted' in kind)
            elif kind.endswith('pk') or kind in ('pk','pk-uncompressed'):code=bytes(s.CScript([pub,s.OP_CHECKSIG]))
            else:code=bytes(s.CScript([s.OP_DUP,s.OP_HASH160,s.hash160(pub),s.OP_EQUALVERIFY,s.OP_CHECKSIG]))
            if 'wpkh' in kind:program=bytes(s.CScript([0,s.hash160(pub)]))
            elif 'wsh' in kind:fields[b'\x05']=code;program=bytes(s.CScript([0,hashlib.sha256(code).digest()]))
            else:program=code
            if kind.startswith('sh-'):
                fields[b'\x04']=program;program=bytes(s.CScript([s.OP_HASH160,s.hash160(program),s.OP_EQUAL]))
            for entry in owners:fields[b'\x06'+(pub if kind=='pk-uncompressed' else entry['public'])]=origin(fps[entry['root']],entry['path'])
            fields[b'\x03']=(1).to_bytes(4,'little')
        return dict(kind=kind,owners=owners,mode=mode,partial=partial,fields=fields,program=program,code=code,leaf=leaf,tr=tr,witness=witness)
    def add(name,parts,selected=(0,),deep=False,both=False):
        parent=m.CTransaction();parent.version=2;parent.vin=[m.CTxIn(m.COutPoint(120000+len(vectors),0),b'',0xfffffffd)]
        parent.vout=[m.CTxOut(100000,part['program']) for part in parts];parent.rehash()
        tx=m.CTransaction();tx.version=2;tx.nLockTime=23;tx.vin=[m.CTxIn(m.COutPoint(parent.sha256,i),b'',0xfffffffd) for i in range(len(parts))]
        tx.vout=[m.CTxOut(len(parts)*100000-1000,b'\x51')]
        records=[];expected=[];children=[]
        mixed=any(not part['kind'].startswith('tr-') for part in parts)
        for i,part in enumerate(parts):
            fields=part['fields'].copy()
            if part['witness']:fields[b'\x01']=parent.vout[i].serialize()
            if mixed:fields[b'\x00']=parent.serialize_without_witness()
            signatures=[]
            for entry in part['owners']:
                if entry['root'] not in selected or (part['tr'] and not part['leaf'] and entry is not part['owners'][0]):continue
                secret=entry['key']['secret'];pub=entry['public'];hash_type=part['mode'] if part['tr'] else 1
                if part['tr']:
                    if part['leaf']:
                        leaf_hash=part['leaf'].leaf_hash;digest=s.TaprootSignatureHash(tx,parent.vout,hash_type,input_index=i,scriptpath=True,leaf_script=part['code'])
                        record=b'\x14'+entry['xonly']+leaf_hash;signing_secret=secret
                    else:
                        leaf_hash=None;digest=s.TaprootSignatureHash(tx,parent.vout,hash_type,input_index=i)
                        record=b'\x13';signing_secret=k.tweak_add_privkey(secret,part['tr'].tweak)
                    signature=k.sign_schnorr(signing_secret,digest,aux=bytes(32))+(bytes([hash_type]) if hash_type else b'')
                else:
                    ec=k.ECKey();ec.set(secret,part['kind']!='pk-uncompressed');pub=ec.get_pubkey().get_bytes()
                    digest=s.SegwitV0SignatureHash(part['code'],tx,i,1,100000) if part['witness'] else s.LegacySignatureHash(s.CScript(part['code']),tx,i,1)[0]
                    signature=ec.sign_ecdsa(digest,rfc6979=True)+b'\x01';record=b'\x02'+pub;leaf_hash=None
                signatures.append(dict(record=record.hex(),signature=signature.hex(),digest=digest.hex(),public_key=(part['tr'].output_pubkey if part['tr'] and not part['leaf'] else entry['xonly'] if part['tr'] else pub).hex(),leaf_hash=leaf_hash.hex() if leaf_hash else None))
                children.append(dict(input=i,public_key=pub.hex(),path=entry['path'],secret=secret.hex(),chain_code=entry['key']['chain'].hex()))
            expected.append(signatures);records.append(fields)
        used_anchors=[anchors[i] for i in selected]
        global_records={b'\x00':tx.serialize_without_witness()}
        for i in range(3):global_records[b'\x01'+serialize(roots[i],k,False)]=origin(fps[i],[])
        if deep:
            first=parts[0]['owners'][0];path=first['path'][:3];account=derive(roots[0],path,k,s)
            annotated='['+fps[0].hex()+'/'+path_text(path)+']'+base58(serialize(account,k))
            used_anchors=([anchors[0],annotated] if both else [annotated])
            global_records[b'\x01'+serialize(account,k,False)]=origin(fps[0],path)
        vectors.append(dict(name=name,anchors=used_anchors,remaining_anchors=[anchors[1]] if any(part['partial'] for part in parts) else [],
                            psbt=maps([global_records,*records,{}]),expected=expected,children=children,script_pubkeys=[part['program'].hex() for part in parts],
                            input_kinds=[part['kind'] for part in parts],script_codes=[part['code'].hex() if part['code'] else None for part in parts],
                            partial=any(part['partial'] for part in parts),deep=deep,master_and_deep=both))
    for kind in ['pk','pkh','sh-pkh','wpkh','sh-wpkh','wsh-pk','sh-wsh-pk','sh-multi','wsh-multi','wsh-sortedmulti']:
        owners=[owner(index=i) for i in range(3)] if 'multi' in kind else [owner()]
        add(kind,[build(kind,owners)])
    add('pk-uncompressed',[build('pk-uncompressed',[owner()])])
    for kind in ['wsh-multi','tr-multi']:
        add(kind+'-partial',[build(kind,[owner(r,i) for i,r in enumerate([0,1,2])],partial=True)])
    for kind in ['tr-key','tr-tree-key']:
        for mode in (0,1):add(kind+str(mode),[build(kind,[owner(purpose=86),owner(1,purpose=86)] if kind=='tr-tree-key' else [owner(purpose=86)],mode)])
    for kind in ['tr-pk','tr-multi','tr-sortedmulti']:
        add(kind,[build(kind,[owner(index=i,purpose=48,hard=True) for i in range(3)] if 'multi' in kind else [owner(purpose=48,hard=True)])])
    chosen=owner(purpose=48,hard=True);part=build('tr-pk',[chosen])
    other=owner(1,purpose=48,hard=True)
    tr=s.taproot_construct(NUMS,[('chosen',part['code']),('unlisted',multi([chosen,other],1,True))]);leaf=tr.leaves['chosen']
    part.update(tr=tr,leaf=leaf,program=bytes(tr.scriptPubKey))
    part['fields']={b'\x17':NUMS,b'\x18':tr.merkle_root,b'\x03':bytes(4),b'\x16'+NUMS:b'\0'+bytes(4),b'\x16'+chosen['xonly']:b'\x01'+leaf.leaf_hash+origin(fps[0],chosen['path'])}
    for value in tr.leaves.values():part['fields'][b'\x15'+bytes([value.version|tr.negflag])+NUMS+value.merklebranch]=bytes(value.script)+bytes([value.version])
    add('tr-declared-leaf-only',[part])
    add('mixed-ecdsa-taproot',[build('wpkh',[owner()]),build('tr-key',[owner(index=1,purpose=86)])])
    add('two-hd-inputs',[build('wpkh',[owner()]),build('wpkh',[owner(index=1)])])
    add('account-anchor',[build('wpkh',[owner()])],deep=True)
    add('master-plus-account',[build('wpkh',[owner()])],deep=True,both=True)
    add('account-hardened-suffix',[build('wpkh',[owner(index=7,hard=True)])],deep=True)
    for count in (128,999):
        owners=[owner(index=i,purpose=48) for i in range(count)]
        part=build('tr-multi',owners)
        # Rebuild the threshold and matching leaf metadata as a complete Core tree.
        code=multi(owners,count,True);tr=s.taproot_construct(NUMS,[('leaf',code)]);leaf=tr.leaves['leaf']
        part.update(code=code,tr=tr,leaf=leaf,program=bytes(tr.scriptPubKey))
        part['fields']={b'\x17':NUMS,b'\x18':tr.merkle_root,b'\x03':bytes(4),b'\x15'+bytes([0xc0|tr.negflag])+NUMS+leaf.merklebranch:code+b'\xc0',b'\x16'+NUMS:b'\0'+bytes(4)}
        for entry in owners:part['fields'][b'\x16'+entry['xonly']]=b'\x01'+leaf.leaf_hash+origin(fps[0],entry['path'])
        add(str(count)+'-hd-keys',[part])
    target=root/'crates/primitives/tests/data/hd-signer.json'
    target.write_text(json.dumps(dict(source=SOURCE,sha256=SOURCES,license='Core MIT; published BIP32 BSD-2-Clause',public_test_private_anchors=True,
        scope='Real stdlib HMAC CKDpriv checked against all 17 published BIP32 keys and unchanged Core curve/preimages/signatures; synthetic-parent equations only.',published_bip32_paths_checked=17,vectors=vectors),indent=2)+'\n')
    target.with_suffix('.keys').write_text('\n'.join(anchors)+'\n')
    print(f'Generated {len(vectors)} real-HMAC HD signer cases; all 17 published BIP32 paths matched',flush=True)


if __name__=='__main__':generate()
