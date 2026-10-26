#!/usr/bin/env python3
"""Package Rust ZK proofs or the archived OP payloads with source checksums."""
import argparse, gzip, hashlib, json, struct, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/leanvm-mixed'))
from rlp import decode
PIN='3e269bd4137976648052a3335845d0c19693ec0d'
p=argparse.ArgumentParser()
p.add_argument('source',type=Path)
p.add_argument('--production',action='store_true')
p.add_argument('--name',default='zk')
a=p.parse_args()
def package(src,target):
    files={}
    for f in sorted(src.rglob('*')):
        if not f.is_file() or f.name=='upstream-commit':continue
        name=str(f.relative_to(src));raw=f.read_bytes()
        out=target/(name+'.gz');out.parent.mkdir(parents=True,exist_ok=True)
        out.write_bytes(gzip.compress(raw,mtime=0))
        files[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    (target/'provenance.json').write_text(json.dumps({'upstream_commit':PIN,
       'generator':'tools/leanvm-zk/package.py','files':files},indent=2)+'\n')
if a.production:
    snapshot=ROOT/'tools/leanvm-zk/production'
    meta=json.loads((snapshot/'provenance.json').read_text())
    for name,entry in meta['files'].items():
        f=snapshot/(name+('.gz' if name.endswith('payload') else ''))
        raw=gzip.decompress(f.read_bytes()) if name.endswith('payload') else f.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==entry['sha256'],name
    for version in ('v2','v3'):
        src=a.source/version
        payload=gzip.decompress((snapshot/(version+'-tree.payload.gz')).read_bytes())
        fields=decode(payload)
        version_tag,through,digest,statements,proof=fields
        root,seal=decode(proof)
        assert (src/'class-key.digest').read_text()==digest.hex()
        groups=[]
        for label,member in statements:
            assert len(label)==len(member)==32
            label+=bytes(16)
            if not groups or groups[-1][0]!=label:groups.append((label,[]))
            groups[-1][1].append(member)
        claims=struct.pack('<I',len(groups))
        for label,members in groups:
            claims+=label+struct.pack('<I',len(members))+b''.join(members)
        out=src/'production';out.mkdir(exist_ok=True)
        for name,raw in [('root',root),('claims',claims),('seal',seal)]:
            (out/(name+'.bin')).write_bytes(raw)
        package(src,ROOT/'experimental/leanvmclaims/testdata'/('operational-'+version))
else:
    assert (a.source/'upstream-commit').read_text()==PIN
    package(a.source,ROOT/'experimental/leanvmclaims/testdata'/a.name)
