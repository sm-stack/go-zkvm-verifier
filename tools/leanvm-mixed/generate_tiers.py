#!/usr/bin/env python3
"""Explicit generation/check of genuine two-tier proofs (not a normal CI rebuild).

Only pinned Rust creates proof/key/config bytes. Python packages and hashes them.
--from-directory packages a completed run without repeating expensive proving.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
PIN='da5c964831c993b011464e4fd4a573b7172d5295'
p=argparse.ArgumentParser()
p.add_argument('--check',action='store_true')
p.add_argument('--from-directory',type=Path)
a=p.parse_args()
names=['class-key.bin','class-key.digest','class-config.json']+[f'{n}/{part}.bin' for n in ('first','small-node','wide') for part in ('root','claims','seal')]
target=ROOT/'experimental/leanvmclaims/testdata/tiers'
with tempfile.TemporaryDirectory(prefix='mixed-tiers-') as tmp:
    source=a.from_directory or Path(tmp)
    if a.from_directory is None:
        subprocess.run(['cargo','run','--locked','--release','-j','2','--manifest-path',str(ROOT/'tools/leanvm-mixed/Cargo.toml'),'--bin','tier_proofs','--',str(source)],cwd=ROOT,env=dict(os.environ,CARGO_BUILD_JOBS='2'),check=True)
    manifest={'upstream_commit':PIN,'generator':'tools/leanvm-mixed/src/bin/tier_proofs.rs','workers':2,'files':{}}
    for name in names:
        raw=(source/name).read_bytes()
        manifest['files'][name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        path=target/(name+'.gz')
        if a.check:
            if gzip.decompress(path.read_bytes())!=raw:
                raise SystemExit(f'tier fixture differs: {name}')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(gzip.compress(raw,mtime=0))
    path=target/'provenance.json'
    if a.check:
        if json.loads(path.read_text())!=manifest:
            raise SystemExit('tier provenance differs')
    else:
        path.write_text(json.dumps(manifest,indent=2)+'\n')
print('verified/packaged 12 two-tier upstream artifacts')
