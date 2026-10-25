#!/usr/bin/env python3
"""Explicit generation/check of genuine two-tier proofs (not a normal CI rebuild).

Only pinned Rust creates proof/key/config bytes. Python packages and hashes them.
--from-directory packages a completed run without repeating expensive proving.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from common import ROOT, PIN, checkout, write_gzip, write_manifest
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
        write_gzip(path, raw, a.check)
    path=target/'provenance.json'
    write_manifest(path, manifest, a.check)
print('verified/packaged 12 two-tier upstream artifacts')
