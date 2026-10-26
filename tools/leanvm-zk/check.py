#!/usr/bin/env python3
"""Replay checked-in v2/v3 proofs with the current pinned Rust verifier."""
import gzip, json, os, subprocess, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
DATA=ROOT/'experimental/leanvmclaims/testdata'
PIN='3e269bd4137976648052a3335845d0c19693ec0d'
env=dict(os.environ,CARGO_BUILD_JOBS='2',RAYON_NUM_THREADS='2')
def run(binary,*args):
    subprocess.run(['cargo','run','--locked','--release','-j','2','--manifest-path',
      str(ROOT/'tools/leanvm-zk/Cargo.toml'),'--bin',binary,'--',*map(str,args)],env=env,check=True)
with tempfile.TemporaryDirectory(prefix='leanvm-zk-check-') as tmp:
    tmp=Path(tmp)
    for corpus,vector in [('roots','root-components'),('one-tier','one-tier-components'),
                          ('production','production-components'),('zk','zk-components'),
                          ('zk-only','zk-only-components'),('operational-v2','operational-v2-components'),
                          ('operational-v3','operational-v3-components')]:
        out=tmp/(vector+'.json');run('root_components',DATA/corpus,out)
        got=json.loads(out.read_text());want=json.loads((DATA/(vector+'.json')).read_text())
        assert got.pop('upstream_commit')==PIN
        # Old v2 fixtures retain their original generating revision.
        want.pop('upstream_commit')
        assert got==want,vector
        print('matched:',vector,flush=True)
    out=tmp/'zk-key-vectors.json'
    run('key_vectors',DATA/'zk/class-key.bin.gz',out)
    assert out.read_bytes()==(DATA/out.name).read_bytes()
    run('production',tmp/'production')
    for version in ('v2','v3'):
        raw=(tmp/'production'/version/'class-key.bin').read_bytes()
        assert raw==gzip.decompress((DATA/('operational-'+version)/'class-key.bin.gz').read_bytes())
        print('matched: operational-'+version+' key',flush=True)
