#!/usr/bin/env python3
"""Export private circuit metadata from an isolated, exactly pinned Rust checkout.

Only inspection methods and an example are appended; no verifier method changes.
No original workspace or Cargo checkout is ever edited.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
PIN='da5c964831c993b011464e4fd4a573b7172d5295'
p=argparse.ArgumentParser()
p.add_argument('--check',action='store_true')
a=p.parse_args()
env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(ROOT/'tools/leanvm-mixed/target/upstream-example'))
def run(cmd,**kw):
    return subprocess.run(cmd,env=env,check=True,**kw)
with tempfile.TemporaryDirectory(prefix='mixed-metadata-') as tmp:
    source=Path(tmp)/'source'
    run(['git','init','-q',str(source)])
    run(['git','-C',str(source),'fetch','--depth=1','https://github.com/sm-stack/leanVM',PIN])
    run(['git','-C',str(source),'checkout','-q','--detach','FETCH_HEAD'])
    got=run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
    if got!=PIN:
        raise SystemExit('unexpected upstream revision')
    snippets=ROOT/'tools/leanvm-mixed/exporter'
    for name,path in [('flock.rs','crates/flock/src/circuit.rs'),('leanvm.rs','crates/leanvm_core/src/lib.rs'),('rec.rs','crates/leanvm_core/src/rec/mod.rs'),('cpu.rs','crates/leanvm_core/src/cpu/mod.rs')]:
        target=source/path
        target.write_text(target.read_text()+'\n'+(snippets/name).read_text())
    (source/'crates/leanvm_core/examples/go_port_metadata.rs').write_bytes((snippets/'example.rs').read_bytes())
    output=Path(tmp)/'metadata.json'
    run(['cargo','run','--locked','--release','-j','2','-p','leanvm','--example','go_port_metadata','--',str(output)],cwd=source)
    metadata=json.loads(output.read_text())
    if metadata['upstream_commit']!=PIN:
        raise SystemExit('exported metadata pin differs')
    probes={'upstream_commit':PIN,'circuits':[{'index':c['index'],'probes':c.pop('probes')} for c in metadata['circuits']]}
    layouts={'upstream_commit':PIN,'cases':metadata.pop('rec_layouts'),'leaf_cases':metadata.pop('leaf_sizes')}
    outputs={ROOT/'experimental/leanvmclaims/internal/machine/metadata.json':metadata,
             ROOT/'experimental/leanvmclaims/testdata/matrices.json':probes,
             ROOT/'experimental/leanvmclaims/testdata/layouts.json':layouts}
    for target,value in outputs.items():
        content=(json.dumps(value,separators=(',',':'))+'\n').encode()
        if a.check:
            if target.read_bytes()!=content:
                raise SystemExit(f'generated circuit metadata differs: {target.name}')
            print(f'matched: {target.name}')
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(content)
