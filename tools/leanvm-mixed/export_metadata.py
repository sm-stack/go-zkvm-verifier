#!/usr/bin/env python3
"""Export private circuit metadata from an isolated, exactly pinned Rust checkout.

Only inspection methods and an example are appended; no verifier method changes.
No original workspace or Cargo checkout is ever edited.
"""
import argparse
import json
import hashlib
import os
from pathlib import Path
import tempfile

from common import ROOT, PIN, checkout, run as run_reference
p=argparse.ArgumentParser()
p.add_argument('--check',action='store_true')
p.add_argument('--summary-only', action='store_true', help='review the checked-in metadata without fetching or building Rust')
a=p.parse_args()
env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(ROOT/'tools/leanvm-mixed/target/upstream-example'))
def run(cmd,**kw):
    return run_reference(cmd,env=env,**kw)
def review_summary(metadata):
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    result = {k:v for k,v in metadata.items() if k not in ('circuits', 'rec_tables')}
    result['rec_tables_sha256'] = digest(metadata['rec_tables'])
    result['circuits'] = []
    for circuit in metadata['circuits']:
        entry = {k:v for k,v in circuit.items() if k != 'gates'}
        gates = circuit['gates']
        entry['gate_count'] = len(gates)
        entry['gate_kinds'] = {str(kind):sum(g[0] == kind for g in gates) for kind in sorted({g[0] for g in gates})}
        entry['gates_sha256'] = digest(gates)
        result['circuits'].append(entry)
    target = ROOT/'experimental/leanvmclaims/internal/machine/metadata-review.json'
    content = json.dumps(result, indent=2, sort_keys=True)+'\n'
    if a.check:
        if target.read_text() != content:
            raise SystemExit('metadata review summary differs')
    else:
        target.write_text(content)

if a.summary_only:
    review_summary(json.loads((ROOT/'experimental/leanvmclaims/internal/machine/metadata.json').read_text()))
    raise SystemExit(0)

with tempfile.TemporaryDirectory(prefix='mixed-metadata-') as tmp:
    source=Path(tmp)/'source'
    checkout(source)
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

    review_summary(metadata)
