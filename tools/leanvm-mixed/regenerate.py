#!/usr/bin/env python3
"""Regenerate pinned Rust component vectors and the small two-class proof corpus."""
import argparse
import os
from pathlib import Path
import sys
import tempfile

from common import ROOT, run as run_reference
p = argparse.ArgumentParser()
p.add_argument('--check', action='store_true', help='compare compact loader vectors without modifying them')
p.add_argument('--export-proofs', type=Path, help='generate and package the small two-class proof corpus')
a = p.parse_args()
if a.check and a.export_proofs:
    p.error('--check and --export-proofs are separate operations')
env = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2', PWD=str(ROOT))
def run(cmd, **kw):
    return run_reference(cmd, env=env, **kw)
if a.export_proofs:
    out = a.export_proofs.resolve()
    out.mkdir(parents=True, exist_ok=True)
    run(['cargo','run','--locked','--release','-j','2','--manifest-path',
         str(ROOT/'tools/leanvm-mixed/Cargo.toml'),'--bin','tier_proofs','--',str(out)],cwd=ROOT)
    run([sys.executable,str(ROOT/'tools/leanvm-mixed/pack_proofs.py'),str(out)],cwd=ROOT)

else:
    with tempfile.TemporaryDirectory(prefix='mixed-vectors-') as tmp:
        out = Path(tmp) if a.check else ROOT/'experimental/leanvmclaims/testdata'
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--', str(out)], cwd=ROOT)
        for component in ('transcript', 'wire', 'field', 'merkle', 'whir', 'stack', 'flock', 'statements'):
            run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
                 str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', component, '--', str(out/(component+'.json'))], cwd=ROOT)
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'root_components', '--',
             str(ROOT/'experimental/leanvmclaims/testdata/roots'), str(out/'root-components.json')], cwd=ROOT)
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'root_components', '--',
             str(ROOT/'experimental/leanvmclaims/testdata/one-tier'), str(out/'one-tier-components.json')], cwd=ROOT)
        for component, source, output in [('class_mutations', 'roots', 'class-mutations.json'), ('root_components', 'production', 'production-components.json')]:
            run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path', str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', component, '--', str(ROOT/'experimental/leanvmclaims/testdata'/source), str(out/output)], cwd=ROOT)
        production = Path(tmp)/'production'
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path', str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'production_key', '--', str(production)], cwd=ROOT)
        run([sys.executable, str(ROOT/'tools/leanvm-mixed/production_fixture.py'), str(production), *(['--check'] if a.check else [])], cwd=ROOT)
        generated_config = Path(tmp)/'config_table_gen.go'
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'config', '--', str(generated_config)], cwd=ROOT)
        run(['gofmt', '-w', str(generated_config)], cwd=ROOT)
        config_target = ROOT/'experimental/leanvmclaims/internal/pcs/config_table_gen.go'
        if a.check:
            if generated_config.read_bytes() != config_target.read_bytes():
                raise SystemExit('generated WHIR profiles differ')
            print('matched: config_table_gen.go')
        else:
            config_target.write_bytes(generated_config.read_bytes())
        if a.check:
            for name in ('one-tier.key.gz', 'two-tier.key.gz', 'classes.json', 'transcript.json', 'wire.json', 'field.json', 'merkle.json', 'whir.json', 'stack.json', 'flock.json', 'statements.json', 'root-components.json', 'one-tier-components.json', 'class-mutations.json', 'production-components.json'):
                if (out/name).read_bytes() != (ROOT/'experimental/leanvmclaims/testdata'/name).read_bytes():
                    raise SystemExit(f'generated fixture differs: {name}')
                print(f'matched: {name}')

    run([sys.executable, str(ROOT/'tools/leanvm-mixed/export_metadata.py'), *(['--check'] if a.check else [])], cwd=ROOT)
