#!/usr/bin/env python3
"""Pinned Rust loader vectors, or real mixed proof exports from the upstream example."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from common import ROOT, PIN, checkout, run as run_reference
p = argparse.ArgumentParser()
p.add_argument('--check', action='store_true', help='compare compact loader vectors without modifying them')
p.add_argument('--export-proofs', type=Path, help='generate real proofs and the large class key using the pinned upstream example')
a = p.parse_args()
if a.check and a.export_proofs:
    p.error('--check and --export-proofs are separate operations')
env = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2', PWD=str(ROOT))
def run(cmd, **kw):
    return run_reference(cmd, env=env, **kw)
if a.export_proofs:
    # Never use or modify another local workspace. This is a disposable development checkout.
    with tempfile.TemporaryDirectory(prefix='mixed-source-') as tmp:
        source = Path(tmp)
        checkout(source)
        example = source/'crates/leanvm_core/examples/mixed_program_tree.rs'
        code = example.read_text()
        old = 'NonZeroUsize::new(16)'
        if code.count(old) != 1:
            raise SystemExit('upstream worker setting changed')
        # Sole source adjustment: respect the caller-requested low worker count.
        example.write_text(code.replace(old, 'NonZeroUsize::new(2)'))
        env['CARGO_TARGET_DIR'] = str(ROOT/'tools/leanvm-mixed/target/upstream-example')
        out = a.export_proofs.resolve()
        out.mkdir(parents=True, exist_ok=True)
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path', str(source/'Cargo.toml'),
             '-p', 'leanvm', '--example', 'mixed_program_tree', '--', str(out)], cwd=source)
        # The example itself validates generated roots; additionally exercise its checked loader.
        pin = (out/'class-key.digest').read_text().strip()
        for name in ('distinct-1', 'distinct-2', 'distinct-4'):
            run([str(Path(env['CARGO_TARGET_DIR'])/'release/examples/mixed_program_tree'),
                 '--verify', str(out/name), pin], cwd=source)
        # Compare the whole real class-key digest and wire load in Go as well.
        # Full proof verification is exercised by the root-component vectors and Go tests.
        run(['go', 'run', './experimental/leanvmclaims/cmd/inspect-class-key', '-key', str(out/'class-key.bin'),
             '-digest', pin], cwd=ROOT)
        import hashlib
        manifest = {str(f.relative_to(out)): {'bytes': f.stat().st_size, 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()}
                    for f in sorted(out.rglob('*')) if f.is_file() and f.name != 'provenance.json'}
        (out/'provenance.json').write_text(json.dumps({'upstream_commit': PIN,
            'example': 'crates/leanvm_core/examples/mixed_program_tree.rs',
            'source_adjustment': 'parallel pool 16 -> 2 workers only', 'files': manifest}, indent=2)+'\n')
else:
    with tempfile.TemporaryDirectory(prefix='mixed-vectors-') as tmp:
        out = Path(tmp) if a.check else ROOT/'experimental/leanvmclaims/testdata'
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--', str(out)], cwd=ROOT)
        for component in ('transcript', 'wire', 'field', 'merkle', 'whir', 'stack', 'flock'):
            run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
                 str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', component, '--', str(out/(component+'.json'))], cwd=ROOT)
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'root_components', '--',
             str(ROOT/'experimental/leanvmclaims/testdata/roots'), str(out/'root-components.json')], cwd=ROOT)
        run(['cargo', 'run', '--locked', '--release', '-j', '2', '--manifest-path',
             str(ROOT/'tools/leanvm-mixed/Cargo.toml'), '--bin', 'root_components', '--',
             str(ROOT/'experimental/leanvmclaims/testdata/tiers'), str(out/'tier-verdicts.json')], cwd=ROOT)
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
            for name in ('one-tier.key.gz', 'two-tier.key.gz', 'classes.json', 'transcript.json', 'wire.json', 'field.json', 'merkle.json', 'whir.json', 'stack.json', 'flock.json', 'root-components.json', 'tier-verdicts.json'):
                if (out/name).read_bytes() != (ROOT/'experimental/leanvmclaims/testdata'/name).read_bytes():
                    raise SystemExit(f'generated fixture differs: {name}')
                print(f'matched: {name}')

    run([sys.executable, str(ROOT/'tools/leanvm-mixed/export_metadata.py'), *(['--check'] if a.check else [])], cwd=ROOT)
