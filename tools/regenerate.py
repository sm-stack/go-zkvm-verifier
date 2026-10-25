#!/usr/bin/env python3
"""Regenerate reference artifacts without proving; --check compares without overwriting."""
import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
env = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2')

def cargo(package, example, extra=(), extra_env=None):
    subprocess.run(['cargo', 'run', '--locked', '--release', '-j', '2',
                    '--manifest-path', str(root/'tools'/package/'Cargo.toml'),
                    '--example', example, '--', *map(str, extra)],
                   cwd=root, env=env | (extra_env or {}), check=True)

with tempfile.TemporaryDirectory(prefix='stark-reference-') as tmp:
    tmp = Path(tmp)
    lean = tmp/'lean-vectors.json'
    cargo('leanvm', 'go_vectors', extra_env={'STARK_VECTORS_OUT': str(lean)})
    fixture = tmp/'fixture'
    fixture.mkdir()
    for name in ('vkey_hash.bin', 'public_values.bin'):
        shutil.copyfile(root/'sp1/testdata/fixture'/name, fixture/name)
    (fixture/'proof.bin').write_bytes(gzip.decompress((root/'sp1/testdata/fixture/proof.bin.gz').read_bytes()))
    sp = tmp/'sp1'
    (sp/'testdata').mkdir(parents=True)
    cargo('sp1', 'go_verifier_tables', (sp, fixture))
    subprocess.run(['gofmt', '-w', str(sp/'compress_machine_gen.go')], check=True)
    pairs = [(lean, root/'leanvm/testdata/vectors.json')]
    pairs += [(sp/p, root/'sp1'/p) for p in (
        'compress_machine_gen.go', 'testdata/vectors.json',
        'testdata/mutations.json', 'testdata/statements.json')]
    for generated, checked_in in pairs:
        if args.check:
            if generated.read_bytes() != checked_in.read_bytes():
                raise SystemExit(f'artifact differs: {checked_in.relative_to(root)}')
        else:
            shutil.copyfile(generated, checked_in)
        print(('matched: ' if args.check else 'wrote: ') + str(checked_in.relative_to(root)))
