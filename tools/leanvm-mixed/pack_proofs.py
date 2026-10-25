#!/usr/bin/env python3
"""Package pinned Rust proof-generator outputs as deterministic gzip fixtures.

Run after regenerate.py --export-proofs DIR. The stored manifest checks the
uncompressed upstream bytes; gzip is only a storage format, not proof encoding.
"""
import argparse
import hashlib
import json
from pathlib import Path

from common import ROOT, PIN, write_gzip, write_manifest
p = argparse.ArgumentParser()
p.add_argument('source', type=Path)
p.add_argument('--check', action='store_true')
p.add_argument('--one-tier', action='store_true')
a = p.parse_args()
if (a.source/'upstream-commit').read_text().strip() != PIN:
    raise SystemExit('wrong upstream pin')
names = ('first', 'first-class1', 'one-member', 'small-node', 'wide', 'fold-dedup')
if a.one_tier:
    names = names[:4]
expected = {'class-key.bin', 'class-key.digest'} | {
    f'{name}/{part}.bin' for name in names for part in ('root', 'claims', 'seal')}
manifest = {'upstream_commit': PIN, 'generator': 'tools/leanvm-mixed/src/bin/tier_proofs.rs',
            'files': {name: {'bytes': (a.source/name).stat().st_size,
                             'sha256': hashlib.sha256((a.source/name).read_bytes()).hexdigest()}
                      for name in sorted(expected)}}
target = ROOT/'experimental/leanvmclaims/testdata'/('one-tier' if a.one_tier else 'roots')
for name, entry in manifest['files'].items():
    raw = (a.source/name).read_bytes()
    if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
        raise SystemExit(f'upstream manifest mismatch: {name}')
    path = target/(name+'.gz')
    write_gzip(path, raw, a.check)
write_manifest(target/'provenance.json', manifest, a.check)

print(f'packaged {len(expected)} upstream files; uncompressed bytes verified')
