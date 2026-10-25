#!/usr/bin/env python3
"""Package unchanged pinned upstream example outputs as deterministic gzip fixtures.

Run after regenerate.py --export-proofs DIR. The stored manifest checks the
uncompressed upstream bytes; gzip is only a storage format, not proof encoding.
"""
import argparse
import hashlib
import json
from pathlib import Path

from common import ROOT, PIN, checkout, write_gzip, write_manifest
p = argparse.ArgumentParser()
p.add_argument('source', type=Path)
p.add_argument('--check', action='store_true')
a = p.parse_args()
manifest = json.loads((a.source/'provenance.json').read_text())
if manifest['upstream_commit'] != PIN:
    raise SystemExit('wrong upstream pin')
target = ROOT/'experimental/leanvmclaims/testdata/roots'
expected = {'class-key.bin', 'class-key.digest', 'class.bin'} | {
    f'distinct-{n}/{part}.bin' for n in (1, 2, 4) for part in ('root', 'claims', 'seal')}
if set(manifest['files']) != expected:
    raise SystemExit('missing or unexpected upstream outputs')
for name, entry in manifest['files'].items():
    raw = (a.source/name).read_bytes()
    if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
        raise SystemExit(f'upstream manifest mismatch: {name}')
    path = target/(name+'.gz')
    write_gzip(path, raw, a.check)
write_manifest(target/'provenance.json', manifest, a.check)

print(f'packaged {len(expected)} upstream files; uncompressed bytes verified')
