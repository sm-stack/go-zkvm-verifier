#!/usr/bin/env python3
"""Package unchanged pinned upstream example outputs as deterministic gzip fixtures.

Run after regenerate.py --export-proofs DIR. The stored manifest checks the
uncompressed upstream bytes; gzip is only a storage format, not proof encoding.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PIN = 'da5c964831c993b011464e4fd4a573b7172d5295'
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
    if a.check:
        if gzip.decompress(path.read_bytes()) != raw:
            raise SystemExit(f'fixture differs: {name}')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(raw, mtime=0))
if a.check:
    if json.loads((target/'provenance.json').read_text()) != manifest:
        raise SystemExit('provenance differs')
else:
    (target/'provenance.json').write_text(json.dumps(manifest, indent=2)+'\n')
print(f'packaged {len(expected)} upstream files; uncompressed bytes verified')
