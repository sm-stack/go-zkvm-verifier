#!/usr/bin/env python3
"""Extract a snapshotted Rust aggregate into standalone verifier inputs.

Run production_key first, then this tool with the same output directory.
The RLP adapter is development tooling only; the Go library has no OP dependency.
"""
import argparse, gzip, hashlib, json, struct
from pathlib import Path
from common import ROOT, PIN, write_gzip, write_manifest

from rlp import decode

p = argparse.ArgumentParser()
p.add_argument('out', type=Path)
p.add_argument('--check', action='store_true')
a = p.parse_args()
source = ROOT/'tools/leanvm-mixed/production'
raw = gzip.decompress((source/'tree.payload.gz').read_bytes())
provenance = json.loads((source/'provenance.json').read_text())
for local, original in [('class.rs','rust/op-leanvm-tree/src/class.rs'), ('fixtures.rs','rust/op-leanvm-tree/examples/fixtures.rs')]:
    assert hashlib.sha256((source/local).read_bytes()).hexdigest() == provenance['files'][original]
assert hashlib.sha256(raw).hexdigest() == provenance['files']['rust/op-leanvm-tree/testdata/tree.payload']
version, through, digest, statements, proof = decode(raw)
root, seal = decode(proof)
assert (a.out/'class-key.digest').read_text() == digest.hex()
groups = []
for label, member in statements:
    assert len(label) == len(member) == 32
    label = label + bytes(16)
    if not groups or groups[-1][0] != label: groups.append((label, []))
    groups[-1][1].append(member)
claims = struct.pack('<I',len(groups))
for label, members in groups:
    claims += label + struct.pack('<I',len(members)) + b''.join(members)
for name, data in [('root.bin',root),('seal.bin',seal),('claims.bin',claims)]:
    (a.out/name).write_bytes(data)
target = ROOT/'experimental/leanvmclaims/testdata/production'
files = {}
for name in ('class-key.bin','class-key.digest','root.bin','claims.bin','seal.bin'):
    raw = (a.out/name).read_bytes()
    files[name] = {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    write_gzip(target/(name+'.gz'),raw,a.check)
write_manifest(target/'provenance.json', {'upstream_commit':PIN,'generator':'tools/leanvm-mixed/production_fixture.py','files':files},a.check)
