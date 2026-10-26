#!/usr/bin/env python3
"""Check sizes and SHA-256 hashes of all shipped fixtures and generated artifacts."""
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
manifest = root/'artifacts.json'
paths = sorted([*root.glob('leanvm/testdata/*'), *root.glob('tools/leanvm-mixed/production/*'), *root.glob('tools/leanvm-zk/production/*'), *root.glob('experimental/leanvmclaims/testdata/**/*'), *root.glob('sp1/testdata/*.json'),
                *root.glob('sp1/testdata/fixture/*'), root/'experimental/leanvmclaims/internal/machine/metadata.json', root/'experimental/leanvmclaims/internal/machine/metadata-review.json', root/'experimental/leanvmclaims/internal/pcs/config_table_gen.go', root/'sp1/compress_machine_gen.go', root/'sp1/poseidon2_fast_gen.go'])
actual = {str(p.relative_to(root)): {'bytes': p.stat().st_size,
          'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths if p.is_file()}
if sys.argv[1:] == ['--update']:
    manifest.write_text(json.dumps(actual, indent=2, sort_keys=True)+'\n')
elif sys.argv[1:]:
    raise SystemExit('usage: check_artifacts.py [--update]')
elif json.loads(manifest.read_text()) != actual:
    raise SystemExit('artifact checksum, size, or file inventory mismatch')
else:
    print(f'verified {len(actual)} artifacts')
