"""Shared pin, process limits and isolated checkout for reference generators."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = 'da5c964831c993b011464e4fd4a573b7172d5295'

def run(cmd, *, env=None, **kwargs):
    environment = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2', PWD=str(ROOT))
    environment.update(env or {})
    return subprocess.run(cmd, env=environment, check=True, **kwargs)

def checkout(source):
    run(['git', 'init', '-q', str(source)])
    run(['git', '-C', str(source), 'fetch', '--depth=1', 'https://github.com/sm-stack/leanVM', PIN])
    run(['git', '-C', str(source), 'checkout', '-q', '--detach', 'FETCH_HEAD'])
    got = run(['git', '-C', str(source), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
    if got != PIN:
        raise SystemExit('unexpected upstream revision')

def write_gzip(path, raw, check):
    import gzip
    if check:
        if gzip.decompress(path.read_bytes()) != raw:
            raise SystemExit(f'fixture differs: {path}')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(raw, mtime=0))

def write_manifest(path, manifest, check):
    import json
    if check:
        if json.loads(path.read_text()) != manifest:
            raise SystemExit(f'provenance differs: {path}')
    else:
        path.write_text(json.dumps(manifest, indent=2)+'\n')
