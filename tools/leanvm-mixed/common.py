"""Shared pin, process limits and isolated checkout for reference generators."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = '3e7da4e783dad4c39115e5a231849e52cae5b22f'

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
