"""Shared pin, process limits and isolated checkout for reference generators."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN = 'fc3fc9ec0ec218d6b5196ecae85a975590729ae6'

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
