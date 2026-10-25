#!/usr/bin/env python3
"""Generate the uncommitted 100-signature/357-claim benchmark at the exact pin."""
import argparse
import tempfile
from pathlib import Path
from common import ROOT, PIN, checkout, run
p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args()
out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='member-production-') as tmp:
    source=Path(tmp)/'source';checkout(source)
    example=source/'crates/leanvm_core/examples/claim_set_leaves.rs'
    code=example.read_text()
    if code.count('NonZeroUsize::new(16)')!=1: raise SystemExit('upstream worker marker changed')
    code=code.replace('NonZeroUsize::new(16)','NonZeroUsize::new(2)').replace('threads=16','threads=2')
    # The requested artifact is the two-class tree; omit the independent common-class comparison.
    if code.count('for shared in [false, true]')!=1: raise SystemExit('upstream comparison loop changed')
    code=code.replace('for shared in [false, true]','for shared in [false]')
    example.write_text(code)
    run(['cargo','run','--locked','--release','-j','2','-p','leanvm','--example','claim_set_leaves','--','100','4097',str(out)],cwd=source,
        env={'CARGO_TARGET_DIR':str(ROOT/'tools/leanvm-mixed/target/upstream-example')})
    (out/'upstream-commit').write_text(PIN+'\n')
