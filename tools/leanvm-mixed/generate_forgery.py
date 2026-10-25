#!/usr/bin/env python3
"""Export the real upstream fake-large-wrap regression against the shipped tier key.

Only pool initialization, fixture I/O and the helper's large arity parameter
change. No prover/verifier method or assertion is weakened. All upstream
forgery assertions must pass before outputs are installed.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile

from common import ROOT, PIN, checkout, write_gzip, write_manifest, run as run_reference
p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(ROOT/'tools/leanvm-mixed/target/upstream-example'))
def run(cmd,**kw):return run_reference(cmd,env=env,**kw)
with tempfile.TemporaryDirectory(prefix='mixed-forgery-') as tmp:
    source=Path(tmp)/'source';inputs=Path(tmp)/'inputs';out=Path(tmp)/'out'
    checkout(source)
    for name in ['class-key.bin','wide/root.bin','wide/claims.bin']:
        path=inputs/name;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(gzip.decompress((ROOT/'experimental/leanvmclaims/testdata/tiers'/(name+'.gz')).read_bytes()))
    target=source/'crates/leanvm_core/src/rec/tree/mod.rs'
    code=target.read_text()
    start=code.index('pub(crate) fn assert_fake_large_wrap_refused(')
    end=code.index('\n        // At a capacity of many chunks',start)
    helper=code[start:end]
    old='d.place(LARGE, Level::Node(3))'
    if helper.count(old)!=1:raise SystemExit('forgery helper changed')
    helper=helper.replace(old,'d.place(LARGE, Level::Node(d.arity))')
    marker='            let seal = tree.seal(&prover, &root).unwrap();'
    if helper.count(marker)!=1:raise SystemExit('forgery seal marker changed')
    snippets=ROOT/'tools/leanvm-mixed/exporter'
    helper=helper.replace(marker,marker+'\n'+(snippets/'forgery_export.rs').read_text())
    code=code[:start]+helper+code[end:]+'\n'+(snippets/'forgery_test.rs').read_text()
    target.write_text(code)
    env.update(GO_PORT_INPUT_DIR=str(inputs),GO_PORT_FORGERY_DIR=str(out))
    run(['cargo','test','--locked','--release','-j','2','-p','leanvm','--lib','go_port_export_forged_wrap','--','--test-threads=1','--nocapture'],cwd=source)
    names=['class-key.digest','root.bin','claims.bin','seal.bin','child-root.bin']
    fixture=ROOT/'experimental/leanvmclaims/testdata/forgery'
    manifest={'upstream_commit':PIN,'source':'crates/leanvm_core/src/rec/tree/mod.rs::assert_fake_large_wrap_refused','adjustments':['large arity 3 -> design arity (2 for shipped class)','2-worker initialization and export adapter only'],'rust_verdicts':{'child_recursion':False,'wrap_recursion':True,'wrap_sealed':False},'files':{}}
    for name in names:
        raw=(out/name).read_bytes();manifest['files'][name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        path=fixture/(name+'.gz')
        write_gzip(path, raw, a.check)
    path=fixture/'provenance.json'
    write_manifest(path, manifest, a.check)
print('verified upstream forged-wrap regression and exported 5 files')
