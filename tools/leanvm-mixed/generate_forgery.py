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
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
PIN='da5c964831c993b011464e4fd4a573b7172d5295'
p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');a=p.parse_args()
env=dict(os.environ,CARGO_BUILD_JOBS='2',CARGO_TARGET_DIR=str(ROOT/'tools/leanvm-mixed/target/upstream-example'))
def run(cmd,**kw):return subprocess.run(cmd,env=env,check=True,**kw)
with tempfile.TemporaryDirectory(prefix='mixed-forgery-') as tmp:
    source=Path(tmp)/'source';inputs=Path(tmp)/'inputs';out=Path(tmp)/'out'
    run(['git','init','-q',str(source)])
    run(['git','-C',str(source),'fetch','--depth=1','https://github.com/sm-stack/leanVM',PIN])
    run(['git','-C',str(source),'checkout','-q','--detach','FETCH_HEAD'])
    if run(['git','-C',str(source),'rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()!=PIN:raise SystemExit('wrong revision')
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
        if a.check:
            if gzip.decompress(path.read_bytes())!=raw:raise SystemExit(f'forgery differs: {name}')
        else:
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(gzip.compress(raw,mtime=0))
    path=fixture/'provenance.json'
    if a.check:
        if json.loads(path.read_text())!=manifest:raise SystemExit('forgery provenance differs')
    else:path.write_text(json.dumps(manifest,indent=2)+'\n')
print('verified upstream forged-wrap regression and exported 5 files')
