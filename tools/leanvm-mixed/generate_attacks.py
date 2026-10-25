#!/usr/bin/env python3
"""Export pinned member-list and class-shape attacks, retaining upstream assertions."""
import argparse
import hashlib
import tempfile
from pathlib import Path
from common import ROOT, PIN, checkout, run, write_gzip, write_manifest
p=argparse.ArgumentParser()
p.add_argument('--check',action='store_true')
a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='member-attacks-') as tmp:
    source=Path(tmp)/'source'; out=Path(tmp)/'out'
    checkout(source)
    path=source/'crates/leanvm_core/src/rec/tree/member_tests.rs'
    code=path.read_text()
    marker='assert!(!row_failures(f, 0, leaf, &declared).is_empty());'
    # The third occurrence belongs to the wrong-announcement test, before its
    # root/seal variables exist. Export the first two member-list loops only.
    if code.count(marker)!=3: raise SystemExit('upstream row markers changed')
    code=code.replace(marker,marker+'\n        go_port_member_dump(&honest.proof,&declared,&seal);',2)
    marker='let refusal = TreeError::Claim(FalseClaim::Dense(DensePoly::Fixed));'
    if code.count(marker)!=1: raise SystemExit('upstream shape marker changed')
    marker='    assert_eq!(\n        f.tree.verify_claims_sealed(&root, &claims, &sealer.roots(), &seal),'
    if code.count(marker)!=1: raise SystemExit('upstream seal marker changed')
    code=code.replace(marker,'    go_port_dump("foreign-kind", &root, &claims, &seal);\n'+marker)
    marker='    assert!(f.tree.verify_claims(&honest.proof, &listed_as_set).is_err());'
    if code.count(marker)!=1: raise SystemExit('upstream list/set marker changed')
    code=code.replace(marker,marker+'\n    go_port_member_dump(&honest.proof,&listed_as_set,&seal);')
    path.write_text(code+'\n'+(ROOT/'tools/leanvm-mixed/exporter/member_exports.rs').read_text())
    run(['cargo','test','--locked','--release','-j','2','-p','leanvm','--lib','go_port_export_member_attacks','--','--test-threads=1','--nocapture'],cwd=source,
        env={'CARGO_TARGET_DIR':str(ROOT/'tools/leanvm-mixed/target/upstream-example'),'GO_PORT_ATTACK_DIR':str(out)})
    files={}
    target=ROOT/'experimental/leanvmclaims/testdata/member-attacks'
    for file in sorted(out.rglob('*')):
        if not file.is_file(): continue
        name=str(file.relative_to(out)); raw=file.read_bytes()
        files[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        write_gzip(target/(name+'.gz'),raw,a.check)
    write_manifest(target/'provenance.json',{'upstream_commit':PIN,'source':'rec/tree/member_tests.rs','adjustments':['2 workers and fixture I/O only; all upstream assertions retained'],'files':files},a.check)
    print(f'packaged {len(files)} member attack artifacts')
