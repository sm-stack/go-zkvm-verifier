#!/usr/bin/env python3
"""Export raw ZK First proofs from a pinned, isolated source checkout.

The hook only serializes the prover's intermediate Aggregate before LeafWrap;
all verifier code is unchanged. Never modifies the supplied source repository.
"""
import argparse, os, subprocess, tarfile, io
from pathlib import Path
PIN = '3e269bd4137976648052a3335845d0c19693ec0d'
ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('source', type=Path, help='git checkout containing the pinned commit')
p.add_argument('work', type=Path, help='new temporary directory for source and proofs')
a = p.parse_args()
a.work = a.work.resolve()
source = a.work/'source'
source.mkdir(parents=True, exist_ok=False)
archive = subprocess.check_output(['git','-C',str(a.source),'archive',PIN])
with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
    tar.extractall(source, filter='data')
p = source/'crates/leanvm_core/src/rec/tree/mixed.rs'
s = p.read_text()
needle = '        if tier != SMALL {\n            self.wrap_at(0, &first, Level::LeafWrap(class_index), tier)'
assert s.count(needle) == 1
hook = '''        if tier != SMALL {
            let dir = std::path::PathBuf::from(std::env::var("LEANVM_RAW_EXPORT").unwrap());
            std::fs::create_dir_all(&dir).unwrap();
            let seal = self.seal(&self.seal_prover()?, &first.proof)?;
            self.verify_claims_sealed(&first.proof, &first.claims, &self.seal_prover()?.roots(), &seal)?;
            assert!(self.aggregate(&[&first, &first], None).is_err());
            std::fs::write(dir.join("root.bin"), first.proof.to_bytes()).unwrap();
            std::fs::write(dir.join("claims.bin"), first.claims.to_bytes()).unwrap();
            std::fs::write(dir.join("seal.bin"), seal.to_bytes()).unwrap();
            self.wrap_at(0, &first, Level::LeafWrap(class_index), tier)'''
p.write_text(s.replace(needle, hook))
example = (ROOT/'tools/leanvm-zk/src/main.rs').read_text().replace('use leanvm_mixed_reference::{PIN, hex};',
    f'const PIN: &str = "{PIN}";\nfn hex(b: &[u8]) -> String {{ b.iter().map(|x|format!("{{x:02x}}")).collect() }}')
(source/'crates/leanvm_core/examples/zk_port.rs').write_text(example)
out = a.work/'proofs'
env = dict(os.environ, CARGO_BUILD_JOBS='2', RAYON_NUM_THREADS='2',
           CARGO_TARGET_DIR=str(ROOT/'tools/leanvm-zk/target'), LEANVM_RAW_EXPORT=str(out/'raw-zk-first'))
subprocess.run(['cargo','run','--locked','--release','-j','2','--manifest-path',str(source/'Cargo.toml'),
                '-p','leanvm','--example','zk_port','--',str(out)],env=env,check=True)
