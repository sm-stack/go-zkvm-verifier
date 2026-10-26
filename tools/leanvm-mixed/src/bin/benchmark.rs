//! Sequential loaded-key verification of the same raw files as tools/benchmark-claims.
use leanvm::{
    ProofTranscript,
    aggregate::{ClaimSet, Tree, TreeProof, ZkPlacement},
};
use leanvm_mixed_reference::{PIN, descriptor};
use std::{path::Path, time::Instant};
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(1).unwrap()).unwrap();
    let arg = std::env::args().nth(1).expect("raw artifact directory");
    let dir = Path::new(&arg);
    let read = |s: &str| std::fs::read(dir.join(s)).unwrap();
    let key = read("class-key.bin");
    let pin = Tree::mixed_class_key_digest(&key);
    let (classes, shape) = descriptor(&key);
    let start = Instant::now();
    let placement = if u64::from_le_bytes(key[8..16].try_into().unwrap()) == 0 {
        ZkPlacement::Shared
    } else {
        ZkPlacement::Isolated
    };
    let tree = Tree::mixed_classes_from_bytes_with(&classes, shape, placement, &key, &pin).unwrap();
    let load = start.elapsed();
    let root = TreeProof::from_bytes(&read("root.bin")).unwrap();
    let claims = ClaimSet::from_bytes(&read("claims.bin")).unwrap();
    let seal = ProofTranscript::from_bytes(&read("seal.bin")).unwrap();
    let verify = || {
        tree.verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
            .unwrap()
    };
    assert!(tree.verify_claims(&root, &claims).is_err());
    verify();
    let start = Instant::now();
    for _ in 0..100 {
        verify()
    }
    println!(
        "{}",
        serde_json::json!({"upstream_commit":PIN,"claims":claims.n_claims(),"class_key_bytes":key.len(),"load_ns":load.as_nanos(),"sealed_ns":start.elapsed().as_nanos()/100,"iterations":100,"workers":1})
    );
}
