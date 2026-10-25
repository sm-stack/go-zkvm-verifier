//! Sequential verification of the exact same files as the Go benchmark command.
use leanvm::ProofTranscript;
use leanvm::aggregate::{ClaimSet, Tree, TreeProof};
use leanvm_mixed_reference::{PIN, descriptor};
use std::{path::Path, time::Instant};
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(1).unwrap()).unwrap();
    let arg = std::env::args().nth(1).expect("artifact directory");
    let dir = Path::new(&arg);
    let key = std::fs::read(dir.join("class-key.bin")).unwrap();
    let pin = Tree::mixed_class_key_digest(&key);
    let (classes, shape) = descriptor(&key);
    let start = Instant::now();
    let tree = Tree::mixed_classes_from_bytes(&classes, shape, &key, &pin).unwrap();
    let load = start.elapsed();
    let root = TreeProof::from_bytes(&std::fs::read(dir.join("root.bin")).unwrap()).unwrap();
    let claims = ClaimSet::from_bytes(&std::fs::read(dir.join("claims.bin")).unwrap()).unwrap();
    let seal = ProofTranscript::from_bytes(&std::fs::read(dir.join("seal.bin")).unwrap()).unwrap();
    let sealed = || {
        tree.verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
            .unwrap()
    };
    let direct = || tree.verify_claims(&root, &claims).unwrap();
    sealed();
    direct();
    let start = Instant::now();
    for _ in 0..100 {
        direct();
    }
    let direct = start.elapsed().as_nanos() / 100;
    let start = Instant::now();
    for _ in 0..100 {
        sealed();
    }
    let sealed = start.elapsed().as_nanos() / 100;
    println!(
        "{}",
        serde_json::json!({"upstream_commit":PIN,"claims":claims.n_claims(),"class_key_bytes":key.len(),"load_ns":load.as_nanos(),"direct_ns":direct,"sealed_ns":sealed,"iterations":100,"workers":1})
    );
}
