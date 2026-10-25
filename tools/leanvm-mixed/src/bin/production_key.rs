//! Rebuild the authenticated Optimism class; no leaf proving is required.
#[allow(dead_code)]
mod class {
    include!("../../production/class.rs");
}
use leanvm::aggregate::Tree;
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::path::PathBuf::from(std::env::args().nth(1).expect("output directory"));
    std::fs::create_dir_all(&out).unwrap();
    let tree = Tree::mixed_classes(&class::classes(), class::shape()).unwrap();
    let roots = tree.seal_prover().unwrap().roots();
    let key = tree.mixed_verifier_bytes(&roots).unwrap();
    let digest = Tree::mixed_class_key_digest(&key);
    assert_eq!(digest, class::CLASS_KEY_DIGEST);
    std::fs::write(out.join("class-key.bin"), key).unwrap();
    std::fs::write(
        out.join("class-key.digest"),
        leanvm_mixed_reference::hex(&digest),
    )
    .unwrap();
}
