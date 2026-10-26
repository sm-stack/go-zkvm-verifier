//! Regenerate the snapshotted OP class keys without proving leaves.
#[allow(dead_code)]
mod v2 {
    include!("../production/v2-class.rs");
}
#[allow(dead_code)]
mod v3 {
    include!("../production/v3-class.rs");
}
use leanvm::aggregate::Tree;
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::path::PathBuf::from(std::env::args().nth(1).unwrap());
    for (name, classes, shape, expected) in [
        (
            "v2",
            v2::classes().to_vec(),
            v2::shape(),
            v2::CLASS_KEY_DIGEST,
        ),
        (
            "v3",
            v3::classes().to_vec(),
            v3::shape(),
            v3::CLASS_KEY_DIGEST,
        ),
    ] {
        let tree = Tree::mixed_classes(&classes, shape).unwrap();
        let key = tree
            .mixed_verifier_bytes(&tree.seal_prover().unwrap().roots())
            .unwrap();
        let digest = Tree::mixed_class_key_digest(&key);
        assert_eq!(digest, expected);
        let dir = out.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("class-key.bin"), key).unwrap();
        std::fs::write(
            dir.join("class-key.digest"),
            leanvm_mixed_reference::hex(&digest),
        )
        .unwrap();
    }
}
