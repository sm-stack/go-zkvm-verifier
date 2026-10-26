//! Rehashed mutations exercise the checked upstream loader beyond digest matching.
use leanvm::aggregate::Tree;
use leanvm_mixed_reference::{PIN, descriptor, hex};
use std::io::Read;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mut key = vec![];
    flate2::read::GzDecoder::new(std::fs::File::open(&args[1]).unwrap())
        .read_to_end(&mut key)
        .unwrap();
    let original = descriptor(&key);
    let n = original.0.len();
    let mut cases = vec![];
    for (name, at, value, derive) in [
        ("shared-placement", 8, 0, false),
        ("unknown-placement", 8, 2, false),
        ("unknown-kind", 24 + 136, 2, false),
        ("plain-to-ZK", 24 + 136, 1, true),
        ("ZK-to-plain", 24 + 2 * 144 + 136, 0, true),
        ("wrong-leaf-rate", 24 + 2 * 144 + 128, 1, true),
        ("no-classes", 16, 0, false),
        ("too-many-classes", 16, u64::MAX, false),
        ("wrong-tier-count", 24 + n * 144 + 10 * 8, 2, false),
    ] {
        let mut edited = key.clone();
        edited[at..at + 8].copy_from_slice(&value.to_le_bytes());
        let digest = Tree::mixed_class_key_digest(&edited);
        let (classes, shape) = if derive {
            descriptor(&edited)
        } else {
            original.clone()
        };
        let loaded = Tree::mixed_classes_from_bytes(&classes, shape, &edited, &digest);
        let accept = loaded.is_ok();
        let root_accept = loaded.is_ok_and(|tree| {
            let base = std::path::Path::new(&args[1]).parent().unwrap();
            let read = |name: &str| {
                let mut v = vec![];
                flate2::read::GzDecoder::new(std::fs::File::open(base.join(name)).unwrap())
                    .read_to_end(&mut v)
                    .unwrap();
                v
            };
            let root =
                leanvm::aggregate::TreeProof::from_bytes(&read("one-member/root.bin.gz")).unwrap();
            let claims =
                leanvm::aggregate::ClaimSet::from_bytes(&read("one-member/claims.bin.gz")).unwrap();
            let seal =
                leanvm::ProofTranscript::from_bytes(&read("one-member/seal.bin.gz")).unwrap();
            tree.verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
                .is_ok()
        });
        cases.push(serde_json::json!({"name":name,"at":at,"word":value,"digest":hex(&digest),"accept":accept,"root_accept":root_accept}));
    }
    std::fs::write(
        &args[2],
        serde_json::to_vec(&serde_json::json!({"upstream_commit":PIN,"cases":cases})).unwrap(),
    )
    .unwrap();
}
