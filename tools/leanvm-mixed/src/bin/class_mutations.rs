//! Authenticated malformed descriptors: every case recomputes the digest.
use leanvm::ProofTranscript;
use leanvm::aggregate::{ClaimSet, Tree, TreeProof};
use leanvm_mixed_reference::{PIN, descriptor};
use serde_json::json;
use std::{io::Read, path::Path};
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let f = std::fs::File::open(Path::new(&args[1]).join("class-key.bin.gz")).unwrap();
    let mut key = vec![];
    flate2::read::GzDecoder::new(f)
        .read_to_end(&mut key)
        .unwrap();
    let word = |offset: usize| u64::from_le_bytes(key[offset..offset + 8].try_into().unwrap());
    let n = word(16) as usize;
    assert_eq!(n, 3);
    let shape = 24 + 144 * n;
    assert_eq!(word(shape + 40), 1, "this corpus has two tiers");
    let roots = shape + 6 * 8 + 3 * 8 + 8;
    let tiers = roots + 8 + 3 * 32 + n * 32;
    let circuits = tiers + 8 + 3 * 48;
    let changes = vec![
        ("original", shape, word(shape)),
        ("version3", 0, u64::from_le_bytes(*b"LVMXCK03")),
        ("zero-leaves", 16, 0),
        ("invalid-small-flag", shape + 40, 2),
        ("first-k-zero", 56, 0),
        ("second-k-zero", 200, 0),
        ("second-ram", 176, 28),
        ("second-image", 192, 0),
        ("arity-zero", shape, 0),
        ("node-arity-one", shape + 8, 1),
        ("small-arity-one", shape + 48, 1),
        ("small-claims-too-large", shape + 56, word(shape + 24) + 1),
        ("small-groups-too-large", shape + 64, word(shape + 32) + 1),
        ("circuit-count", circuits, word(circuits) + 1),
        ("tier-height", tiers + 8, word(tiers + 8) + 1),
        ("circuit-height", circuits + 16, word(circuits + 16) + 1),
        ("second-k-change", 200, word(200) + 1),
        ("class-swap", shape, word(shape)),
    ];
    let read = |name: &str| {
        let f = std::fs::File::open(Path::new(&args[1]).join(format!("{name}.gz"))).unwrap();
        let mut bytes = vec![];
        flate2::read::GzDecoder::new(f)
            .read_to_end(&mut bytes)
            .unwrap();
        bytes
    };
    let root = TreeProof::from_bytes(&read("one-zk/root.bin")).unwrap();
    let claims = ClaimSet::from_bytes(&read("one-zk/claims.bin")).unwrap();
    let seal = ProofTranscript::from_bytes(&read("one-zk/seal.bin")).unwrap();
    let mut cases = vec![];
    for (name, offset, value) in changes {
        let mut bytes = key.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        if name == "class-swap" {
            let a = bytes[24..168].to_vec();
            bytes.copy_within(168..312, 24);
            bytes[168..312].copy_from_slice(&a);
        }
        let descriptor_bytes =
            if name == "zero-leaves" || name == "invalid-small-flag" || name == "version3" {
                &key
            } else {
                &bytes
            };
        let (classes, shape) = descriptor(descriptor_bytes);
        let digest = Tree::mixed_class_key_digest(&bytes);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match Tree::mixed_classes_from_bytes(&classes, shape, &bytes, &digest) {
                Ok(tree) => (
                    true,
                    tree.verify_claims_sealed(&root, &claims, tree.seal_roots().unwrap(), &seal)
                        .is_ok(),
                ),
                Err(_) => (false, false),
            }
        }));
        let ((accept, root_accept), panicked) = match result {
            Ok(ok) => (ok, false),
            Err(_) => ((false, false), true),
        };
        cases.push(json!({"name":name,"offset":offset,"value":value,"accept":accept,"rust_panicked":panicked,"root_accept":root_accept}));
    }
    std::fs::write(
        &args[2],
        serde_json::to_string_pretty(&json!({"upstream_commit":PIN,"cases":cases})).unwrap() + "\n",
    )
    .unwrap();
}
