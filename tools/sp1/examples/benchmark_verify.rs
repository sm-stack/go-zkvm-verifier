//! Warm upstream verification with a reused recursion verifier, including decoding.
use std::{hint::black_box, time::Instant};
fn main() {
    let root = std::path::PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("fixture directory with uncompressed proof.bin"),
    );
    let proof = std::fs::read(root.join("proof.bin")).unwrap();
    let pv = std::fs::read(root.join("public_values.bin")).unwrap();
    let words = std::fs::read(root.join("vkey_hash.bin")).unwrap();
    let key = sp1_reference::vkey_hash_from_words(core::array::from_fn(|i| {
        u32::from_le_bytes(words[4 * i..4 * i + 4].try_into().unwrap())
    }));
    let verifier = sp1_reference::ReferenceVerifier::new();
    let run = || {
        verifier
            .verify_with_public_values(black_box(key), black_box(&pv), black_box(&proof))
            .unwrap()
    };
    for _ in 0..3 {
        run();
    }
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..20 {
            run();
        }
        println!("sp1 upstream ns/op {}", start.elapsed().as_nanos() / 20);
    }
}
