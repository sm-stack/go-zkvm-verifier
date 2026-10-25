//! Warm end-to-end upstream verification, excluding fixture I/O.
use std::{hint::black_box, time::Instant};
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../leanvm/testdata");
    let preimage = std::env::args().nth(1).as_deref() == Some("preimage");
    let (elf_name, proof_name) = if preimage {
        ("preimage.elf", "preimage-40000")
    } else {
        ("fibonacci.elf", "fibonacci-1000")
    };
    let elf = std::fs::read(root.join(elf_name)).unwrap();
    let proof = std::fs::read(root.join(format!("{proof_name}.proof"))).unwrap();
    let output: [u8; 32] = std::fs::read(root.join(format!("{proof_name}.output")))
        .unwrap()
        .try_into()
        .unwrap();
    let run =
        || leanvm_reference::verify(black_box(&elf), black_box(output), black_box(&proof)).unwrap();
    for _ in 0..3 {
        run();
    }
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..20 {
            run();
        }
        println!("leanvm upstream ns/op {}", start.elapsed().as_nanos() / 20);
    }
}
