//! Explicit, comparatively expensive first/small-node/Wide fixture generation.
use leanvm::aggregate::{
    Capacity, ClaimShape, LeafShape, MixedLeaf, ProgramClass, Tier, Tree, TreeShape,
};
use leanvm::asm::{Asm, Reg};
use leanvm::{PerTable, Program, Rate, TableId};
use std::path::Path;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let arg = std::env::args().nth(1).unwrap();
    let out = Path::new(&arg);
    std::fs::create_dir_all(out).unwrap();
    let originals: Vec<_> = (0..4)
        .map(|i| {
            Program::new(
                &Asm::new().li(Reg::A0, i).exit().finish(),
                0x10000000,
                vec![],
                0,
                0,
            )
            .unwrap()
        })
        .collect();
    let class = ProgramClass {
        log_bytecode: 12,
        log_ram: 4,
        log_advice: 4,
        image_words: 1,
    };
    let programs: Vec<_> = originals
        .iter()
        .map(|p| class.normalize(p).unwrap())
        .collect();
    let mut stats = programs[0].measure(&[]).unwrap();
    for p in programs.iter().skip(1) {
        let s = p.measure(&[]).unwrap();
        stats.counts = PerTable::from_fn(|t: TableId| stats.counts[t].max(s.counts[t]));
    }
    let leaf = LeafShape::measured(&stats, Rate::MIN);
    let shape = TreeShape {
        leaf,
        arity_0: 2,
        arity: 2,
        rate: Rate::MIN,
        claims: Some(ClaimShape {
            capacity: Capacity {
                claims: 8,
                groups: 4,
            },
            small: Some(Tier {
                arity: 2,
                capacity: Capacity {
                    claims: 4,
                    groups: 2,
                },
            }),
        }),
    };
    eprintln!("building two-tier class");
    let tree = Tree::mixed(class, shape).unwrap();
    let sealer = tree.seal_prover().unwrap();
    let roots = sealer.roots();
    let key = tree.mixed_verifier_bytes(&roots).unwrap();
    let pin = Tree::mixed_class_key_digest(&key);
    let verifier = Tree::mixed_from_bytes(class, shape, &key, &pin).unwrap();
    std::fs::write(out.join("class-key.bin"), &key).unwrap();
    std::fs::write(out.join("class-key.digest"), hex(&pin)).unwrap();
    let config = serde_json::json!({"LogBytecode":12,"LogRAM":4,"LogAdvice":4,"ImageWords":1,"LeafHeights":leaf.heights().into_values(),"LeafRate":1,"Arity0":2,"Arity":2,"TreeRate":1,"Claims":8,"Groups":4,"Small":{"Arity":2,"Claims":4,"Groups":2}});
    std::fs::write(
        out.join("class-config.json"),
        serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let prover = class.prover(leaf);
    let runs: Vec<_> = programs
        .iter()
        .map(|p| prover.prove(p, &[]).unwrap())
        .collect();
    let leaves: Vec<_> = programs
        .iter()
        .zip(&runs)
        .map(|(p, r)| MixedLeaf {
            key: p.verifying_key(),
            proof: &r.proof,
            output: r.output,
        })
        .collect();
    eprintln!("proving first-level roots");
    let first = tree.aggregate_programs(&leaves[..2], None).unwrap();
    let second = tree.aggregate_programs(&leaves[2..], None).unwrap();
    eprintln!("proving small node");
    let small = tree.aggregate(&[&first, &first], None).unwrap();
    eprintln!("proving Wide node");
    let wide = tree.aggregate(&[&first, &second], None).unwrap();
    for (name, root) in [("first", first), ("small-node", small), ("wide", wide)] {
        let seal = tree.seal(&sealer, &root.proof).unwrap();
        verifier
            .verify_claims_sealed(&root.proof, &root.claims, &roots, &seal)
            .unwrap();
        let path = out.join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("root.bin"), root.proof.to_bytes()).unwrap();
        std::fs::write(path.join("claims.bin"), root.claims.to_bytes()).unwrap();
        std::fs::write(path.join("seal.bin"), seal.to_bytes()).unwrap();
        eprintln!("verified {name}");
    }
}
