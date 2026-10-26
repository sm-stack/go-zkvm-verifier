//! Generate plain/plain/ZK root-verifier fixtures; no leaf proof is shipped.
use leanvm::aggregate::{
    Accumulator, Capacity, ClaimShape, LeafClass, LeafShape, MixedLeaf, ProgramClass, Tier, Tree,
    TreeShape,
};
use leanvm::asm::{Addi, Asm, Bne, Reg};
use leanvm::{Program, Rate, TableId};
use leanvm_mixed_reference::{PIN, hex};
use std::path::Path;

fn program(members: &[[u64; 4]]) -> Program {
    let output = leanvm_guest::members::output(members);
    let mut a = Asm::new();
    a.li(Reg::T0, 9000)
        .label("loop")
        .i(Addi, Reg::T0, Reg::T0, -1)
        .branch(Bne, Reg::T0, Reg::ZERO, "loop");
    for (reg, value) in [Reg::A0, Reg::A1, Reg::A2, Reg::A3].into_iter().zip(output) {
        a.li(reg, value);
    }
    a.exit();
    Program::new(&a.finish(), 0x10000000, vec![], 0, 0).unwrap()
}
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let arg = std::env::args().nth(1).unwrap();
    let out = Path::new(&arg);
    std::fs::create_dir_all(out).unwrap();
    let members = [
        vec![[1, 2, 3, 4], [2, 3, 4, 5], [2, 3, 4, 5], [3, 4, 5, 6]],
        vec![[9; 4]],
        vec![[10; 4]],
    ];
    let bounds = ProgramClass {
        log_bytecode: 12,
        log_ram: 4,
        log_advice: 4,
        image_words: 1,
        max_members: 4,
    };
    let programs: Vec<_> = members
        .iter()
        .map(|m| bounds.normalize(&program(m)).unwrap())
        .collect();
    let mut stats = programs[0].measure(&[]).unwrap();
    stats.counts[TableId::ALU] *= 2;
    let first = LeafShape::measured(&stats, Rate::MIN);
    stats.counts[TableId::ALU] *= 2;
    let one_tier = std::env::args().any(|a| a == "--one-tier");
    // The one-tier corpus also covers asymmetric leaf rates in the root session.
    let second = LeafShape::measured(
        &stats,
        if one_tier {
            Rate::new(2).unwrap()
        } else {
            Rate::MIN
        },
    );
    let mut classes = vec![
        LeafClass {
            program: bounds,
            shape: first,
        },
        LeafClass {
            program: ProgramClass {
                max_members: 1,
                ..bounds
            },
            shape: second,
        },
        LeafClass {
            program: bounds,
            shape: LeafShape::measured(&stats, Rate::new(2).unwrap()).zero_knowledge(),
        },
    ];
    let zk_only = std::env::args().any(|a| a == "--zk-only");
    if zk_only {
        classes = vec![classes[2]];
    }
    let shape = TreeShape {
        leaf: classes[0].shape,
        arity_0: 1,
        arity: 2,
        rate: Rate::MIN,
        claims: Some(ClaimShape {
            capacity: Capacity {
                claims: 8,
                groups: 4,
            },
            small: if one_tier {
                None
            } else {
                Some(Tier {
                    arity: 2,
                    capacity: Capacity {
                        claims: 4,
                        groups: 2,
                    },
                })
            },
        }),
    };
    eprintln!("building three-class ZK member tree");
    let tree = Tree::mixed_classes(&classes, shape).unwrap();
    let sealer = tree.seal_prover().unwrap();
    let key = tree.mixed_verifier_bytes(&sealer.roots()).unwrap();
    let pin = Tree::mixed_class_key_digest(&key);
    std::fs::write(out.join("class-key.bin"), &key).unwrap();
    std::fs::write(out.join("class-key.digest"), hex(&pin)).unwrap();
    let verifier = Tree::mixed_classes_from_bytes(&classes, shape, &key, &pin).unwrap();
    let mut roots = vec![];
    for (i, name) in ["first", "first-class1", "one-member"]
        .into_iter()
        .enumerate()
    {
        let class = if zk_only { 0 } else { i };
        let run = classes[class]
            .program
            .prover(classes[class].shape)
            .prove(&programs[i], &[])
            .unwrap();
        let root = tree
            .aggregate_programs_at(
                class,
                &[MixedLeaf {
                    key: programs[i].verifying_key(),
                    proof: &run.proof,
                    output: run.output,
                    members: &members[i],
                }],
                None,
            )
            .unwrap();
        roots.push((name, root));
        eprintln!("proved {name}");
    }
    let small = tree.aggregate(&[&roots[1].1, &roots[2].1], None).unwrap();
    roots.push(("small-node", small));
    if !one_tier {
        let mut acc = Accumulator::default();
        tree.fold(&mut acc, &roots[3].1).unwrap();
        tree.fold(&mut acc, &roots[0].1).unwrap();
        roots.push(("wide", acc.close().unwrap()));
        tree.fold(&mut acc, &roots[4].1).unwrap();
        tree.fold(&mut acc, &roots[0].1).unwrap();
        roots.push(("fold-dedup", acc.close().unwrap()));
        assert_eq!(roots[4].1.claims, roots[5].1.claims);
    }
    for (name, root) in roots {
        let seal = tree.seal(&sealer, &root.proof).unwrap();
        verifier.verify_claims(&root.proof, &root.claims).unwrap();
        verifier
            .verify_claims_sealed(
                &root.proof,
                &root.claims,
                verifier.seal_roots().unwrap(),
                &seal,
            )
            .unwrap();
        let path = out.join(name);
        std::fs::create_dir_all(&path).unwrap();
        for (part, bytes) in [
            ("root", root.proof.to_bytes()),
            ("claims", root.claims.to_bytes()),
            ("seal", seal.to_bytes()),
        ] {
            std::fs::write(path.join(format!("{part}.bin")), bytes).unwrap();
        }
        eprintln!("verified {name}");
    }
    std::fs::write(out.join("upstream-commit"), PIN).unwrap();
}
