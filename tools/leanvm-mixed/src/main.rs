//! Class-key fixtures from the pinned Rust setup; never constructs proof bytes by hand.
use leanvm::aggregate::{Capacity, ClaimShape, LeafShape, ProgramClass, Tier, Tree, TreeShape};
use leanvm::asm::{Asm, Reg};
use leanvm::{Program, Rate, VerifyingKey};
use leanvm_mixed_reference::{PIN, hex};
use std::{io::Write, path::Path};
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::env::args().nth(1).expect("output directory");
    let full = std::env::args().any(|s| s == "--full");
    let out = Path::new(&out);
    std::fs::create_dir_all(out).unwrap();
    let program = Program::new(
        &Asm::new().li(Reg::A0, 1).exit().finish(),
        0x1000_0000,
        vec![],
        0,
        0,
    )
    .unwrap();
    let class = ProgramClass {
        log_bytecode: program.rv().entries().len().ilog2() as usize,
        log_ram: 4,
        log_advice: 4,
        image_words: 1,
    };
    let program = class.normalize(&program).unwrap();
    let stats = program.measure(&[]).unwrap();
    let leaf = LeafShape::measured(&stats, Rate::MIN);
    let mut reports = vec![];
    for (name, small) in [
        ("one-tier", None),
        (
            "two-tier",
            Some(Tier {
                arity: 2,
                capacity: Capacity {
                    claims: 2,
                    groups: 2,
                },
            }),
        ),
    ] {
        let shape = TreeShape {
            leaf,
            arity_0: 2,
            arity: 2,
            rate: Rate::MIN,
            claims: Some(ClaimShape {
                capacity: Capacity {
                    claims: 4,
                    groups: 4,
                },
                small,
            }),
        };
        let tree = Tree::mixed(class, shape).unwrap();
        let roots = tree.seal_prover().unwrap().roots();
        let mut key = tree.mixed_verifier_bytes(&roots).unwrap();
        let setup_digest = Tree::mixed_class_key_digest(&key);
        let descriptor_end = if small.is_some() { 216 } else { 192 };
        let descriptor = key[8..descriptor_end].to_vec();
        // Compact loader-only fixtures: zero the generated column payloads, retaining
        // exact lengths/layout. These are NOT trusted circuit keys or proof fixtures.
        // Rust accepts their wire structure under their own pin; no proof is generated.
        let tiers = if small.is_some() { 2 } else { 1 };
        let mut pos = descriptor_end + 8 + 32 * tiers + 32 + 8 + 48 * tiers;
        let word = |key: &[u8], at: usize| {
            u64::from_le_bytes(key[at..at + 8].try_into().unwrap()) as usize
        };
        let circuits = word(&key, pos);
        pos += 8;
        let first_circuit = pos;
        for _ in 0..circuits {
            pos += 8 + 48;
            let columns = word(&key, pos);
            pos += 8;
            for _ in 0..columns {
                let n = word(&key, pos);
                pos += 8;
                if !full {
                    key[pos..pos + 8 * n].fill(0);
                }
                pos += 8 * n;
            }
        }
        assert_eq!(pos, key.len());
        let digest = Tree::mixed_class_key_digest(&key);
        Tree::mixed_from_bytes(class, shape, &key, &digest).unwrap();
        let mut gz = flate2::GzBuilder::new()
            .mtime(0)
            .write(Vec::new(), flate2::Compression::best());
        gz.write_all(&key).unwrap();
        let gz = gz.finish().unwrap();
        std::fs::write(out.join(format!("{name}.key.gz")), &gz).unwrap();
        let placeholder_at = descriptor_end + 8 + 32 * tiers;
        let mut vk = key[placeholder_at..placeholder_at + 32].to_vec();
        for w in [
            class.log_bytecode as u64,
            0x1000_0000,
            class.log_ram as u64,
            class.log_advice as u64,
            class.image_words as u64,
        ] {
            vk.extend_from_slice(&w.to_le_bytes());
        }
        vk.extend(std::iter::repeat_n(0, 8 * class.image_words));
        let placeholder_digest = *VerifyingKey::from_bytes(&vk).unwrap().digest();
        let mut semantic_cases = vec![];
        for (index, value) in [
            (0, 11),
            (0, 13),
            (0, 25),
            (1, 0),
            (1, 5),
            (1, 27),
            (1, 28),
            (2, 0),
            (2, 26),
            (2, 27),
            (3, 0),
            (3, 2),
            (3, 3),
            (3, 32),
        ] {
            let mut changed = class;
            match index {
                0 => changed.log_bytecode = value,
                1 => changed.log_ram = value,
                2 => changed.log_advice = value,
                _ => changed.image_words = value,
            }
            let mut bytes = key.clone();
            bytes[8 + 8 * index..16 + 8 * index].copy_from_slice(&(value as u64).to_le_bytes());
            let d = Tree::mixed_class_key_digest(&bytes);
            let accepted = Tree::mixed_from_bytes(changed, shape, &bytes, &d).is_ok();
            semantic_cases.push(
                serde_json::json!({"index":index,"value":value,"accept":accepted,"digest":hex(&d)}),
            );
        }
        let mut cases = vec![];
        // Rehash mutations to exercise the structural parser, not just authentication.
        for (label, at, value) in [
            ("magic", 0, 0),
            ("statement-length", first_circuit, 0),
            ("descriptor", 8, 255),
            ("seal-rate", descriptor_end - 8, 0),
            ("root-count", descriptor_end, 0),
            ("column-count", first_circuit + 56, 0),
            (
                "column-length",
                first_circuit + 64,
                key[first_circuit + 64] ^ 1,
            ),
        ] {
            let mut bytes = key.clone();
            bytes[at] = value;
            assert_ne!(bytes, key, "ineffective mutation: {label}");
            let d = Tree::mixed_class_key_digest(&bytes);
            let accepted = Tree::mixed_from_bytes(class, shape, &bytes, &d).is_ok();
            cases.push(serde_json::json!({"name":label,"offset":at,"value":value,"accept":accepted,"digest":hex(&d)}));
        }
        reports.push(serde_json::json!({"name":name,"placeholder_digest":hex(&placeholder_digest),"descriptor":hex(&descriptor),"setup_digest":hex(&setup_digest),"loader_only_zero_columns":!full,"bytes":key.len(),"gzip_bytes":gz.len(),"digest":hex(&digest),"mutations":cases,"semantic_cases":semantic_cases}));
        eprintln!("{name}: {} bytes, {} compressed", key.len(), gz.len());
    }
    std::fs::write(
        out.join("classes.json"),
        serde_json::to_vec_pretty(&serde_json::json!({"upstream_commit":PIN,"classes":reports}))
            .unwrap(),
    )
    .unwrap();
}
