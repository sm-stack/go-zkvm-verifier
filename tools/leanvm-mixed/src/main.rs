use leanvm::{
    ProofTranscript,
    aggregate::{ClaimSet, Tree, TreeProof},
};
use leanvm_mixed_reference::{PIN, descriptor};
use std::path::Path;
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let read = |s: &str| std::fs::read(dir.join(s)).unwrap();
    let key = read("class-key.bin");
    let pin = Tree::mixed_class_key_digest(&key);
    let (classes, shape) = descriptor(&key);
    let tree = Tree::mixed_classes_from_bytes(&classes, shape, &key, &pin).unwrap();
    for line in String::from_utf8(read("verdicts.tsv")).unwrap().lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || f[0] == "name" || f[0].starts_with('#') {
            continue;
        }
        let digest: [u8; 32] = read(f[3]).try_into().unwrap();
        let accepted = Tree::mixed_classes_from_bytes(&classes, shape, &read(f[2]), &digest)
            .is_ok_and(|t| {
                TreeProof::from_bytes(&read(f[4])).is_ok_and(|r| {
                    ClaimSet::from_bytes(&read(f[5])).is_some_and(|c| {
                        ProofTranscript::from_bytes(&read(f[6])).is_some_and(|s| {
                            t.verify_claims_sealed(&r, &c, t.seal_roots().unwrap(), &s)
                                .is_ok()
                        })
                    })
                })
            });
        assert_eq!(accepted, f[1] == "accept", "{}", f[0]);
    }
    let mut cases = vec![];
    for name in ["plain-small", "plain-large", "mixed-zk", "one-zk"] {
        let root = read(&format!("{name}/root.bin"));
        let claims = read(&format!("{name}/claims.bin"));
        let seal = read(&format!("{name}/seal.bin"));
        let verify = |r: &[u8], s: &[u8]| {
            TreeProof::from_bytes(r).is_ok_and(|r| {
                ClaimSet::from_bytes(&claims).is_some_and(|c| {
                    ProofTranscript::from_bytes(s).is_some_and(|s| {
                        tree.verify_claims_sealed(&r, &c, tree.seal_roots().unwrap(), &s)
                            .is_ok()
                    })
                })
            })
        };
        assert!(verify(&root, &seal));
        let mut variants = vec![];
        let words = u32::from_le_bytes(root[7..11].try_into().unwrap()) as usize;
        // S = 3 + D + P + T + 2*14 + 2*21; T=3, P=5 for this class.
        let usage = words - 2 * 14 - 2 * 21 - 3;
        let unused = (0..3)
            .find(|tier| {
                root[11 + 24 * (usage + tier)..11 + 24 * (usage + tier + 1)]
                    .iter()
                    .all(|&b| b == 0)
            })
            .expect("fixture needs unused tier");
        for (label, at) in [
            ("usage", 11 + 24 * usage),
            ("unused-fixed", 11 + 24 * (usage - 3 + unused)),
            ("root-proof", 11 + 24 * words + 8),
        ] {
            let mut r = root.clone();
            r[at] ^= 1;
            variants.push(
                serde_json::json!({"name":label,"part":"root","at":at,"accept":verify(&r,&seal)}),
            );
        }
        for (label, at) in [
            ("pub-contribution", 16 + 98 * 24),
            ("column-value", 16),
            ("last-seal-byte", seal.len() - 1),
        ] {
            let mut s = seal.clone();
            s[at] ^= 1;
            variants.push(
                serde_json::json!({"name":label,"part":"seal","at":at,"accept":verify(&root,&s)}),
            );
        }
        cases.push(serde_json::json!({"name":name,"mutations":variants}));
    }
    std::fs::write(
        &args[2],
        serde_json::to_vec_pretty(&serde_json::json!({"upstream_commit":PIN,"cases":cases}))
            .unwrap(),
    )
    .unwrap();
}
