//! Replay caller-pinned placement and malformed shared-tier inputs without proving.
use leanvm::{
    ProofTranscript,
    aggregate::{ClaimSet, Tree, TreeProof, ZkPlacement},
};
use leanvm_mixed_reference::{PIN, descriptor};
use serde_json::json;
use std::path::Path;
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let read = |s: &str| std::fs::read(dir.join(s)).unwrap();
    let key = read("class-key.bin");
    let (classes, shape) = descriptor(&key);
    let load = |key: &[u8], digest: &[u8; 32], placement| {
        Tree::mixed_classes_from_bytes_with(&classes, shape, placement, key, digest)
    };
    let mut fixtures = vec![];
    for line in String::from_utf8(read("verdicts.tsv")).unwrap().lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || f[0] == "name" {
            continue;
        };
        let digest: [u8; 32] = read(f[3]).try_into().unwrap();
        let ok = load(&read(f[2]), &digest, ZkPlacement::Shared).is_ok_and(|t| {
            TreeProof::from_bytes(&read(f[4])).is_ok_and(|r| {
                ClaimSet::from_bytes(&read(f[5])).is_some_and(|c| {
                    ProofTranscript::from_bytes(&read(f[6])).is_some_and(|s| {
                        t.verify_claims_sealed(&r, &c, t.seal_roots().unwrap(), &s)
                            .is_ok()
                    })
                })
            })
        });
        assert_eq!(ok, f[1] == "accept");
        fixtures.push(json!({"name":f[0],"accept":ok}));
    }
    let mut loaders = vec![];
    for (name, p) in [
        ("shared", ZkPlacement::Shared),
        ("isolated", ZkPlacement::Isolated),
    ] {
        for file in ["class-key.bin", "isolated-key.bin"] {
            let b = read(file);
            let d = Tree::mixed_class_key_digest(&b);
            loaders.push(json!({"placement":name,"key":file,"accept":load(&b,&d,p).is_ok()}));
        }
    }
    let pin = Tree::mixed_class_key_digest(&key);
    let tree = load(&key, &pin, ZkPlacement::Shared).unwrap();
    let root = read("root.bin");
    let claims = ClaimSet::from_bytes(&read("claims.bin")).unwrap();
    let seal = ProofTranscript::from_bytes(&read("seal.bin")).unwrap();
    let accepts = |b: &[u8], s: &ProofTranscript| {
        TreeProof::from_bytes(b).is_ok_and(|r| {
            tree.verify_claims_sealed(&r, &claims, tree.seal_roots().unwrap(), s)
                .is_ok()
        })
    };
    let words = u32::from_le_bytes(root[7..11].try_into().unwrap()) as usize;
    let usage = words - 2 * 14 - 2 * 21 - 1;
    let at = 11 + 24 * usage;
    let mut mutations = vec![];
    for extra in [false, true] {
        let mut b = root.clone();
        if extra {
            b.splice(at..at, [0u8; 24]);
        } else {
            b.drain(at..at + 24);
        }
        let n = if extra { words + 1 } else { words - 1 };
        b[7..11].copy_from_slice(&(n as u32).to_le_bytes());
        mutations.push(json!({"action":if extra{"usage-extra"}else{"usage-missing"},"accept":accepts(&b,&seal)}));
    }
    let mut s = seal.clone();
    s.narg.extend_from_within(8 + 102 * 24..);
    s.hints.extend_from_within(..);
    mutations.push(json!({"action":"second-opening","accept":accepts(&root,&s)}));
    assert!(mutations.iter().all(|m| m["accept"] == false));
    std::fs::write(&args[2],serde_json::to_vec_pretty(&json!({"upstream_commit":PIN,"fixtures":fixtures,"loaders":loaders,"mutations":mutations})).unwrap()).unwrap();
}
