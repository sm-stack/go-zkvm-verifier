//! Replay the pinned full Rust verifier on shipped genuine example roots.
use leanvm::ProofTranscript;
use leanvm::aggregate::{ClaimSet, Tree, TreeProof};
use leanvm_mixed_reference::PIN;
use serde_json::json;
use std::{io::Read, path::Path};
fn read(base: &Path, name: &str) -> Vec<u8> {
    let name = if base.join(format!("{name}.gz")).exists() {
        name
    } else {
        name.strip_prefix("production/").unwrap_or(name)
    };
    let f = std::fs::File::open(base.join(format!("{name}.gz"))).unwrap();
    let mut out = vec![];
    flate2::read::GzDecoder::new(f)
        .read_to_end(&mut out)
        .unwrap();
    out
}
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let args: Vec<_> = std::env::args().collect();
    let base = Path::new(&args[1]);
    let key = read(base, "class-key.bin");
    let pin = Tree::mixed_class_key_digest(&key);
    let (classes, shape) = leanvm_mixed_reference::descriptor(&key);
    let tree = Tree::mixed_classes_from_bytes(&classes, shape, &key, &pin).unwrap();
    let mut cases = vec![];
    let all_names = [
        "first",
        "first-class1",
        "one-member",
        "small-node",
        "wide",
        "fold-dedup",
    ];
    let names = if base.join("production/root.bin.gz").exists() || base.ends_with("production") {
        &["production"][..]
    } else if shape.claims.unwrap().small.is_none() {
        &all_names[..4]
    } else {
        &all_names[..]
    };
    let mut names = names.to_vec();
    if base.join("raw-zk-first/root.bin.gz").exists() {
        names.push("raw-zk-first");
    }
    for (i, name) in names.iter().enumerate() {
        let bytes = read(base, &format!("{name}/root.bin"));
        let root = TreeProof::from_bytes(&bytes).unwrap();
        let claim_bytes = read(base, &format!("{name}/claims.bin"));
        let claims = ClaimSet::from_bytes(&claim_bytes).unwrap();
        let seal = ProofTranscript::from_bytes(&read(base, &format!("{name}/seal.bin"))).unwrap();
        let accepts = |r: &TreeProof, c: &ClaimSet, s: &ProofTranscript| {
            tree.verify_claims_sealed(r, c, tree.seal_roots().unwrap(), s)
                .is_ok()
        };
        assert!(accepts(&root, &claims, &seal));
        let mut verdicts = vec![json!({"action":"original","accept":true})];
        let mut changed = claim_bytes.clone();
        changed[4] ^= 1;
        let wrong = ClaimSet::from_bytes(&changed).unwrap();
        verdicts.push(json!({"action":"claims-label","accept":accepts(&root,&wrong,&seal)}));
        let words = u32::from_le_bytes(bytes[7..11].try_into().unwrap()) as usize;
        let mut changed = bytes.clone();
        changed[11 + 24 * (words - 1)] ^= 1;
        let wrong = TreeProof::from_bytes(&changed).unwrap();
        verdicts.push(json!({"action":"matrix-value","accept":accepts(&wrong,&claims,&seal)}));
        if !seal.narg.is_empty() {
            for cut in [0, seal.narg.len() / 2, seal.narg.len() - 1] {
                let mut s = seal.clone();
                s.narg.truncate(cut);
                verdicts.push(
                    json!({"action":"seal-cut","cut":cut,"accept":accepts(&root,&claims,&s)}),
                );
            }
            let mut s = seal.clone();
            let last = s.narg.len() - 1;
            s.narg[last] ^= 1;
            verdicts.push(json!({"action":"seal-flip","accept":accepts(&root,&claims,&s)}));
        }
        let mut s = seal.clone();
        s.narg.push(0);
        verdicts.push(json!({"action":"seal-trailing","accept":accepts(&root,&claims,&s)}));
        let other = names[if i < 3 { names.len() - 1 } else { 0 }];
        let s = ProofTranscript::from_bytes(&read(base, &format!("{other}/seal.bin"))).unwrap();
        if names.len() > 1 {
            verdicts.push(json!({"action":"seal-swap","accept":accepts(&root,&claims,&s)}));
        }
        let mut changed = bytes.clone();
        changed[6] = if bytes[6] == 1 { 2 } else { 1 };
        let wrong = TreeProof::from_bytes(&changed).unwrap();
        verdicts.push(json!({"action":"root-rate","accept":accepts(&wrong,&claims,&seal)}));
        let transcript_at = 11 + 24 * words;
        let narg = u64::from_le_bytes(bytes[transcript_at..transcript_at + 8].try_into().unwrap())
            as usize;
        let start = transcript_at + 8;
        let mut positions = std::collections::BTreeSet::from([
            0,
            4,
            6,
            11,
            19,
            transcript_at,
            start,
            start + 31,
            start + 32,
            start + narg - 1,
            bytes.len() - 1,
        ]);
        for i in 1..16 {
            positions.insert(start + narg * i / 16);
        }
        if start + narg < bytes.len() {
            positions.insert(start + narg);
            positions.insert((start + narg + bytes.len()) / 2);
        }
        for at in positions {
            let mut edited = bytes.clone();
            edited[at] ^= 1;
            let accept = TreeProof::from_bytes(&edited).is_ok_and(|r| accepts(&r, &claims, &seal));
            verdicts.push(json!({"action":"root-byte-flip","at":at,"accept":accept}));
        }
        for cut in [0, 10, transcript_at, start + narg / 2, bytes.len() - 1] {
            let accept =
                TreeProof::from_bytes(&bytes[..cut]).is_ok_and(|r| accepts(&r, &claims, &seal));
            verdicts.push(json!({"action":"root-cut","cut":cut,"accept":accept}));
        }
        assert!(
            verdicts
                .iter()
                .skip(1)
                .all(|v| v["action"] == "seal-swap" || v["accept"] == false)
        );
        cases.push(json!({"name":name,"verdicts":verdicts}));
    }
    std::fs::write(
        &args[2],
        serde_json::to_vec(&json!({"upstream_commit":PIN,"cases":cases})).unwrap(),
    )
    .unwrap();
}
