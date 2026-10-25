//! Wire/claim-digest vectors, not valid recursive proofs.
use leanvm::aggregate::{Capacity, ClaimGroup, ClaimSet, TreeProof};
use leanvm_mixed_reference::{PIN, hex};
use serde_json::json;
fn main() {
    let out = std::env::args().nth(1).expect("output file");
    let a = ClaimGroup {
        label: [1, 2, 3, 4, 5, 6],
        members: vec![[1, 2, 3, 4], [2, 3, 4, 5], [3, 4, 5, 6]],
    };
    let b = ClaimGroup {
        label: [2, 1, 0, 0, 0, 0],
        members: vec![[9, 8, 7, 6]],
    };
    let mut empty = a.clone();
    empty.members.clear();
    let mut repeated = a.clone();
    repeated.members.push(repeated.members[2]);
    let mut unsorted = a.clone();
    unsorted.members.reverse();
    let mut cases = vec![];
    for groups in [
        vec![],
        vec![a.clone()],
        vec![a.clone(), b.clone()],
        vec![b, a.clone()],
        vec![a.clone(), a],
        vec![empty],
        vec![repeated],
        vec![unsorted],
    ] {
        let set = ClaimSet { groups };
        let digest: Vec<u8> = set.digest().iter().flat_map(|w| w.to_le_bytes()).collect();
        let checks:Vec<_>=[(0,0),(1,1),(4,4),(5,1),(5,2),(100,100)].into_iter().map(|(claims,groups)|json!({"claims":claims,"groups":groups,"accept":set.check(Capacity{claims,groups}).is_ok()})).collect();
        cases.push(json!({"bytes":hex(&set.to_bytes()),"digest":hex(&digest),"checks":checks}));
    }
    let mut roots = vec![];
    // These test only TreeProof::from_bytes, never the cryptographic verifier.
    for rate in [0u8, 1, 2, 3, 4, 5, 255] {
        for circuit in [0u64, 1, u64::MAX] {
            for high in [0u64, 1] {
                let mut bytes = b"LVMT\x14\x00".to_vec();
                bytes.push(rate);
                bytes.extend(1u32.to_le_bytes());
                for word in [circuit, high, 0] {
                    bytes.extend(word.to_le_bytes());
                }
                bytes.extend(0u64.to_le_bytes());
                roots.push(
                    json!({"bytes":hex(&bytes),"accept":TreeProof::from_bytes(&bytes).is_ok()}),
                );
            }
        }
    }
    std::fs::write(
        out,
        serde_json::to_string_pretty(&json!({"upstream_commit":PIN,"claims":cases,"roots":roots}))
            .unwrap()
            + "\n",
    )
    .unwrap();
}
