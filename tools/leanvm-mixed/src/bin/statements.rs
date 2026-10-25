//! Match op_leanvm_tree::claim_set: canonicalize in Rust, then compare to input.
use leanvm::aggregate::{Claim, ClaimSet};
use leanvm_mixed_reference::{PIN, hex};
use serde_json::json;
fn main() {
    let a = ([1, 0, 0, 0, 0, 0], [256, 2, 3, 4]);
    let b = ([1, 0, 0, 0, 0, 0], [257, 0, 0, 0]);
    let c = ([256, 0, 0, 0, 0, 0], [1, 0, 0, 0]);
    let d = ([u64::MAX, 2, 3, 4, 0, 0], [u64::MAX, 0, 0, 0]);
    let mut cases = vec![];
    for input in [
        vec![],
        vec![a],
        vec![a, b, c, d],
        vec![b, a],
        vec![c, a],
        vec![a, a],
        vec![a, c, b],
    ] {
        let claims: Vec<_> = input
            .iter()
            .map(|&(label, member)| Claim { label, member })
            .collect();
        let set = ClaimSet::from_claims(claims.iter().copied());
        let accept = set.claims().eq(claims.iter().copied());
        let statements: Vec<_> = input
            .iter()
            .map(|(label, member)| {
                json!({
                    "vkey":hex(&label[..4].iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>()),
                    "member":hex(&member.iter().flat_map(|w|w.to_le_bytes()).collect::<Vec<_>>())
                })
            })
            .collect();
        cases
            .push(json!({"statements":statements,"accept":accept,"encoding":hex(&set.to_bytes())}));
    }
    std::fs::write(
        std::env::args().nth(1).unwrap(),
        serde_json::to_vec_pretty(&json!({"upstream_commit":PIN,"cases":cases})).unwrap(),
    )
    .unwrap();
}
