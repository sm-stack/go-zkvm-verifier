use fiat_shamir::{ProofTranscript, SessionId, VerifierState};
use pcs::{
    merkle::{hash_leaf, hash_pair},
    verifier::OpeningVerifier,
};
use serde_json::json;
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn main() {
    let out = std::env::args().nth(1).expect("output file");
    let session = SessionId::new(b"go-port-merkle-components");
    let mut openings = vec![];
    for depth in [0, 1, 3, 5] {
        let n = 1 << depth;
        for (row_words, leaf_words) in [(1, 1), (1, 8), (3, 4), (8, 8), (9, 16)] {
            let rows: Vec<Vec<u64>> = (0..n)
                .map(|i| (0..row_words).map(|j| (i * 101 + j + 1) as u64).collect())
                .collect();
            let mut levels = vec![
                rows.iter()
                    .map(|r| {
                        let mut bytes = vec![0; 8 * (leaf_words - row_words)];
                        bytes.extend(r.iter().flat_map(|w| w.to_le_bytes()));
                        hash_leaf(&bytes)
                    })
                    .collect::<Vec<_>>(),
            ];
            for l in 0..depth {
                levels.push(
                    levels[l]
                        .chunks(2)
                        .map(|p| hash_pair(&p[0], &p[1]))
                        .collect(),
                );
            }
            let root = levels[depth][0];
            for queries in [vec![0], vec![n - 1, 0, n - 1], (0..n).collect()] {
                let mut sorted = queries.clone();
                sorted.sort_unstable();
                sorted.dedup();
                let mut hint: Vec<u8> = sorted
                    .iter()
                    .flat_map(|&i| rows[i].iter().flat_map(|w| w.to_le_bytes()))
                    .collect();
                let mut indices = sorted;
                for level in levels.iter().take(depth) {
                    for &i in &indices {
                        if indices.binary_search(&(i ^ 1)).is_err() {
                            hint.extend(level[i ^ 1]);
                        }
                    }
                    indices = indices.iter().map(|i| i >> 1).collect();
                    indices.dedup();
                }
                let mut variants = vec![hint.clone()];
                let mut flip = hint.clone();
                flip[0] ^= 1;
                variants.push(flip);
                variants.push(hint[..hint.len() - 1].to_vec());
                let mut tail = hint.clone();
                tail.extend([0; 32]);
                variants.push(tail);
                for hint in variants {
                    let mut proof = ProofTranscript::default();
                    proof.push_hint(&hint);
                    let mut v = VerifierState::new(&session, &1u64, &proof);
                    let result = v.open_rows(&root, depth, &queries, row_words, leaf_words);
                    let got = result.as_ref().ok().map(|rows| {
                        rows.iter()
                            .map(|r| r.iter().map(|w| w.0).collect::<Vec<_>>())
                            .collect::<Vec<_>>()
                    });
                    openings.push(json!({"depth":depth,"root":hex(&root),"queries":queries,"row_words":row_words,"leaf_words":leaf_words,"hint":hex(&hint),"accept":result.is_ok(),"rows":got}));
                }
            }
        }
    }
    let mut samples = vec![];
    for depth in [1, 2, 7, 16, 17, 31, 32, 33, 63] {
        for count in [0, 1, 3, 8, 17, 65] {
            let proof = ProofTranscript::default();
            let mut v = VerifierState::new(&session, &1u64, &proof);
            let queries = v.sample_queries(depth, count);
            samples.push(json!({"depth":depth,"count":count,"queries":queries}));
        }
    }
    std::fs::write(out,serde_json::to_string_pretty(&json!({"upstream_commit":"da5c964831c993b011464e4fd4a573b7172d5295","session":hex(&session.0),"openings":openings,"samples":samples})).unwrap()+"\n").unwrap();
}
