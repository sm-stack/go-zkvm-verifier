//! Small component vectors; no setup or proof generation required.
use fiat_shamir::{Blake2sDuplex, ProofTranscript, ProverState, SessionId};
use leanvm_mixed_reference::{PIN, hex};
use serde_json::json;
fn main() {
    let out = std::env::args().nth(1).expect("output file");
    let relation = std::array::from_fn::<_, 32, _>(|i| i as u8);
    let session = SessionId::tagged(b"leanvm/mixed-tree-seal/v3", &relation);
    let mut p = ProverState::new(&session, &7u64);
    p.public_message(&[1u8; 24]);
    p.prover_message(&[5u8; 32]);
    let a: [u8; 24] = p.verifier_message();
    p.prover_message(&[7u8; 24]);
    p.prover_hint(b"opening");
    p.challenge_pow(8);
    let b: [u8; 24] = p.verifier_message();
    p.challenge_pow(0);
    let c: [u8; 24] = p.verifier_message();
    let proof = p.into_proof().to_bytes();
    let mut cases = vec![];
    for input_len in [0, 1, 63, 64, 65, 127, 128, 129, 256] {
        for output_len in [1, 31, 32, 33, 64, 65] {
            let mut d = Blake2sDuplex::new(relation);
            let input: Vec<u8> = (0..input_len).map(|i| i as u8).collect();
            d.absorb(&input);
            let mut first = vec![0; output_len];
            d.squeeze(&mut first);
            d.absorb(b"next");
            let mut second = [0; 40];
            d.squeeze(&mut second);
            cases.push(json!({"input":hex(&input),"first":hex(&first),"second":hex(&second)}));
        }
    }
    let mut framing = vec![];
    for n in 0..proof.len() {
        framing.push(json!({"bytes":hex(&proof[..n]),"accept":ProofTranscript::from_bytes(&proof[..n]).is_some()}));
    }
    for tail in [vec![0], vec![0; 4], vec![255; 8]] {
        let mut edited = proof.clone();
        edited.extend(tail);
        framing.push(
            json!({"bytes":hex(&edited),"accept":ProofTranscript::from_bytes(&edited).is_some()}),
        );
    }
    std::fs::write(
        out,
        serde_json::to_string_pretty(&json!({
          "upstream_commit":PIN,
          "relation":hex(&relation),"session":hex(&session.0),"proof":hex(&proof),
          "challenges":[hex(&a),hex(&b),hex(&c)],"duplex":cases,"framing":framing
        }))
        .unwrap()
            + "\n",
    )
    .unwrap();
}
