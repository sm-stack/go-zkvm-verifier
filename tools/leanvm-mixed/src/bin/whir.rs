//! Genuine small weighted PCS openings for end-to-end WHIR verification.
use fiat_shamir::{ProofTranscript, ProverState, SessionId, VerifierState};
use pcs::{
    stack::{CommittedStack, StackCommitment, Weighted},
    whir::Config,
};
use primitives::field::{F64, F192};
use serde_json::json;
use std::num::NonZeroUsize;
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn main() {
    parallel::init_with_threads(NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::env::args().nth(1).expect("output file");
    let session = SessionId::new(b"go-port-whir-components");
    let mut cases = vec![];
    for (log_n, rate, lanes) in [(15, 1, 3), (15, 4, 16), (18, 2, 5)] {
        let c = Config::for_rate(log_n, rate).unwrap();
        let words: Vec<F64> = (0..lanes << (log_n - c.initial_k()))
            .map(|i| F64(i as u64 * 1234567 + 5))
            .collect();
        let stack = CommittedStack::new(&words, log_n, c.clone());
        let root = stack.root();
        let weight = [F192::new(1, 2, 3), F192::new(4, 5, 6)];
        let target = weight[0].mul_base(words[0]) + weight[1].mul_base(words[1]);
        let instance = [
            root.to_vec(),
            target.to_le_bytes().to_vec(),
            weight.iter().flat_map(|w| w.to_le_bytes()).collect(),
        ]
        .concat();
        // A fixed-size byte instance, so no runtime Vec Encoding is needed.
        let instance: [u8; 104] = instance.try_into().unwrap();
        let mut p = ProverState::new(&session, &instance);
        stack.open_weighted(
            &mut p,
            &words,
            Weighted {
                weight: &weight,
                value: target,
            },
        );
        let proof = p.into_proof();
        let commitment = StackCommitment::new(root, log_n, lanes, c);
        let verify = |proof: &ProofTranscript, value: F192| {
            let mut v = VerifierState::new(&session, &instance, proof);
            commitment
                .verify_weighted(
                    &mut v,
                    Weighted {
                        weight: &weight,
                        value,
                    },
                )
                .is_ok()
                && v.check_eof().is_ok()
        };
        assert!(verify(&proof, target));
        let mut mutations = vec![];
        for offset in [0, 23, 24, 47, proof.narg.len() / 2, proof.narg.len() - 1] {
            let mut edit = proof.clone();
            edit.narg[offset] ^= 1;
            mutations
                .push(json!({"part":"messages","offset":offset,"accept":verify(&edit,target)}));
        }
        for offset in [0, proof.hints.len() / 2, proof.hints.len() - 1] {
            let mut edit = proof.clone();
            edit.hints[offset] ^= 1;
            mutations.push(json!({"part":"hints","offset":offset,"accept":verify(&edit,target)}));
        }
        let wrong = target + F192::ONE;
        cases.push(json!({"log_n":log_n,"rate":rate,"lanes":lanes,"root":hex(&root),"instance":hex(&instance),"proof":hex(&proof.to_bytes()),"target":[target.c0,target.c1,target.c2],"weight":weight.map(|w|[w.c0,w.c1,w.c2]),"wrong_target_accept":verify(&proof,wrong),"mutations":mutations}));
    }
    std::fs::write(out,serde_json::to_string_pretty(&json!({"upstream_commit":"da5c964831c993b011464e4fd4a573b7172d5295","session":hex(&session.0),"cases":cases})).unwrap()+"\n").unwrap();
}
