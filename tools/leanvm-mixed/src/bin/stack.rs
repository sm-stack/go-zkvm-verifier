//! Genuine point/strided/ring-switch openings, produced and checked by pinned Rust.
use fiat_shamir::{ProofTranscript, ProverState, SessionId, VerifierState};
use pcs::{
    ring_switch::{RingSwitch, SliceClaim},
    stack::{CommittedStack, StackClaim, StackCommitment, Statement},
    whir::Config,
};
use primitives::field::{F64, F192};
use serde_json::json;
use std::num::NonZeroUsize;
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn limbs(x: F192) -> [u64; 3] {
    [x.c0, x.c1, x.c2]
}
fn eval(mut v: Vec<F192>, point: &[F192]) -> F192 {
    for &r in point {
        for i in 0..v.len() / 2 {
            let (a, b) = (v[2 * i], v[2 * i + 1]);
            v[i] = a + r * (a + b);
        }
        v.truncate(v.len() / 2);
    }
    v[0]
}
fn main() {
    parallel::init_with_threads(NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::env::args().nth(1).expect("output file");
    let session = SessionId::new(b"go-port-stack-components");
    let log_n = 15;
    let rate = 2;
    let lanes = 3;
    let config = Config::for_rate(log_n, rate).unwrap();
    let words: Vec<F64> = (0..lanes << (log_n - config.initial_k()))
        .map(|i| F64((i as u64).wrapping_mul(0xdeadbeef01234567) ^ 0xf0123456789abcde))
        .collect();
    let stack = CommittedStack::new(&words, log_n, config.clone());
    let root = stack.root();
    let commitment = StackCommitment::new(root, log_n, lanes, config);
    let point = vec![F192::new(2, 3, 4), F192::new(5, 6, 7)];
    let plain = StackClaim::Point {
        offset: 0,
        low_point: point.clone(),
        value: eval(words[..4].iter().map(|&x| F192::from(x)).collect(), &point),
    };
    let strided = StackClaim::Strided {
        offset: 8,
        slot: 1,
        stride_log: 1,
        point: point.clone(),
        value: eval(
            (0..4).map(|i| F192::from(words[8 + 1 + i * 2])).collect(),
            &point,
        ),
    };
    let ring = |offset: usize, point: Vec<F192>| {
        let values = &words[offset..offset + (1 << point.len())];
        let slices = (0..64)
            .map(|b| {
                eval(
                    values
                        .iter()
                        .map(|w| F192::new((w.0 >> b) & 1, 0, 0))
                        .collect(),
                    &point,
                )
            })
            .collect();
        RingSwitch {
            offset,
            qflock_vars: point.len(),
            claims: vec![SliceClaim {
                suffix_point: point,
                s_hat_v: slices,
            }],
        }
    };
    let mut cases = vec![];
    for mode in 0..4 {
        let points = match mode {
            0 => vec![plain.clone()],
            1 => vec![strided.clone()],
            2 => vec![],
            _ => vec![plain.clone(), strided.clone()],
        };
        let rings = if mode >= 2 {
            vec![ring(0, point.clone()), ring(4, point[..1].to_vec())]
        } else {
            vec![]
        };
        let point_json:Vec<_>=points.iter().map(|p|match p {
   StackClaim::Point{offset,low_point,value}=>json!({"offset":offset,"slot":0,"stride_log":0,"point":low_point.iter().copied().map(limbs).collect::<Vec<_>>(),"value":limbs(*value)}),
   StackClaim::Strided{offset,slot,stride_log,point,value}=>json!({"offset":offset,"slot":slot,"stride_log":stride_log,"point":point.iter().copied().map(limbs).collect::<Vec<_>>(),"value":limbs(*value)})
  }).collect();
        let ring_json:Vec<_>=rings.iter().map(|r|json!({"offset":r.offset,"vars":r.qflock_vars,"claims":r.claims.iter().map(|c|json!({"point":c.suffix_point.iter().copied().map(limbs).collect::<Vec<_>>(),"slices":c.s_hat_v.iter().copied().map(limbs).collect::<Vec<_>>() })).collect::<Vec<_>>() })).collect();
        let bound =
            serde_json::to_vec(&json!({"root":hex(&root),"points":point_json,"rings":ring_json}))
                .unwrap();
        let instance = primitives::hash::hash(&bound);
        let mut p = ProverState::new(&session, &instance);
        stack.open(
            &mut p,
            &words,
            Statement {
                points: &points,
                rings: &rings,
            },
        );
        let proof = p.into_proof();
        let verify = |p: &ProofTranscript, points: &[StackClaim], rings: &[RingSwitch]| {
            let mut v = VerifierState::new(&session, &instance, p);
            commitment
                .verify(&mut v, Statement { points, rings })
                .is_ok()
                && v.check_eof().is_ok()
        };
        assert!(verify(&proof, &points, &rings));
        let mut mutations = vec![];
        for offset in [0, proof.narg.len() / 2, proof.narg.len() - 1] {
            let mut edit = proof.clone();
            edit.narg[offset] ^= 1;
            mutations.push(json!({"offset":offset,"accept":verify(&edit,&points,&rings)}));
        }
        let mut bad_points = points.clone();
        let mut bad_rings = rings.clone();
        if let Some(p) = bad_points.first_mut() {
            match p {
                StackClaim::Point { value, .. } | StackClaim::Strided { value, .. } => {
                    *value += F192::ONE
                }
            }
        } else {
            bad_rings[0].claims[0].s_hat_v[0] += F192::ONE;
        }
        cases.push(json!({"log_n":log_n,"rate":rate,"lanes":lanes,"root":hex(&root),"instance":hex(&instance),"proof":hex(&proof.to_bytes()),"points":point_json,"rings":ring_json,"mutations":mutations,"wrong_claim_accept":verify(&proof,&bad_points,&bad_rings)}));
    }
    std::fs::write(out,serde_json::to_string_pretty(&json!({"upstream_commit":"da5c964831c993b011464e4fd4a573b7172d5295","session":hex(&session.0),"cases":cases})).unwrap()+"\n").unwrap();
}
