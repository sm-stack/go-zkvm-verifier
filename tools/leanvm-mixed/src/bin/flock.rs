//! Actual pinned flock reductions; no handcrafted proof messages.
use fiat_shamir::{ProverState, SessionId, VerifierState};
use flock::{
    BatchRows,
    circuit::{Builder, Circuit},
    gadgets::Multiplier,
    reduction,
    test_util::Witness,
};
use primitives::field::{F192, PHI8_TABLE};
use serde_json::json;
fn limbs(x: F192) -> [u64; 3] {
    [x.c0, x.c1, x.c2]
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn circuit(mul: bool) -> Circuit {
    let mut c = Builder::new(&[64, 64], &[64]);
    let a = c.input::<64>(0);
    let b = c.input::<64>(1);
    if mul {
        let out = Multiplier::build::<64>(&mut c, &a, &b).0;
        for (i, w) in out.into_iter().enumerate() {
            c.output(0, i, w)
        }
    } else {
        for i in 0..64 {
            c.and_output(0, i, a[i], b[i]);
        }
    }
    c.finish()
}
fn main() {
    parallel::init_with_threads(std::num::NonZeroUsize::new(2).unwrap()).unwrap();
    let out = std::env::args().nth(1).unwrap();
    let session = SessionId::new(b"go-port-flock-components");
    let cs = [circuit(false), circuit(true)];
    let mut cases = vec![];
    for which in [vec![(0, 5)], vec![(1, 3)], vec![(0, 5), (1, 4)]] {
        let witnesses: Vec<_> = which
            .iter()
            .map(|&(i, n)| {
                let rows: Vec<[u64; 2]> = (0..1 << n)
                    .map(|j| [(j as u64).wrapping_mul(0xdeadbeef01234567), !(j as u64)])
                    .collect();
                Witness::by_walk(&cs[i], BatchRows::new(&rows, &[0; 2], n), |row, words| {
                    words.copy_from_slice(row)
                })
            })
            .collect();
        let inputs: Vec<_> = which
            .iter()
            .zip(&witnesses)
            .map(|(&(i, n), w)| w.instance(cs[i].block(), n))
            .collect();
        let shapes: Vec<_> = which
            .iter()
            .map(|&(i, n)| (cs[i].block().shape(), n))
            .collect();
        let mut ps = ProverState::new(&session, &0u64);
        let claims = reduction::prove(&inputs, &mut ps);
        let proof = ps.into_proof();
        let mut vs = VerifierState::new(&session, &0u64, &proof);
        let replay = reduction::verify(&shapes, &mut vs).unwrap();
        vs.check_eof().unwrap();
        for ((r, c), &(i, _)) in replay.iter().zip(&claims).zip(&which) {
            assert_eq!(&r.claim, c);
            r.matrices.check(&cs[i]).unwrap()
        }
        let results:Vec<_>=replay.iter().map(|r|json!({"point":r.claim.suffix_point.iter().copied().map(limbs).collect::<Vec<_>>(),"slices":r.claim.s_hat_v.iter().copied().map(limbs).collect::<Vec<_>>(),"alpha":limbs(r.matrices.form.alpha),"skip":limbs(r.matrices.form.z_skip),"rows":r.matrices.form.x_inner_rest.iter().copied().map(limbs).collect::<Vec<_>>(),"cols":r.matrices.form.r_inner_rest.iter().copied().map(limbs).collect::<Vec<_>>(),"value":limbs(r.matrices.value)})).collect();
        let mut mutations = vec![];
        for at in [
            0,
            63 * 24,
            64 * 24,
            proof.narg.len() / 2,
            proof.narg.len() - 1,
        ] {
            let mut edited = proof.clone();
            edited.narg[at] ^= 1;
            let mut vs = VerifierState::new(&session, &0u64, &edited);
            let accept = reduction::verify(&shapes, &mut vs).is_ok() && vs.check_eof().is_ok();
            mutations.push(json!({"at":at,"accept":accept}));
        }
        cases.push(json!({"shapes":shapes.iter().map(|(s,n)|json!({"KLog":s.k_log,"Pin":s.const_pin_col,"LogInstances":n})).collect::<Vec<_>>(),"messages":hex(&proof.narg),"results":results,"mutations":mutations}));
    }
    std::fs::write(out,serde_json::to_vec(&json!({"upstream_commit":"da5c964831c993b011464e4fd4a573b7172d5295","session":hex(&session.0),"phi":PHI8_TABLE.iter().copied().map(limbs).collect::<Vec<_>>(),"cases":cases})).unwrap()).unwrap();
}
