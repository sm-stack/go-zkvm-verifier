use primitives::field::{F64, F192};
use serde_json::json;
fn words(a: F192) -> [u64; 3] {
    [a.c0, a.c1, a.c2]
}
fn main() {
    let out = std::env::args().nth(1).expect("output file");
    let mut state = 0xdefaced123456789u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut cases = vec![];
    for i in 0..260 {
        let a = if i < 4 {
            F192::new([0, 1, u64::MAX, 1 << 63][i], 0, 0)
        } else {
            F192::new(next(), next(), next())
        };
        let b = F192::new(next(), next(), next());
        cases.push(json!({"a":words(a),"b":words(b),"product":words(a*b),"square":words(a.square()),"inverse":words(a.inv()),"frobenius":words(a.frobenius()),"base_product":(F64(a.c0)*F64(b.c0)).0,"base_inverse":F64(a.c0).inv().0}));
    }
    std::fs::write(
        out,
        serde_json::to_string_pretty(
            &json!({"upstream_commit":"da5c964831c993b011464e4fd4a573b7172d5295","cases":cases}),
        )
        .unwrap()
            + "\n",
    )
    .unwrap();
}
