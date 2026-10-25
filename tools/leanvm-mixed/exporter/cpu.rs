// Development-only inspection; appended to pinned temporary cpu/mod.rs.
pub(crate) fn go_port_leaf_sizes() -> String {
    use crate::tables::{PerTable, TableId};
    let floors: [usize; 11] = std::array::from_fn(|i| TableId::ALL[i].spec().n_blocks_log(1));
    let mut cases = vec![([12, 4, 4], floors)];
    for axis in 0..11 {
        for h in [0, 4, 12, 20, 28, 32, 33] {
            let mut hs = floors;
            hs[axis] = h;
            cases.push(([12, 4, 4], hs));
        }
    }
    for axis in 0..3 {
        for h in [0, 12, 24, 26, 27, 28, 32] {
            let mut dims = [12, 4, 4];
            dims[axis] = h;
            cases.push((dims, floors));
        }
    }
    let mut out = String::from("[");
    for (i, (dims, hs)) in cases.into_iter().enumerate() {
        if i != 0 {
            out.push(',');
        }
        let valid = hs
            .iter()
            .zip(floors)
            .all(|(&h, f)| h >= f && h <= MAX_LOG_ROWS);
        let mu = if valid {
            let taus = PerTable::from_fn(|t: TableId| hs[t.index()]);
            layout::Sizes {
                log_bytecode: dims[0],
                log_ram: dims[1],
                log_advice: dims[2],
            }
            .stack(&taus)
            .1
            .mu
        } else {
            0
        };
        out += &format!(
            "{{\"dims\":{:?},\"heights\":{:?},\"mu\":{},\"accept\":{}}}",
            dims,
            hs,
            mu,
            valid && mu <= crate::commitment::MAX_MU
        );
    }
    out.push(']');
    out
}
