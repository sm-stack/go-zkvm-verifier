// Development-only inspection; appended to pinned temporary rec/mod.rs.
pub(crate) fn go_port_hash_metadata() -> (usize, usize) {
    (hash::CIRCUIT.index(), hash::N_PORTS)
}

pub(crate) fn go_port_layouts() -> String {
    use crate::stacking::Placement;
    use crate::tables::PerTable;
    let mut cases = Vec::new();
    cases.push([0usize; 6]);
    for axis in 0..6 {
        for h in [1, 5, 10, 20, 25, 28, 32, 33] {
            let mut hs = [0usize; 6];
            hs[axis] = h;
            cases.push(hs);
        }
    }
    cases.push([12, 12, 12, 12, 12, 12]);
    let mut out = String::from("[");
    for (i, hs) in cases.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let taus = PerTable::from_fn(|t: table::Table| hs[t as usize]);
        match RecLayout::from_taus(taus) {
            Err(_) => out += &format!("{{\"heights\":{:?},\"accept\":false}}", hs),
            Ok(layout) => {
                let places: Vec<[usize; 4]> = layout
                    .placements
                    .iter()
                    .map(|p| match *p {
                        Placement::Committed(w) => [0, w.offset, w.n_vars, 0],
                        Placement::Port {
                            offset,
                            port,
                            stride_log,
                        } => [1, offset, port, stride_log],
                        Placement::Sliced => [2, 0, 0, 0],
                    })
                    .collect();
                out += &format!(
                    "{{\"heights\":{:?},\"accept\":true,\"mu\":{},\"lanes\":{},\"placements\":{:?}}}",
                    hs, layout.shape.mu, layout.shape.n_lanes, places
                );
            }
        }
    }
    out.push(']');
    out
}

pub(crate) fn go_port_tables() -> String {
    use crate::bus::{BusForm, Coord};
    use primitives::field::F192;
    fn add(c: &Coord, f: &mut BusForm) {
        match c {
            Coord::Const(x) => f.constant += F192::from(*x),
            Coord::Col(i) => f.coeffs[*i] += F192::ONE,
            Coord::Prod(a, b) => f.prods.push((*a, *b, F192::ONE)),
            Coord::Scaled(c, i) => f.coeffs[*i] += F192::from(*c),
            Coord::Sum(xs) => {
                for x in xs {
                    add(x, f);
                }
            }
            _ => panic!("unexpected recursion slot coordinate"),
        }
    }
    fn form(f: &BusForm) -> String {
        let limbs = |x: F192| [x.c0, x.c1, x.c2];
        let prods: Vec<String> = f
            .prods
            .iter()
            .map(|&(a, b, w)| format!("{{\"a\":{},\"b\":{},\"value\":{:?}}}", a, b, limbs(w)))
            .collect();
        format!(
            "{{\"coeffs\":{:?},\"prods\":[{}],\"constant\":{:?}}}",
            f.coeffs.iter().copied().map(limbs).collect::<Vec<_>>(),
            prods.join(","),
            limbs(f.constant)
        )
    }
    let mut out = vec![];
    for t in table::Table::OWNED {
        let mut slots = vec![];
        for s in 0..t.n_slots() {
            let limbs: Vec<String> = t
                .slot(s)
                .0
                .iter()
                .map(|c| {
                    let mut f = BusForm {
                        coeffs: vec![F192::ZERO; t.n_cols()],
                        prods: vec![],
                        constant: F192::ZERO,
                    };
                    add(c, &mut f);
                    form(&f)
                })
                .collect();
            slots.push(format!("[{}]", limbs.join(",")));
        }
        out.push(format!(
            "{{\"columns\":{},\"slots\":[{}],\"identities\":[{}]}}",
            t.n_cols(),
            slots.join(","),
            t.identities()
                .iter()
                .map(form)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    format!("[{}]", out.join(","))
}
