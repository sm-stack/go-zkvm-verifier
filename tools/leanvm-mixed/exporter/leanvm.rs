// Development-only inspection; appended to the pinned temporary lib.rs.
pub fn go_port_metadata() -> String {
    use crate::tables::{CircuitId, TableId};
    use flock::lincheck::LincheckCircuit;
    use primitives::{field::F192, multilinear::eq_table};
    let floors: Vec<usize> = TableId::ALL
        .iter()
        .map(|t| t.spec().n_blocks_log(1))
        .collect();
    let mut out = format!(
        "{{\"upstream_commit\":\"59c25cccfd5742f8216f259f9dd4d80d9a5f66e5\",\"leaf_min_heights\":{:?},\"max_log_rows\":{},\"max_mu\":{},\"min_mu\":{},\"tuple_bits\":{},\"hash_circuit\":{},\"hash_ports\":{},\"max_k_log\":{},\"circuits\":[",
        floors,
        cpu::MAX_LOG_ROWS,
        commitment::MAX_MU,
        commitment::MIN_MU,
        bus::N_TUPLE_BITS,
        rec::go_port_hash_metadata().0,
        rec::go_port_hash_metadata().1,
        CircuitId::MAX_K_LOG
    );
    for (i, id) in CircuitId::ALL.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let c = id.circuit();
        let mut probes = String::from("[");
        for seed in 0..3 {
            if seed > 0 {
                probes.push(',');
            }
            let row: Vec<F192> = (0..c.k_log())
                .map(|i| F192::new((i + seed + 2) as u64, (i * 3 + seed) as u64, 7))
                .collect();
            let col: Vec<F192> = (0..c.k_log())
                .map(|i| F192::new((i + seed + 11) as u64, 13, (i * 5 + seed) as u64))
                .collect();
            let alpha = match seed {
                0 => F192::ZERO,
                1 => F192::ONE,
                _ => F192::new(3, 5, 7),
            };
            let value = c.bilinear_form(alpha, &eq_table(&row), &eq_table(&col));
            let form = flock::lincheck::MatrixForm {
                alpha,
                z_skip: F192::new(19 + seed as u64, 23, 29),
                x_inner_rest: row[..c.k_log() - 6].to_vec(),
                r_inner_rest: col[..c.k_log() - 6].to_vec(),
                s_hat_v: (0..64)
                    .map(|i| F192::new(i + seed as u64, i * 7, i * 13))
                    .collect(),
            };
            let flock_value = form.evaluate(c);
            let limbs = |x: F192| [x.c0, x.c1, x.c2];
            probes += &format!(
                "{{\"row\":{:?},\"column\":{:?},\"alpha\":{:?},\"value\":{:?},\"flock\":{{\"skip\":{:?},\"slices\":{:?},\"value\":{:?}}}}}",
                row.iter().copied().map(limbs).collect::<Vec<_>>(),
                col.iter().copied().map(limbs).collect::<Vec<_>>(),
                limbs(alpha),
                limbs(value),
                limbs(form.z_skip),
                form.s_hat_v.iter().copied().map(limbs).collect::<Vec<_>>(),
                limbs(flock_value)
            );
        }
        probes.push(']');
        out += &format!(
            "{{\"index\":{},\"k_log\":{},\"const_pos\":{},\"useful_bits\":{},\"input_words\":{},\"gates\":{:?},\"probes\":{}}}",
            id.index(),
            c.k_log(),
            c.const_pos(),
            c.useful_bits(),
            c.n_input_words(),
            c.go_port_gates(),
            probes
        );
    }
    let leaf_columns: Vec<usize> = TableId::ALL
        .iter()
        .map(|t| {
            let table = t.class_table();
            let mut owned = vec![true; table.n_committed_columns()];
            for f in CircuitId::class(*t)
                .into_iter()
                .chain([CircuitId::clock(*t)])
            {
                for (_, c) in table.word_columns(f.part()) {
                    owned[c] = false;
                }
            }
            for f in table.register_bits().fields {
                owned[f.col] = false;
            }
            owned.iter().filter(|&&x| x).count()
        })
        .collect();
    let register_bits: Vec<usize> = TableId::ALL
        .iter()
        .map(|t| t.class_table().register_bits().n_slices())
        .collect();
    let tables: Vec<usize> = CircuitId::ALL.iter().map(|f| f.table().index()).collect();
    let text = crate::rv::asm::Asm::new()
        .li(crate::rv::asm::Reg::A0, 0)
        .exit()
        .finish();
    let placeholder =
        crate::cpu::Program::uncommitted(&text, crate::rv::Region::TEXT.base(), vec![], 0, 0)
            .unwrap();
    out += &format!(
        "],\"leaf_columns\":{:?},\"register_bits\":{:?},\"circuit_tables\":{:?},\"min_bytecode\":{},\"register_log\":{},\"min_cube_log\":{},\"initial_k\":{},\"rec_layouts\":{},\"leaf_sizes\":{},\"rec_tables\":{}}}",
        leaf_columns,
        register_bits,
        tables,
        placeholder.rv().entries().len().ilog2(),
        crate::rv::RegisterFile::LOG_CELLS,
        crate::tables::MIN_CUBE_LOG,
        crate::commitment::LOG_BATCH,
        rec::go_port_layouts(),
        cpu::go_port_leaf_sizes(),
        rec::go_port_tables()
    );
    out
}
