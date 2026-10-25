// Development-only inspection; appended to the pinned temporary circuit.rs.
impl Circuit {
    pub fn go_port_gates(&self) -> Vec<[usize; 4]> {
        self.gates
            .iter()
            .map(|g| match *g {
                Gate::Free(s) => [0, s.index(), 0, 0],
                Gate::Xor(a, b) => [1, a.index(), b.index(), 0],
                Gate::And(a, b, s) => [2, a.index(), b.index(), s.index()],
                Gate::Copy(a, s) => [3, a.index(), s.index(), 0],
            })
            .collect()
    }
}
