fn main() {
    std::fs::write(
        std::env::args().nth(1).expect("output file"),
        leanvm::go_port_metadata(),
    )
    .unwrap();
}
