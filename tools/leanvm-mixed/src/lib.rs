pub const PIN: &str = "da5c964831c993b011464e4fd4a573b7172d5295";
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
