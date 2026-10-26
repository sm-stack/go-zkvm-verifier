pub const PIN: &str = "59c25cccfd5742f8216f259f9dd4d80d9a5f66e5";
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

mod descriptor;
pub use descriptor::descriptor;
