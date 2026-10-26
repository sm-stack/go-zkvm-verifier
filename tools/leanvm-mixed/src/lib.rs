pub const PIN: &str = "3e7da4e783dad4c39115e5a231849e52cae5b22f";
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
mod descriptor;
pub use descriptor::descriptor;
