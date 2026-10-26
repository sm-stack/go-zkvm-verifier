pub const PIN: &str = "fc3fc9ec0ec218d6b5196ecae85a975590729ae6";
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
mod descriptor;
pub use descriptor::descriptor;
