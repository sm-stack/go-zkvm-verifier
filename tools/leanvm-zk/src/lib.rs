pub const PIN: &str = "3e269bd4137976648052a3335845d0c19693ec0d";
#[path = "../../leanvm-mixed/src/descriptor.rs"]
mod descriptor;
pub use descriptor::descriptor;
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
