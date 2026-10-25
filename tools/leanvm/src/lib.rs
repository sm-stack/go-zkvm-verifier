use leanvm::{Program, Proof};
/// The digest leanVM identifies `elf`'s program by.
pub fn program_digest(elf: &[u8]) -> Result<[u8; 32], String> {
    Ok(*load(elf)?.digest())
}

/// Checks that `proof` proves a run of the guest `elf` that exits with `output`.
pub fn verify(elf: &[u8], output: [u8; 32], proof: &[u8]) -> Result<(), String> {
    check(&load(elf)?, output, proof)
}

fn check(program: &Program, output: [u8; 32], proof: &[u8]) -> Result<(), String> {
    let proof = Proof::from_bytes(proof).map_err(|err| format!("malformed proof: {err:?}"))?;
    leanvm::verify(program, &output_words(output), &proof).map_err(|err| format!("{err:?}"))
}

fn load(elf: &[u8]) -> Result<Program, String> {
    Program::from_elf(elf).map_err(|err| format!("malformed guest: {err:?}"))
}

/// The output's four words, little-endian.
fn output_words(output: [u8; 32]) -> [u64; 4] {
    core::array::from_fn(|i| u64::from_le_bytes(output[8 * i..8 * i + 8].try_into().unwrap()))
}
