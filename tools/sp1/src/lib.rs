use serde::de::DeserializeOwned;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::SP1Field;
use sp1_verifier::{SP1Proof, compressed::SP1CompressedVerifier};
use std::sync::OnceLock;
const _: () = assert!(
    core::mem::size_of::<sp1_hypercube::UntrustedConfig<SP1Field>>()
        == core::mem::size_of::<SP1Field>()
);
pub fn decode_bincode<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, String> {
    let (value, read) = bincode::serde::decode_from_slice(
        bytes,
        bincode::config::legacy().with_limit::<{ 16 * 1024 * 1024 }>(),
    )
    .map_err(|e| format!("{what}: {e}"))?;
    if read != bytes.len() {
        return Err("trailing bytes".into());
    }
    Ok(value)
}
pub fn vkey_hash_from_words(words: [u32; 8]) -> [u8; 32] {
    let mut out = [0; 32];
    for (chunk, word) in out.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}
pub struct ReferenceVerifier {
    verifier: OnceLock<SP1CompressedVerifier>,
}
impl ReferenceVerifier {
    pub fn new() -> Self {
        Self {
            verifier: OnceLock::new(),
        }
    }
    pub fn verify_with_public_values(
        &self,
        hash: [u8; 32],
        public_values: &[u8],
        proof: &[u8],
    ) -> Result<(), String> {
        let mut vkey = [SP1Field::zero(); 8];
        for (dst, chunk) in vkey.iter_mut().zip(hash.chunks_exact(4)) {
            let word = u32::from_be_bytes(chunk.try_into().unwrap());
            if word >= SP1Field::ORDER_U32 {
                return Err("noncanonical vkey".into());
            }
            *dst = SP1Field::from_canonical_u32(word);
        }
        let SP1Proof::Compressed(proof) = decode_bincode(proof, "proof")? else {
            return Err("not compressed".into());
        };
        let chips = &proof.proof.opened_values.chips;
        if chips.len() > 32 || chips.keys().any(|n| n.len() > 64) {
            return Err("invalid shape".into());
        }
        self.verifier
            .get_or_init(SP1CompressedVerifier::new)
            .verify_compressed_with_public_values(&proof, public_values, &vkey)
            .map_err(|e| e.to_string())
    }
}
