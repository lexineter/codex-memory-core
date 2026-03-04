use sha2::{Digest, Sha256};

use crate::{CodexError, CodexResult, HASH_LEN};

pub fn sha256(input: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(input);
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Domain-separated hash: sha256(domain || 0x00 || payload)
/// The 0x00 delimiter prevents accidental domain/payload concatenation ambiguity.
pub fn hash_domain(domain: &[u8], payload: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0u8]); // delimiter
    h.update(payload);
    let out = h.finalize();
    let mut arr = [0u8; HASH_LEN];
    arr.copy_from_slice(&out);
    arr
}

/// Strict equality check for commitments; returns deterministic error on mismatch.
pub fn verify_eq(
    expected: &[u8; HASH_LEN],
    actual: &[u8; HASH_LEN],
    what: &'static str,
) -> CodexResult<()> {
    if expected == actual {
        Ok(())
    } else {
        Err(CodexError::IntegrityError(what))
    }
}
