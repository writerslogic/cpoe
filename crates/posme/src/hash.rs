// SPDX-License-Identifier: Apache-2.0

//! BLAKE3-based hash primitives with domain separation per draft-condrey-cfrg-posme.

use crate::block::LAMBDA;

// Domain separation tags from the IETF draft.
pub const DST_INIT: &[u8] = b"PoSME-init-v1";
pub const DST_CAUSAL: &[u8] = b"PoSME-causal-v1";
pub const DST_TRANSCRIPT: &[u8] = b"PoSME-transcript-v1";
pub const DST_ADDR: &[u8] = b"PoSME-addr-v1";
pub const DST_FIAT_SHAMIR: &[u8] = b"PoSME-challenge-v1";

/// Compute BLAKE3(input_0 || input_1 || ... || input_n) -> 32 bytes.
pub fn posme_hash(inputs: &[&[u8]]) -> [u8; LAMBDA] {
    let mut hasher = blake3::Hasher::new();
    for input in inputs {
        hasher.update(input);
    }
    *hasher.finalize().as_bytes()
}

/// Integer-to-Octet-String Primitive: encode u32 as 4 big-endian bytes.
pub fn i2osp(x: u32) -> [u8; 4] {
    x.to_be_bytes()
}

/// XOF-based address derivation: BLAKE3 XOF at (DST_ADDR || cursor || I2OSP(index)),
/// producing 4 bytes interpreted as big-endian u32, reduced mod n.
pub fn addr_from(cursor: &[u8; LAMBDA], index: u32, n: u32) -> u32 {
    let h = posme_hash(&[DST_ADDR, cursor, &i2osp(index)]);
    u32::from_be_bytes([h[0], h[1], h[2], h[3]]) % n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let a = posme_hash(&[b"hello", b"world"]);
        let b = posme_hash(&[b"hello", b"world"]);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_domain_separation() {
        let a = posme_hash(&[DST_INIT, b"seed"]);
        let b = posme_hash(&[DST_CAUSAL, b"seed"]);
        assert_ne!(a, b);
    }

    #[test]
    fn addr_in_range() {
        let cursor = posme_hash(&[b"test"]);
        for n in [1u32, 7, 1024, 1 << 20] {
            for j in 0..16 {
                assert!(addr_from(&cursor, j, n) < n);
            }
        }
    }

    #[test]
    fn addr_deterministic() {
        let cursor = posme_hash(&[b"cursor"]);
        let a = addr_from(&cursor, 0, 1024);
        let b = addr_from(&cursor, 0, 1024);
        assert_eq!(a, b);
    }

    #[test]
    fn addr_varies_with_index() {
        let cursor = posme_hash(&[b"cursor"]);
        let a = addr_from(&cursor, 0, 1 << 24);
        let b = addr_from(&cursor, 1, 1 << 24);
        // With 2^24 possible values, collision probability is negligible.
        assert_ne!(a, b);
    }
}
