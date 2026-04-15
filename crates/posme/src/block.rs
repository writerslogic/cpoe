// SPDX-License-Identifier: Apache-2.0

//! Arena block type for PoSME.

/// Hash output and block field size in bytes (BLAKE3 produces 32 bytes).
pub const LAMBDA: usize = 32;

/// Total block size: data (32) + causal (32) = 64 bytes.
pub const BLOCK_SIZE: usize = LAMBDA * 2;

/// A single arena block containing a data field and a causal hash chain.
///
/// The `data` field stores the block's computational value.
/// The `causal` field stores a running digest binding the block's
/// current value to the cursor of the step that last wrote it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub data: [u8; LAMBDA],
    pub causal: [u8; LAMBDA],
}

impl Block {
    /// Create a zero-initialized block.
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; LAMBDA],
            causal: [0u8; LAMBDA],
        }
    }

    /// Serialize block as 64 bytes: data || causal.
    pub fn to_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut out = [0u8; BLOCK_SIZE];
        out[..LAMBDA].copy_from_slice(&self.data);
        out[LAMBDA..].copy_from_slice(&self.causal);
        out
    }
}

impl Default for Block {
    fn default() -> Self {
        Self::zeroed()
    }
}
