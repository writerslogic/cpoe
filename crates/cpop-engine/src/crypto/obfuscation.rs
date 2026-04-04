// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// In-memory XOR-obfuscated string (defense-in-depth against memory scraping).
/// NOT encryption — does not resist an attacker who can read the nonce.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ObfuscatedString {
    nonce: [u8; 8],
    data: Vec<u8>,
}

impl ObfuscatedString {
    /// XOR-mask the string with a random 8-byte nonce.
    pub fn new(s: &str) -> Self {
        let mut nonce = [0u8; 8];
        rand::rng().fill_bytes(&mut nonce);

        let mut data = s.as_bytes().to_vec();
        Self::xor(&mut data, &nonce);

        Self { nonce, data }
    }

    /// Unmask and return the plaintext string wrapped in [`Zeroizing`] so
    /// callers cannot accidentally leave cleartext in memory.
    pub fn reveal(&self) -> Zeroizing<String> {
        let mut data = self.data.clone();
        Self::xor(&mut data, &self.nonce);
        let s = match String::from_utf8(std::mem::take(&mut data)) {
            Ok(s) => s,
            Err(e) => {
                log::error!(
                    "ObfuscatedString reveal failed: UTF-8 decode error \
                     (possible corruption): {e}"
                );
                String::new()
            }
        };
        data.zeroize();
        Zeroizing::new(s)
    }

    fn xor(data: &mut [u8], nonce: &[u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= nonce[i % nonce.len()];
        }
    }
}

impl fmt::Debug for ObfuscatedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "***OBFUSCATED***")
    }
}

impl Default for ObfuscatedString {
    fn default() -> Self {
        Self::new("")
    }
}

// Serialization intentionally outputs cleartext — obfuscation targets in-memory
// protection only (XOR masking against passive memory scraping).
impl Serialize for ObfuscatedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.reveal().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ObfuscatedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Zeroizing::new(String::deserialize(deserializer)?);
        Ok(Self::new(&s))
    }
}

/// **Not constant-time.** This comparison reveals timing information proportional
/// to the shared prefix length. Do not use for secret comparison; use
/// `subtle::ConstantTimeEq` on the revealed bytes if timing resistance is needed.
impl PartialEq for ObfuscatedString {
    fn eq(&self, other: &Self) -> bool {
        // Optimization: if nonces are same, compare data directly
        if self.nonce == other.nonce {
            return self.data == other.data;
        }
        self.reveal() == other.reveal()
    }
}

impl Eq for ObfuscatedString {}
