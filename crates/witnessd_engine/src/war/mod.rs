// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! WAR (Witnessd Authorship Record) block encoding and verification.
//!
//! This module implements the WAR evidence block format, a PGP-style ASCII-armored
//! representation of witnessd evidence that is human-readable and independently verifiable.

pub mod encoding;
pub mod types;
pub mod verification;

#[cfg(test)]
mod tests;

pub use encoding::word_wrap;
pub use types::{Block, CheckResult, ForensicDetails, Seal, VerificationReport, Version};
pub use verification::compute_seal;

use crate::evidence::Packet;
use witnessd_protocol::crypto::PoPSigner;

impl Block {
    /// Create a WAR block from an evidence packet.
    pub fn from_packet(packet: &Packet) -> Result<Self, String> {
        let declaration = packet
            .declaration
            .as_ref()
            .ok_or("evidence packet missing declaration")?;

        let version = if declaration.has_jitter_seal() {
            Version::V1_1
        } else {
            Version::V1_0
        };

        let document_id = hex::decode(&packet.document.final_hash)
            .map_err(|e| format!("invalid document hash: {e}"))?;
        if document_id.len() != 32 {
            return Err("document hash must be 32 bytes".to_string());
        }
        let mut doc_id = [0u8; 32];
        doc_id.copy_from_slice(&document_id);

        let author = if declaration.author_public_key.len() == 32 {
            let fingerprint = &hex::encode(&declaration.author_public_key)[..16];
            format!("key:{}", fingerprint)
        } else {
            "unknown".to_string()
        };

        let seal = compute_seal(packet, declaration)?;

        Ok(Self {
            version,
            author,
            document_id: doc_id,
            timestamp: packet.exported_at,
            statement: declaration.statement.clone(),
            seal,
            evidence: Some(Box::new(packet.clone())),
            signed: false,
            verifier_nonce: packet.verifier_nonce,
        })
    }

    /// Create a signed WAR block from an evidence packet.
    pub fn from_packet_signed(packet: &Packet, signer: &dyn PoPSigner) -> Result<Self, String> {
        let mut block = Self::from_packet(packet)?;
        block.sign(signer)?;
        Ok(block)
    }

    /// Sign the WAR block's seal with the given signer (software or hardware).
    pub fn sign(&mut self, signer: &dyn PoPSigner) -> Result<(), String> {
        let signature_bytes = signer
            .sign(&self.seal.h3)
            .map_err(|e| format!("signing failed: {}", e))?;

        if signature_bytes.len() != 64 {
            return Err(format!(
                "invalid signature length: expected 64, got {}",
                signature_bytes.len()
            ));
        }

        self.seal.signature.copy_from_slice(&signature_bytes);
        self.signed = true;

        Ok(())
    }
}
