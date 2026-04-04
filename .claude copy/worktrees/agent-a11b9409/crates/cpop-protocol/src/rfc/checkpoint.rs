

//! RFC-compliant checkpoint structure for CBOR encoding.
//!
//! Implements the checkpoint CDDL structure from draft-condrey-rats-pop-schema-01:
//!
//! ```cddl
//! checkpoint = {
//!     1 => uint,           ; sequence
//!     2 => uuid,           ; checkpoint-id
//!     3 => pop-timestamp,  ; timestamp
//!     4 => bstr .size 32,  ; content-hash
//!     5 => bstr .size 32,  ; prev-hash
//!     6 => bstr .size 32,  ; checkpoint-hash
//!     ? 7 => vdf-proof,    ; silicon-anchored VDF (optional for partial construction)
//!     ? 8 => jitter-binding, ; behavioral binding (optional for partial construction)
//!     ? 9 => bstr .size 32,  ; chain-mac (optional for partial construction)
//! }
//! ```

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::fixed_point::{Millibits, RhoMillibits};
use super::jitter_binding::JitterBinding;
use super::serde_helpers::{hex_bytes, hex_bytes_32_opt, hex_bytes_vec};
use super::vdf::VdfProofRfc;

/
/
/
const CHECKPOINT_HASH_DST: &[u8] = b"witnessd-checkpoint-v3";

/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRfc {
    #[serde(rename = "1")]
    pub sequence: u64,

    #[serde(rename = "2")]
    pub checkpoint_id: Uuid,

    #[serde(rename = "3")]
    pub timestamp: u64,

    #[serde(rename = "4", with = "hex_bytes")]
    pub content_hash: [u8; 32],

    /
    #[serde(rename = "5", with = "hex_bytes")]
    pub prev_hash: [u8; 32],

    #[serde(rename = "6", with = "hex_bytes")]
    pub checkpoint_hash: [u8; 32],

    #[serde(rename = "7", skip_serializing_if = "Option::is_none")]
    pub vdf_proof: Option<VdfProofRfc>,

    #[serde(rename = "8", skip_serializing_if = "Option::is_none")]
    pub jitter_binding: Option<JitterBinding>,

    #[serde(
        rename = "9",
        skip_serializing_if = "Option::is_none",
        with = "hex_bytes_32_opt"
    )]
    pub chain_mac: Option<[u8; 32]>,
}

impl CheckpointRfc {
    /
    pub fn new(sequence: u64, timestamp: u64, content_hash: [u8; 32], prev_hash: [u8; 32]) -> Self {
        Self {
            sequence,
            checkpoint_id: Uuid::new_v4(),
            timestamp,
            content_hash,
            prev_hash,
            checkpoint_hash: [0u8; 32],
            vdf_proof: None,
            jitter_binding: None,
            chain_mac: None,
        }
    }

    /
    pub fn with_vdf(mut self, proof: VdfProofRfc) -> Self {
        self.vdf_proof = Some(proof);
        self
    }

    /
    pub fn with_jitter(mut self, binding: JitterBinding) -> Self {
        self.jitter_binding = Some(binding);
        self
    }

    /
    pub fn with_chain_mac(mut self, mac: [u8; 32]) -> Self {
        self.chain_mac = Some(mac);
        self
    }

    /
    pub fn compute_hash(&mut self) {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        hasher.update(CHECKPOINT_HASH_DST);

        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.checkpoint_id.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.content_hash);
        hasher.update(self.prev_hash);

        if let Some(vdf) = &self.vdf_proof {
            hasher.update(b"\x01");
            hasher.update(vdf.challenge);
            hasher.update(vdf.output);
            hasher.update(vdf.iterations.to_be_bytes());
            hasher.update(vdf.duration_ms.to_be_bytes());
        } else {
            hasher.update(b"\x00");
        }

        if let Some(jitter) = &self.jitter_binding {
            hasher.update(b"\x01");
            hasher.update(jitter.entropy_commitment.hash);
        } else {
            hasher.update(b"\x00");
        }

        if let Some(mac) = &self.chain_mac {
            hasher.update(b"\x01");
            hasher.update(mac);
        } else {
            hasher.update(b"\x00");
        }

        self.checkpoint_hash = hasher.finalize().into();
    }

    /
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.timestamp == 0 {
            errors.push("timestamp must be non-zero".into());
        }

        if self.content_hash == [0u8; 32] {
            errors.push("content_hash is zero".into());
        }

        if self.checkpoint_hash == [0u8; 32] {
            errors.push("checkpoint_hash is zero (call compute_hash first)".into());
        }

        if let Some(vdf) = &self.vdf_proof {
            errors.extend(vdf.validate());
        }

        if let Some(jitter) = &self.jitter_binding {
            errors.extend(jitter.validate_strings());
        }

        errors
    }

    /
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

/
/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaVdfProof {
    /
    #[serde(rename = "1")]
    pub algorithm: u32,

    #[serde(rename = "2")]
    pub iterations: u64,

    #[serde(rename = "3")]
    pub cycle_count: u64,

    #[serde(rename = "4", with = "hex_bytes_vec")]
    pub output: Vec<u8>,
}

/
/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BioBinding {
    #[serde(rename = "1")]
    pub rho_millibits: RhoMillibits,

    #[serde(rename = "2")]
    pub hurst_millibits: Millibits,

    #[serde(rename = "3")]
    pub recognition_gap_ms: u32,
}

impl BioBinding {
    /
    pub fn new(rho: f64, hurst: f64, gap_ms: u32) -> Self {
        Self {
            rho_millibits: RhoMillibits::from_float(rho),
            hurst_millibits: Millibits::from_float(hurst),
            recognition_gap_ms: gap_ms,
        }
    }

    /
    pub fn is_hurst_human_like(&self) -> bool {
        let h = self.hurst_millibits.raw();
        h > 550 && h < 850
    }

    /
    pub fn is_correlation_valid(&self) -> bool {
        let rho = self.rho_millibits.raw();
        (500..=950).contains(&rho)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_creation() {
        let cp = CheckpointRfc::new(0, 1700000000, [1u8; 32], [0u8; 32]);

        assert_eq!(cp.sequence, 0);
        assert_eq!(cp.content_hash, [1u8; 32]);
        assert_eq!(cp.prev_hash, [0u8; 32]);
    }

    #[test]
    fn test_checkpoint_hash_computation() {
        let mut cp = CheckpointRfc::new(1, 1700000000, [1u8; 32], [2u8; 32]);

        assert_eq!(cp.checkpoint_hash, [0u8; 32]);
        cp.compute_hash();
        assert_ne!(cp.checkpoint_hash, [0u8; 32]);
    }

    #[test]
    fn test_bio_binding_hurst() {
        let binding = BioBinding::new(0.75, 0.72, 250);
        assert!(binding.is_hurst_human_like());
        assert!(binding.is_correlation_valid());

        
        let white_noise = BioBinding::new(0.75, 0.5, 250);
        assert!(!white_noise.is_hurst_human_like());
    }

    #[test]
    fn test_checkpoint_serialization() {
        let cp = CheckpointRfc::new(0, 1700000000, [1u8; 32], [0u8; 32]);

        let json = serde_json::to_string(&cp).unwrap();
        assert!(json.contains("\"1\":0")); 
        assert!(json.contains("\"3\":1700000000")); 
    }

    /
    /
    #[test]
    fn test_checkpoint_hash_dst_is_stable() {
        assert_eq!(
            super::CHECKPOINT_HASH_DST,
            b"witnessd-checkpoint-v3",
            "CHECKPOINT_HASH_DST must not change; see comment on the constant"
        );
    }
}
