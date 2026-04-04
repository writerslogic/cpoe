

//! RFC-compliant evidence packet structure for CBOR encoding.
//!
//! Implements the evidence-packet CDDL structure from draft-condrey-rats-pop-schema-01:
//!
//! ```cddl
//! tagged-evidence-packet = #6.1129336656(evidence-packet)
//!
//! evidence-packet = {
//!     1 => uint,                      ; version (1)
//!     2 => vdf-structure,             ; VDF
//!     3 => jitter-seal-structure,     ; Jitter Seal
//!     4 => content-hash-tree,         ; Merkle for segments
//!     5 => correlation-proof,         ; Spearman Correlation
//!     ? 6 => error-topology,          ; Fractal Error Pattern
//!     ? 7 => enclave-vise,            ; Hardware Observation Post
//!     ? 8 => zk-process-verdict,      ; Process Consistency Verdict
//!     ? 9 => profile-declaration,     ; Profile tier and features
//!     ? 18 => privacy-budget-certificate,
//!     ? 19 => key-rotation-metadata,
//!     * tstr => any,                  ; extensions
//! }
//! ```
//!
//! CBOR Semantic Tag: 1129336656 (0x43504F50, "CPOP" per IANA)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::fixed_point::{Centibits, Decibits, Millibits, RhoMillibits, SlopeDecibits};
use super::serde_helpers::{hex_bytes_vec, hex_bytes_vec_opt};

/
/
pub const CBOR_TAG_EVIDENCE_PACKET: u64 = crate::codec::CBOR_TAG_CPOP;

/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRfc {
    /
    /
    #[serde(rename = "1")]
    pub version: u32,

    /
    /
    #[serde(rename = "2")]
    pub vdf: VdfStructure,

    /
    /
    #[serde(rename = "3")]
    pub jitter_seal: JitterSealStructure,

    /
    /
    #[serde(rename = "4")]
    pub content_hash_tree: ContentHashTree,

    /
    /
    #[serde(rename = "5")]
    pub correlation_proof: CorrelationProof,

    /
    /
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub error_topology: Option<ErrorTopology>,

    /
    /
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub enclave_vise: Option<EnclaveVise>,

    /
    /
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub zk_verdict: Option<ZkProcessVerdict>,

    /
    /
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ProfileDeclaration>,

    /
    /
    #[serde(rename = "18", default, skip_serializing_if = "Option::is_none")]
    pub privacy_budget: Option<PrivacyBudgetCertificate>,

    /
    /
    #[serde(rename = "19", default, skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotationMetadata>,

    /
    /
    /
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, serde_json::Value>,
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
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdfStructure {
    /
    #[serde(rename = "1", with = "hex_bytes_vec")]
    pub input: Vec<u8>,

    /
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub output: Vec<u8>,

    /
    #[serde(rename = "3")]
    pub iterations: u64,

    /
    #[serde(rename = "4")]
    pub rdtsc_checkpoints: Vec<u64>,

    /
    #[serde(rename = "5", with = "hex_bytes_vec")]
    pub entropic_pulse: Vec<u8>,
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
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterSealStructure {
    /
    #[serde(rename = "1")]
    pub lang: String,

    /
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub bucket_commitment: Vec<u8>,

    /
    #[serde(rename = "3")]
    pub entropy_millibits: u64,

    /
    #[serde(rename = "4")]
    pub dp_epsilon_centibits: Centibits,

    /
    #[serde(rename = "5")]
    pub pink_noise_slope_decibits: SlopeDecibits,
}

/
/
/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentHashTree {
    /
    #[serde(rename = "1", with = "hex_bytes_vec")]
    pub root: Vec<u8>,

    /
    #[serde(rename = "2")]
    pub segment_count: u16,
}

impl ContentHashTree {
    /
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.root.is_empty() {
            errors.push("content hash tree root is empty".into());
        }
        if self.segment_count < 20 {
            errors.push(format!(
                "segment_count {} is below CDDL minimum 20",
                self.segment_count
            ));
        }
        errors
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationProof {
    /
    #[serde(rename = "1")]
    pub rho: RhoMillibits,

    /
    #[serde(rename = "2")]
    pub threshold: i16,
}

impl Default for CorrelationProof {
    fn default() -> Self {
        Self {
            rho: RhoMillibits::new(0),
            threshold: 700,
        }
    }
}

/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorTopology {
    /
    #[serde(rename = "1")]
    pub fractal_dimension_decibits: Decibits,

    /
    #[serde(rename = "2")]
    pub clustering_millibits: Millibits,

    /
    #[serde(rename = "3", with = "hex_bytes_vec")]
    pub temporal_signature: Vec<u8>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveVise {
    /
    #[serde(rename = "1")]
    pub enclave_type: u8,

    /
    #[serde(rename = "2", with = "hex_bytes_vec")]
    pub attestation: Vec<u8>,

    /
    #[serde(rename = "3")]
    pub timestamp: u64,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProcessVerdict {
    /
    #[serde(rename = "1")]
    pub verdict: u8,

    /
    #[serde(rename = "2")]
    pub confidence_millibits: Millibits,

    /
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_bytes_vec_opt"
    )]
    pub proof: Option<Vec<u8>>,
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
pub struct ProfileDeclaration {
    /
    #[serde(rename = "1")]
    pub tier: u8,

    /
    #[serde(rename = "2")]
    pub uri: String,

    /
    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub enabled_features: Option<Vec<u8>>,

    /
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub implementation_id: Option<String>,
}

impl ProfileDeclaration {
    /
    pub fn core() -> Self {
        Self {
            tier: 1,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }

    /
    pub fn enhanced() -> Self {
        Self {
            tier: 2,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }

    /
    pub fn maximum() -> Self {
        Self {
            tier: 3,
            uri: "urn:ietf:params:pop:profile:1.0".to_string(),
            enabled_features: None,
            implementation_id: None,
        }
    }
}

/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBudgetCertificate {
    /
    #[serde(rename = "1")]
    pub key_generation_method: String,

    /
    #[serde(rename = "2")]
    pub key_valid_from: u64,

    /
    #[serde(rename = "3")]
    pub key_valid_until: u64,

    /
    #[serde(rename = "4")]
    pub session_epsilon_centibits: Centibits,

    /
    #[serde(rename = "5")]
    pub cumulative_epsilon_micros_before: u64,

    /
    #[serde(rename = "6")]
    pub cumulative_epsilon_micros_after: u64,

    /
    #[serde(rename = "7")]
    pub sessions_used_this_key: u8,

    /
    #[serde(rename = "8")]
    pub max_sessions_recommended: u8,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationMetadata {
    /
    #[serde(rename = "1")]
    pub rotation_method: String,

    /
    #[serde(rename = "2")]
    pub next_rotation_date: u64,

    /
    #[serde(rename = "3")]
    pub sessions_remaining: u8,

    /
    #[serde(rename = "4")]
    pub cumulative_epsilon_micros: u64,
}

impl PacketRfc {
    /
    pub fn new_core(
        vdf: VdfStructure,
        jitter_seal: JitterSealStructure,
        content_hash_tree: ContentHashTree,
        correlation_proof: CorrelationProof,
    ) -> Self {
        Self {
            version: 1,
            vdf,
            jitter_seal,
            content_hash_tree,
            correlation_proof,
            error_topology: None,
            enclave_vise: None,
            zk_verdict: None,
            profile: Some(ProfileDeclaration::core()),
            privacy_budget: None,
            key_rotation: None,
            extensions: HashMap::new(),
        }
    }

    /
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if self.version != 1 {
            errors.push(format!("unsupported version: {}", self.version));
        }

        if self.vdf.input.len() != 32 {
            errors.push(format!(
                "VDF input must be 32 bytes per CDDL, got {}",
                self.vdf.input.len()
            ));
        }

        if self.vdf.output.len() != 32 && self.vdf.output.len() != 64 {
            errors.push(format!(
                "VDF output must be 32 or 64 bytes per CDDL, got {}",
                self.vdf.output.len()
            ));
        }

        if self.vdf.iterations == 0 {
            errors.push("VDF iterations must be non-zero".into());
        }

        if self.content_hash_tree.root.is_empty() {
            errors.push("content hash tree root is empty".into());
        }

        if self.content_hash_tree.segment_count < 20 {
            errors.push(format!(
                "segment_count {} is below minimum 20",
                self.content_hash_tree.segment_count
            ));
        }

        if self.correlation_proof.threshold != 700 {
            errors.push(format!(
                "non-standard correlation threshold: {} (expected 700)",
                self.correlation_proof.threshold
            ));
        }

        errors
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet() -> PacketRfc {
        PacketRfc::new_core(
            VdfStructure {
                input: vec![1u8; 32],
                output: vec![2u8; 64],
                iterations: 1_000_000,
                rdtsc_checkpoints: vec![1000, 2000, 3000],
                entropic_pulse: vec![3u8; 32],
            },
            JitterSealStructure {
                lang: "en-US".to_string(),
                bucket_commitment: vec![4u8; 32],
                entropy_millibits: 8500,
                dp_epsilon_centibits: Centibits::from_float(0.5),
                pink_noise_slope_decibits: SlopeDecibits::from_float(-1.0),
            },
            ContentHashTree {
                root: vec![5u8; 32],
                segment_count: 25,
            },
            CorrelationProof {
                rho: RhoMillibits::from_float(0.75),
                threshold: 700,
            },
        )
    }

    #[test]
    fn test_packet_creation() {
        let packet = create_test_packet();
        assert_eq!(packet.version, 1);
        assert!(packet.profile.is_some());
        assert_eq!(packet.profile.as_ref().unwrap().tier, 1);
    }

    #[test]
    fn test_packet_validation() {
        let packet = create_test_packet();
        let errors = packet.validate();
        assert!(errors.is_empty(), "errors: {:?}", errors);
    }

    #[test]
    fn test_packet_validation_empty_vdf() {
        let mut packet = create_test_packet();
        packet.vdf.input = vec![];
        let errors = packet.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("VDF input must be 32 bytes")));
    }

    #[test]
    fn test_packet_serialization() {
        let packet = create_test_packet();
        let json = serde_json::to_string(&packet).unwrap();

        assert!(json.contains("\"1\":1"));
        assert!(json.contains("\"2\":{"));
        assert!(json.contains("\"3\":{"));

        let decoded: PacketRfc = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.version, packet.version);
    }

    #[test]
    fn test_profile_tiers() {
        assert_eq!(ProfileDeclaration::core().tier, 1);
        assert_eq!(ProfileDeclaration::enhanced().tier, 2);
        assert_eq!(ProfileDeclaration::maximum().tier, 3);
    }
}
