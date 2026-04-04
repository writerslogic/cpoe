

//! Evidence component types for wire-format structures.
//!
//! Implements `document-ref`, `edit-delta`, `proof-params`, `merkle-proof`,
//! `process-proof`, `jitter-binding`, `physical-state`, `physical-liveness`,
//! `presence-challenge`, `channel-binding`, `self-receipt`, `active-probe`,
//! `profile-declaration`, `baseline-verification`, `baseline-digest`,
//! `session-behavioral-summary`, and `streaming-stats` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::{BindingType, ConfidenceTier, HashSaltMode, ProbeType, ProofAlgorithm};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_32, fixed_bytes_32_opt, serde_bytes_opt};

/
const ALLOWED_SALT_LENGTHS: &[usize] = &[32, 48, 64];

/
const MIN_CHALLENGE_NONCE_LEN: usize = 16;
/
const MAX_CHALLENGE_NONCE_LEN: usize = 256;

/
/
/
pub const SWF_MIN_DURATION_FACTOR: f64 = 0.5;

/
/
/
pub const SWF_MAX_DURATION_FACTOR: f64 = 3.0;

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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DocumentRef {
    #[serde(rename = "1")]
    pub content_hash: HashValue,

    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    #[serde(rename = "3")]
    pub byte_length: u64,

    #[serde(rename = "4")]
    pub char_count: u64,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub salt_mode: Option<HashSaltMode>,

    /
    #[serde(
        rename = "6",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub salt_commitment: Option<Vec<u8>>,
}

impl DocumentRef {
    /
    pub fn validate(&self) -> Result<(), String> {
        self.content_hash.validate_digest_length()?;
        if let Some(ref salt) = self.salt_commitment {
            if !ALLOWED_SALT_LENGTHS.contains(&salt.len()) {
                return Err(format!(
                    "salt_commitment length {} invalid (must be {:?} bytes)",
                    salt.len(),
                    ALLOWED_SALT_LENGTHS
                ));
            }
        }
        Ok(())
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
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EditDelta {
    #[serde(rename = "1")]
    pub chars_added: u64,

    #[serde(rename = "2")]
    pub chars_deleted: u64,

    #[serde(rename = "3")]
    pub op_count: u64,

    /
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub positions: Option<Vec<(u64, i64)>>,

    /
    #[serde(
        rename = "5",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub edit_graph_hash: Option<Vec<u8>>,

    /
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub cursor_trajectory_histogram: Option<Vec<u64>>,

    /
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub revision_depth_histogram: Option<Vec<u64>>,

    /
    #[serde(rename = "11", default, skip_serializing_if = "Option::is_none")]
    pub pause_duration_histogram: Option<Vec<u64>>,
}

/
/
/
const MAX_EDIT_POSITIONS: usize = 100_000;

impl EditDelta {
    /
    pub fn validate(&self) -> Result<(), String> {
        if let Some(ref positions) = self.positions {
            if positions.len() > MAX_EDIT_POSITIONS {
                return Err(format!(
                    "too many edit positions: {} (max {})",
                    positions.len(),
                    MAX_EDIT_POSITIONS
                ));
            }
            for (i, &(_offset, change)) in positions.iter().enumerate() {
                if change == 0 {
                    return Err(format!(
                        "edit position[{}] has zero change value (no-op not allowed)",
                        i
                    ));
                }
            }
        }
        
        for (name, hist) in [
            (
                "cursor_trajectory_histogram",
                &self.cursor_trajectory_histogram,
            ),
            ("revision_depth_histogram", &self.revision_depth_histogram),
            ("pause_duration_histogram", &self.pause_duration_histogram),
        ] {
            if let Some(h) = hist {
                if h.len() != 8 {
                    return Err(format!(
                        "{} must have exactly 8 elements, got {}",
                        name,
                        h.len()
                    ));
                }
            }
        }
        Ok(())
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
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofParams {
    #[serde(rename = "1")]
    pub time_cost: u64,

    /
    #[serde(rename = "2")]
    pub memory_cost: u64,

    #[serde(rename = "3")]
    pub parallelism: u64,

    #[serde(rename = "4")]
    pub steps: u64,

    /
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub waypoint_interval: Option<u64>,

    /
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub waypoint_memory: Option<u64>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MerkleProof {
    #[serde(rename = "1")]
    pub leaf_index: u64,

    /
    #[serde(rename = "2")]
    pub sibling_path: Vec<serde_bytes::ByteBuf>,

    #[serde(rename = "3", with = "serde_bytes")]
    pub leaf_value: Vec<u8>,
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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessProof {
    #[serde(rename = "1")]
    pub algorithm: ProofAlgorithm,

    #[serde(rename = "2")]
    pub params: ProofParams,

    #[serde(rename = "3", with = "serde_bytes")]
    pub input: Vec<u8>,

    #[serde(rename = "4", with = "serde_bytes")]
    pub merkle_root: Vec<u8>,

    #[serde(rename = "5")]
    pub sampled_proofs: Vec<MerkleProof>,

    /
    #[serde(rename = "6")]
    pub claimed_duration: u64,
}

/
/
const MAX_SAMPLED_PROOFS: usize = 1000;
/
/
const MAX_MERKLE_DEPTH: usize = 64;
/
/
const MAX_DIGEST_LEN: usize = 64;
/
/
pub(crate) const MAX_JITTER_INTERVALS: usize = 100_000;
/
/
const MAX_THERMAL_SAMPLES: usize = 10_000;
/
/
const MAX_THERMAL_TRAJECTORY: usize = 10_000;
/
/
const MAX_FEATURE_FLAGS: usize = 100;
/
const SHA256_DIGEST_LEN: usize = 32;

impl ProcessProof {
    /
    /
    /
    pub fn is_duration_within_bounds(&self, expected_duration_ms: u64) -> bool {
        if expected_duration_ms == 0 || self.claimed_duration == 0 {
            return false;
        }
        let ratio = self.claimed_duration as f64 / expected_duration_ms as f64;
        (SWF_MIN_DURATION_FACTOR..=SWF_MAX_DURATION_FACTOR).contains(&ratio)
    }

    /
    pub fn validate(&self) -> Result<(), String> {
        if self.input.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "process_proof input too long: {} (max {})",
                self.input.len(),
                MAX_DIGEST_LEN
            ));
        }
        if self.merkle_root.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "merkle_root too long: {} (max {})",
                self.merkle_root.len(),
                MAX_DIGEST_LEN
            ));
        }
        if self.sampled_proofs.len() > MAX_SAMPLED_PROOFS {
            return Err(format!(
                "too many sampled_proofs: {} (max {})",
                self.sampled_proofs.len(),
                MAX_SAMPLED_PROOFS
            ));
        }
        for (i, proof) in self.sampled_proofs.iter().enumerate() {
            proof
                .validate()
                .map_err(|e| format!("sampled_proofs[{}]: {}", i, e))?;
        }
        Ok(())
    }
}

impl MerkleProof {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.sibling_path.len() > MAX_MERKLE_DEPTH {
            return Err(format!(
                "sibling_path too deep: {} (max {})",
                self.sibling_path.len(),
                MAX_MERKLE_DEPTH
            ));
        }
        if self.leaf_value.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "leaf_value too long: {} (max {})",
                self.leaf_value.len(),
                MAX_DIGEST_LEN
            ));
        }
        for (i, sibling) in self.sibling_path.iter().enumerate() {
            if sibling.len() != SHA256_DIGEST_LEN {
                return Err(format!(
                    "sibling_path[{}] length {} != {} (expected SHA-256 digest)",
                    i,
                    sibling.len(),
                    SHA256_DIGEST_LEN
                ));
            }
        }
        Ok(())
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitterBindingWire {
    /
    #[serde(rename = "1")]
    pub intervals: Vec<u64>,

    /
    #[serde(rename = "2")]
    pub entropy_estimate: u64,

    /
    #[serde(rename = "3", with = "serde_bytes")]
    pub jitter_seal: Vec<u8>,
}

impl JitterBindingWire {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.intervals.len() > MAX_JITTER_INTERVALS {
            return Err(format!(
                "too many jitter intervals: {} (max {})",
                self.intervals.len(),
                MAX_JITTER_INTERVALS
            ));
        }
        if self.jitter_seal.len() > MAX_DIGEST_LEN {
            return Err(format!(
                "jitter_seal too long: {} (max {})",
                self.jitter_seal.len(),
                MAX_DIGEST_LEN
            ));
        }
        Ok(())
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
/
/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalState {
    /
    #[serde(rename = "1")]
    pub thermal: Vec<i64>,

    #[serde(rename = "2")]
    pub entropy_delta: i64,

    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "fixed_bytes_32_opt"
    )]
    pub kernel_commitment: Option<[u8; 32]>,

    /
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub inertial_samples: Option<Vec<InertialSample>>,
}

impl PhysicalState {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.thermal.len() > MAX_THERMAL_SAMPLES {
            return Err(format!(
                "too many thermal samples: {} (max {})",
                self.thermal.len(),
                MAX_THERMAL_SAMPLES
            ));
        }
        Ok(())
    }
}

/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InertialSample {
    /
    pub timestamp: u64,
    /
    pub x: i64,
    /
    pub y: i64,
    /
    pub z: i64,
}

/
/
/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhysicalLiveness {
    /
    #[serde(rename = "1")]
    pub thermal_trajectory: Vec<(u64, i64)>,

    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub entropy_anchor: [u8; 32],
}

impl PhysicalLiveness {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.thermal_trajectory.len() > MAX_THERMAL_TRAJECTORY {
            return Err(format!(
                "too many thermal_trajectory entries: {} (max {})",
                self.thermal_trajectory.len(),
                MAX_THERMAL_TRAJECTORY
            ));
        }
        Ok(())
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceChallenge {
    /
    #[serde(rename = "1", with = "serde_bytes")]
    pub challenge_nonce: Vec<u8>,

    /
    /
    #[serde(rename = "2", with = "serde_bytes")]
    pub device_signature: Vec<u8>,

    /
    #[serde(rename = "3")]
    pub response_time: u64,
}

impl PresenceChallenge {
    /
    /
    /
    /
    /
    /
    pub fn wrap_device_signature_cose(
        payload: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
        platform_attestation: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
        use ed25519_dalek::Signer;

        let protected = HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .build();

        let mut unprotected_builder = HeaderBuilder::new();
        if let Some(att) = platform_attestation {
            
            
            unprotected_builder = unprotected_builder
                .text_value("att".to_string(), ciborium::Value::Bytes(att.to_vec()));
        }
        let unprotected = unprotected_builder.build();

        CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_vec())
            .create_signature(&[], |sig_data| {
                signing_key.sign(sig_data).to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .map_err(|e| format!("COSE_Sign1 serialization: {e}"))
    }

    /
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.challenge_nonce.len() < MIN_CHALLENGE_NONCE_LEN
            || self.challenge_nonce.len() > MAX_CHALLENGE_NONCE_LEN
        {
            return Err(format!(
                "challenge_nonce length {} out of range (must be {}..={} bytes)",
                self.challenge_nonce.len(),
                MIN_CHALLENGE_NONCE_LEN,
                MAX_CHALLENGE_NONCE_LEN
            ));
        }
        Ok(())
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelBinding {
    #[serde(rename = "1")]
    pub binding_type: BindingType,

    /
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub binding_value: [u8; 32],
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelfReceipt {
    #[serde(rename = "1")]
    pub tool_id: String,

    #[serde(rename = "2")]
    pub output_commit: HashValue,

    #[serde(rename = "3")]
    pub evidence_ref: HashValue,

    /
    #[serde(rename = "4")]
    pub transfer_time: u64,
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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolReceipt {
    #[serde(rename = "1")]
    pub tool_id: String,

    #[serde(rename = "2")]
    pub output_commit: HashValue,

    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<HashValue>,

    /
    #[serde(rename = "4")]
    pub issued_at: u64,

    /
    #[serde(rename = "5", with = "serde_bytes")]
    pub tool_signature: Vec<u8>,

    #[serde(rename = "6", skip_serializing_if = "Option::is_none")]
    pub output_char_count: Option<u64>,
}

/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Receipt {
    /
    Tool(ToolReceipt),
    /
    SelfReceipt(SelfReceipt),
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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveProbe {
    #[serde(rename = "1")]
    pub probe_type: ProbeType,

    /
    #[serde(rename = "2")]
    pub stimulus_time: u64,

    /
    #[serde(rename = "3")]
    pub response_time: u64,

    #[serde(rename = "4", with = "serde_bytes")]
    pub stimulus_data: Vec<u8>,

    #[serde(rename = "5", with = "serde_bytes")]
    pub response_data: Vec<u8>,

    /
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub response_latency: Option<u64>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HatProof {
    /
    #[serde(rename = "1", with = "serde_bytes")]
    pub time_before: Vec<u8>,

    /
    #[serde(rename = "2", with = "serde_bytes")]
    pub time_after: Vec<u8>,

    /
    #[serde(rename = "3", with = "serde_bytes")]
    pub sig_before: Vec<u8>,

    /
    #[serde(rename = "4", with = "serde_bytes")]
    pub sig_after: Vec<u8>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BeaconAnchor {
    /
    #[serde(rename = "1")]
    pub source_url: String,

    /
    #[serde(rename = "2")]
    pub beacon_round: u64,

    /
    #[serde(rename = "3", with = "fixed_bytes_32")]
    pub beacon_value: [u8; 32],
}

/
/
/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileDeclarationWire {
    #[serde(rename = "1")]
    pub profile_id: String,

    #[serde(rename = "2")]
    pub feature_flags: Vec<u64>,
}

impl ProfileDeclarationWire {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.feature_flags.len() > MAX_FEATURE_FLAGS {
            return Err(format!(
                "too many feature_flags: {} (max {})",
                self.feature_flags.len(),
                MAX_FEATURE_FLAGS
            ));
        }
        Ok(())
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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamingStats {
    #[serde(rename = "1")]
    pub count: u64,

    #[serde(rename = "2")]
    pub mean: f64,

    #[serde(rename = "3")]
    pub m2: f64,

    #[serde(rename = "4")]
    pub min: f64,

    #[serde(rename = "5")]
    pub max: f64,
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
/
/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineDigest {
    #[serde(rename = "1")]
    pub version: u32,

    #[serde(rename = "2")]
    pub session_count: u64,

    #[serde(rename = "3")]
    pub total_keystrokes: u64,

    #[serde(rename = "4")]
    pub iki_stats: StreamingStats,

    #[serde(rename = "5")]
    pub cv_stats: StreamingStats,

    #[serde(rename = "6")]
    pub hurst_stats: StreamingStats,

    #[serde(rename = "7")]
    pub aggregate_iki_histogram: [f64; 9],

    #[serde(rename = "8")]
    pub pause_stats: StreamingStats,

    #[serde(rename = "9", with = "fixed_bytes_32")]
    pub session_merkle_root: [u8; 32],

    #[serde(rename = "10")]
    pub confidence_tier: ConfidenceTier,

    #[serde(rename = "11")]
    pub computed_at: u64,

    #[serde(rename = "12", with = "fixed_bytes_32")]
    pub identity_fingerprint: [u8; 32],
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
/
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionBehavioralSummary {
    /
    #[serde(rename = "1")]
    pub iki_histogram: [f64; 9],

    #[serde(rename = "2")]
    pub iki_cv: f64,

    /
    #[serde(rename = "3")]
    pub hurst: f64,

    #[serde(rename = "4")]
    pub pause_frequency: f64,

    #[serde(rename = "5")]
    pub duration_secs: u64,

    #[serde(rename = "6")]
    pub keystroke_count: u64,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineVerification {
    /
    #[serde(rename = "1", default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<BaselineDigest>,

    #[serde(rename = "2")]
    pub session_summary: SessionBehavioralSummary,

    /
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub digest_signature: Option<Vec<u8>>,
}
