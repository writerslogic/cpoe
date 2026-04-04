

//! Core evidence types: structs, enums, and trait implementations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::analysis::{BehavioralFingerprint, ForgeryAnalysis};
use crate::collaboration;
use crate::continuation;
use crate::declaration;
use crate::jitter;
use crate::presence;
use crate::provenance;
use crate::tpm;
use crate::vdf;
use cpop_protocol::rfc::{BiologyInvariantClaim, JitterBinding, TimeEvidence};

use crate::platform::HidDeviceInfo;

use crate::serde_utils::{
    deserialize_optional_nonce, deserialize_optional_pubkey, deserialize_optional_signature,
    serialize_optional_nonce, serialize_optional_pubkey, serialize_optional_signature,
};

/
/
/
/
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustTier {
    /
    Local = 1,
    /
    Signed = 2,
    /
    NonceBound = 3,
    /
    Attested = 4,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub version: i32,
    pub exported_at: DateTime<Utc>,
    pub provenance: Option<RecordProvenance>,
    pub document: DocumentInfo,
    pub checkpoints: Vec<CheckpointProof>,
    pub vdf_params: vdf::Parameters,
    pub chain_hash: String,
    pub declaration: Option<declaration::Declaration>,
    pub presence: Option<presence::Evidence>,
    pub hardware: Option<HardwareEvidence>,
    pub keystroke: Option<KeystrokeEvidence>,
    pub behavioral: Option<BehavioralEvidence>,
    pub contexts: Vec<ContextPeriod>,
    pub external: Option<ExternalAnchors>,
    pub key_hierarchy: Option<KeyHierarchyEvidencePacket>,
    /
    /
    pub jitter_binding: Option<JitterBinding>,
    /
    /
    pub time_evidence: Option<TimeEvidence>,
    /
    pub provenance_links: Option<provenance::ProvenanceSection>,
    /
    pub continuation: Option<continuation::ContinuationSection>,
    /
    pub collaboration: Option<collaboration::CollaborationSection>,
    /
    pub vdf_aggregate: Option<vdf::VdfAggregateProof>,
    /
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub verifier_nonce: Option<[u8; 32]>,
    /
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_signature",
        deserialize_with = "deserialize_optional_signature"
    )]
    pub packet_signature: Option<[u8; 64]>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_pubkey",
        deserialize_with = "deserialize_optional_pubkey"
    )]
    pub signing_public_key: Option<[u8; 32]>,
    /
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub biology_claim: Option<BiologyInvariantClaim>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub physical_context: Option<PhysicalContextEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_root: Option<String>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmr_proof: Option<String>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writersproof_certificate_id: Option<String>,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline_verification: Option<cpop_protocol::baseline::BaselineVerification>,
    /
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dictation_events: Vec<DictationEvent>,
    pub claims: Vec<Claim>,
    pub limitations: Vec<String>,
    /
    /
    /
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_attestation: Option<WpBeaconAttestation>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHierarchyEvidencePacket {
    pub version: i32,
    pub master_fingerprint: String,
    pub master_public_key: String,
    pub device_id: String,
    pub session_id: String,
    pub session_public_key: String,
    pub session_started: DateTime<Utc>,
    pub session_certificate: String,
    pub ratchet_count: i32,
    pub ratchet_public_keys: Vec<String>,
    pub checkpoint_signatures: Vec<CheckpointSignature>,
    /
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_document_hash: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointSignature {
    pub ordinal: u64,
    pub checkpoint_hash: String,
    pub ratchet_index: i32,
    pub signature: String,
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
pub struct WpBeaconAttestation {
    /
    pub drand_round: u64,
    /
    pub drand_randomness: String,
    /
    pub nist_pulse_index: u64,
    /
    pub nist_output_value: String,
    /
    pub nist_timestamp: String,
    /
    pub fetched_at: String,
    /
    pub wp_signature: String,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPeriod {
    #[serde(rename = "type")]
    pub period_type: String,
    pub note: Option<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    pub title: String,
    pub path: String,
    pub final_hash: String,
    pub final_size: u64,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordProvenance {
    pub device_id: String,
    pub signing_pubkey: String,
    pub key_source: String,
    pub hostname: String,
    pub os: String,
    pub os_version: Option<String>,
    pub architecture: String,
    pub session_id: String,
    pub session_started: DateTime<Utc>,
    pub input_devices: Vec<InputDeviceInfo>,
    pub access_control: Option<AccessControlInfo>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDeviceInfo {
    pub vendor_id: u16,
    pub product_id: u16,
    pub product_name: String,
    pub serial_number: Option<String>,
    pub connection_type: String,
    pub fingerprint: String,
}

impl From<&HidDeviceInfo> for InputDeviceInfo {
    fn from(hid: &HidDeviceInfo) -> Self {
        let transport = hid.transport_type();
        Self {
            vendor_id: u16::try_from(hid.vendor_id).unwrap_or(0),
            product_id: u16::try_from(hid.product_id).unwrap_or(0),
            product_name: hid.product_name.clone(),
            serial_number: hid.serial_number.clone(),
            connection_type: transport.as_str().to_string(),
            fingerprint: hid.fingerprint(),
        }
    }
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlInfo {
    pub captured_at: DateTime<Utc>,
    pub file_owner_uid: i32,
    pub file_owner_name: Option<String>,
    pub file_permissions: String,
    pub file_group_gid: Option<i32>,
    pub file_group_name: Option<String>,
    pub process_uid: i32,
    pub process_euid: i32,
    pub process_username: Option<String>,
    pub limitations: Vec<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointProof {
    pub ordinal: u64,
    pub content_hash: String,
    pub content_size: u64,
    pub timestamp: DateTime<Utc>,
    pub message: Option<String>,
    pub vdf_input: Option<String>,
    pub vdf_output: Option<String>,
    pub vdf_iterations: Option<u64>,
    pub elapsed_time: Option<Duration>,
    pub previous_hash: String,
    /
    pub hash: String,
    pub signature: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareEvidence {
    pub bindings: Vec<tpm::Binding>,
    pub device_id: String,
    /
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_nonce",
        deserialize_with = "deserialize_optional_nonce"
    )]
    pub attestation_nonce: Option<[u8; 32]>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystrokeEvidence {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration: Duration,
    pub total_keystrokes: u64,
    pub total_samples: i32,
    pub keystrokes_per_minute: f64,
    pub unique_doc_states: i32,
    pub chain_valid: bool,
    pub plausible_human_rate: bool,
    pub samples: Vec<jitter::Sample>,
    /
    #[serde(default)]
    pub phys_ratio: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEvidence {
    pub edit_topology: Vec<EditRegion>,
    pub metrics: Option<ForensicMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<BehavioralFingerprint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forgery_analysis: Option<ForgeryAnalysis>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditRegion {
    pub start_pct: f64,
    pub end_pct: f64,
    pub delta_sign: i32,
    pub byte_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicMetrics {
    pub monotonic_append_ratio: f64,
    pub edit_entropy: f64,
    pub median_interval_seconds: f64,
    pub positive_negative_ratio: f64,
    pub deletion_clustering: f64,
    pub assessment: Option<String>,
    pub anomaly_count: Option<i32>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalContextEvidence {
    pub clock_skew: u64,
    pub thermal_proxy: u32,
    pub silicon_puf_hash: String,
    pub io_latency_ns: u64,
    pub combined_hash: String,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DictationEvent {
    /
    pub start_ns: i64,
    /
    pub end_ns: i64,
    /
    pub word_count: u32,
    /
    pub char_count: u32,
    /
    pub input_method: String,
    /
    pub mic_active: bool,
    /
    pub words_per_minute: f64,
    /
    /
    pub plausibility_score: f64,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnchors {
    pub opentimestamps: Vec<OtsProof>,
    pub rfc3161: Vec<Rfc3161Proof>,
    pub proofs: Vec<AnchorProof>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtsProof {
    pub chain_hash: String,
    pub proof: String,
    pub status: String,
    pub block_height: Option<u64>,
    pub block_time: Option<DateTime<Utc>>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rfc3161Proof {
    pub chain_hash: String,
    pub tsa_url: String,
    pub response: String,
    pub timestamp: DateTime<Utc>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorProof {
    pub provider: String,
    pub provider_name: String,
    pub legal_standing: String,
    pub regions: Vec<String>,
    pub hash: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub raw_proof: String,
    pub verify_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    #[serde(rename = "type")]
    pub claim_type: ClaimType,
    pub description: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClaimType {
    /
    #[serde(rename = "chain_integrity")]
    ChainIntegrity,
    /
    #[serde(rename = "time_elapsed")]
    TimeElapsed,
    /
    #[serde(rename = "process_declared")]
    ProcessDeclared,
    /
    #[serde(rename = "presence_verified")]
    PresenceVerified,
    /
    #[serde(rename = "keystrokes_verified")]
    KeystrokesVerified,
    /
    #[serde(rename = "hardware_attested")]
    HardwareAttested,
    /
    #[serde(rename = "behavior_analyzed")]
    BehaviorAnalyzed,
    /
    #[serde(rename = "contexts_recorded")]
    ContextsRecorded,
    /
    #[serde(rename = "external_anchored")]
    ExternalAnchored,
    /
    #[serde(rename = "key_hierarchy")]
    KeyHierarchy,
    /
    #[serde(rename = "dictation_verified")]
    DictationVerified,
}
