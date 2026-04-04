

//! Request/response types for the WritersProof attestation API.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NonceResponse {
    /
    pub nonce: String,
    /
    pub expires_at: String,
    pub nonce_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollRequest {
    /
    pub public_key: String,
    /
    pub device_id: String,
    pub platform: String,
    /
    pub attestation_type: String,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub hardware_key_id: String,
    /
    pub assurance_tier: String,
    pub enrolled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestResponse {
    pub attestation_id: String,
    /
    pub status: String,
    /
    pub verification_status: String,
    /
    pub chain_position: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRequest {
    /
    pub evidence_hash: String,
    /
    pub author_did: String,
    /
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AnchorMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnchorResponse {
    pub anchor_id: String,
    pub timestamp: String,
    pub log_index: u64,
    pub inclusion_proof: Vec<String>,
    pub signed_tree_head: SignedTreeHead,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root_hash: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub verdict: String,
    pub confidence: f64,
    pub tier: String,
    pub anchored: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparency_log: Option<TransparencyLogInfo>,
    pub evidence_summary: EvidenceSummary,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub war: Option<String>,
}

impl VerifyResponse {
    /
    /
    /
    pub fn sanitize(&mut self) {
        self.confidence = self.confidence.clamp(0.0, 1.0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogInfo {
    pub log_index: u64,
    pub inclusion_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceSummary {
    pub duration: String,
    pub keystrokes: u64,
    pub sessions: u64,
    pub behavioral_plausibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_modal_consistency: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconRequest {
    /
    pub checkpoint_hash: String,
}

/
/
/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BeaconResponse {
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
#[serde(rename_all = "camelCase")]
pub struct QueuedAttestation {
    pub id: String,
    /
    pub evidence_b64: String,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub hardware_key_id: String,
    /
    pub signature: String,
    /
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_nonce: Option<String>,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: String,
}
