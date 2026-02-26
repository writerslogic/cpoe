// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Wire-format attestation result and forensic types per CDDL schema.
//!
//! Implements `entropy-report`, `forgery-cost-estimate`, `absence-claim`,
//! `forensic-flag`, `forensic-summary`, and `attestation-result`.

use serde::{Deserialize, Serialize};

use super::enums::{AbsenceType, AttestationTier, CostUnit, Verdict};
use super::hash::{HashValue, TimeWindow};
use super::CBOR_TAG_ATTESTATION_RESULT;
use crate::codec::{self, CodecError};

/// Entropy assessment report per CDDL `entropy-report`.
///
/// ```cddl
/// entropy-report = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    /// Timing entropy (bits/sample)
    #[serde(rename = "1")]
    pub timing_entropy: f32,

    /// Revision entropy (bits)
    #[serde(rename = "2")]
    pub revision_entropy: f32,

    /// Pause entropy (bits)
    #[serde(rename = "3")]
    pub pause_entropy: f32,

    /// Whether entropy meets the required threshold
    #[serde(rename = "4")]
    pub meets_threshold: bool,
}

/// Forgery cost estimate per CDDL `forgery-cost-estimate`.
///
/// ```cddl
/// forgery-cost-estimate = {
///     1 => float32,
///     2 => float32,
///     3 => float32,
///     4 => float32,
///     5 => cost-unit,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryCostEstimate {
    /// Cost to forge sequential work function
    #[serde(rename = "1")]
    pub c_swf: f32,

    /// Cost to forge entropy
    #[serde(rename = "2")]
    pub c_entropy: f32,

    /// Cost to forge hardware attestation
    #[serde(rename = "3")]
    pub c_hardware: f32,

    /// Total forgery cost
    #[serde(rename = "4")]
    pub c_total: f32,

    /// Currency unit
    #[serde(rename = "5")]
    pub currency: CostUnit,
}

/// Absence claim per CDDL `absence-claim`.
///
/// ```cddl
/// absence-claim = {
///     1 => absence-type,
///     2 => time-window,
///     3 => tstr,
///     ? 4 => any,
///     5 => bool,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsenceClaim {
    /// Proof category
    #[serde(rename = "1")]
    pub absence_type: AbsenceType,

    /// Claimed time window
    #[serde(rename = "2")]
    pub window: TimeWindow,

    /// Claim identifier
    #[serde(rename = "3")]
    pub claim_id: String,

    /// Optional threshold/parameter
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ciborium::Value>,

    /// Assertion result
    #[serde(rename = "5")]
    pub assertion: bool,
}

/// Individual forensic flag per CDDL `forensic-flag`.
///
/// ```cddl
/// forensic-flag = {
///     1 => tstr,
///     2 => bool,
///     3 => uint,
///     4 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFlag {
    /// Mechanism name (e.g., "SNR", "CLC")
    #[serde(rename = "1")]
    pub mechanism: String,

    /// Whether this flag was triggered
    #[serde(rename = "2")]
    pub triggered: bool,

    /// Number of affected windows
    #[serde(rename = "3")]
    pub affected_windows: u64,

    /// Total windows evaluated
    #[serde(rename = "4")]
    pub total_windows: u64,
}

/// Forensic assessment summary per CDDL `forensic-summary`.
///
/// ```cddl
/// forensic-summary = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     4 => uint,
///     ? 5 => [+ forensic-flag],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSummary {
    /// Number of forensic flags triggered
    #[serde(rename = "1")]
    pub flags_triggered: u64,

    /// Total number of flags evaluated
    #[serde(rename = "2")]
    pub flags_evaluated: u64,

    /// Number of checkpoints with anomalies
    #[serde(rename = "3")]
    pub affected_checkpoints: u64,

    /// Total number of checkpoints analyzed
    #[serde(rename = "4")]
    pub total_checkpoints: u64,

    /// Per-flag detail (optional)
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<ForensicFlag>>,
}

/// Wire-format attestation result per CDDL `attestation-result`.
///
/// Wrapped with CBOR tag 1129791826 for transmission.
///
/// ```cddl
/// attestation-result = {
///     1 => uint,                    ; version
///     2 => hash-value,              ; evidence-ref
///     3 => verdict,                 ; appraisal verdict
///     4 => attestation-tier,        ; assessed assurance level
///     5 => uint,                    ; chain-length
///     6 => uint,                    ; chain-duration (seconds)
///     ? 7 => entropy-report,
///     ? 8 => forgery-cost-estimate,
///     ? 9 => [+ absence-claim],
///     ? 10 => [* tstr],             ; warnings
///     11 => bstr,                   ; verifier-signature
///     12 => pop-timestamp,          ; created
///     ? 13 => forensic-summary,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultWire {
    /// Schema version (MUST be 1)
    #[serde(rename = "1")]
    pub version: u64,

    /// Reference to the evidence packet being appraised
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,

    /// Appraisal verdict
    #[serde(rename = "3")]
    pub verdict: Verdict,

    /// Assessed attestation tier
    #[serde(rename = "4")]
    pub assessed_tier: AttestationTier,

    /// Number of checkpoints in the chain
    #[serde(rename = "5")]
    pub chain_length: u64,

    /// Total chain duration in seconds
    #[serde(rename = "6")]
    pub chain_duration: u64,

    /// Entropy assessment (omit for CORE tier)
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub entropy_report: Option<EntropyReport>,

    /// Quantified forgery cost
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub forgery_cost: Option<ForgeryCostEstimate>,

    /// Absence claims (must contain at least 1 when present)
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub absence_claims: Option<Vec<AbsenceClaim>>,

    /// Warning messages
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// Verifier signature (COSE_Sign1)
    #[serde(rename = "11", with = "serde_bytes")]
    pub verifier_signature: Vec<u8>,

    /// Appraisal timestamp (epoch milliseconds)
    #[serde(rename = "12")]
    pub created: u64,

    /// Forensic assessment summary
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummary>,
}

impl AttestationResultWire {
    /// Encode this attestation result to CBOR with the standard tag (1129791826).
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Decode an attestation result from tagged CBOR bytes.
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode_tagged(data, CBOR_TAG_ATTESTATION_RESULT)
    }

    /// Encode this attestation result to untagged CBOR.
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /// Decode an attestation result from untagged CBOR bytes.
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        codec::cbor::decode(data)
    }
}
