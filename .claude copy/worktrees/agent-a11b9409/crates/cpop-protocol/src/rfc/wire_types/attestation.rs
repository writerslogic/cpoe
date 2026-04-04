

//! Wire-format attestation result and forensic types per CDDL schema.
//!
//! Implements `entropy-report`, `forgery-cost-estimate`, `absence-claim`,
//! `forensic-flag`, `forensic-summary`, and `attestation-result`.

use serde::{Deserialize, Serialize};

use super::enums::{AbsenceType, AttestationTier, ConfidenceTier, CostUnit, Verdict};
use super::hash::{HashValue, TimeWindow};
use super::CBOR_TAG_ATTESTATION_RESULT;
use crate::codec::{self, CodecError};

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
pub struct EntropyReport {
    /
    #[serde(rename = "1")]
    pub timing_entropy: f32,

    /
    #[serde(rename = "2")]
    pub revision_entropy: f32,

    /
    #[serde(rename = "3")]
    pub pause_entropy: f32,

    /
    /
    /
    #[serde(rename = "4")]
    pub meets_threshold: bool,
}

impl EntropyReport {
    /
    pub fn validate_thresholds(&self) -> bool {
        self.timing_entropy >= 3.0 && self.revision_entropy >= 3.0 && self.pause_entropy >= 2.0
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeryCostEstimate {
    /
    #[serde(rename = "1")]
    pub c_swf: f32,

    /
    #[serde(rename = "2")]
    pub c_entropy: f32,

    /
    #[serde(rename = "3")]
    pub c_hardware: f32,

    /
    #[serde(rename = "4")]
    pub c_total: f32,

    /
    #[serde(rename = "5")]
    pub currency: CostUnit,
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
pub struct AbsenceClaim {
    /
    #[serde(rename = "1")]
    pub absence_type: AbsenceType,

    /
    #[serde(rename = "2")]
    pub window: TimeWindow,

    /
    #[serde(rename = "3")]
    pub claim_id: String,

    /
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<ciborium::Value>,

    /
    #[serde(rename = "5")]
    pub assertion: bool,
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
pub struct ForensicFlag {
    /
    #[serde(rename = "1")]
    pub mechanism: String,

    /
    #[serde(rename = "2")]
    pub triggered: bool,

    /
    #[serde(rename = "3")]
    pub affected_windows: u64,

    /
    #[serde(rename = "4")]
    pub total_windows: u64,
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
pub struct ForensicSummary {
    /
    #[serde(rename = "1")]
    pub flags_triggered: u64,

    /
    #[serde(rename = "2")]
    pub flags_evaluated: u64,

    /
    #[serde(rename = "3")]
    pub affected_checkpoints: u64,

    /
    #[serde(rename = "4")]
    pub total_checkpoints: u64,

    /
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<ForensicFlag>>,
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
pub struct EffortAttribution {
    #[serde(rename = "1")]
    pub human_fraction: f32,

    #[serde(rename = "2")]
    pub human_checkpoints: u64,

    #[serde(rename = "3")]
    pub receipt_checkpoints: u64,

    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub tool_attributed_chars: Option<u64>,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub total_chars: Option<u64>,
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
pub struct AttestationResultWire {
    /
    #[serde(rename = "1")]
    pub version: u64,

    /
    #[serde(rename = "2")]
    pub evidence_ref: HashValue,

    /
    #[serde(rename = "3")]
    pub verdict: Verdict,

    /
    #[serde(rename = "4")]
    pub assessed_tier: AttestationTier,

    /
    #[serde(rename = "5")]
    pub chain_length: u64,

    /
    #[serde(rename = "6")]
    pub chain_duration: u64,

    /
    #[serde(rename = "7", default, skip_serializing_if = "Option::is_none")]
    pub entropy_report: Option<EntropyReport>,

    /
    #[serde(rename = "8", default, skip_serializing_if = "Option::is_none")]
    pub forgery_cost: Option<ForgeryCostEstimate>,

    /
    #[serde(rename = "9", default, skip_serializing_if = "Option::is_none")]
    pub absence_claims: Option<Vec<AbsenceClaim>>,

    /
    #[serde(rename = "10", default, skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /
    #[serde(rename = "11", with = "serde_bytes")]
    pub verifier_signature: Vec<u8>,

    /
    #[serde(rename = "12")]
    pub created: u64,

    /
    #[serde(rename = "13", default, skip_serializing_if = "Option::is_none")]
    pub forensic_summary: Option<ForensicSummary>,

    /
    #[serde(rename = "14", default, skip_serializing_if = "Option::is_none")]
    pub confidence_tier: Option<ConfidenceTier>,

    /
    #[serde(rename = "15", default, skip_serializing_if = "Option::is_none")]
    pub effort_attribution: Option<EffortAttribution>,
}

/
const MAX_ABSENCE_CLAIMS: usize = 100;
/
const MAX_WARNINGS: usize = 100;
use super::MAX_STRING_LEN;
/
const MAX_FORENSIC_FLAGS: usize = 200;

impl AttestationResultWire {
    /
    pub fn encode_cbor(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode_tagged(self, CBOR_TAG_ATTESTATION_RESULT)
    }

    /
    pub fn decode_cbor(data: &[u8]) -> Result<Self, CodecError> {
        let result: Self = codec::cbor::decode_tagged(data, CBOR_TAG_ATTESTATION_RESULT)?;
        result.validate()?;
        Ok(result)
    }

    /
    pub fn encode_cbor_untagged(&self) -> Result<Vec<u8>, CodecError> {
        codec::cbor::encode(self)
    }

    /
    pub fn decode_cbor_untagged(data: &[u8]) -> Result<Self, CodecError> {
        let result: Self = codec::cbor::decode(data)?;
        result.validate()?;
        Ok(result)
    }

    /
    pub fn validate(&self) -> Result<(), CodecError> {
        if self.version != 1 {
            return Err(CodecError::Validation(format!(
                "unsupported WAR version {}, expected 1",
                self.version
            )));
        }
        if self.created == 0 {
            return Err(CodecError::Validation(
                "created timestamp must be non-zero".into(),
            ));
        }
        if self.chain_length == 0 {
            return Err(CodecError::Validation(
                "chain_length must be non-zero".into(),
            ));
        }
        if let Some(ref claims) = self.absence_claims {
            if claims.len() > MAX_ABSENCE_CLAIMS {
                return Err(CodecError::Validation(format!(
                    "too many absence_claims: {} (max {})",
                    claims.len(),
                    MAX_ABSENCE_CLAIMS
                )));
            }
            for (i, claim) in claims.iter().enumerate() {
                if claim.claim_id.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "absence_claims[{}].claim_id too long: {}",
                        i,
                        claim.claim_id.len()
                    )));
                }
            }
        }
        self.evidence_ref
            .validate_digest_length()
            .map_err(CodecError::Validation)?;
        if let Some(ref warnings) = self.warnings {
            if warnings.len() > MAX_WARNINGS {
                return Err(CodecError::Validation(format!(
                    "too many warnings: {} (max {})",
                    warnings.len(),
                    MAX_WARNINGS
                )));
            }
            for (i, w) in warnings.iter().enumerate() {
                if w.len() > MAX_STRING_LEN {
                    return Err(CodecError::Validation(format!(
                        "warning[{}] too long: {} (max {})",
                        i,
                        w.len(),
                        MAX_STRING_LEN
                    )));
                }
            }
        }
        if let Some(tier) = self.confidence_tier {
            let raw = tier as u8;
            if raw == 0 || raw > 4 {
                return Err(CodecError::Validation(format!(
                    "confidence_tier out of range: {} (must be 1..=4)",
                    raw
                )));
            }
        }
        if let Some(ref summary) = self.forensic_summary {
            if let Some(ref flags) = summary.flags {
                if flags.len() > MAX_FORENSIC_FLAGS {
                    return Err(CodecError::Validation(format!(
                        "too many forensic_flags: {} (max {})",
                        flags.len(),
                        MAX_FORENSIC_FLAGS
                    )));
                }
            }
        }
        Ok(())
    }
}
