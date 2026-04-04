

//! RFC-compliant time-evidence structure.
//!
//! Implements the time-evidence CDDL structure from draft-condrey-rats-pop-01
//! with tiered binding levels based on anchor diversity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum TimeBindingTier {
    /
    #[serde(rename = "maximum")]
    Maximum = 1,

    /
    #[serde(rename = "enhanced")]
    Enhanced = 2,

    /
    #[serde(rename = "standard")]
    Standard = 3,

    /
    #[serde(rename = "degraded")]
    #[default]
    Degraded = 4,
}

impl TimeBindingTier {
    /
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Maximum => "maximum",
            Self::Enhanced => "enhanced",
            Self::Standard => "standard",
            Self::Degraded => "degraded",
        }
    }

    /
    pub fn compute(
        blockchain_count: usize,
        tsa_count: usize,
        roughtime_count: usize,
        has_vdf: bool,
    ) -> Self {
        if blockchain_count >= 2 && tsa_count >= 2 {
            Self::Maximum
        } else if (blockchain_count >= 1 && tsa_count >= 1) || roughtime_count >= 2 {
            
            
            Self::Enhanced
        } else if has_vdf && (blockchain_count >= 1 || tsa_count >= 1 || roughtime_count >= 1) {
            Self::Standard
        } else {
            Self::Degraded
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeEvidence {
    #[serde(rename = "1")]
    pub tier: TimeBindingTier,

    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub tsa_responses: Option<Vec<TsaResponse>>,

    #[serde(rename = "3", default, skip_serializing_if = "Option::is_none")]
    pub blockchain_anchors: Option<Vec<BlockchainAnchor>>,

    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub roughtime_samples: Option<Vec<RoughtimeSample>>,

    #[serde(rename = "5", with = "super::serde_helpers::hex_bytes")]
    pub vdf_proof_hash: [u8; 32],

    /
    #[serde(rename = "6")]
    pub timestamp_ms: u64,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsaResponse {
    #[serde(rename = "1")]
    pub tsa_url: String,

    #[serde(rename = "2")]
    pub tsa_name: String,

    /
    #[serde(rename = "3")]
    pub timestamp_token: Vec<u8>,

    /
    #[serde(rename = "4")]
    pub timestamp_ms: u64,

    #[serde(rename = "5", with = "super::serde_helpers::hex_bytes")]
    pub timestamped_hash: [u8; 32],

    #[serde(rename = "6")]
    pub hash_algorithm: String,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainAnchor {
    /
    #[serde(rename = "1")]
    pub chain: String,

    #[serde(rename = "2")]
    pub block_height: u64,

    #[serde(rename = "3", with = "super::serde_helpers::hex_bytes")]
    pub block_hash: [u8; 32],

    /
    #[serde(rename = "4")]
    pub block_timestamp: u64,

    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub tx_id: Option<String>,

    #[serde(rename = "6", with = "super::serde_helpers::hex_bytes")]
    pub anchored_hash: [u8; 32],

    /
    #[serde(rename = "7")]
    pub merkle_proof: Vec<[u8; 32]>,

    /
    #[serde(rename = "8")]
    pub anchor_method: String,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoughtimeSample {
    #[serde(rename = "1")]
    pub server: String,

    #[serde(rename = "2", with = "super::serde_helpers::hex_bytes")]
    pub public_key: [u8; 32],

    /
    #[serde(rename = "3")]
    pub midpoint_us: u64,

    /
    #[serde(rename = "4")]
    pub radius_us: u32,

    #[serde(rename = "5", with = "super::serde_helpers::hex_bytes")]
    pub signature: [u8; 64],

    #[serde(rename = "6", with = "super::serde_helpers::hex_bytes")]
    pub nonce: [u8; 32],
}

/
/
fn current_timestamp_ms() -> Result<u64, String> {
    let ts = Utc::now().timestamp_millis();
    if ts < 0 {
        return Err(format!(
            "system clock returned pre-epoch timestamp: {}ms",
            ts
        ));
    }
    Ok(ts as u64)
}

impl TimeEvidence {
    /
    /
    /
    pub fn new_degraded(vdf_proof_hash: [u8; 32]) -> Result<Self, String> {
        Ok(Self {
            tier: TimeBindingTier::Degraded,
            tsa_responses: None,
            blockchain_anchors: None,
            roughtime_samples: None,
            vdf_proof_hash,
            timestamp_ms: current_timestamp_ms()?,
        })
    }

    /
    pub fn from_components(
        vdf_proof_hash: [u8; 32],
        tsa_responses: Vec<TsaResponse>,
        blockchain_anchors: Vec<BlockchainAnchor>,
        roughtime_samples: Vec<RoughtimeSample>,
    ) -> Result<Self, String> {
        let tier = TimeBindingTier::compute(
            blockchain_anchors.len(),
            tsa_responses.len(),
            roughtime_samples.len(),
            true, 
        );

        Ok(Self {
            tier,
            tsa_responses: if tsa_responses.is_empty() {
                None
            } else {
                Some(tsa_responses)
            },
            blockchain_anchors: if blockchain_anchors.is_empty() {
                None
            } else {
                Some(blockchain_anchors)
            },
            roughtime_samples: if roughtime_samples.is_empty() {
                None
            } else {
                Some(roughtime_samples)
            },
            vdf_proof_hash,
            timestamp_ms: current_timestamp_ms()?,
        })
    }

    /
    pub fn add_tsa_response(&mut self, response: TsaResponse) {
        self.tsa_responses
            .get_or_insert_with(Vec::new)
            .push(response);
        self.recalculate_tier();
    }

    /
    pub fn add_blockchain_anchor(&mut self, anchor: BlockchainAnchor) {
        self.blockchain_anchors
            .get_or_insert_with(Vec::new)
            .push(anchor);
        self.recalculate_tier();
    }

    /
    pub fn add_roughtime_sample(&mut self, sample: RoughtimeSample) {
        self.roughtime_samples
            .get_or_insert_with(Vec::new)
            .push(sample);
        self.recalculate_tier();
    }

    /
    pub fn recalculate_tier(&mut self) {
        self.tier = TimeBindingTier::compute(
            self.blockchain_anchors.as_ref().map_or(0, |v| v.len()),
            self.tsa_responses.as_ref().map_or(0, |v| v.len()),
            self.roughtime_samples.as_ref().map_or(0, |v| v.len()),
            true,
        );
    }

    /
    fn anchor_timestamps_ms(&self) -> impl Iterator<Item = u64> + '_ {
        let tsa = self
            .tsa_responses
            .iter()
            .flat_map(|v| v.iter().map(|r| r.timestamp_ms));
        let bc = self
            .blockchain_anchors
            .iter()
            .flat_map(|v| v.iter().map(|a| a.block_timestamp.saturating_mul(1000)));
        let rt = self
            .roughtime_samples
            .iter()
            .flat_map(|v| v.iter().map(|s| s.midpoint_us / 1000));
        tsa.chain(bc).chain(rt)
    }

    /
    pub fn earliest_anchor_time(&self) -> Option<DateTime<Utc>> {
        self.anchor_timestamps_ms()
            .min()
            .and_then(|ms| i64::try_from(ms).ok())
            .and_then(DateTime::from_timestamp_millis)
    }

    /
    pub fn latest_anchor_time(&self) -> Option<DateTime<Utc>> {
        self.anchor_timestamps_ms()
            .max()
            .and_then(|ms| i64::try_from(ms).ok())
            .and_then(DateTime::from_timestamp_millis)
    }

    /
    pub fn anchor_count(&self) -> usize {
        self.tsa_responses.as_ref().map_or(0, |v| v.len())
            + self.blockchain_anchors.as_ref().map_or(0, |v| v.len())
            + self.roughtime_samples.as_ref().map_or(0, |v| v.len())
    }

    /
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        
        if self.timestamp_ms == 0 {
            errors.push("evidence_timestamp_ms must be non-zero".to_string());
        }

        if self.vdf_proof_hash == [0u8; 32] {
            errors.push("vdf_proof_hash must be non-zero".to_string());
        }

        
        let blockchain_count = self.blockchain_anchors.as_ref().map_or(0, |v| v.len());
        let tsa_count = self.tsa_responses.as_ref().map_or(0, |v| v.len());
        let roughtime_count = self.roughtime_samples.as_ref().map_or(0, |v| v.len());
        let has_vdf = self.vdf_proof_hash != [0u8; 32];
        let expected_tier =
            TimeBindingTier::compute(blockchain_count, tsa_count, roughtime_count, has_vdf);

        if self.tier != expected_tier {
            errors.push(format!(
                "tier mismatch: declared {:?} but expected {:?} based on anchor counts \
                (blockchain={}, tsa={}, roughtime={})",
                self.tier, expected_tier, blockchain_count, tsa_count, roughtime_count
            ));
        }

        
        if let Some(tsa_responses) = &self.tsa_responses {
            for (i, tsa) in tsa_responses.iter().enumerate() {
                if tsa.timestamp_token.is_empty() {
                    errors.push(format!(
                        "tsa_response[{}]: timestamp_token must be non-empty",
                        i
                    ));
                }
                if tsa.tsa_url.is_empty() {
                    errors.push(format!("tsa_response[{}]: tsa_url must be non-empty", i));
                }
                if tsa.tsa_name.is_empty() {
                    errors.push(format!("tsa_response[{}]: tsa_name must be non-empty", i));
                }
            }
        }

        
        if let Some(blockchain_anchors) = &self.blockchain_anchors {
            for (i, anchor) in blockchain_anchors.iter().enumerate() {
                if let Some(tx_id) = &anchor.tx_id {
                    if tx_id.is_empty() {
                        errors.push(format!(
                            "blockchain_anchor[{}]: tx_id when present must be non-empty",
                            i
                        ));
                    }
                }
                if anchor.chain.is_empty() {
                    errors.push(format!("blockchain_anchor[{}]: chain must be non-empty", i));
                }
                if anchor.anchor_method.is_empty() {
                    errors.push(format!(
                        "blockchain_anchor[{}]: anchor_method must be non-empty",
                        i
                    ));
                }
            }
        }

        
        if let Some(roughtime_samples) = &self.roughtime_samples {
            for (i, sample) in roughtime_samples.iter().enumerate() {
                if sample.server.is_empty() {
                    errors.push(format!(
                        "roughtime_sample[{}]: server name must be non-empty",
                        i
                    ));
                }
                if sample.public_key.iter().all(|&b| b == 0) {
                    errors.push(format!(
                        "roughtime_sample[{}]: public_key must not be all-zero",
                        i
                    ));
                }
                if sample.signature.iter().all(|&b| b == 0) {
                    errors.push(format!(
                        "roughtime_sample[{}]: signature must not be all-zero",
                        i
                    ));
                }
                if sample.nonce.iter().all(|&b| b == 0) {
                    errors.push(format!(
                        "roughtime_sample[{}]: nonce must not be all-zero",
                        i
                    ));
                }
                if sample.midpoint_us == 0 {
                    errors.push(format!(
                        "roughtime_sample[{}]: midpoint_us must be non-zero",
                        i
                    ));
                }
            }
        }

        errors
    }

    /
    pub fn is_valid(&self) -> bool {
        self.validate().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_calculation() {
        assert_eq!(
            TimeBindingTier::compute(2, 2, 0, true),
            TimeBindingTier::Maximum
        );
        assert_eq!(
            TimeBindingTier::compute(3, 2, 0, true),
            TimeBindingTier::Maximum
        );

        assert_eq!(
            TimeBindingTier::compute(1, 1, 0, true),
            TimeBindingTier::Enhanced
        );
        assert_eq!(
            TimeBindingTier::compute(0, 0, 2, true),
            TimeBindingTier::Enhanced
        );

        assert_eq!(
            TimeBindingTier::compute(1, 0, 0, true),
            TimeBindingTier::Standard
        );
        assert_eq!(
            TimeBindingTier::compute(0, 1, 0, true),
            TimeBindingTier::Standard
        );
        assert_eq!(
            TimeBindingTier::compute(0, 0, 1, true),
            TimeBindingTier::Standard
        );

        assert_eq!(
            TimeBindingTier::compute(0, 0, 0, true),
            TimeBindingTier::Degraded
        );
    }

    #[test]
    fn test_time_evidence_serialization() {
        let evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();

        let json = serde_json::to_string_pretty(&evidence).unwrap();
        let decoded: TimeEvidence = serde_json::from_str(&json).unwrap();

        assert_eq!(evidence.tier, decoded.tier);
        assert_eq!(evidence.vdf_proof_hash, decoded.vdf_proof_hash);
    }

    #[test]
    fn test_add_anchors_updates_tier() {
        let mut evidence = TimeEvidence::new_degraded([0u8; 32]).unwrap();
        assert_eq!(evidence.tier, TimeBindingTier::Degraded);

        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https:
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![1, 2, 3],
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Standard);

        evidence.add_blockchain_anchor(BlockchainAnchor {
            chain: "bitcoin".to_string(),
            block_height: 800000,
            block_hash: [2u8; 32],
            block_timestamp: 1700000000,
            tx_id: Some("abc123".to_string()),
            anchored_hash: [3u8; 32],
            merkle_proof: vec![],
            anchor_method: "opentimestamps".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Enhanced);

        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https:
            tsa_name: "Example TSA 2".to_string(),
            timestamp_token: vec![4, 5, 6],
            timestamp_ms: 1700000001000,
            timestamped_hash: [4u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        evidence.add_blockchain_anchor(BlockchainAnchor {
            chain: "ethereum".to_string(),
            block_height: 18000000,
            block_hash: [5u8; 32],
            block_timestamp: 1700000012,
            tx_id: None,
            anchored_hash: [6u8; 32],
            merkle_proof: vec![],
            anchor_method: "direct".to_string(),
        });
        assert_eq!(evidence.tier, TimeBindingTier::Maximum);
    }

    #[test]
    fn test_validate_valid_evidence() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        assert!(evidence.is_valid());

        evidence.add_tsa_response(TsaResponse {
            tsa_url: "https:
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![1, 2, 3],
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        });
        assert!(evidence.is_valid());
    }

    #[test]
    fn test_validate_zero_vdf_hash() {
        let evidence = TimeEvidence::new_degraded([0u8; 32]).unwrap();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("vdf_proof_hash must be non-zero")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_zero_timestamp() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        evidence.timestamp_ms = 0;
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("evidence_timestamp_ms must be non-zero")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_tier_mismatch() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        evidence.tier = TimeBindingTier::Maximum;
        let errors = evidence.validate();
        assert!(errors.iter().any(|e| e.contains("tier mismatch")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_tsa_token() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        evidence.tsa_responses = Some(vec![TsaResponse {
            tsa_url: "https:
            tsa_name: "Example TSA".to_string(),
            timestamp_token: vec![],
            timestamp_ms: 1700000000000,
            timestamped_hash: [1u8; 32],
            hash_algorithm: "SHA-256".to_string(),
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("timestamp_token must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_blockchain_tx_id() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        evidence.blockchain_anchors = Some(vec![BlockchainAnchor {
            chain: "bitcoin".to_string(),
            block_height: 800000,
            block_hash: [2u8; 32],
            block_timestamp: 1700000000,
            tx_id: Some("".to_string()),
            anchored_hash: [3u8; 32],
            merkle_proof: vec![],
            anchor_method: "opentimestamps".to_string(),
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("tx_id when present must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_empty_roughtime_server() {
        let mut evidence = TimeEvidence::new_degraded([1u8; 32]).unwrap();
        evidence.roughtime_samples = Some(vec![RoughtimeSample {
            server: "".to_string(),
            public_key: [0u8; 32],
            midpoint_us: 1700000000000000,
            radius_us: 1000,
            signature: [0u8; 64],
            nonce: [0u8; 32],
        }]);
        evidence.recalculate_tier();
        let errors = evidence.validate();
        assert!(errors
            .iter()
            .any(|e| e.contains("server name must be non-empty")));
        assert!(!evidence.is_valid());
    }

    #[test]
    fn test_validate_multiple_errors() {
        let evidence = TimeEvidence {
            tier: TimeBindingTier::Maximum,
            tsa_responses: Some(vec![TsaResponse {
                tsa_url: "".to_string(),
                tsa_name: "".to_string(),
                timestamp_token: vec![],
                timestamp_ms: 1700000000000,
                timestamped_hash: [1u8; 32],
                hash_algorithm: "SHA-256".to_string(),
            }]),
            blockchain_anchors: None,
            roughtime_samples: None,
            vdf_proof_hash: [0u8; 32],
            timestamp_ms: 0,
        };
        let errors = evidence.validate();
        assert!(errors.len() >= 4);
        assert!(!evidence.is_valid());
    }
}
