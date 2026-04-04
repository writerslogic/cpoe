

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::serde_utils::{base64_serde, hex_serde, hex_vec_serde};

/
#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("provider unavailable: {0}")]
    Unavailable(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("submission failed: {0}")]
    Submission(String),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("proof not ready")]
    NotReady,
    #[error("proof expired")]
    Expired,
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid proof format: {0}")]
    InvalidFormat(String),
    #[error("hash mismatch")]
    HashMismatch,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /
    #[serde(rename = "ots")]
    OpenTimestamps,
    /
    #[serde(rename = "rfc3161")]
    Rfc3161,
    /
    Bitcoin,
    Ethereum,
    Notary,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofStatus {
    Pending,
    Confirmed,
    Failed,
    Expired,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    /
    pub id: String,
    pub provider: ProviderType,
    pub status: ProofStatus,
    #[serde(with = "hex_serde")]
    pub anchored_hash: [u8; 32],
    pub submitted_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
    /
    #[serde(with = "base64_serde")]
    pub proof_data: Vec<u8>,
    /
    pub location: Option<String>,
    pub attestation_path: Option<Vec<AttestationStep>>,
    #[serde(default)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStep {
    pub operation: AttestationOp,
    /
    #[serde(with = "hex_vec_serde")]
    pub data: Vec<u8>,
}

/
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AttestationOp {
    Sha256,
    Ripemd160,
    Append,
    Prepend,
    /
    Verify,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider_type: ProviderType,
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub api_key: Option<String>,
    /
    pub timeout_seconds: u64,
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub version: u32,
    #[serde(with = "hex_serde")]
    pub hash: [u8; 32],
    pub document_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
    /
    pub status: ProofStatus,
}

impl Anchor {
    /
    pub fn new(hash: [u8; 32]) -> Self {
        Self {
            version: 1,
            hash,
            document_id: None,
            created_at: Utc::now(),
            proofs: Vec::new(),
            status: ProofStatus::Pending,
        }
    }

    /
    pub fn add_proof(&mut self, proof: Proof) {
        if proof.status == ProofStatus::Confirmed {
            self.status = ProofStatus::Confirmed;
        }
        self.proofs.push(proof);
    }

    /
    pub fn best_proof(&self) -> Option<&Proof> {
        self.proofs
            .iter()
            .filter(|p| p.status == ProofStatus::Confirmed)
            .min_by_key(|p| match p.provider {
                ProviderType::Bitcoin => 0,
                ProviderType::Ethereum => 1,
                ProviderType::OpenTimestamps => 2,
                ProviderType::Rfc3161 => 3,
                ProviderType::Notary => 4,
            })
            .or_else(|| self.proofs.first())
    }

    /
    pub fn is_confirmed(&self) -> bool {
        self.proofs
            .iter()
            .any(|p| p.status == ProofStatus::Confirmed)
    }
}
