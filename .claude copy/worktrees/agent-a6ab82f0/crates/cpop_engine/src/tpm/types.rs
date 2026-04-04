

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("hardware not available")]
    NotAvailable,
    #[error("not initialized")]
    NotInitialized,
    #[error("key not found")]
    KeyNotFound,
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("key export failed: {0}")]
    KeyExport(String),
    #[error("key deletion failed: {0}")]
    KeyDeletion(String),
    #[error("access control error: {0}")]
    AccessControl(String),
    #[error("signing failed: {0}")]
    Signing(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("quote failed: {0}")]
    Quote(String),
    #[error("sealing failed: {0}")]
    Sealing(String),
    #[error("unsealing failed: {0}")]
    Unsealing(String),
    #[error("counter not initialized")]
    CounterNotInit,
    #[error("counter rollback detected")]
    CounterRollback,
    #[error("clock is not in safe state")]
    ClockNotSafe,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("binding is invalid")]
    InvalidBinding,
    #[error("unsupported public key type")]
    UnsupportedPublicKey,
    #[error("unsupported sealed data version")]
    SealedVersionUnsupported,
    #[error("sealed data too short")]
    SealedDataTooShort,
    #[error("sealed data corrupted")]
    SealedCorrupted,
    #[error("communication error: {0}")]
    CommunicationError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
    Sha384 = 0x000C,
    Sha512 = 0x000D,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSelection {
    pub hash: HashAlgorithm,
    pub pcrs: Vec<u32>,
}

/
pub fn default_pcr_selection() -> PcrSelection {
    PcrSelection {
        hash: HashAlgorithm::Sha256,
        pcrs: super::DEFAULT_QUOTE_PCRS.to_vec(),
    }
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: bool,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub payload: Vec<u8>,
    pub quote: Option<Vec<u8>>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub version: u32,
    pub provider_type: String,
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
    pub attested_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub monotonic_counter: Option<u64>,
    pub safe_clock: Option<bool>,
    pub attestation: Option<Attestation>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    pub index: u32,
    pub value: Vec<u8>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    pub provider_type: String,
    pub device_id: String,
    pub timestamp: DateTime<Utc>,
    pub nonce: Vec<u8>,
    pub attested_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub pcr_values: Vec<PcrValue>,
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub report_id: String,
    pub verifier_nonce: Vec<u8>,
    pub attestation_nonce: Vec<u8>,
    pub evidence_hash: [u8; 32],
    pub hardware_quote: Quote,
    pub signature: Vec<u8>, 
}

/
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Capabilities {
    pub hardware_backed: bool,
    pub supports_pcrs: bool,
    pub supports_sealing: bool,
    pub supports_attestation: bool,
    pub monotonic_counter: bool,
    pub secure_clock: bool,
}
