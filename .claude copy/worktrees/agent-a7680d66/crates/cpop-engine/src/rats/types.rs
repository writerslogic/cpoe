

//! RATS architecture types per RFC 9334 (Remote Attestation Procedures).
//!
//! Defines the principal roles and data structures from the RATS
//! reference architecture for use in CPOP's proof-of-process flow.

use serde::{Deserialize, Serialize};

/
/
/
/
/
/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RatsRole {
    /
    Attester,
    /
    Verifier,
    /
    RelyingParty,
}

impl RatsRole {
    /
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Attester => "attester",
            Self::Verifier => "verifier",
            Self::RelyingParty => "relying-party",
        }
    }
}

/
/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    /
    pub cbor_bytes: Vec<u8>,
    /
    pub media_type: &'static str,
}

impl Evidence {
    /
    pub const MEDIA_TYPE: &'static str = "application/vnd.writersproof.cpop+cbor";

    /
    pub fn new(cbor_bytes: Vec<u8>) -> Self {
        Self {
            cbor_bytes,
            media_type: Self::MEDIA_TYPE,
        }
    }

    /
    pub fn as_bytes(&self) -> &[u8] {
        &self.cbor_bytes
    }
}

/
/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationResult {
    /
    pub cwt_bytes: Vec<u8>,
    /
    pub media_type: &'static str,
}

impl AttestationResult {
    /
    pub const MEDIA_TYPE: &'static str = "application/vnd.writersproof.cwar+cbor";

    /
    pub fn new(cwt_bytes: Vec<u8>) -> Self {
        Self {
            cwt_bytes,
            media_type: Self::MEDIA_TYPE,
        }
    }

    /
    pub fn as_bytes(&self) -> &[u8] {
        &self.cwt_bytes
    }
}
