

//! Base hash and reference types for wire-format structures.
//!
//! Implements `hash-value`, `compact-ref`, and `time-window` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::HashAlgorithm;

/
/
/
/
/
/
/
/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashValue {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    #[serde(rename = "2", with = "serde_bytes")]
    pub digest: Vec<u8>,
}

impl HashValue {
    /
    /
    /
    /
    #[deprecated(note = "panics on invalid input; use try_sha256 instead")]
    pub fn sha256(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 32,
            "SHA-256 digest must be 32 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest,
        }
    }

    /
    pub fn try_sha256(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 32 {
            return Err(format!(
                "SHA-256 digest must be 32 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha256,
            digest,
        })
    }

    /
    /
    /
    /
    #[deprecated(note = "panics on invalid input; use try_sha384 instead")]
    pub fn sha384(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 48,
            "SHA-384 digest must be 48 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha384,
            digest,
        }
    }

    /
    pub fn try_sha384(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 48 {
            return Err(format!(
                "SHA-384 digest must be 48 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha384,
            digest,
        })
    }

    /
    /
    /
    /
    #[deprecated(note = "panics on invalid input; use try_sha512 instead")]
    pub fn sha512(digest: Vec<u8>) -> Self {
        assert!(
            digest.len() == 64,
            "SHA-512 digest must be 64 bytes, got {}",
            digest.len()
        );
        Self {
            algorithm: HashAlgorithm::Sha512,
            digest,
        }
    }

    /
    pub fn try_sha512(digest: Vec<u8>) -> Result<Self, String> {
        if digest.len() != 64 {
            return Err(format!(
                "SHA-512 digest must be 64 bytes, got {}",
                digest.len()
            ));
        }
        Ok(Self {
            algorithm: HashAlgorithm::Sha512,
            digest,
        })
    }

    /
    pub fn zero_sha256() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest: vec![0u8; 32],
        }
    }

    /
    pub fn validate_digest_length(&self) -> Result<(), String> {
        let expected = match self.algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        };
        if self.digest.len() != expected {
            return Err(format!(
                "{:?} digest must be {} bytes, got {}",
                self.algorithm,
                expected,
                self.digest.len()
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRef {
    #[serde(rename = "1")]
    pub algorithm: HashAlgorithm,

    /
    #[serde(rename = "2", with = "serde_bytes")]
    pub truncated_digest: Vec<u8>,

    /
    #[serde(rename = "3")]
    pub prefix_length: u64,
}

impl CompactRef {
    /
    pub fn validate(&self) -> Result<(), String> {
        if self.truncated_digest.is_empty() {
            return Err("truncated_digest must be non-empty".to_string());
        }
        if self.truncated_digest.len() < 8 || self.truncated_digest.len() > 32 {
            return Err(format!(
                "truncated_digest length {} outside CDDL range 8..32",
                self.truncated_digest.len()
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /
    #[serde(rename = "1")]
    pub start: u64,

    /
    #[serde(rename = "2")]
    pub end: u64,
}
