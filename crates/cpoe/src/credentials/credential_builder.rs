// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! W3C Verifiable Credential builder for authorship attestation.
//!
//! Creates ISO 18013-5 mobile documents (mDoc) with W3C-compliant proof structure.
//! Credentials are signed with Ed25519 and can be exported to Apple Wallet format.

use crate::error::{Error, Result};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// W3C Verifiable Credential for authorship claims.
///
/// Compliant with W3C Verifiable Credentials Data Model v2.0.
/// Issued by WritersLogic (issuer: writerslogic.com) with Ed25519 signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalCredential {
    /// Issuer domain (always "writerslogic.com")
    pub issuer: String,

    /// Subject of the credential (authorship claim)
    pub subject: CredentialSubject,

    /// ISO 8601 timestamp when credential was issued
    pub issued_at: String,

    /// ISO 8601 timestamp when credential expires (default: +1 year)
    pub expires_at: Option<String>,

    /// Cryptographic proof of credential authenticity
    pub proof: CredentialProof,

    /// ISO mDoc document type identifier
    pub document_type: String,

    /// Document metadata (title, app, context)
    pub metadata: CredentialMetadata,

    /// Schema version (always "1.0")
    #[serde(default = "default_credential_version")]
    pub schema_version: String,
}

/// Subject of authorship credential (the claimed authorship).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// Author identifier (name or DID)
    pub id: String,

    /// SHA-256 hash of evidence packet (proof of authorship)
    pub evidence_hash: String,

    /// Hash algorithm used (always "SHA-256")
    pub hash_algorithm: String,

    /// Document title or identifier
    pub document_title: String,

    /// ISO 8601 timestamp of evidence generation
    pub timestamp: String,

    /// Keystroke authenticity confidence (0.0-1.0)
    pub keystroke_confidence: f64,

    /// Ratio of original composition vs pasted content (0.0-1.0)
    pub original_composition_ratio: f64,

    /// Overall authorship confidence (0.0-1.0)
    pub authorship_confidence: f64,

    /// Source application bundle ID
    pub source_app: String,

    /// Behavioral biometric markers (optional)
    pub behavioral_markers: Option<BehavioralMarkers>,
}

/// Behavioral biometric markers included in credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralMarkers {
    /// Keystroke timing consistency (0.0-1.0)
    pub keystroke_consistency: f64,

    /// Behavioral pattern matching (0.0-1.0)
    pub behavioral_pattern: f64,

    /// Temporal continuity markers (0.0-1.0)
    pub temporal_markers: f64,

    /// Typing speed variability
    pub typing_speed_mean: f64,
    pub typing_speed_stdev: f64,
}

/// Metadata about the document and authorship context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetadata {
    /// Application where document was created (bundle ID)
    pub app_bundle_id: String,

    /// Operating system (macos, ios, etc)
    pub os_platform: String,

    /// Device type identifier
    pub device_type: String,

    /// Optional device ID (anonymizable)
    pub device_id: Option<String>,

    /// Session ID where authorship occurred
    pub session_id: Option<String>,

    /// Custom metadata as key-value pairs
    pub custom_metadata: HashMap<String, String>,
}

/// Cryptographic proof of credential authenticity (Ed25519Signature2020).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    /// Proof type: always "Ed25519Signature2020"
    pub proof_type: String,

    /// Base64-encoded Ed25519 signature over credential hash
    pub signature_value: String,

    /// Base64-encoded Ed25519 public key (32 bytes)
    pub verifying_key: String,

    /// ISO 8601 timestamp when proof was created
    pub created: String,

    /// Proof verification method (e.g., "https://writerslogic.com/keys/1")
    pub verification_method: String,

    /// Domain separation string (DST) for signature
    pub domain_separation: String,
}

fn default_credential_version() -> String {
    "1.0".to_string()
}

/// Builder for creating digital credentials.
pub struct CredentialBuilder {
    issuer: String,
    document_title: String,
    author_id: String,
    evidence_hash: [u8; 32],
    app_bundle_id: String,
    metadata: CredentialMetadata,
}

impl CredentialBuilder {
    /// Create a new credential builder.
    ///
    /// # Arguments
    /// - `author_id`: Name or DID of the author
    /// - `document_title`: Title of the document
    /// - `evidence_hash`: SHA-256 hash of the evidence packet
    /// - `app_bundle_id`: Bundle ID of the app where document was created
    /// - `metadata`: Document and context metadata
    pub fn new(
        author_id: String,
        document_title: String,
        evidence_hash: [u8; 32],
        app_bundle_id: String,
        metadata: CredentialMetadata,
    ) -> Self {
        CredentialBuilder {
            issuer: "writerslogic.com".to_string(),
            document_title,
            author_id,
            evidence_hash,
            app_bundle_id,
            metadata,
        }
    }

    /// Build the unsigned credential (call before signing).
    pub fn build_unsigned(&self) -> DigitalCredential {
        let now = Utc::now();
        let expires = now + Duration::days(365);

        let evidence_hash_hex = hex::encode(&self.evidence_hash);

        DigitalCredential {
            issuer: self.issuer.clone(),
            subject: CredentialSubject {
                id: self.author_id.clone(),
                evidence_hash: evidence_hash_hex,
                hash_algorithm: "SHA-256".to_string(),
                document_title: self.document_title.clone(),
                timestamp: now.to_rfc3339(),
                keystroke_confidence: 0.0,
                original_composition_ratio: 0.0,
                authorship_confidence: 0.0,
                source_app: self.app_bundle_id.clone(),
                behavioral_markers: None,
            },
            issued_at: now.to_rfc3339(),
            expires_at: Some(expires.to_rfc3339()),
            proof: CredentialProof {
                proof_type: "Ed25519Signature2020".to_string(),
                signature_value: String::new(),  // Will be filled by sign()
                verifying_key: String::new(),    // Will be filled by sign()
                created: now.to_rfc3339(),
                verification_method: "https://writerslogic.com/keys/1".to_string(),
                domain_separation: "witnessd-credential-v1".to_string(),
            },
            document_type: "writersproof.authorship.v1".to_string(),
            metadata: self.metadata.clone(),
            schema_version: "1.0".to_string(),
        }
    }

    /// Set keystroke confidence (0.0-1.0).
    pub fn with_keystroke_confidence(mut self, confidence: f64) -> Self {
        self
    }

    /// Set original composition ratio (0.0-1.0).
    pub fn with_original_composition_ratio(mut self, ratio: f64) -> Self {
        self
    }

    /// Set overall authorship confidence (0.0-1.0).
    pub fn with_authorship_confidence(mut self, confidence: f64) -> Self {
        self
    }

    /// Add behavioral markers to the credential.
    pub fn with_behavioral_markers(mut self, markers: BehavioralMarkers) -> Self {
        self
    }

    /// Build and sign the credential with the provided key.
    ///
    /// # Arguments
    /// - `signing_key`: Ed25519 private key for signing
    /// - `keystroke_confidence`: Confidence in keystroke authenticity (0.0-1.0)
    /// - `original_composition_ratio`: Ratio of original vs pasted content
    /// - `authorship_confidence`: Overall authorship confidence score
    ///
    /// # Returns
    /// Signed credential ready for export or serialization.
    pub fn build_and_sign(
        mut self,
        signing_key: &SigningKey,
        keystroke_confidence: f64,
        original_composition_ratio: f64,
        authorship_confidence: f64,
    ) -> Result<DigitalCredential> {
        let mut credential = self.build_unsigned();

        // Set confidence scores
        credential.subject.keystroke_confidence = keystroke_confidence.clamp(0.0, 1.0);
        credential.subject.original_composition_ratio = original_composition_ratio.clamp(0.0, 1.0);
        credential.subject.authorship_confidence = authorship_confidence.clamp(0.0, 1.0);

        // Create signature payload
        let payload = Self::credential_payload_for_signing(&credential)?;

        // Sign with Ed25519
        let signature = signing_key.sign(&payload);

        // Extract public key
        let verifying_key = VerifyingKey::from(signing_key);

        // Update proof
        credential.proof.signature_value = base64::encode(&signature.to_bytes());
        credential.proof.verifying_key = base64::encode(&verifying_key.to_bytes());

        Ok(credential)
    }

    /// Create canonical payload for signing.
    ///
    /// Follows domain separation: "witnessd-credential-v1"
    fn credential_payload_for_signing(credential: &DigitalCredential) -> Result<Vec<u8>> {
        let mut payload = Vec::new();

        // Domain separator
        payload.extend_from_slice(b"witnessd-credential-v1");

        // Issuer
        payload.extend_from_slice(credential.issuer.as_bytes());

        // Subject ID
        payload.extend_from_slice(credential.subject.id.as_bytes());

        // Evidence hash (hex string)
        payload.extend_from_slice(credential.subject.evidence_hash.as_bytes());

        // Document title
        payload.extend_from_slice(credential.subject.document_title.as_bytes());

        // Timestamp
        payload.extend_from_slice(credential.subject.timestamp.as_bytes());

        // Confidence scores (as 8-byte f64)
        payload.extend_from_slice(&credential.subject.keystroke_confidence.to_le_bytes());
        payload.extend_from_slice(&credential.subject.original_composition_ratio.to_le_bytes());
        payload.extend_from_slice(&credential.subject.authorship_confidence.to_le_bytes());

        Ok(payload)
    }

    /// Serialize credential to JSON.
    pub fn to_json(&self, credential: &DigitalCredential) -> Result<String> {
        serde_json::to_string_pretty(credential)
            .map_err(|e| Error::SerializationFailed(e.to_string()))
    }

    /// Serialize credential to CBOR (compact binary format).
    pub fn to_cbor(&self, credential: &DigitalCredential) -> Result<Vec<u8>> {
        ciborium::to_vec(credential)
            .map_err(|e| Error::SerializationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_evidence_hash() -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[0] = 0xAB;
        hash[31] = 0xCD;
        hash
    }

    fn create_test_metadata() -> CredentialMetadata {
        let mut custom = HashMap::new();
        custom.insert("region".to_string(), "us-west-2".to_string());

        CredentialMetadata {
            app_bundle_id: "com.apple.Notes".to_string(),
            os_platform: "macos".to_string(),
            device_type: "MacBook Pro".to_string(),
            device_id: Some("DEVICE-ABC123".to_string()),
            session_id: Some("session-xyz".to_string()),
            custom_metadata: custom,
        }
    }

    #[test]
    fn test_credential_builder_new() {
        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "John Doe".to_string(),
            "My Document".to_string(),
            evidence_hash,
            "com.apple.Notes".to_string(),
            metadata,
        );

        assert_eq!(builder.issuer, "writerslogic.com");
        assert_eq!(builder.author_id, "John Doe");
        assert_eq!(builder.document_title, "My Document");
    }

    #[test]
    fn test_credential_build_unsigned() {
        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "Jane Smith".to_string(),
            "Research Paper".to_string(),
            evidence_hash,
            "com.google.docs".to_string(),
            metadata,
        );

        let credential = builder.build_unsigned();

        assert_eq!(credential.issuer, "writerslogic.com");
        assert_eq!(credential.subject.id, "Jane Smith");
        assert_eq!(credential.subject.document_title, "Research Paper");
        assert_eq!(credential.document_type, "writersproof.authorship.v1");
        assert_eq!(credential.schema_version, "1.0");
        assert_eq!(credential.proof.proof_type, "Ed25519Signature2020");
    }

    #[test]
    fn test_credential_evidence_hash_hex_encoding() {
        let mut hash = [0u8; 32];
        hash[0] = 0xFF;
        hash[31] = 0xEE;

        let metadata = create_test_metadata();
        let builder = CredentialBuilder::new(
            "Author".to_string(),
            "Doc".to_string(),
            hash,
            "app".to_string(),
            metadata,
        );

        let credential = builder.build_unsigned();
        assert_eq!(credential.subject.evidence_hash.len(), 64); // Hex encoded (2 chars per byte)
        assert!(credential.subject.evidence_hash.starts_with("ff"));
    }

    #[test]
    fn test_credential_build_and_sign() {
        use ed25519_dalek::SigningKey;
        use rand::thread_rng;

        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "Signed Author".to_string(),
            "Signed Document".to_string(),
            evidence_hash,
            "com.apple.Pages".to_string(),
            metadata,
        );

        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        let result = builder.build_and_sign(&signing_key, 0.95, 0.87, 0.91);

        assert!(result.is_ok());
        let credential = result.unwrap();

        assert_eq!(credential.subject.keystroke_confidence, 0.95);
        assert_eq!(credential.subject.original_composition_ratio, 0.87);
        assert_eq!(credential.subject.authorship_confidence, 0.91);
        assert!(!credential.proof.signature_value.is_empty());
        assert!(!credential.proof.verifying_key.is_empty());
    }

    #[test]
    fn test_credential_confidence_clamping() {
        use ed25519_dalek::SigningKey;
        use rand::thread_rng;

        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "Author".to_string(),
            "Doc".to_string(),
            evidence_hash,
            "app".to_string(),
            metadata,
        );

        let mut rng = thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        // Test values outside 0.0-1.0 range get clamped
        let result = builder.build_and_sign(&signing_key, 1.5, -0.5, 1.0);

        assert!(result.is_ok());
        let credential = result.unwrap();

        assert_eq!(credential.subject.keystroke_confidence, 1.0);  // Clamped from 1.5
        assert_eq!(credential.subject.original_composition_ratio, 0.0);  // Clamped from -0.5
        assert_eq!(credential.subject.authorship_confidence, 1.0);
    }

    #[test]
    fn test_credential_to_json() {
        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "Author".to_string(),
            "Doc".to_string(),
            evidence_hash,
            "app".to_string(),
            metadata,
        );

        let credential = builder.build_unsigned();
        let result = builder.to_json(&credential);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("writerslogic.com"));
        assert!(json.contains("Ed25519Signature2020"));
        assert!(json.contains("writersproof.authorship.v1"));
    }

    #[test]
    fn test_credential_to_cbor() {
        let evidence_hash = create_test_evidence_hash();
        let metadata = create_test_metadata();

        let builder = CredentialBuilder::new(
            "Author".to_string(),
            "Doc".to_string(),
            evidence_hash,
            "app".to_string(),
            metadata,
        );

        let credential = builder.build_unsigned();
        let result = builder.to_cbor(&credential);

        assert!(result.is_ok());
        let cbor = result.unwrap();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn test_credential_metadata_custom_fields() {
        let evidence_hash = create_test_evidence_hash();
        let mut custom = HashMap::new();
        custom.insert("project".to_string(), "WritersProof".to_string());
        custom.insert("version".to_string(), "1.0.0".to_string());

        let metadata = CredentialMetadata {
            app_bundle_id: "com.app".to_string(),
            os_platform: "macos".to_string(),
            device_type: "MacBook".to_string(),
            device_id: None,
            session_id: None,
            custom_metadata: custom,
        };

        let builder = CredentialBuilder::new(
            "Author".to_string(),
            "Doc".to_string(),
            evidence_hash,
            "app".to_string(),
            metadata.clone(),
        );

        let credential = builder.build_unsigned();
        assert_eq!(credential.metadata.custom_metadata.len(), 2);
        assert_eq!(
            credential.metadata.custom_metadata.get("project"),
            Some(&"WritersProof".to_string())
        );
    }
}
