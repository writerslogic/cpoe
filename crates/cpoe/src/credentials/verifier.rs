// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! W3C Verifiable Credential verification and validation.
//!
//! Verifies Ed25519 signatures, checks issuer identity, validates evidence hash,
//! and confirms temporal bounds.

use crate::error::{Error, Result};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_SIZE, SIGNATURE_BYTES};
use std::str::FromStr;

use super::credential_builder::DigitalCredential;

/// Credential verification result with confidence and details.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Credential is valid and trusted
    pub is_valid: bool,

    /// Overall confidence in credential (0.0-1.0)
    pub confidence: f64,

    /// Details about verification
    pub details: VerificationDetails,

    /// Any warnings encountered during verification
    pub warnings: Vec<String>,
}

/// Detailed breakdown of verification checks.
#[derive(Debug, Clone)]
pub struct VerificationDetails {
    /// Issuer check passed
    pub issuer_valid: bool,

    /// Signature verification passed
    pub signature_valid: bool,

    /// Temporal bounds check passed (not expired, not future-issued)
    pub temporal_valid: bool,

    /// Evidence hash is valid format
    pub evidence_hash_valid: bool,

    /// Public key format is valid
    pub key_format_valid: bool,

    /// Issuer public key available
    pub issuer_key_available: bool,
}

/// Credential verifier for W3C Verifiable Credentials.
pub struct CredentialVerifier {
    /// WritersLogic issuer public key (32 bytes Ed25519)
    issuer_public_key: Option<[u8; 32]>,

    /// Tolerance for time skew (seconds, default: 300)
    time_skew_tolerance: i64,

    /// Require non-expired credentials
    require_valid_expiration: bool,
}

impl Default for CredentialVerifier {
    fn default() -> Self {
        CredentialVerifier {
            issuer_public_key: None,
            time_skew_tolerance: 300,  // 5 minutes
            require_valid_expiration: true,
        }
    }
}

impl CredentialVerifier {
    /// Create new verifier with issuer public key.
    pub fn new(issuer_public_key: [u8; 32]) -> Self {
        CredentialVerifier {
            issuer_public_key: Some(issuer_public_key),
            time_skew_tolerance: 300,
            require_valid_expiration: true,
        }
    }

    /// Set time skew tolerance (seconds).
    ///
    /// Credentials issued or expiring within this window are still accepted.
    /// Default: 300 seconds (5 minutes).
    pub fn with_time_skew_tolerance(mut self, seconds: i64) -> Self {
        self.time_skew_tolerance = seconds;
        self
    }

    /// Set whether to require valid (non-expired) credentials.
    pub fn require_valid_expiration(mut self, require: bool) -> Self {
        self.require_valid_expiration = require;
        self
    }

    /// Verify a digital credential completely.
    ///
    /// Performs checks:
    /// 1. Issuer is writerslogic.com
    /// 2. Signature is valid Ed25519 (if issuer key available)
    /// 3. Temporal bounds (issue time <= now <= expiration + skew)
    /// 4. Evidence hash is valid hex format
    /// 5. Confidence scores are in valid range (0.0-1.0)
    pub fn verify(&self, credential: &DigitalCredential) -> VerificationResult {
        let mut details = VerificationDetails {
            issuer_valid: false,
            signature_valid: false,
            temporal_valid: false,
            evidence_hash_valid: false,
            key_format_valid: false,
            issuer_key_available: self.issuer_public_key.is_some(),
        };

        let mut warnings = Vec::new();
        let mut check_count = 0;
        let mut passed_count = 0;

        // Check 1: Issuer
        check_count += 1;
        if credential.issuer == "writerslogic.com" {
            details.issuer_valid = true;
            passed_count += 1;
        } else {
            warnings.push(format!("Invalid issuer: {}", credential.issuer));
        }

        // Check 2: Signature validity
        check_count += 1;
        if let Some(issuer_key) = self.issuer_public_key {
            match self.verify_signature(credential, &issuer_key) {
                Ok(true) => {
                    details.signature_valid = true;
                    passed_count += 1;
                }
                Ok(false) => {
                    warnings.push("Signature verification failed: signature does not match".to_string());
                }
                Err(e) => {
                    warnings.push(format!("Signature verification error: {}", e));
                }
            }
        } else {
            warnings.push("Issuer public key not available; signature cannot be verified".to_string());
        }

        // Check 3: Temporal bounds
        check_count += 1;
        match self.verify_temporal_bounds(credential) {
            Ok(()) => {
                details.temporal_valid = true;
                passed_count += 1;
            }
            Err(e) => {
                warnings.push(format!("Temporal validation failed: {}", e));
            }
        }

        // Check 4: Evidence hash format
        check_count += 1;
        if self.is_valid_evidence_hash(&credential.subject.evidence_hash) {
            details.evidence_hash_valid = true;
            passed_count += 1;
        } else {
            warnings.push("Evidence hash is not valid hex format".to_string());
        }

        // Check 5: Confidence scores
        check_count += 1;
        if self.are_valid_confidence_scores(credential) {
            passed_count += 1;
        } else {
            warnings.push("Confidence scores outside valid range (0.0-1.0)".to_string());
        }

        // Check 6: Public key format
        check_count += 1;
        if self.is_valid_public_key_format(&credential.proof.verifying_key) {
            details.key_format_valid = true;
            passed_count += 1;
        } else {
            warnings.push("Public key is not valid base64 or wrong length".to_string());
        }

        let is_valid = passed_count == check_count;
        let confidence = passed_count as f64 / check_count as f64;

        VerificationResult {
            is_valid,
            confidence,
            details,
            warnings,
        }
    }

    /// Verify only the Ed25519 signature.
    ///
    /// Returns true if signature is valid, false if invalid.
    /// Returns Err only on format/parsing errors.
    pub fn verify_signature(
        &self,
        credential: &DigitalCredential,
        issuer_public_key: &[u8; 32],
    ) -> Result<bool> {
        // Decode public key
        let verifying_key = VerifyingKey::from_bytes(issuer_public_key)
            .map_err(|_| Error::validation("invalid public key"))?;

        // Decode signature from base64
        let sig_bytes = base64::decode(&credential.proof.signature_value)
            .map_err(|_| Error::validation("signature is not valid base64"))?;

        if sig_bytes.len() != SIGNATURE_BYTES {
            return Err(Error::validation(&format!(
                "signature wrong length: {} != {}",
                sig_bytes.len(),
                SIGNATURE_BYTES
            )));
        }

        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

        // Reconstruct signing payload
        let payload = Self::credential_payload_for_verification(credential)?;

        // Verify
        match verifying_key.verify_strict(&payload, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify temporal bounds (issued_at <= now <= expires_at + skew).
    fn verify_temporal_bounds(&self, credential: &DigitalCredential) -> Result<()> {
        let now = Utc::now();

        // Parse issued_at
        let issued_at = chrono::DateTime::parse_from_rfc3339(&credential.issued_at)
            .map_err(|_| Error::validation("invalid issued_at format"))?
            .with_timezone(&Utc);

        // Check not issued in future (with skew tolerance)
        let max_issue_time = now + chrono::Duration::seconds(self.time_skew_tolerance);
        if issued_at > max_issue_time {
            return Err(Error::validation("credential issued in the future"));
        }

        // Check expiration if present and required
        if self.require_valid_expiration {
            if let Some(expires_str) = &credential.expires_at {
                let expires_at = chrono::DateTime::parse_from_rfc3339(expires_str)
                    .map_err(|_| Error::validation("invalid expires_at format"))?
                    .with_timezone(&Utc);

                // Check not expired (with skew tolerance)
                let min_expiry_time = now - chrono::Duration::seconds(self.time_skew_tolerance);
                if expires_at < min_expiry_time {
                    return Err(Error::validation("credential has expired"));
                }
            }
        }

        Ok(())
    }

    /// Check if evidence hash is valid hex format (64 hex chars = 32 bytes).
    fn is_valid_evidence_hash(&self, hash: &str) -> bool {
        if hash.len() != 64 {
            return false;
        }

        hash.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Check if confidence scores are in valid range (0.0-1.0).
    fn are_valid_confidence_scores(&self, credential: &DigitalCredential) -> bool {
        let subject = &credential.subject;

        (0.0..=1.0).contains(&subject.keystroke_confidence)
            && (0.0..=1.0).contains(&subject.original_composition_ratio)
            && (0.0..=1.0).contains(&subject.authorship_confidence)
    }

    /// Check if public key format is valid base64 and correct length.
    fn is_valid_public_key_format(&self, key_b64: &str) -> bool {
        match base64::decode(key_b64) {
            Ok(decoded) => decoded.len() == PUBLIC_KEY_SIZE,
            Err(_) => false,
        }
    }

    /// Reconstruct canonical payload for signature verification.
    fn credential_payload_for_verification(credential: &DigitalCredential) -> Result<Vec<u8>> {
        let mut payload = Vec::new();

        payload.extend_from_slice(b"witnessd-credential-v1");
        payload.extend_from_slice(credential.issuer.as_bytes());
        payload.extend_from_slice(credential.subject.id.as_bytes());
        payload.extend_from_slice(credential.subject.evidence_hash.as_bytes());
        payload.extend_from_slice(credential.subject.document_title.as_bytes());
        payload.extend_from_slice(credential.subject.timestamp.as_bytes());

        payload.extend_from_slice(&credential.subject.keystroke_confidence.to_le_bytes());
        payload.extend_from_slice(&credential.subject.original_composition_ratio.to_le_bytes());
        payload.extend_from_slice(&credential.subject.authorship_confidence.to_le_bytes());

        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::credential_builder::{CredentialBuilder, CredentialMetadata};
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;
    use std::collections::HashMap;

    fn create_test_signing_key() -> SigningKey {
        let mut rng = thread_rng();
        SigningKey::generate(&mut rng)
    }

    fn create_test_credential_signed(signing_key: &SigningKey) -> DigitalCredential {
        let evidence_hash = [0xABu8; 32];
        let metadata = CredentialMetadata {
            app_bundle_id: "com.apple.Notes".to_string(),
            os_platform: "macos".to_string(),
            device_type: "MacBook".to_string(),
            device_id: None,
            session_id: None,
            custom_metadata: HashMap::new(),
        };

        let builder = CredentialBuilder::new(
            "Test Author".to_string(),
            "Test Doc".to_string(),
            evidence_hash,
            "com.apple.Notes".to_string(),
            metadata,
        );

        builder
            .build_and_sign(signing_key, 0.95, 0.87, 0.91)
            .unwrap()
    }

    #[test]
    fn test_verifier_default() {
        let verifier = CredentialVerifier::default();
        assert_eq!(verifier.time_skew_tolerance, 300);
        assert!(verifier.require_valid_expiration);
        assert!(verifier.issuer_public_key.is_none());
    }

    #[test]
    fn test_verifier_with_key() {
        let key = [0xFFu8; 32];
        let verifier = CredentialVerifier::new(key);
        assert_eq!(verifier.issuer_public_key, Some(key));
    }

    #[test]
    fn test_verifier_with_time_skew_tolerance() {
        let verifier = CredentialVerifier::default().with_time_skew_tolerance(600);
        assert_eq!(verifier.time_skew_tolerance, 600);
    }

    #[test]
    fn test_verify_signature_valid() {
        let signing_key = create_test_signing_key();
        let credential = create_test_credential_signed(&signing_key);

        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let verifier = CredentialVerifier::new(*verifying_key.as_bytes());

        let result = verifier.verify_signature(&credential, verifying_key.as_bytes());

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_signature_invalid_key() {
        let signing_key = create_test_signing_key();
        let credential = create_test_credential_signed(&signing_key);

        let wrong_key = [0xCCu8; 32];
        let verifier = CredentialVerifier::new(wrong_key);

        let result = verifier.verify_signature(&credential, &wrong_key);

        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_valid_evidence_hash() {
        let verifier = CredentialVerifier::default();

        assert!(verifier.is_valid_evidence_hash(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));

        assert!(!verifier.is_valid_evidence_hash("too-short"));
        assert!(!verifier.is_valid_evidence_hash(
            "gg0000000000000000000000000000000000000000000000000000000000000000"
        )); // Invalid hex
    }

    #[test]
    fn test_are_valid_confidence_scores() {
        let signing_key = create_test_signing_key();
        let credential = create_test_credential_signed(&signing_key);

        let verifier = CredentialVerifier::default();
        assert!(verifier.are_valid_confidence_scores(&credential));
    }

    #[test]
    fn test_are_valid_confidence_scores_invalid() {
        let signing_key = create_test_signing_key();
        let mut credential = create_test_credential_signed(&signing_key);

        credential.subject.keystroke_confidence = 1.5;  // Out of range

        let verifier = CredentialVerifier::default();
        assert!(!verifier.are_valid_confidence_scores(&credential));
    }

    #[test]
    fn test_is_valid_public_key_format() {
        let verifier = CredentialVerifier::default();

        let valid_key = base64::encode(&[0xAAu8; 32]);
        assert!(verifier.is_valid_public_key_format(&valid_key));

        assert!(!verifier.is_valid_public_key_format("not-base64!@#$"));
        assert!(!verifier.is_valid_public_key_format(&base64::encode(&[0xBBu8; 16])));  // Wrong length
    }

    #[test]
    fn test_verify_complete_valid_credential() {
        let signing_key = create_test_signing_key();
        let credential = create_test_credential_signed(&signing_key);

        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let verifier = CredentialVerifier::new(*verifying_key.as_bytes());

        let result = verifier.verify(&credential);

        assert!(result.is_valid);
        assert_eq!(result.confidence, 1.0);
        assert!(result.warnings.is_empty());
        assert!(result.details.issuer_valid);
        assert!(result.details.signature_valid);
        assert!(result.details.temporal_valid);
        assert!(result.details.evidence_hash_valid);
    }

    #[test]
    fn test_verify_invalid_issuer() {
        let signing_key = create_test_signing_key();
        let mut credential = create_test_credential_signed(&signing_key);

        credential.issuer = "bad-issuer.com".to_string();

        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let verifier = CredentialVerifier::new(*verifying_key.as_bytes());

        let result = verifier.verify(&credential);

        assert!(!result.is_valid);
        assert!(!result.details.issuer_valid);
    }

    #[test]
    fn test_verify_expired_credential() {
        let signing_key = create_test_signing_key();
        let mut credential = create_test_credential_signed(&signing_key);

        credential.expires_at = Some("2020-01-01T00:00:00Z".to_string());

        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let verifier = CredentialVerifier::new(*verifying_key.as_bytes());

        let result = verifier.verify(&credential);

        assert!(!result.is_valid);
        assert!(!result.details.temporal_valid);
    }

    #[test]
    fn test_verify_without_issuer_key() {
        let signing_key = create_test_signing_key();
        let credential = create_test_credential_signed(&signing_key);

        let verifier = CredentialVerifier::default();  // No key
        let result = verifier.verify(&credential);

        // Should still verify other checks but skip signature
        assert!(!result.details.issuer_key_available);
    }

    #[test]
    fn test_verification_result_confidence_partial() {
        let signing_key = create_test_signing_key();
        let mut credential = create_test_credential_signed(&signing_key);

        credential.subject.evidence_hash = "invalid-hex".to_string();  // Invalid hash

        let verifying_key = ed25519_dalek::VerifyingKey::from(&signing_key);
        let verifier = CredentialVerifier::new(*verifying_key.as_bytes());

        let result = verifier.verify(&credential);

        assert!(!result.is_valid);
        assert!(result.confidence < 1.0);
        assert!(!result.warnings.is_empty());
    }
}
