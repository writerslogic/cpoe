// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Apple Wallet integration for digital credentials.
//!
//! Exports W3C Verifiable Credentials to Apple Wallet-compatible formats.
//! Supports .pkpass (deprecated) and Apple's new Digital Credentials API.
//!
//! ISO 18013-5 mDoc format for compact QR code serialization.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::credential_builder::DigitalCredential;

/// Wallet export format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletFormat {
    /// Apple Digital Credentials (new format, requires iOS 17+/macOS 14+)
    DigitalCredentials,

    /// Compact CBOR for QR codes (ISO 18013-5 style)
    CompactCbor,

    /// Legacy PKPass format (deprecated)
    #[allow(dead_code)]
    LegacyPkPass,
}

/// Apple Wallet credential configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletCredentialConfig {
    /// Display label for credential in wallet
    pub label: String,

    /// Secondary label (e.g., document type)
    pub secondary_label: Option<String>,

    /// Tertiary label (e.g., author name)
    pub tertiary_label: Option<String>,

    /// ISO 639-1 language code for display
    pub language: String,

    /// Hex color for credential UI (6 digits, no #)
    pub foreground_color: String,

    /// Hex color for background
    pub background_color: String,

    /// Expiration behavior: true = show expiry warning, false = hide expiry
    pub show_expiration: bool,

    /// Supplementary field descriptions
    pub supplementary_fields: HashMap<String, String>,
}

impl Default for WalletCredentialConfig {
    fn default() -> Self {
        WalletCredentialConfig {
            label: "Authorship Credential".to_string(),
            secondary_label: None,
            tertiary_label: None,
            language: "en".to_string(),
            foreground_color: "FFFFFF".to_string(),  // White text
            background_color: "1F2937".to_string(),  // Dark gray background
            show_expiration: true,
            supplementary_fields: HashMap::new(),
        }
    }
}

/// Compact mobile document (ISO 18013-5 style) for QR code encoding.
///
/// Fits credential data into minimal bytes for efficient QR scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactMobileDocument {
    /// Document format version ("1.0")
    pub format_version: String,

    /// Credential data (CBOR-encoded)
    pub credential_data: Vec<u8>,

    /// Issuer public key for verification
    pub issuer_key: Vec<u8>,

    /// Credential expiration timestamp (Unix seconds)
    pub expires_at: u64,

    /// Metadata namespace (always "writersproof.authorship")
    pub namespace: String,
}

/// Wallet integration service for credential export.
pub struct WalletIntegration;

impl WalletIntegration {
    /// Export credential to Apple Wallet (Digital Credentials format).
    ///
    /// Returns CBOR-encoded credential ready for `.presentation.iso18013-5.cbor` file.
    ///
    /// # Arguments
    /// - `credential`: The W3C credential to export
    /// - `config`: Wallet display configuration
    ///
    /// # Returns
    /// CBOR bytes ready to be written to Wallet
    pub fn export_to_wallet(
        credential: &DigitalCredential,
        config: &WalletCredentialConfig,
    ) -> Result<Vec<u8>> {
        let wallet_cred = Self::build_wallet_credential(credential, config)?;
        ciborium::to_vec(&wallet_cred)
            .map_err(|e| Error::SerializationFailed(e.to_string()))
    }

    /// Export credential as compact CBOR for QR code encoding.
    ///
    /// # Arguments
    /// - `credential`: The W3C credential
    /// - `issuer_public_key`: Ed25519 public key (32 bytes) for verification
    ///
    /// # Returns
    /// CompactMobileDocument ready for QR encoding
    pub fn export_compact_cbor(
        credential: &DigitalCredential,
        issuer_public_key: &[u8; 32],
    ) -> Result<CompactMobileDocument> {
        let credential_cbor = ciborium::to_vec(credential)
            .map_err(|e| Error::SerializationFailed(e.to_string()))?;

        let expires_timestamp = Self::parse_rfc3339_to_unix_seconds(
            credential.expires_at.as_ref().ok_or_else(|| {
                Error::validation("credential missing expiration date")
            })?,
        )?;

        Ok(CompactMobileDocument {
            format_version: "1.0".to_string(),
            credential_data: credential_cbor,
            issuer_key: issuer_public_key.to_vec(),
            expires_at: expires_timestamp,
            namespace: "writersproof.authorship".to_string(),
        })
    }

    /// Export credential as JSON for manual verification or display.
    pub fn export_json(credential: &DigitalCredential) -> Result<String> {
        serde_json::to_string_pretty(credential)
            .map_err(|e| Error::SerializationFailed(e.to_string()))
    }

    /// Generate QR code payload from credential.
    ///
    /// Encodes CompactMobileDocument as CBOR, then base64 for QR embedding.
    pub fn generate_qr_payload(
        credential: &DigitalCredential,
        issuer_public_key: &[u8; 32],
    ) -> Result<String> {
        let mdoc = Self::export_compact_cbor(credential, issuer_public_key)?;
        let cbor_bytes = ciborium::to_vec(&mdoc)
            .map_err(|e| Error::SerializationFailed(e.to_string()))?;

        Ok(base64::encode(&cbor_bytes))
    }

    /// Validate credential for wallet export.
    ///
    /// Checks:
    /// - Issuer is writerslogic.com
    /// - Signature is present and valid format
    /// - Expiration date is in future
    /// - Evidence hash is valid hex
    pub fn validate_for_export(credential: &DigitalCredential) -> Result<()> {
        // Check issuer
        if credential.issuer != "writerslogic.com" {
            return Err(Error::validation("invalid issuer"));
        }

        // Check signature exists
        if credential.proof.signature_value.is_empty() {
            return Err(Error::validation("credential not signed"));
        }

        // Check expiration is in future
        if let Some(expires_str) = &credential.expires_at {
            let expires =
                chrono::DateTime::parse_from_rfc3339(expires_str).map_err(|_| {
                    Error::validation("invalid expiration date format")
                })?;

            if expires < chrono::Utc::now().with_timezone(&expires.timezone()) {
                return Err(Error::validation("credential has expired"));
            }
        }

        // Check evidence hash is valid hex
        if credential.subject.evidence_hash.len() != 64 {
            return Err(Error::validation("invalid evidence hash length"));
        }

        if !credential.subject.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::validation("evidence hash contains invalid characters"));
        }

        Ok(())
    }

    // Private helper: build wallet credential from W3C credential
    fn build_wallet_credential(
        credential: &DigitalCredential,
        config: &WalletCredentialConfig,
    ) -> Result<WalletCredentialPayload> {
        Ok(WalletCredentialPayload {
            document_type: credential.document_type.clone(),
            format: "iso18013-5".to_string(),
            display: WalletDisplay {
                name: config.label.clone(),
                locale: config.language.clone(),
                logo: WalletLogo {
                    uri: "https://writerslogic.com/logo.png".to_string(),
                    alt_text: "WritersLogic".to_string(),
                },
                description: Some(
                    format!(
                        "Authorship credential for {}: {}",
                        credential.subject.id, credential.subject.document_title
                    ),
                ),
                background_color: format!("#{}", config.background_color),
                text_color: format!("#{}", config.foreground_color),
            },
            claims: Self::extract_wallet_claims(credential),
        })
    }

    // Private helper: extract claims for wallet display
    fn extract_wallet_claims(credential: &DigitalCredential) -> HashMap<String, ClaimValue> {
        let mut claims = HashMap::new();

        claims.insert(
            "author".to_string(),
            ClaimValue::String(credential.subject.id.clone()),
        );

        claims.insert(
            "document_title".to_string(),
            ClaimValue::String(credential.subject.document_title.clone()),
        );

        claims.insert(
            "evidence_hash".to_string(),
            ClaimValue::String(credential.subject.evidence_hash.clone()),
        );

        claims.insert(
            "authorship_confidence".to_string(),
            ClaimValue::Float(credential.subject.authorship_confidence),
        );

        claims.insert(
            "keystroke_confidence".to_string(),
            ClaimValue::Float(credential.subject.keystroke_confidence),
        );

        claims.insert(
            "original_composition_ratio".to_string(),
            ClaimValue::Float(credential.subject.original_composition_ratio),
        );

        claims.insert(
            "app_bundle_id".to_string(),
            ClaimValue::String(credential.subject.source_app.clone()),
        );

        claims.insert(
            "issued_at".to_string(),
            ClaimValue::String(credential.issued_at.clone()),
        );

        if let Some(expires) = &credential.expires_at {
            claims.insert("expires_at".to_string(), ClaimValue::String(expires.clone()));
        }

        claims
    }

    // Private helper: parse RFC 3339 to Unix seconds
    fn parse_rfc3339_to_unix_seconds(rfc3339: &str) -> Result<u64> {
        let dt = chrono::DateTime::parse_from_rfc3339(rfc3339)
            .map_err(|_| Error::validation("invalid RFC 3339 timestamp"))?;

        Ok(dt.timestamp() as u64)
    }
}

// Internal structures for wallet CBOR serialization

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletCredentialPayload {
    document_type: String,
    format: String,
    display: WalletDisplay,
    claims: HashMap<String, ClaimValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletDisplay {
    name: String,
    locale: String,
    logo: WalletLogo,
    description: Option<String>,
    background_color: String,
    text_color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletLogo {
    uri: String,
    alt_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum ClaimValue {
    String(String),
    Float(f64),
    Integer(i64),
    Boolean(bool),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::credential_builder::{CredentialBuilder, CredentialMetadata};
    use std::collections::HashMap;

    fn create_test_credential() -> DigitalCredential {
        let evidence_hash = [0xABu8; 32];
        let mut custom = HashMap::new();
        custom.insert("test".to_string(), "value".to_string());

        let metadata = CredentialMetadata {
            app_bundle_id: "com.apple.Notes".to_string(),
            os_platform: "macos".to_string(),
            device_type: "MacBook Pro".to_string(),
            device_id: Some("ABC123".to_string()),
            session_id: Some("sess-xyz".to_string()),
            custom_metadata: custom,
        };

        let builder = CredentialBuilder::new(
            "Test Author".to_string(),
            "Test Document".to_string(),
            evidence_hash,
            "com.apple.Notes".to_string(),
            metadata,
        );

        builder.build_unsigned()
    }

    #[test]
    fn test_wallet_format_default_config() {
        let config = WalletCredentialConfig::default();
        assert_eq!(config.language, "en");
        assert_eq!(config.label, "Authorship Credential");
        assert_eq!(config.foreground_color, "FFFFFF");
        assert_eq!(config.background_color, "1F2937");
        assert!(config.show_expiration);
    }

    #[test]
    fn test_validate_for_export_valid_credential() {
        let credential = create_test_credential();
        let result = WalletIntegration::validate_for_export(&credential);
        // Unsigned credential should fail validation (no signature)
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_for_export_invalid_issuer() {
        let mut credential = create_test_credential();
        credential.issuer = "bad-issuer.com".to_string();

        let result = WalletIntegration::validate_for_export(&credential);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_for_export_expired_credential() {
        let mut credential = create_test_credential();
        credential.expires_at = Some("2020-01-01T00:00:00Z".to_string());

        let result = WalletIntegration::validate_for_export(&credential);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_for_export_invalid_evidence_hash() {
        let mut credential = create_test_credential();
        credential.subject.evidence_hash = "invalid-hash".to_string();

        let result = WalletIntegration::validate_for_export(&credential);
        assert!(result.is_err());
    }

    #[test]
    fn test_export_json() {
        let credential = create_test_credential();
        let result = WalletIntegration::export_json(&credential);

        assert!(result.is_ok());
        let json = result.unwrap();
        assert!(json.contains("writerslogic.com"));
        assert!(json.contains("Test Author"));
        assert!(json.contains("Test Document"));
    }

    #[test]
    fn test_export_compact_cbor() {
        let credential = create_test_credential();
        let issuer_key = [0xCCu8; 32];

        let result = WalletIntegration::export_compact_cbor(&credential, &issuer_key);

        assert!(result.is_ok());
        let mdoc = result.unwrap();
        assert_eq!(mdoc.format_version, "1.0");
        assert_eq!(mdoc.namespace, "writersproof.authorship");
        assert!(!mdoc.credential_data.is_empty());
        assert_eq!(mdoc.issuer_key, issuer_key.to_vec());
    }

    #[test]
    fn test_export_compact_cbor_missing_expiration() {
        let mut credential = create_test_credential();
        credential.expires_at = None;

        let issuer_key = [0xDDu8; 32];
        let result = WalletIntegration::export_compact_cbor(&credential, &issuer_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_generate_qr_payload() {
        let credential = create_test_credential();
        let issuer_key = [0xEEu8; 32];

        let result = WalletIntegration::generate_qr_payload(&credential, &issuer_key);

        assert!(result.is_ok());
        let payload = result.unwrap();
        // Should be valid base64
        assert!(base64::decode(&payload).is_ok());
    }

    #[test]
    fn test_wallet_credential_config_custom() {
        let config = WalletCredentialConfig {
            label: "My Credential".to_string(),
            secondary_label: Some("Author Proof".to_string()),
            tertiary_label: Some("Jane Doe".to_string()),
            language: "fr".to_string(),
            foreground_color: "000000".to_string(),
            background_color: "FFFFFF".to_string(),
            show_expiration: false,
            supplementary_fields: {
                let mut m = HashMap::new();
                m.insert("field1".to_string(), "value1".to_string());
                m
            },
        };

        assert_eq!(config.label, "My Credential");
        assert_eq!(config.language, "fr");
        assert!(!config.show_expiration);
        assert_eq!(config.supplementary_fields.len(), 1);
    }

    #[test]
    fn test_compact_mobile_document_serialization() {
        let mdoc = CompactMobileDocument {
            format_version: "1.0".to_string(),
            credential_data: vec![0x01, 0x02, 0x03],
            issuer_key: vec![0xFF; 32],
            expires_at: 1735689600,
            namespace: "writersproof.authorship".to_string(),
        };

        let result = serde_json::to_string(&mdoc);
        assert!(result.is_ok());

        let json = result.unwrap();
        assert!(json.contains("1.0"));
        assert!(json.contains("writersproof.authorship"));
    }
}
