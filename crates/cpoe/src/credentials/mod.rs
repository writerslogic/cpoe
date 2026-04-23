// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Digital Credentials + Wallet Integration (Phase 4)
//!
//! W3C Verifiable Credentials for authorship attestation, exportable to Apple Wallet.
//! Implements ISO 18013-5 mobile documents with Ed25519 signatures.
//!
//! # Usage
//!
//! ```ignore
//! use cpoe_engine::credentials::credential_builder::{CredentialBuilder, CredentialMetadata};
//! use cpoe_engine::credentials::wallet_integration::WalletIntegration;
//! use cpoe_engine::credentials::verifier::CredentialVerifier;
//!
//! // Build credential
//! let builder = CredentialBuilder::new(
//!     "Author Name".to_string(),
//!     "Document Title".to_string(),
//!     evidence_hash,  // [u8; 32]
//!     "com.apple.Notes".to_string(),
//!     metadata,
//! );
//!
//! // Sign credential
//! let credential = builder.build_and_sign(&signing_key, 0.95, 0.87, 0.91)?;
//!
//! // Export to wallet
//! let wallet_bytes = WalletIntegration::export_to_wallet(&credential, &config)?;
//!
//! // Verify credential
//! let verifier = CredentialVerifier::new(issuer_public_key);
//! let result = verifier.verify(&credential);
//! assert!(result.is_valid);
//! ```

pub mod credential_builder;
pub mod verifier;
pub mod wallet_integration;

pub use credential_builder::{
    BehavioralMarkers, CredentialBuilder, CredentialMetadata, CredentialProof,
    CredentialSubject, DigitalCredential,
};

pub use verifier::{CredentialVerifier, VerificationDetails, VerificationResult};

pub use wallet_integration::{CompactMobileDocument, WalletCredentialConfig, WalletIntegration};
