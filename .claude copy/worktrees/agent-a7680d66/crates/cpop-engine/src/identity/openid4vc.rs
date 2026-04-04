

//! OpenID for Verifiable Credential Issuance (OID4VCI) metadata.
//!
//! Describes WritersProof as a credential issuer per the OpenID4VCI
//! specification. This module generates the issuer metadata that a
//! credential wallet uses to discover supported credential types and
//! claim schemas.

use serde::{Deserialize, Serialize};

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /
    pub credential_issuer: String,
    /
    pub credential_endpoint: String,
    /
    pub display: Vec<IssuerDisplay>,
    /
    pub credentials_supported: Vec<CredentialSupported>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerDisplay {
    /
    pub name: String,
    /
    pub locale: String,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSupported {
    /
    pub format: String,
    /
    pub credential_type: String,
    /
    pub display: Vec<CredentialDisplay>,
    /
    pub claims: Vec<ClaimDescriptor>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDisplay {
    /
    pub name: String,
    /
    pub locale: String,
    /
    pub description: String,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDescriptor {
    /
    pub name: String,
    /
    pub mandatory: bool,
    /
    pub value_type: String,
}

/
/
/
/
/
pub fn writersproof_issuer_metadata() -> CredentialIssuerMetadata {
    let claims = vec![
        ClaimDescriptor {
            name: "author_did".into(),
            mandatory: true,
            value_type: "string".into(),
        },
        ClaimDescriptor {
            name: "process_verdict".into(),
            mandatory: true,
            value_type: "string".into(),
        },
        ClaimDescriptor {
            name: "attestation_tier".into(),
            mandatory: true,
            value_type: "string".into(),
        },
        ClaimDescriptor {
            name: "evidence_ref".into(),
            mandatory: false,
            value_type: "string".into(),
        },
        ClaimDescriptor {
            name: "chain_duration_secs".into(),
            mandatory: false,
            value_type: "number".into(),
        },
        ClaimDescriptor {
            name: "ai_disclosure".into(),
            mandatory: false,
            value_type: "string".into(),
        },
    ];

    let display = CredentialDisplay {
        name: "Process Attestation Credential".into(),
        locale: "en-US".into(),
        description: "Cryptographic proof of human authorship process".into(),
    };

    CredentialIssuerMetadata {
        credential_issuer: "https:
        credential_endpoint: "https:
        display: vec![IssuerDisplay {
            name: "WritersProof".into(),
            locale: "en-US".into(),
        }],
        credentials_supported: vec![
            CredentialSupported {
                format: "vc+sd-jwt".into(),
                credential_type: "ProcessAttestationCredential".into(),
                display: vec![display.clone()],
                claims: claims.clone(),
            },
            CredentialSupported {
                format: "vc+cose".into(),
                credential_type: "ProcessAttestationCredential".into(),
                display: vec![display],
                claims,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issuer_metadata_endpoint() {
        let meta = writersproof_issuer_metadata();
        assert_eq!(meta.credential_issuer, "https:
        assert!(meta.credential_endpoint.starts_with("https:
    }

    #[test]
    fn test_two_formats_supported() {
        let meta = writersproof_issuer_metadata();
        assert_eq!(meta.credentials_supported.len(), 2);
        let formats: Vec<&str> = meta
            .credentials_supported
            .iter()
            .map(|c| c.format.as_str())
            .collect();
        assert!(formats.contains(&"vc+sd-jwt"));
        assert!(formats.contains(&"vc+cose"));
    }

    #[test]
    fn test_mandatory_claims_present() {
        let meta = writersproof_issuer_metadata();
        let cred = &meta.credentials_supported[0];
        let mandatory: Vec<&str> = cred
            .claims
            .iter()
            .filter(|c| c.mandatory)
            .map(|c| c.name.as_str())
            .collect();
        assert!(mandatory.contains(&"author_did"));
        assert!(mandatory.contains(&"process_verdict"));
        assert!(mandatory.contains(&"attestation_tier"));
    }

    #[test]
    fn test_credential_type() {
        let meta = writersproof_issuer_metadata();
        for cred in &meta.credentials_supported {
            assert_eq!(cred.credential_type, "ProcessAttestationCredential");
        }
    }

    #[test]
    fn test_metadata_serialization_roundtrip() {
        let meta = writersproof_issuer_metadata();
        let json = serde_json::to_string(&meta).expect("serialize");
        let decoded: CredentialIssuerMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.credential_issuer, meta.credential_issuer);
        assert_eq!(
            decoded.credentials_supported.len(),
            meta.credentials_supported.len()
        );
    }
}
