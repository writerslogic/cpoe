

//! W3C Verifiable Credential profile — projects an EAR token into a VC 2.0.
//!
//! Supports two securing mechanisms per the W3C "Securing Verifiable Credentials
//! using JOSE and COSE" Recommendation (May 2025):
//!
//! - **Data Integrity proof** (`to_signed_verifiable_credential`): Ed25519 proof
//!   embedded in the VC JSON, using `eddsa-rdfc-2022` cryptosuite.
//! - **COSE_Sign1 envelope** (`to_cose_secured_vc`): VC payload serialized as
//!   CBOR and wrapped in a COSE_Sign1 structure with EdDSA signing.

use chrono::{DateTime, Utc};
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::tpm;
use crate::war::common::{derive_attestation_tier, SerializedTrustVector};
use crate::war::ear::EarToken;

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<VcEvidence>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<VcProof>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub subject_type: String,
    #[serde(rename = "processAttestation")]
    pub process_attestation: ProcessAttestation,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAttestation {
    pub status: String,
    #[serde(rename = "trustVector", skip_serializing_if = "Option::is_none")]
    pub trust_vector: Option<SerializedTrustVector>,
    #[serde(rename = "documentRef", skip_serializing_if = "Option::is_none")]
    pub document_ref: Option<String>,
    #[serde(rename = "chainDuration", skip_serializing_if = "Option::is_none")]
    pub chain_duration: Option<String>,
    #[serde(rename = "attestationTier", skip_serializing_if = "Option::is_none")]
    pub attestation_tier: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcEvidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub verifier: String,
    #[serde(rename = "sealHash", skip_serializing_if = "Option::is_none")]
    pub seal_hash: Option<String>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/
fn build_vc_core(ear: &EarToken, author_did: &str) -> Result<VerifiableCredential> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let tv_vc = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(SerializedTrustVector::from);

    let document_ref = appr.pop_evidence_ref.as_ref().map(hex::encode);

    let chain_duration = appr.pop_chain_duration.map(|secs| {
        let hours = secs / 3600;
        let minutes = (secs % 3600) / 60;
        let remaining_secs = secs % 60;
        if hours > 0 {
            format!("PT{}H{}M{}S", hours, minutes, remaining_secs)
        } else if minutes > 0 {
            format!("PT{}M{}S", minutes, remaining_secs)
        } else {
            format!("PT{}S", remaining_secs)
        }
    });

    let tier_str = appr
        .ear_trustworthiness_vector
        .as_ref()
        .map(|tv| derive_attestation_tier(tv).to_string());

    let valid_from: DateTime<Utc> = DateTime::from_timestamp(ear.iat, 0).unwrap_or_else(Utc::now);

    let seal_hash = appr.pop_seal.as_ref().map(|s| hex::encode(s.h3));

    let evidence = vec![VcEvidence {
        evidence_type: "ProofOfProcessEvidence".to_string(),
        verifier: ear.ear_verifier_id.build.clone(),
        seal_hash,
    }];

    Ok(VerifiableCredential {
        context: vec![
            "https:
            "https:
        ],
        vc_type: vec![
            "VerifiableCredential".to_string(),
            "ProcessAttestationCredential".to_string(),
        ],
        issuer: "did:web:writerslogic.com".to_string(),
        valid_from: valid_from.to_rfc3339(),
        credential_subject: CredentialSubject {
            id: author_did.to_string(),
            subject_type: "Author".to_string(),
            process_attestation: ProcessAttestation {
                status: appr.ear_status.as_str().to_string(),
                trust_vector: tv_vc,
                document_ref,
                chain_duration,
                attestation_tier: tier_str,
            },
        },
        evidence: Some(evidence),
        proof: None,
    })
}

/
/
/
/
/
pub fn to_verifiable_credential(ear: &EarToken, author_did: &str) -> Result<VerifiableCredential> {
    let mut vc = build_vc_core(ear, author_did)?;

    
    vc.proof = Some(VcProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-rdfc-2022".to_string(),
        verification_method: format!("{}#key-1", author_did),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: String::new(),
    });

    Ok(vc)
}

/
/
/
/
/
pub fn to_signed_verifiable_credential(
    ear: &EarToken,
    author_did: &str,
    signer: &dyn tpm::Provider,
) -> Result<VerifiableCredential> {
    let mut vc = build_vc_core(ear, author_did)?;

    
    let canon_json = serde_json::to_string(&vc)
        .map_err(|e| Error::evidence(format!("VC JSON serialization failed: {e}")))?;
    let digest = Sha256::digest(canon_json.as_bytes());

    
    let signature = signer
        .sign(&digest)
        .map_err(|e| Error::crypto(format!("VC signing failed: {e}")))?;

    
    let proof_value = format!("f{}", hex::encode(&signature));

    vc.proof = Some(VcProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "eddsa-rdfc-2022".to_string(),
        verification_method: format!("{}#key-1", author_did),
        proof_purpose: "assertionMethod".to_string(),
        proof_value,
    });

    Ok(vc)
}

/
const COSE_VC_CONTENT_TYPE: &str = "application/vc";

/
/
/
/
/
/
/
/
pub fn to_cose_secured_vc(
    ear: &EarToken,
    author_did: &str,
    signer: &dyn tpm::Provider,
) -> Result<Vec<u8>> {
    let vc = build_vc_core(ear, author_did)?;

    
    let vc_json = serde_json::to_value(&vc)
        .map_err(|e| Error::evidence(format!("VC serialization failed: {e}")))?;
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(&vc_json, &mut payload_bytes)
        .map_err(|e| Error::crypto(format!("CBOR encode error: {e}")))?;

    let kid = format!("{}#key-1", author_did);
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .content_type(COSE_VC_CONTENT_TYPE.to_string())
        .key_id(kid.into_bytes())
        .build();

    let mut sign_error: Option<Error> = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |sig_data| match signer.sign(sig_data) {
            Ok(sig) => sig,
            Err(e) => {
                sign_error = Some(Error::crypto(format!("COSE VC sign error: {e}")));
                Vec::new()
            }
        })
        .build();

    if let Some(e) = sign_error {
        return Err(e);
    }

    if sign1.signature.is_empty() {
        return Err(Error::crypto("COSE VC signing produced empty signature"));
    }

    sign1
        .to_vec()
        .map_err(|e| Error::crypto(format!("COSE encoding error: {e}")))
}

/
/
/
/
/
pub fn from_cose_secured_vc(bytes: &[u8]) -> Result<VerifiableCredential> {
    let sign1 = coset::CoseSign1::from_slice(bytes)
        .map_err(|e| Error::crypto(format!("COSE decode error: {e}")))?;

    let payload = sign1
        .payload
        .ok_or_else(|| Error::crypto("missing COSE VC payload"))?;

    
    let json_value: serde_json::Value = ciborium::from_reader(payload.as_slice())
        .map_err(|e| Error::crypto(format!("CBOR payload decode error: {e}")))?;

    serde_json::from_value(json_value)
        .map_err(|e| Error::evidence(format!("VC deserialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint;
    use crate::declaration;
    use crate::evidence;
    use crate::tpm::SoftwareProvider;
    use crate::trust_policy::profiles::basic;
    use crate::vdf;
    use crate::war::Block;
    use coset::CborSerializable;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::time::Duration;
    use tempfile::TempDir;

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn create_test_ear() -> (EarToken, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("test_doc.txt");
        fs::write(&path, b"Test document for VC encoding").expect("write");

        let mut chain = checkpoint::Chain::new(&path, vdf::default_parameters()).expect("chain");
        chain
            .commit_with_vdf_duration(None, Duration::from_millis(10))
            .expect("commit");

        let latest = chain.latest().expect("latest");
        let signing_key = test_signing_key();
        let decl = declaration::no_ai_declaration(
            latest.content_hash,
            latest.hash,
            "Test VC Doc",
            "I wrote this.",
        )
        .sign(&signing_key)
        .expect("sign");

        let packet = evidence::Builder::new("Test VC Doc", &chain)
            .with_declaration(&decl)
            .build()
            .expect("build");

        let policy = basic();
        let block =
            Block::from_packet_appraised(&packet, &signing_key, &policy).expect("appraised block");
        let ear = block.ear.expect("EAR token");
        (ear, dir)
    }

    #[test]
    fn test_cose_vc_roundtrip() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkTest123";

        let cose_bytes = to_cose_secured_vc(&ear, did, &provider).expect("COSE encode");
        assert!(!cose_bytes.is_empty());

        let decoded = from_cose_secured_vc(&cose_bytes).expect("COSE decode");
        assert_eq!(decoded.issuer, "did:web:writerslogic.com");
        assert_eq!(decoded.credential_subject.id, did);
        assert_eq!(decoded.credential_subject.subject_type, "Author");
        assert!(decoded.evidence.is_some());
        
        assert!(decoded.proof.is_none());
    }

    #[test]
    fn test_cose_vc_has_correct_headers() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkHeaders";

        let cose_bytes = to_cose_secured_vc(&ear, did, &provider).expect("COSE encode");

        let sign1 = coset::CoseSign1::from_slice(&cose_bytes).expect("parse COSE_Sign1");

        
        let alg = sign1.protected.header.alg.expect("alg header missing");
        assert_eq!(
            alg,
            coset::RegisteredLabelWithPrivate::Assigned(coset::iana::Algorithm::EdDSA)
        );

        
        let ct = sign1
            .protected
            .header
            .content_type
            .expect("content_type header missing");
        assert_eq!(ct, coset::ContentType::Text("application/vc".to_string()));

        
        let kid_str =
            String::from_utf8(sign1.protected.header.key_id.clone()).expect("kid is valid UTF-8");
        assert_eq!(kid_str, format!("{}#key-1", did));

        
        assert!(!sign1.signature.is_empty());
    }

    #[test]
    fn test_signed_vc_has_proof() {
        let (ear, _dir) = create_test_ear();
        let provider = SoftwareProvider::new();
        let did = "did:key:z6MkSigned";

        let vc = to_signed_verifiable_credential(&ear, did, &provider).expect("signed VC");

        let proof = vc.proof.expect("proof should be present");
        assert_eq!(proof.proof_type, "DataIntegrityProof");
        assert_eq!(proof.cryptosuite, "eddsa-rdfc-2022");
        assert_eq!(proof.verification_method, format!("{}#key-1", did));
        assert_eq!(proof.proof_purpose, "assertionMethod");

        
        assert!(
            proof.proof_value.starts_with('f'),
            "proofValue should be multibase base16"
        );
        let hex_part = &proof.proof_value[1..];
        assert!(
            hex::decode(hex_part).is_ok(),
            "proofValue hex portion should be valid hex"
        );
        
        assert_eq!(hex_part.len(), 128);
    }

    #[test]
    fn test_unsigned_vc_backward_compat() {
        let (ear, _dir) = create_test_ear();
        let did = "did:key:z6MkCompat";

        let vc = to_verifiable_credential(&ear, did).expect("unsigned VC");
        let proof = vc.proof.expect("proof placeholder");
        assert!(
            proof.proof_value.is_empty(),
            "unsigned VC should have empty proofValue"
        );
    }
}
