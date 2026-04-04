

//! CAWG (Creator Assertions Working Group) profile projections.
//!
//! Maps CPOP evidence and declarations onto CAWG assertion structures:
//!
//! - **Identity Assertion v1.2**: projects an EAR token and author DID into
//!   a `cawg.identity` assertion with WritersProof as an Identity Claims
//!   Aggregator (ICA).
//!
//! - **Training and Data Mining Assertion v1.1**: projects a CPOP declaration
//!   into a `cawg.training-mining` assertion with per-use-type permissions.

use serde::{Deserialize, Serialize};

use crate::declaration::{AiExtent, Declaration};
use crate::error::{Error, Result};
use crate::war::ear::EarToken;

/
pub const IDENTITY_LABEL: &str = "cawg.identity";

/
pub const TDM_LABEL: &str = "cawg.training-mining";

/
pub const WRITERSPROOF_ICA_PROVIDER: &str = "https:





/
/
/
/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgIdentityAssertion {
    /
    pub signer_payload: CawgSignerPayload,
    /
    #[serde(with = "serde_bytes_vec", default)]
    pub pad1: Vec<u8>,
    /
    #[serde(with = "serde_bytes_vec", default)]
    pub signature: Vec<u8>,
    /
    #[serde(with = "serde_bytes_vec", default)]
    pub pad2: Vec<u8>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgSignerPayload {
    /
    pub sig_type: String,
    /
    pub credential: CawgCredential,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CawgCredential {
    /
    /
    #[serde(rename = "ica")]
    Ica {
        /
        provider: String,
        /
        claims: Vec<CawgIdentityClaim>,
    },
    /
    #[serde(rename = "verifiable_credential")]
    VerifiableCredential {
        /
        vc: serde_json::Value,
    },
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgIdentityClaim {
    /
    pub claim_type: String,
    /
    pub value: String,
}

/
/
/
/
pub fn to_cawg_identity(ear: &EarToken, author_did: &str) -> Result<CawgIdentityAssertion> {
    let appr = ear
        .pop_appraisal()
        .ok_or_else(|| Error::evidence("EAR token missing 'pop' submodule"))?;

    let mut claims = vec![
        CawgIdentityClaim {
            claim_type: "did".to_string(),
            value: author_did.to_string(),
        },
        CawgIdentityClaim {
            claim_type: "attestation_status".to_string(),
            value: appr.ear_status.as_str().to_string(),
        },
    ];

    if let Some(chain_len) = appr.pop_chain_length {
        claims.push(CawgIdentityClaim {
            claim_type: "chain_length".to_string(),
            value: chain_len.to_string(),
        });
    }

    if let Some(chain_dur) = appr.pop_chain_duration {
        claims.push(CawgIdentityClaim {
            claim_type: "chain_duration_secs".to_string(),
            value: chain_dur.to_string(),
        });
    }

    Ok(CawgIdentityAssertion {
        signer_payload: CawgSignerPayload {
            sig_type: IDENTITY_LABEL.to_string(),
            credential: CawgCredential::Ica {
                provider: WRITERSPROOF_ICA_PROVIDER.to_string(),
                claims,
            },
        },
        pad1: Vec::new(),
        signature: Vec::new(),
        pad2: Vec::new(),
    })
}





/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgTdmAssertion {
    /
    pub label: String,
    /
    pub entries: Vec<CawgTdmEntry>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CawgTdmEntry {
    /
    /
    pub use_type: String,
    /
    pub permission: String,
    /
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint_info: Option<String>,
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
pub fn to_cawg_tdm(decl: &Declaration) -> CawgTdmAssertion {
    let max_extent = decl.max_ai_extent();
    let is_primarily_human = matches!(max_extent, AiExtent::None | AiExtent::Minimal);

    let entries = if is_primarily_human {
        vec![
            CawgTdmEntry {
                use_type: "cawg.data_mining".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_inference".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_generative_training".to_string(),
                permission: "notAllowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_training".to_string(),
                permission: "constrained".to_string(),
                constraint_info: Some(
                    "Human-authored content; generative training requires explicit license."
                        .to_string(),
                ),
            },
        ]
    } else {
        vec![
            CawgTdmEntry {
                use_type: "cawg.data_mining".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_inference".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_generative_training".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
            CawgTdmEntry {
                use_type: "cawg.ai_training".to_string(),
                permission: "allowed".to_string(),
                constraint_info: None,
            },
        ]
    };

    CawgTdmAssertion {
        label: TDM_LABEL.to_string(),
        entries,
    }
}

/
mod serde_bytes_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        bytes.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        Vec::<u8>::deserialize(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declaration::{
        AiExtent, AiPurpose, AiToolUsage, Declaration, InputModality, ModalityType,
    };
    use crate::war::ear::{Ar4siStatus, EarAppraisal, EarToken, VerifierId};
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn make_decl(ai_tools: Vec<AiToolUsage>) -> Declaration {
        Declaration {
            document_hash: [1u8; 32],
            chain_hash: [2u8; 32],
            title: "Test".to_string(),
            input_modalities: vec![InputModality {
                modality_type: ModalityType::Keyboard,
                percentage: 100.0,
                note: None,
            }],
            ai_tools,
            collaborators: Vec::new(),
            statement: "I wrote this.".to_string(),
            created_at: Utc::now(),
            version: 1,
            author_public_key: Vec::new(),
            signature: Vec::new(),
            jitter_sealed: None,
        }
    }

    fn make_ai_tool(extent: AiExtent) -> AiToolUsage {
        AiToolUsage {
            tool: "TestTool".to_string(),
            version: None,
            purpose: AiPurpose::Drafting,
            interaction: None,
            extent,
            sections: Vec::new(),
        }
    }

    fn make_ear() -> EarToken {
        let mut submods = BTreeMap::new();
        submods.insert(
            "pop".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Affirming,
                ear_trustworthiness_vector: None,
                ear_appraisal_policy_id: None,
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: Some(5),
                pop_chain_duration: Some(3600),
                pop_absence_claims: None,
                pop_warnings: None,
                pop_process_start: None,
                pop_process_end: None,
            },
        );
        EarToken {
            eat_profile: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
            iat: Utc::now().timestamp(),
            ear_verifier_id: VerifierId::default(),
            submods,
        }
    }

    

    #[test]
    fn test_cawg_identity_has_did_claim() {
        let ear = make_ear();
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");
        assert_eq!(assertion.signer_payload.sig_type, IDENTITY_LABEL);

        if let CawgCredential::Ica { provider, claims } = &assertion.signer_payload.credential {
            assert_eq!(provider, WRITERSPROOF_ICA_PROVIDER);
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "did" && c.value == "did:key:z6MkTest"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_has_attestation_status() {
        let ear = make_ear();
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");

        if let CawgCredential::Ica { claims, .. } = &assertion.signer_payload.credential {
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "attestation_status" && c.value == "affirming"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_includes_chain_metadata() {
        let ear = make_ear();
        let assertion = to_cawg_identity(&ear, "did:key:z6MkTest").expect("identity assertion");

        if let CawgCredential::Ica { claims, .. } = &assertion.signer_payload.credential {
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "chain_length" && c.value == "5"));
            assert!(claims
                .iter()
                .any(|c| c.claim_type == "chain_duration_secs" && c.value == "3600"));
        } else {
            panic!("expected ICA credential");
        }
    }

    #[test]
    fn test_cawg_identity_missing_pop_submod() {
        let ear = EarToken {
            eat_profile: "urn:ietf:params:rats:eat:profile:pop:1.0".to_string(),
            iat: Utc::now().timestamp(),
            ear_verifier_id: VerifierId::default(),
            submods: BTreeMap::new(),
        };
        let result = to_cawg_identity(&ear, "did:key:z6MkTest");
        assert!(result.is_err());
    }

    #[test]
    fn test_cawg_identity_assertion_structure() {
        let ear = make_ear();
        let assertion =
            to_cawg_identity(&ear, "did:key:z6MkStructure").expect("identity assertion");
        
        assert_eq!(assertion.signer_payload.sig_type, "cawg.identity");
        
        match &assertion.signer_payload.credential {
            CawgCredential::Ica { provider, claims } => {
                assert_eq!(provider, "https:
                
                let claim_types: Vec<&str> = claims.iter().map(|c| c.claim_type.as_str()).collect();
                assert!(claim_types.contains(&"did"));
                assert!(claim_types.contains(&"attestation_status"));
            }
            _ => panic!("expected ICA credential type"),
        }
        
        assert!(assertion.pad1.is_empty());
        assert!(assertion.pad2.is_empty());
    }

    #[test]
    fn test_cawg_tdm_human_authored_notallowed() {
        let decl = make_decl(Vec::new());
        let tdm = to_cawg_tdm(&decl);
        
        let gen = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("missing generative training entry");
        assert_eq!(gen.permission, "notAllowed");
    }

    #[test]
    fn test_cawg_tdm_ai_generated_allowed() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let tdm = to_cawg_tdm(&decl);
        
        for entry in &tdm.entries {
            assert_eq!(
                entry.permission, "allowed",
                "{} should be allowed for AI content",
                entry.use_type
            );
        }
    }

    

    #[test]
    fn test_cawg_tdm_human_authored() {
        let decl = make_decl(Vec::new());
        let tdm = to_cawg_tdm(&decl);
        assert_eq!(tdm.label, TDM_LABEL);
        assert_eq!(tdm.entries.len(), 4);

        
        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(gen_training.permission, "notAllowed");

        
        let training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_training")
            .expect("training entry");
        assert_eq!(training.permission, "constrained");
        assert!(training.constraint_info.is_some());
    }

    #[test]
    fn test_cawg_tdm_ai_generated() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Substantial)]);
        let tdm = to_cawg_tdm(&decl);

        
        for entry in &tdm.entries {
            assert_eq!(
                entry.permission, "allowed",
                "AI-generated content should allow all TDM use types, but {} was {}",
                entry.use_type, entry.permission
            );
        }
    }

    #[test]
    fn test_cawg_tdm_minimal_ai_is_protective() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Minimal)]);
        let tdm = to_cawg_tdm(&decl);

        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(
            gen_training.permission, "notAllowed",
            "minimal AI assistance should still protect against generative training"
        );
    }

    #[test]
    fn test_cawg_tdm_moderate_ai_allows_training() {
        let decl = make_decl(vec![make_ai_tool(AiExtent::Moderate)]);
        let tdm = to_cawg_tdm(&decl);

        let gen_training = tdm
            .entries
            .iter()
            .find(|e| e.use_type == "cawg.ai_generative_training")
            .expect("generative training entry");
        assert_eq!(
            gen_training.permission, "allowed",
            "moderate AI content should allow generative training"
        );
    }
}
