

//! Multi-standard compliance metadata for CPOP evidence packets.
//!
//! Generates structured compliance annotations mapping CPOP evidence
//! to external standard identifiers and vocabularies without altering
//! the evidence itself. This module is additive — it reads evidence
//! and produces cross-references, never modifying source data.
//!
//! Standards covered:
//! - IETF RATS (draft-ietf-rats-eat, draft-ietf-rats-ear, draft-ietf-rats-ar4si)
//! - W3C DID Core 1.0 / Verifiable Credentials Data Model 2.0
//! - C2PA (ISO 19566-5, content credentials)
//! - NIST AI RMF 1.0 (AI 100-1) / NIST AI 100-4 (synthetic content)
//! - ISO/IEC 42001 (AI management systems)
//! - IPTC Digital Source Type vocabulary
//! - W3C AI Content Disclosure (proposed)
//! - WGA MBA / SAG-AFTRA AI provisions (creative rights)

use serde::{Deserialize, Serialize};

use crate::declaration::{AiExtent, Declaration};
use crate::war::ear::{Ar4siStatus, EarToken};





/
pub const IPTC_HUMAN_CREATION: &str =
    "http:

/
pub const IPTC_COMPOSITE_WITH_TRAINED_MODEL: &str =
    "http:

/
pub const IPTC_TRAINED_ALGORITHMIC_MEDIA: &str =
    "http:





/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AiDisclosureLevel {
    /
    #[serde(rename = "none")]
    None,
    /
    #[serde(rename = "ai-assisted")]
    AiAssisted,
    /
    #[serde(rename = "ai-generated")]
    AiGenerated,
}

impl AiDisclosureLevel {
    /
    pub fn from_ai_extent(extent: AiExtent) -> Self {
        match extent {
            AiExtent::None => Self::None,
            AiExtent::Minimal | AiExtent::Moderate => Self::AiAssisted,
            AiExtent::Substantial => Self::AiGenerated,
        }
    }

    /
    pub fn to_iptc_digital_source_type(&self) -> &'static str {
        match self {
            Self::None => IPTC_HUMAN_CREATION,
            Self::AiAssisted => IPTC_COMPOSITE_WITH_TRAINED_MODEL,
            Self::AiGenerated => IPTC_TRAINED_ALGORITHMIC_MEDIA,
        }
    }

    /
    pub fn to_html_meta_tag(&self) -> String {
        let value = match self {
            Self::None => "none",
            Self::AiAssisted => "ai-assisted",
            Self::AiGenerated => "ai-generated",
        };
        format!(r#"<meta name="ai-disclosure" content="{}">"#, value)
    }
}





/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistRmfMapping {
    /
    pub subcategories: Vec<NistSubcategory>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NistSubcategory {
    /
    pub id: String,
    /
    pub description: String,
    /
    pub cpop_coverage: String,
}

/
pub fn nist_rmf_mapping() -> NistRmfMapping {
    NistRmfMapping {
        subcategories: vec![
            NistSubcategory {
                id: "GV-1.1".into(),
                description: "Legal and regulatory requirements documented".into(),
                cpop_coverage: "Evidence packets carry declaration with AI disclosure fields per EU AI Act Article 50".into(),
            },
            NistSubcategory {
                id: "GV-1.2".into(),
                description: "Trustworthiness characteristics integrated".into(),
                cpop_coverage: "AR4SI trustworthiness vector maps 8 components per draft-ietf-rats-ar4si".into(),
            },
            NistSubcategory {
                id: "MS-2.6".into(),
                description: "AI system performance assessed".into(),
                cpop_coverage: "Forensic analysis produces assessment_score with 5 verdict levels".into(),
            },
            NistSubcategory {
                id: "MS-2.11".into(),
                description: "Fairness assessed and documented".into(),
                cpop_coverage: "Behavioral analysis uses biological plausibility ranges, not demographic profiling".into(),
            },
            NistSubcategory {
                id: "MG-4.1".into(),
                description: "Post-deployment monitoring procedures".into(),
                cpop_coverage: "Continuous sentinel monitoring with checkpoint chain for lifecycle tracking".into(),
            },
        ],
    }
}





/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso42001Mapping {
    pub controls: Vec<Iso42001Control>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso42001Control {
    pub id: String,
    pub topic: String,
    pub cpop_coverage: String,
}

/
pub fn iso_42001_mapping() -> Iso42001Mapping {
    Iso42001Mapping {
        controls: vec![
            Iso42001Control {
                id: "A.6".into(),
                topic: "Data governance".into(),
                cpop_coverage: "Evidence data integrity via HMAC chains, WAL, and MMR append-only proofs".into(),
            },
            Iso42001Control {
                id: "A.7".into(),
                topic: "System information documentation".into(),
                cpop_coverage: "Evidence packets include claim_generator_info with version, capabilities, limitations".into(),
            },
            Iso42001Control {
                id: "A.8".into(),
                topic: "Information for interested parties (transparency)".into(),
                cpop_coverage: "Forensic verdict with confidence, anomaly counts, per-checkpoint flags, and limitations array".into(),
            },
            Iso42001Control {
                id: "A.10".into(),
                topic: "Accountability and responsibility".into(),
                cpop_coverage: "Key hierarchy with master→session→ratchet chain ties actions to signing identity".into(),
            },
        ],
    }
}





/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreativeRightsCompliance {
    /
    pub human_authored: bool,
    /
    pub gai_source_disclosed: bool,
    /
    pub ai_disclosure: AiDisclosureLevel,
    /
    pub digital_source_type: String,
    /
    pub wga_mba_compliant: bool,
    /
    pub notes: Vec<String>,
}

/
pub fn creative_rights_compliance(
    declaration: Option<&Declaration>,
    ear: Option<&EarToken>,
) -> CreativeRightsCompliance {
    let mut notes = Vec::new();

    let (ai_disclosure, gai_source_disclosed) = if let Some(decl) = declaration {
        let max_extent = decl.max_ai_extent();
        
        let no_ai = matches!(max_extent, AiExtent::None);
        let disclosure = AiDisclosureLevel::from_ai_extent(max_extent);

        
        let gai_disclosed = !decl.ai_tools.is_empty() || no_ai;

        if !gai_disclosed {
            notes.push(
                "WGA MBA Section 72: AI tool usage should be disclosed in declaration".into(),
            );
        }

        (disclosure, gai_disclosed)
    } else {
        notes.push("No declaration present — cannot verify AI disclosure".into());
        (AiDisclosureLevel::None, false)
    };

    
    let human_authored = if let Some(ear) = ear {
        if let Some(appr) = ear.pop_appraisal() {
            matches!(
                appr.ear_status,
                Ar4siStatus::Affirming | Ar4siStatus::Warning
            )
        } else {
            false
        }
    } else {
        false
    };

    if !human_authored {
        notes.push(
            "EAR appraisal does not affirm human authorship — WGA compliance uncertain".into(),
        );
    }

    let wga_mba_compliant =
        human_authored && gai_source_disclosed && ai_disclosure != AiDisclosureLevel::AiGenerated;

    CreativeRightsCompliance {
        human_authored,
        gai_source_disclosed,
        ai_disclosure,
        digital_source_type: ai_disclosure.to_iptc_digital_source_type().to_string(),
        wga_mba_compliant,
        notes,
    }
}





/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardsComplianceReport {
    /
    pub rats: RatsAlignment,
    /
    pub did_method: Option<String>,
    /
    pub ai_disclosure: AiDisclosureLevel,
    /
    pub iptc_digital_source_type: String,
    /
    pub c2pa_assertion_label: String,
    /
    pub creative_rights: CreativeRightsCompliance,
    /
    pub nist_rmf: NistRmfMapping,
    /
    pub iso_42001: Iso42001Mapping,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatsAlignment {
    /
    pub eat_profile: String,
    /
    pub ear_status: String,
    /
    pub has_trust_vector: bool,
    /
    pub ear_compliant: bool,
}

/
pub fn standards_compliance_report(
    declaration: Option<&Declaration>,
    ear: Option<&EarToken>,
    author_did: Option<&str>,
) -> StandardsComplianceReport {
    let rats = if let Some(ear) = ear {
        RatsAlignment {
            eat_profile: ear.eat_profile.clone(),
            ear_status: ear
                .pop_appraisal()
                .map(|a| a.ear_status.as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            has_trust_vector: ear
                .pop_appraisal()
                .and_then(|a| a.ear_trustworthiness_vector.as_ref())
                .is_some(),
            ear_compliant: true,
        }
    } else {
        RatsAlignment {
            eat_profile: String::new(),
            ear_status: "none".into(),
            has_trust_vector: false,
            ear_compliant: false,
        }
    };

    let ai_disclosure = declaration
        .map(|d| AiDisclosureLevel::from_ai_extent(d.max_ai_extent()))
        .unwrap_or(AiDisclosureLevel::None);

    let creative_rights = creative_rights_compliance(declaration, ear);

    StandardsComplianceReport {
        rats,
        
        did_method: author_did.map(|d| {
            let parts: Vec<&str> = d.splitn(3, ':').collect();
            if parts.len() >= 2 {
                format!("{}:{}", parts[0], parts[1])
            } else {
                d.to_string()
            }
        }),
        ai_disclosure,
        iptc_digital_source_type: ai_disclosure.to_iptc_digital_source_type().to_string(),
        c2pa_assertion_label: super::c2pa::ASSERTION_LABEL.to_string(),
        creative_rights,
        nist_rmf: nist_rmf_mapping(),
        iso_42001: iso_42001_mapping(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_disclosure_none() {
        let level = AiDisclosureLevel::from_ai_extent(AiExtent::None);
        assert_eq!(level, AiDisclosureLevel::None);
        assert_eq!(level.to_iptc_digital_source_type(), IPTC_HUMAN_CREATION);
    }

    #[test]
    fn test_ai_disclosure_minimal() {
        let level = AiDisclosureLevel::from_ai_extent(AiExtent::Minimal);
        assert_eq!(level, AiDisclosureLevel::AiAssisted);
        assert_eq!(
            level.to_iptc_digital_source_type(),
            IPTC_COMPOSITE_WITH_TRAINED_MODEL
        );
    }

    #[test]
    fn test_ai_disclosure_substantial() {
        let level = AiDisclosureLevel::from_ai_extent(AiExtent::Substantial);
        assert_eq!(level, AiDisclosureLevel::AiGenerated);
        assert_eq!(
            level.to_iptc_digital_source_type(),
            IPTC_TRAINED_ALGORITHMIC_MEDIA
        );
    }

    #[test]
    fn test_html_meta_tag() {
        assert_eq!(
            AiDisclosureLevel::None.to_html_meta_tag(),
            r#"<meta name="ai-disclosure" content="none">"#
        );
        assert_eq!(
            AiDisclosureLevel::AiAssisted.to_html_meta_tag(),
            r#"<meta name="ai-disclosure" content="ai-assisted">"#
        );
    }

    #[test]
    fn test_nist_rmf_mapping_has_entries() {
        let mapping = nist_rmf_mapping();
        assert!(!mapping.subcategories.is_empty());
        assert!(mapping.subcategories.iter().any(|s| s.id == "GV-1.2"));
    }

    #[test]
    fn test_iso_42001_mapping_has_a8() {
        let mapping = iso_42001_mapping();
        assert!(mapping.controls.iter().any(|c| c.id == "A.8"));
    }

    #[test]
    fn test_creative_rights_no_declaration() {
        let result = creative_rights_compliance(None, None);
        assert!(!result.human_authored);
        assert!(!result.wga_mba_compliant);
        assert!(!result.notes.is_empty());
    }
}
