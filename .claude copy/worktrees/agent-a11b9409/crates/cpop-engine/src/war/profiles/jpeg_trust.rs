

//! JPEG Trust (ISO/IEC 21617) profile types.
//!
//! JPEG Trust defines Trust Profiles and Trust Reports for media
//! trustworthiness assessment. CPOP's WAR block maps to a JPEG Trust
//! Report, providing process-level evidence as a trust indicator.

use serde::{Deserialize, Serialize};

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JpegTrustProfile {
    /
    pub profile_id: String,
    /
    pub profile_name: String,
    /
    pub trust_indicators: Vec<TrustIndicator>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustIndicator {
    /
    pub indicator_type: String,
    /
    pub source: String,
    /
    pub confidence: f64,
    /
    pub description: String,
}

/
/
/
/
/
pub fn cpop_trust_profile() -> JpegTrustProfile {
    JpegTrustProfile {
        profile_id: "cpop-pop-attestation-v1".into(),
        profile_name: "CPOP Proof-of-Process Attestation".into(),
        trust_indicators: vec![
            TrustIndicator {
                indicator_type: "process_evidence".into(),
                source: "cpop_attestation".into(),
                confidence: 0.9,
                description: "Behavioral keystroke and timing evidence captured \
                              during authoring session"
                    .into(),
            },
            TrustIndicator {
                indicator_type: "identity_binding".into(),
                source: "cpop_attestation".into(),
                confidence: 0.85,
                description: "Author identity bound via Ed25519 key hierarchy \
                              with optional hardware attestation"
                    .into(),
            },
            TrustIndicator {
                indicator_type: "temporal_proof".into(),
                source: "cpop_attestation".into(),
                confidence: 0.95,
                description: "VDF-based verifiable delay proofs and checkpoint \
                              chain with Roughtime anchoring"
                    .into(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpop_trust_profile_has_three_indicators() {
        let profile = cpop_trust_profile();
        assert_eq!(profile.trust_indicators.len(), 3);
        assert_eq!(profile.profile_id, "cpop-pop-attestation-v1");
    }

    #[test]
    fn test_trust_indicator_types() {
        let profile = cpop_trust_profile();
        let types: Vec<&str> = profile
            .trust_indicators
            .iter()
            .map(|i| i.indicator_type.as_str())
            .collect();
        assert!(types.contains(&"process_evidence"));
        assert!(types.contains(&"identity_binding"));
        assert!(types.contains(&"temporal_proof"));
    }

    #[test]
    fn test_confidence_bounds() {
        let profile = cpop_trust_profile();
        for indicator in &profile.trust_indicators {
            assert!(
                (0.0..=1.0).contains(&indicator.confidence),
                "confidence {} out of range for {}",
                indicator.confidence,
                indicator.indicator_type
            );
        }
    }

    #[test]
    fn test_jpeg_trust_profile_indicators_present() {
        let profile = cpop_trust_profile();
        
        let types: Vec<&str> = profile
            .trust_indicators
            .iter()
            .map(|i| i.indicator_type.as_str())
            .collect();
        assert!(
            types.contains(&"process_evidence"),
            "missing process_evidence"
        );
        assert!(
            types.contains(&"identity_binding"),
            "missing identity_binding"
        );
        assert!(types.contains(&"temporal_proof"), "missing temporal_proof");

        
        for indicator in &profile.trust_indicators {
            assert!(!indicator.description.is_empty());
            assert_eq!(indicator.source, "cpop_attestation");
        }
    }

    #[test]
    fn test_profile_serialization_roundtrip() {
        let profile = cpop_trust_profile();
        let json = serde_json::to_string(&profile).expect("serialize");
        let decoded: JpegTrustProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.profile_id, profile.profile_id);
        assert_eq!(
            decoded.trust_indicators.len(),
            profile.trust_indicators.len()
        );
    }
}
