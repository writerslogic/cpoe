

//! EAR (Entity Attestation Result) types per draft-ietf-rats-ear.
//!
//! Maps WritersLogic's proof-of-process appraisal onto standard RATS EAR
//! structures with AR4SI trust vectors. Private-use keys 70001-70009
//! carry WritersLogic-specific claims.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::rfc::wire_types::attestation::{
    AbsenceClaim, EntropyReport, ForensicSummary, ForgeryCostEstimate,
};

/
pub const POP_EAR_PROFILE: &str = "urn:ietf:params:rats:eat:profile:pop:1.0";

pub const CWT_KEY_IAT: i64 = 6;
pub const CWT_KEY_EAT_PROFILE: i64 = 265;
pub const CWT_KEY_SUBMODS: i64 = 266;
pub const EAR_KEY_STATUS: i64 = 1000;
pub const EAR_KEY_TRUST_VECTOR: i64 = 1001;
pub const EAR_KEY_POLICY_ID: i64 = 1003;
pub const EAR_KEY_VERIFIER_ID: i64 = 1004;

pub const POP_KEY_SEAL: i64 = 70001;
pub const POP_KEY_EVIDENCE_REF: i64 = 70002;
pub const POP_KEY_ENTROPY: i64 = 70003;
pub const POP_KEY_FORGERY_COST: i64 = 70004;
pub const POP_KEY_FORENSIC: i64 = 70005;
pub const POP_KEY_CHAIN_LENGTH: i64 = 70006;
pub const POP_KEY_CHAIN_DURATION: i64 = 70007;
pub const POP_KEY_ABSENCE: i64 = 70008;
pub const POP_KEY_WARNINGS: i64 = 70009;

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i8)]
pub enum Ar4siStatus {
    /
    None = 0,
    /
    Affirming = 2,
    /
    Warning = 32,
    /
    Contraindicated = 96,
}

impl Ar4siStatus {
    /
    /
    /
    pub fn from_i8(v: i8) -> Self {
        match v {
            0 => Self::None,
            2 => Self::Affirming,
            32 => Self::Warning,
            96 => Self::Contraindicated,
            _ => Self::Contraindicated,
        }
    }

    /
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Affirming => "affirming",
            Self::Warning => "warning",
            Self::Contraindicated => "contraindicated",
        }
    }
}

/
/
/
/
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustworthinessVector {
    /
    #[serde(rename = "0")]
    pub instance_identity: i8,
    /
    #[serde(rename = "1")]
    pub configuration: i8,
    /
    #[serde(rename = "2")]
    pub executables: i8,
    /
    #[serde(rename = "3")]
    pub file_system: i8,
    /
    #[serde(rename = "4")]
    pub hardware: i8,
    /
    #[serde(rename = "5")]
    pub runtime_opaque: i8,
    /
    #[serde(rename = "6")]
    pub storage_opaque: i8,
    /
    #[serde(rename = "7")]
    pub sourced_data: i8,
}

impl TrustworthinessVector {
    /
    /
    /
    /
    /
    pub fn max_component(&self) -> i8 {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
        .into_iter()
        .max()
        .unwrap_or(0)
    }

    /
    /
    /
    /
    /
    pub fn overall_status(&self) -> Ar4siStatus {
        [
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        ]
        .into_iter()
        .map(Ar4siStatus::from_i8)
        .max_by_key(|s| *s as i8)
        .unwrap_or(Ar4siStatus::None)
    }

    /
    pub fn header_string(&self) -> String {
        format!(
            "II={} CO={} EX={} FS={} HW={} RO={} SO={} SD={}",
            self.instance_identity,
            self.configuration,
            self.executables,
            self.file_system,
            self.hardware,
            self.runtime_opaque,
            self.storage_opaque,
            self.sourced_data,
        )
    }

    /
    pub fn parse_header(s: &str) -> Option<Self> {
        let mut vals = [0i8; 8];
        let labels = ["II=", "CO=", "EX=", "FS=", "HW=", "RO=", "SO=", "SD="];
        for (i, label) in labels.iter().enumerate() {
            let part = s.split_whitespace().find(|p| p.starts_with(label))?;
            vals[i] = part[label.len()..].parse().ok()?;
        }
        Some(Self {
            instance_identity: vals[0],
            configuration: vals[1],
            executables: vals[2],
            file_system: vals[3],
            hardware: vals[4],
            runtime_opaque: vals[5],
            storage_opaque: vals[6],
            sourced_data: vals[7],
        })
    }
}

/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierId {
    /
    pub build: String,
    /
    pub developer: String,
}

impl Default for VerifierId {
    fn default() -> Self {
        Self {
            build: format!("cpop-engine/{}", env!("CARGO_PKG_VERSION")),
            developer: "writerslogic".to_string(),
        }
    }
}

/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealClaims {
    /
    #[serde(with = "hex_bytes_32")]
    pub h1: [u8; 32],
    /
    #[serde(with = "hex_bytes_32")]
    pub h2: [u8; 32],
    /
    #[serde(with = "hex_bytes_32")]
    pub h3: [u8; 32],
    /
    #[serde(with = "hex_bytes_64")]
    pub signature: [u8; 64],
    /
    #[serde(with = "hex_bytes_32")]
    pub public_key: [u8; 32],
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarAppraisal {
    /
    #[serde(rename = "1000")]
    pub ear_status: Ar4siStatus,

    /
    #[serde(rename = "1001", default, skip_serializing_if = "Option::is_none")]
    pub ear_trustworthiness_vector: Option<TrustworthinessVector>,

    /
    #[serde(rename = "1003", default, skip_serializing_if = "Option::is_none")]
    pub ear_appraisal_policy_id: Option<String>,

    /
    #[serde(rename = "70001", default, skip_serializing_if = "Option::is_none")]
    pub pop_seal: Option<SealClaims>,

    /
    #[serde(rename = "70002", default, skip_serializing_if = "Option::is_none")]
    pub pop_evidence_ref: Option<Vec<u8>>,

    /
    #[serde(rename = "70003", default, skip_serializing_if = "Option::is_none")]
    pub pop_entropy_report: Option<EntropyReport>,

    /
    #[serde(rename = "70004", default, skip_serializing_if = "Option::is_none")]
    pub pop_forgery_cost: Option<ForgeryCostEstimate>,

    /
    #[serde(rename = "70005", default, skip_serializing_if = "Option::is_none")]
    pub pop_forensic_summary: Option<ForensicSummary>,

    /
    #[serde(rename = "70006", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_length: Option<u64>,

    /
    #[serde(rename = "70007", default, skip_serializing_if = "Option::is_none")]
    pub pop_chain_duration: Option<u64>,

    /
    #[serde(rename = "70008", default, skip_serializing_if = "Option::is_none")]
    pub pop_absence_claims: Option<Vec<AbsenceClaim>>,

    /
    #[serde(rename = "70009", default, skip_serializing_if = "Option::is_none")]
    pub pop_warnings: Option<Vec<String>>,
}

/
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EarToken {
    /
    #[serde(rename = "265")]
    pub eat_profile: String,

    /
    #[serde(rename = "6")]
    pub iat: i64,

    /
    #[serde(rename = "1004")]
    pub ear_verifier_id: VerifierId,

    /
    #[serde(rename = "266")]
    pub submods: BTreeMap<String, EarAppraisal>,
}

impl EarToken {
    /
    /
    /
    /
    pub fn overall_status(&self) -> Ar4siStatus {
        self.submods
            .values()
            .map(|a| a.ear_status as i8)
            .max()
            .map(Ar4siStatus::from_i8)
            .unwrap_or(Ar4siStatus::None)
    }

    pub fn pop_appraisal(&self) -> Option<&EarAppraisal> {
        self.submods.get("pop")
    }
}

mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

mod hex_bytes_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ar4si_from_i8_known_values() {
        assert_eq!(Ar4siStatus::from_i8(0), Ar4siStatus::None);
        assert_eq!(Ar4siStatus::from_i8(2), Ar4siStatus::Affirming);
        assert_eq!(Ar4siStatus::from_i8(32), Ar4siStatus::Warning);
        assert_eq!(Ar4siStatus::from_i8(96), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_ar4si_from_i8_unknown_values_fail_closed() {
        assert_eq!(Ar4siStatus::from_i8(1), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(-1), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(127), Ar4siStatus::Contraindicated);
        assert_eq!(Ar4siStatus::from_i8(50), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_overall_status_worst_wins() {
        let mut tv = TrustworthinessVector::default();
        assert_eq!(tv.overall_status(), Ar4siStatus::None);

        tv.hardware = Ar4siStatus::Affirming as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Affirming);

        tv.sourced_data = Ar4siStatus::Warning as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Warning);

        tv.file_system = Ar4siStatus::Contraindicated as i8;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_contraindicated_not_masked_by_none() {
        let mut tv = TrustworthinessVector::default();
        tv.hardware = Ar4siStatus::Contraindicated as i8;
        
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_nonstandard_component_values_treated_as_contraindicated() {
        let mut tv = TrustworthinessVector::default();
        
        tv.hardware = 10;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);

        
        tv = TrustworthinessVector::default();
        tv.sourced_data = -5;
        assert_eq!(tv.overall_status(), Ar4siStatus::Contraindicated);
    }

    #[test]
    fn test_ear_token_overall_status_worst_submod() {
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
                pop_chain_length: None,
                pop_chain_duration: None,
                pop_absence_claims: None,
                pop_warnings: None,
            },
        );
        submods.insert(
            "other".to_string(),
            EarAppraisal {
                ear_status: Ar4siStatus::Warning,
                ear_trustworthiness_vector: None,
                ear_appraisal_policy_id: None,
                pop_seal: None,
                pop_evidence_ref: None,
                pop_entropy_report: None,
                pop_forgery_cost: None,
                pop_forensic_summary: None,
                pop_chain_length: None,
                pop_chain_duration: None,
                pop_absence_claims: None,
                pop_warnings: None,
            },
        );

        let token = EarToken {
            eat_profile: POP_EAR_PROFILE.to_string(),
            iat: 0,
            ear_verifier_id: VerifierId::default(),
            submods,
        };

        assert_eq!(token.overall_status(), Ar4siStatus::Warning);
    }

    #[test]
    fn test_max_component() {
        let tv = TrustworthinessVector {
            instance_identity: 0,
            configuration: 2,
            executables: 0,
            file_system: 96,
            hardware: 32,
            runtime_opaque: 0,
            storage_opaque: 2,
            sourced_data: 0,
        };
        assert_eq!(tv.max_component(), 96);
    }

    #[test]
    fn test_header_roundtrip() {
        let tv = TrustworthinessVector {
            instance_identity: 2,
            configuration: 2,
            executables: 0,
            file_system: 2,
            hardware: 32,
            runtime_opaque: 2,
            storage_opaque: 2,
            sourced_data: 96,
        };
        let header = tv.header_string();
        let parsed = TrustworthinessVector::parse_header(&header).unwrap();
        assert_eq!(tv, parsed);
    }
}
