

//! CDDL-defined enumerations for draft-condrey-rats-pop wire format.

use std::fmt;

use serde::{Deserialize, Serialize};

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashAlgorithm {
    /
    Sha256 = 1,
    /
    Sha384 = 2,
    /
    Sha512 = 3,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationTier {
    /
    SoftwareOnly = 1,
    /
    AttestedSoftware = 2,
    /
    HardwareBound = 3,
    /
    HardwareHardened = 4,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentTier {
    /
    Core = 1,
    /
    Enhanced = 2,
    /
    Maximum = 3,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofAlgorithm {
    /
    SwfSha256 = 10,
    /
    SwfArgon2id = 20,
    /
    SwfArgon2idEntangled = 21,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Verdict {
    /
    Authentic = 1,
    /
    Inconclusive = 2,
    /
    Suspicious = 3,
    /
    Invalid = 4,
}

/
/
/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FeatureId {
    /
    SwfArgon2idSha256 = 1,
    /
    ContentBinding = 2,
    /
    CheckpointChain = 4,
    /
    BehavioralEntropy = 50,
    /
    AssistiveMode = 60,
    /
    EditGraphHash = 51,
    /
    EditGraphHistograms = 52,
    /
    HardwareAttestation = 105,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    /
    Unsalted = 0,
    /
    AuthorSalted = 1,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    /
    Usd = 1,
    /
    CpuHours = 2,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AbsenceType {
    /
    ComputationallyBound = 1,
    /
    MonitoringDependent = 2,
    /
    Environmental = 3,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProbeType {
    /
    GaltonBoard = 1,
    /
    ReflexGate = 2,
    /
    SpatialTarget = 3,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    /
    TlsExporter = 1,
}

/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfidenceTier {
    /
    PopulationReference = 1,
    /
    Emerging = 2,
    /
    Established = 3,
    /
    Mature = 4,
}



impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("SHA-256"),
            Self::Sha384 => f.write_str("SHA-384"),
            Self::Sha512 => f.write_str("SHA-512"),
        }
    }
}

impl fmt::Display for AttestationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SoftwareOnly => f.write_str("software-only"),
            Self::AttestedSoftware => f.write_str("attested-software"),
            Self::HardwareBound => f.write_str("hardware-bound"),
            Self::HardwareHardened => f.write_str("hardware-hardened"),
        }
    }
}

impl fmt::Display for ContentTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Core => f.write_str("core"),
            Self::Enhanced => f.write_str("enhanced"),
            Self::Maximum => f.write_str("maximum"),
        }
    }
}

impl fmt::Display for ProofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SwfSha256 => f.write_str("swf-sha256"),
            Self::SwfArgon2id => f.write_str("swf-argon2id"),
            Self::SwfArgon2idEntangled => f.write_str("swf-argon2id-entangled"),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authentic => f.write_str("authentic"),
            Self::Inconclusive => f.write_str("inconclusive"),
            Self::Suspicious => f.write_str("suspicious"),
            Self::Invalid => f.write_str("invalid"),
        }
    }
}

impl fmt::Display for FeatureId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SwfArgon2idSha256 => f.write_str("swf-argon2id-sha256"),
            Self::ContentBinding => f.write_str("content-binding"),
            Self::CheckpointChain => f.write_str("checkpoint-chain"),
            Self::BehavioralEntropy => f.write_str("behavioral-entropy"),
            Self::AssistiveMode => f.write_str("assistive-mode"),
            Self::EditGraphHash => f.write_str("edit-graph-hash"),
            Self::EditGraphHistograms => f.write_str("edit-graph-histograms"),
            Self::HardwareAttestation => f.write_str("hardware-attestation"),
        }
    }
}

impl fmt::Display for HashSaltMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsalted => f.write_str("unsalted"),
            Self::AuthorSalted => f.write_str("author-salted"),
        }
    }
}

impl fmt::Display for CostUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usd => f.write_str("USD"),
            Self::CpuHours => f.write_str("CPU-hours"),
        }
    }
}

impl fmt::Display for AbsenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComputationallyBound => f.write_str("computationally-bound"),
            Self::MonitoringDependent => f.write_str("monitoring-dependent"),
            Self::Environmental => f.write_str("environmental"),
        }
    }
}

impl fmt::Display for ProbeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GaltonBoard => f.write_str("galton-board"),
            Self::ReflexGate => f.write_str("reflex-gate"),
            Self::SpatialTarget => f.write_str("spatial-target"),
        }
    }
}

impl fmt::Display for BindingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TlsExporter => f.write_str("tls-exporter"),
        }
    }
}

impl fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PopulationReference => f.write_str("population-reference"),
            Self::Emerging => f.write_str("emerging"),
            Self::Established => f.write_str("established"),
            Self::Mature => f.write_str("mature"),
        }
    }
}
