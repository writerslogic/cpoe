// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! CDDL-defined enumerations for draft-condrey-rats-pop wire format.

use serde::{Deserialize, Serialize};

/// Hash algorithm identifier per CDDL `hash-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashAlgorithm {
    /// SHA-256 (32-byte digest)
    Sha256 = 1,
    /// SHA-384 (48-byte digest)
    Sha384 = 2,
    /// SHA-512 (64-byte digest)
    Sha512 = 3,
}

/// Attestation tier per CDDL `attestation-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AttestationTier {
    /// T1: Software-only (AAL1)
    SoftwareOnly = 1,
    /// T2: Attested software (AAL2)
    AttestedSoftware = 2,
    /// T3: Hardware-bound (AAL3)
    HardwareBound = 3,
    /// T4: Hardware-hardened (LoA4)
    HardwareHardened = 4,
}

/// Content tier per CDDL `content-tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentTier {
    /// Core tier: minimal required evidence
    Core = 1,
    /// Enhanced tier: additional behavioral evidence
    Enhanced = 2,
    /// Maximum tier: full evidence including hardware
    Maximum = 3,
}

/// Proof algorithm identifier per CDDL `proof-algorithm`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProofAlgorithm {
    /// Sequential work function using Argon2id
    SwfArgon2id = 20,
    /// Entangled sequential work function using Argon2id
    SwfArgon2idEntangled = 21,
}

/// Appraisal verdict per CDDL `verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Verdict {
    /// Consistent with human authorship
    Authentic = 1,
    /// Insufficient evidence
    Inconclusive = 2,
    /// Anomalies detected
    Suspicious = 3,
    /// Chain broken or forged
    Invalid = 4,
}

/// Hash salt mode per CDDL `hash-salt-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum HashSaltMode {
    /// No salt applied
    Unsalted = 0,
    /// Author-provided salt
    AuthorSalted = 1,
}

/// Cost unit for forgery estimates per CDDL `cost-unit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CostUnit {
    /// US Dollars
    Usd = 1,
    /// CPU hours
    CpuHours = 2,
}

/// Absence claim type per CDDL `absence-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AbsenceType {
    /// Verifiable from evidence alone
    ComputationallyBound = 1,
    /// Requires trust in AE monitoring
    MonitoringDependent = 2,
    /// Environmental assertions
    Environmental = 3,
}

/// Active probe type per CDDL `probe-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProbeType {
    /// Galton invariant challenge
    GaltonBoard = 1,
    /// Motor reflex timing gate
    ReflexGate = 2,
    /// Spatial accuracy challenge
    SpatialTarget = 3,
}

/// Channel binding type per CDDL `binding-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BindingType {
    /// TLS Exporter Key Material
    TlsExporter = 1,
}
