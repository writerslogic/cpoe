// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!();

pub mod analysis;
pub mod anchors;
pub mod api_types;
pub mod baseline;
pub mod calibration;
pub mod checkpoint;
pub mod checkpoint_mmr;
pub mod codec;
pub mod collaboration;
pub mod compact_ref;
pub mod config;
pub mod continuation;
pub mod crypto;
pub mod declaration;
pub mod engine;
pub mod error;
pub mod evidence;
pub mod fingerprint;
pub mod forensics;
pub mod identity;
pub mod ipc;
pub mod jitter;
pub mod keyhierarchy;
pub mod mmr;
pub mod physics;
pub mod platform;
pub mod presence;
pub mod provenance;
pub mod research;
pub mod rfc;
pub mod sealed_chain;
pub mod sealed_identity;
pub mod sentinel;
pub mod store;
pub mod timing;
pub mod tpm;
pub mod transcription;
pub mod trust_policy;
pub mod vdf;
pub mod wal;
pub mod war;
#[cfg(feature = "witnessd_jitter")]
pub mod witnessd_jitter_bridge;
pub mod writersproof;

/// Extension trait for safe nanosecond timestamps.
///
/// `DateTime::timestamp_nanos_opt()` returns `None` for dates past ~2262 (i64 overflow).
/// This trait provides a safe fallback that preserves nanosecond precision when possible
/// and falls back to millisecond-derived nanoseconds otherwise.
pub(crate) trait DateTimeNanosExt {
    fn timestamp_nanos_safe(&self) -> i64;
}

impl DateTimeNanosExt for chrono::DateTime<chrono::Utc> {
    fn timestamp_nanos_safe(&self) -> i64 {
        self.timestamp_nanos_opt()
            .unwrap_or_else(|| self.timestamp_millis().saturating_mul(1_000_000))
    }
}

// Re-export common types
pub use crate::config::{FingerprintConfig, PrivacyConfig, ResearchConfig, SentinelConfig};
pub use crate::crypto::{compute_event_hash, compute_event_hmac, derive_hmac_key};
pub use crate::identity::MnemonicHandler;
pub use crate::physics::PhysicalContext;
pub use crate::research::{
    AnonymizedSession, ResearchCollector, ResearchDataExport, ResearchUploader, UploadResult,
};
pub use crate::sentinel::{
    ChangeEvent, ChangeEventType, DaemonManager, DaemonState, DaemonStatus, DocumentSession,
    FocusEvent, FocusEventType, Sentinel, SentinelError, SessionEvent, SessionEventType,
    ShadowManager, WindowInfo,
};
pub use crate::store::{SecureEvent, SecureStore};
pub use crate::vdf::{RoughtimeClient, TimeAnchor, TimeKeeper, VdfProof};

// Re-export collaboration types
pub use crate::collaboration::{
    CollaborationMode, CollaborationPolicy, CollaborationSection, Collaborator, CollaboratorRole,
    ContributionClaim, ContributionSummary, ContributionType, MergeEvent, MergeRecord,
    MergeStrategy, TimeInterval,
};

// Re-export compact reference types
pub use crate::compact_ref::{
    CompactEvidenceRef, CompactMetadata, CompactRefBuilder, CompactRefError, CompactSummary,
};

// Re-export continuation types
pub use crate::continuation::{ContinuationSection, ContinuationSummary};

// Re-export provenance types
pub use crate::provenance::{
    DerivationClaim, DerivationType, ProvenanceLink, ProvenanceMetadata, ProvenanceSection,
};

// Re-export trust policy types
pub use crate::trust_policy::{
    AppraisalPolicy, FactorEvidence, FactorType, PolicyMetadata, ThresholdType, TrustComputation,
    TrustFactor, TrustThreshold,
};

// Re-export VDF aggregation types
pub use crate::vdf::{
    AggregateError, AggregateMetadata, AggregationMethod, MerkleSample, MerkleVdfBuilder,
    MerkleVdfProof, SnarkScheme, SnarkVdfProof, VdfAggregateProof, VerificationMode,
};

// Re-export fingerprint types
pub use crate::fingerprint::{
    ActivityFingerprint, AuthorFingerprint, ConsentManager, ConsentStatus, FingerprintComparison,
    FingerprintManager, FingerprintStatus, ProfileId, VoiceFingerprint,
};

// Re-export RFC-compliant types
pub use crate::rfc::{
    BiologyInvariantClaim, BiologyScoringParameters, BlockchainAnchor, CalibrationAttestation,
    JitterBinding, RoughtimeSample, TimeBindingTier, TimeEvidence, TsaResponse, ValidationStatus,
    VdfProofRfc,
};

// Re-export wire format types (CDDL-conformant)
pub use crate::rfc::wire_types::{
    AttestationResultWire, CheckpointWire, DocumentRef as WireDocumentRef, EvidencePacketWire,
    HashAlgorithm, HashValue as WireHashValue, ProcessProof as WireProcessProof, Verdict,
    CBOR_TAG_ATTESTATION_RESULT, CBOR_TAG_EVIDENCE_PACKET as CBOR_TAG_EVIDENCE_PACKET_WIRE,
};

// Re-export unified error types
pub use crate::error::{Error, Result};

#[cfg(feature = "witnessd_jitter")]
pub use crate::witnessd_jitter_bridge::{
    EntropyQuality, HybridEvidence, HybridJitterSession, HybridSample, ZoneTrackingEngine,
};

/// Re-export pop-crate for protocol integration.
pub use witnessd_protocol;

#[cfg(target_os = "macos")]
#[macro_use]
extern crate objc;
