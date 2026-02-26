// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

//! Evidence component types for wire-format structures.
//!
//! Implements `document-ref`, `edit-delta`, `proof-params`, `merkle-proof`,
//! `process-proof`, `jitter-binding`, `physical-state`, `physical-liveness`,
//! `presence-challenge`, `channel-binding`, `self-receipt`, `active-probe`,
//! and `profile-declaration` from the CDDL schema.

use serde::{Deserialize, Serialize};

use super::enums::{BindingType, HashSaltMode, ProbeType, ProofAlgorithm};
use super::hash::HashValue;
use super::serde_helpers::{fixed_bytes_32, fixed_bytes_32_opt, serde_bytes_opt};

/// Document reference per CDDL `document-ref`.
///
/// ```cddl
/// document-ref = {
///     1 => hash-value,
///     ? 2 => tstr,
///     3 => uint,
///     4 => uint,
///     ? 5 => hash-salt-mode,
///     ? 6 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentRef {
    /// Content hash of the document
    #[serde(rename = "1")]
    pub content_hash: HashValue,

    /// Optional filename
    #[serde(rename = "2", default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,

    /// Total byte length of document
    #[serde(rename = "3")]
    pub byte_length: u64,

    /// Character count of document
    #[serde(rename = "4")]
    pub char_count: u64,

    /// Hash salting mode
    #[serde(rename = "5", default, skip_serializing_if = "Option::is_none")]
    pub salt_mode: Option<HashSaltMode>,

    /// Salt commitment (hash of author salt)
    #[serde(
        rename = "6",
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_opt"
    )]
    pub salt_commitment: Option<Vec<u8>>,
}

/// Edit delta per CDDL `edit-delta`.
///
/// ```cddl
/// edit-delta = {
///     1 => uint,
///     2 => uint,
///     3 => uint,
///     ? 4 => [* edit-position],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditDelta {
    /// Characters added in this checkpoint interval
    #[serde(rename = "1")]
    pub chars_added: u64,

    /// Characters deleted in this checkpoint interval
    #[serde(rename = "2")]
    pub chars_deleted: u64,

    /// Number of edit operations
    #[serde(rename = "3")]
    pub op_count: u64,

    /// Optional position-change pairs (offset, change)
    #[serde(rename = "4", default, skip_serializing_if = "Option::is_none")]
    pub positions: Option<Vec<(u64, i64)>>,
}

/// Proof parameters per CDDL `proof-params`.
///
/// ```cddl
/// proof-params = {
///     1 => uint,  ; time-cost
///     2 => uint,  ; memory-cost (KiB)
///     3 => uint,  ; parallelism
///     4 => uint,  ; iterations
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofParams {
    /// Time cost parameter (t)
    #[serde(rename = "1")]
    pub time_cost: u64,

    /// Memory cost parameter (m, in KiB)
    #[serde(rename = "2")]
    pub memory_cost: u64,

    /// Parallelism parameter (p)
    #[serde(rename = "3")]
    pub parallelism: u64,

    /// Number of iterations
    #[serde(rename = "4")]
    pub iterations: u64,
}

/// Merkle proof per CDDL `merkle-proof`.
///
/// ```cddl
/// merkle-proof = {
///     1 => uint,
///     2 => [+ hash-digest],
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf in the Merkle tree
    #[serde(rename = "1")]
    pub leaf_index: u64,

    /// Sibling path hashes from leaf to root
    #[serde(rename = "2")]
    pub sibling_path: Vec<serde_bytes::ByteBuf>,

    /// The leaf value being proved
    #[serde(rename = "3", with = "serde_bytes")]
    pub leaf_value: Vec<u8>,
}

/// Sequential work function proof per CDDL `process-proof`.
///
/// ```cddl
/// process-proof = {
///     1 => proof-algorithm,
///     2 => proof-params,
///     3 => hash-digest,
///     4 => hash-digest,
///     5 => [+ merkle-proof],
///     6 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessProof {
    /// Algorithm identifier
    #[serde(rename = "1")]
    pub algorithm: ProofAlgorithm,

    /// SWF parameters
    #[serde(rename = "2")]
    pub params: ProofParams,

    /// Input seed (hash digest)
    #[serde(rename = "3", with = "serde_bytes")]
    pub input: Vec<u8>,

    /// Merkle root of computation chain
    #[serde(rename = "4", with = "serde_bytes")]
    pub merkle_root: Vec<u8>,

    /// Sampled Merkle proofs for verification
    #[serde(rename = "5")]
    pub sampled_proofs: Vec<MerkleProof>,

    /// Claimed duration in milliseconds
    #[serde(rename = "6")]
    pub claimed_duration: u64,
}

/// Jitter binding (behavioral entropy) per CDDL `jitter-binding`.
///
/// ```cddl
/// jitter-binding = {
///     1 => [+ uint],
///     2 => uint,
///     3 => hash-digest,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitterBindingWire {
    /// Inter-keystroke intervals in milliseconds
    #[serde(rename = "1")]
    pub intervals: Vec<u64>,

    /// Entropy estimate in centibits
    #[serde(rename = "2")]
    pub entropy_estimate: u64,

    /// Jitter seal (HMAC commitment)
    #[serde(rename = "3", with = "serde_bytes")]
    pub jitter_seal: Vec<u8>,
}

/// Physical state binding per CDDL `physical-state`.
///
/// ```cddl
/// physical-state = {
///     1 => [+ int],
///     2 => int,
///     ? 3 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalState {
    /// Thermal readings (relative, millidegrees)
    #[serde(rename = "1")]
    pub thermal: Vec<i64>,

    /// Entropy delta (signed)
    #[serde(rename = "2")]
    pub entropy_delta: i64,

    /// Optional kernel commitment (32 bytes)
    #[serde(
        rename = "3",
        default,
        skip_serializing_if = "Option::is_none",
        with = "fixed_bytes_32_opt"
    )]
    pub kernel_commitment: Option<[u8; 32]>,
}

/// Physical liveness markers per CDDL `physical-liveness`.
///
/// ```cddl
/// physical-liveness = {
///     1 => [+ thermal-sample],
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalLiveness {
    /// Thermal trajectory samples (timestamp, temperature delta in millidegrees)
    #[serde(rename = "1")]
    pub thermal_trajectory: Vec<(u64, i64)>,

    /// Entropy anchor (32 bytes)
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub entropy_anchor: [u8; 32],
}

/// Presence challenge per CDDL `presence-challenge`.
///
/// ```cddl
/// presence-challenge = {
///     1 => bstr .size (16..256),
///     2 => bstr,
///     3 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceChallenge {
    /// Challenge nonce (128+ bits)
    #[serde(rename = "1", with = "serde_bytes")]
    pub challenge_nonce: Vec<u8>,

    /// Device signature (COSE_Sign1)
    #[serde(rename = "2", with = "serde_bytes")]
    pub device_signature: Vec<u8>,

    /// Response time (epoch milliseconds)
    #[serde(rename = "3")]
    pub response_time: u64,
}

/// Channel binding per CDDL `channel-binding`.
///
/// ```cddl
/// channel-binding = {
///     1 => binding-type,
///     2 => bstr .size 32,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelBinding {
    /// Binding type
    #[serde(rename = "1")]
    pub binding_type: BindingType,

    /// Binding value (EKM output, 32 bytes)
    #[serde(rename = "2", with = "fixed_bytes_32")]
    pub binding_value: [u8; 32],
}

/// Self-receipt for cross-tool composition per CDDL `self-receipt`.
///
/// ```cddl
/// self-receipt = {
///     1 => tstr,
///     2 => hash-value / compact-ref,
///     3 => hash-value / compact-ref,
///     4 => pop-timestamp,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfReceipt {
    /// Tool identifier (source environment)
    #[serde(rename = "1")]
    pub tool_id: String,

    /// Output commitment (hash of tool output)
    #[serde(rename = "2")]
    pub output_commit: HashValue,

    /// Evidence reference (hash of source evidence packet)
    #[serde(rename = "3")]
    pub evidence_ref: HashValue,

    /// Transfer time (epoch milliseconds)
    #[serde(rename = "4")]
    pub transfer_time: u64,
}

/// Active liveness probe per CDDL `active-probe`.
///
/// ```cddl
/// active-probe = {
///     1 => probe-type,
///     2 => pop-timestamp,
///     3 => pop-timestamp,
///     4 => bstr,
///     5 => bstr,
///     ? 6 => uint,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveProbe {
    /// Challenge category
    #[serde(rename = "1")]
    pub probe_type: ProbeType,

    /// Stimulus delivery time (epoch milliseconds)
    #[serde(rename = "2")]
    pub stimulus_time: u64,

    /// Response capture time (epoch milliseconds)
    #[serde(rename = "3")]
    pub response_time: u64,

    /// Stimulus data (challenge payload)
    #[serde(rename = "4", with = "serde_bytes")]
    pub stimulus_data: Vec<u8>,

    /// Response data (captured response)
    #[serde(rename = "5", with = "serde_bytes")]
    pub response_data: Vec<u8>,

    /// Optional response latency in milliseconds
    #[serde(rename = "6", default, skip_serializing_if = "Option::is_none")]
    pub response_latency: Option<u64>,
}

/// Profile declaration per CDDL `profile-declaration`.
///
/// ```cddl
/// profile-declaration = {
///     1 => tstr,
///     2 => [+ uint],
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDeclarationWire {
    /// Profile identifier URI
    #[serde(rename = "1")]
    pub profile_id: String,

    /// Feature flags (list of enabled feature IDs)
    #[serde(rename = "2")]
    pub feature_flags: Vec<u64>,
}
